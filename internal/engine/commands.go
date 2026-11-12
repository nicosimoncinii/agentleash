package engine

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

// Command pattern semantics (commands.deny / commands.ask, design.md §5):
//
//   - '*' matches any run of characters, including '/' and spaces; '?' one
//     character; "\*" a literal '*'. Patterns are anchored (whole command).
//   - Patterns are matched against every simple command after
//     normalisation: words are unquoted and joined with single spaces, the
//     command name is reduced to its lower-case basename (/bin/RM -> rm), and
//     wrappers (sudo, env VAR=x, nohup, timeout N, nice, command, time, xargs,
//     sh -c, eval, find -exec, ...) are stripped by matching the inner
//     command too.
//   - Each command is also matched in a canonical form where short-flag
//     clusters are merged and sorted (rm -r -f / == rm -fr / == rm -rf /),
//     "--" is dropped and path arguments are cleaned (// -> /); patterns are
//     canonicalised the same way.
//   - git: global options (-C dir, -c k=v, --git-dir=...) are removed, and
//     `git push` with -f or a +refspec is also matched as `git push --force`.
//   - A pattern containing '|' matches consecutive pipeline stages, each
//     stage matched as above (with wrappers stripped).
//   - An argument only known at runtime ($X, $(...)) may match anything;
//     such a match is downgraded from deny to ask.
//   - Precedence: deny > ask > allow.

// subjectText converts an alternative to command-matching text: escapes are
// removed (a quoted '*' is a literal star), runtime parts become dynAny.
func subjectText(alt string) string {
	var b strings.Builder
	for i := 0; i < len(alt); i++ {
		c := alt[i]
		switch {
		case c == '\\' && i+1 < len(alt):
			i++
			b.WriteByte(alt[i])
		case c == dynStar:
			b.WriteByte(dynAny)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// argvVariants returns the textual argvs of a command (product of
// alternatives, bounded).
func argvVariants(args []cmdArg) [][]string {
	out := [][]string{nil}
	for _, a := range args {
		alts := a.alts
		if len(out)*len(alts) > 16 {
			alts = alts[:1]
		}
		var next [][]string
		for _, prefix := range out {
			for _, alt := range alts {
				v := append(append([]string(nil), prefix...), subjectText(alt))
				next = append(next, v)
			}
		}
		out = next
	}
	return out
}

func normalizeTokens(tokens []string) []string {
	var out []string
	for _, t := range tokens {
		if strings.TrimSpace(t) == "" && t != "" {
			continue
		}
		out = append(out, t)
	}
	if len(out) > 0 {
		out[0] = cmdBase(out[0])
	}
	return out
}

// rmLong maps rm's long options to short letters ("" drops the option:
// it does not change what is deleted).
var rmLong = map[string]string{
	"--recursive": "r", "--force": "f", "--no-preserve-root": "", "--preserve-root": "",
	"--preserve-root=all": "", "--one-file-system": "", "--verbose": "", "--dir": "",
	"--interactive=never": "",
}

// canonical merges short-flag clusters, drops "--", cleans paths and spells
// the home directory "~" and drive roots "/". For rm, -R/--recursive and
// --force are folded into -r/-f and options that do not change what is
// deleted are dropped, so `rm --recursive --force --no-preserve-root /`
// canonicalises like `rm -rf /`.
func canonical(tokens []string, home string) []string {
	if len(tokens) == 0 {
		return nil
	}
	isRm := tokens[0] == "rm"
	letters := map[rune]bool{}
	var rest []string
	for _, t := range tokens[1:] {
		switch {
		case t == "--":
			continue
		case isRm && strings.HasPrefix(t, "--"):
			if l, ok := rmLong[t]; ok {
				if l != "" {
					letters[rune(l[0])] = true
				}
				continue
			}
			rest = append(rest, t)
		case len(t) > 1 && t[0] == '-' && t[1] != '-' && allLetters(t[1:]):
			for _, r := range t[1:] {
				if isRm {
					switch r {
					case 'R':
						r = 'r'
					case 'r', 'f':
					default:
						continue // -v, -d, -I ... do not change the target
					}
				}
				letters[r] = true
			}
		default:
			rest = append(rest, homeRoot(cleanArg(t), home))
		}
	}
	out := []string{tokens[0]}
	if len(letters) > 0 {
		var ls []string
		for r := range letters {
			ls = append(ls, string(r))
		}
		sort.Strings(ls)
		out = append(out, "-"+strings.Join(ls, ""))
	}
	return append(out, rest...)
}

func cleanArg(t string) string {
	if !strings.Contains(t, "/") || strings.ContainsAny(t, "*?[\x00\x01") {
		return t
	}
	c := path.Clean(t)
	if strings.HasSuffix(t, "/") && c != "/" {
		c += "/"
	}
	return c
}

var driveArgRe = regexp.MustCompile(`^[A-Za-z]:(/(.*))?$`)

// homeRoot rewrites the home directory (literal path, ~, $HOME) to "~" and
// a Windows drive root to "/", so destructive patterns written for
// `rm -rf ~` / `rm -rf /` also cover `rm -rf "$HOME"`, `rm -rf /home/u/`
// and `Remove-Item -Recurse -Force C:\`.
func homeRoot(t, home string) string {
	t = strings.ReplaceAll(t, `\`, "/")
	for _, h := range []string{"${HOME}", "$HOME", "~"} {
		if t == h || t == h+"/" {
			return "~"
		}
		if strings.HasPrefix(t, h+"/") {
			return "~/" + t[len(h)+1:]
		}
	}
	if home != "" {
		h := strings.TrimSuffix(strings.ReplaceAll(home, `\`, "/"), "/")
		lt := strings.ToLower(t)
		lh := strings.ToLower(h)
		if strings.TrimSuffix(lt, "/") == lh {
			return "~"
		}
		if strings.HasPrefix(lt, lh+"/") {
			return "~/" + t[len(h)+1:]
		}
	}
	if m := driveArgRe.FindStringSubmatch(t); m != nil {
		return "/" + m[2]
	}
	return t
}

func allLetters(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return s != ""
}

var gitGlobalWithValue = set("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path", "--super-prefix")

// gitVariants strips git global options and spells force pushes out.
func gitVariants(tokens []string) [][]string {
	if len(tokens) == 0 || tokens[0] != "git" {
		return nil
	}
	i := 1
	for i < len(tokens) && strings.HasPrefix(tokens[i], "-") {
		if gitGlobalWithValue[tokens[i]] {
			i += 2
			continue
		}
		i++
	}
	if i > len(tokens) {
		i = len(tokens)
	}
	stripped := append([]string{"git"}, tokens[i:]...)
	out := [][]string{stripped}
	if len(stripped) > 1 && stripped[1] == "push" {
		force := false
		var args []string
		for _, t := range stripped[2:] {
			switch {
			case strings.HasPrefix(t, "+") && len(t) > 1:
				force = true
				args = append(args, t[1:])
			case t == "-f" || (len(t) > 1 && t[0] == '-' && t[1] != '-' && allLetters(t[1:]) && strings.ContainsRune(t, 'f')):
				force = true
			default:
				args = append(args, t)
			}
		}
		if force {
			out = append(out, append([]string{"git", "push", "--force"}, args...))
		}
	}
	return out
}

// commandForms returns every textual form a simple command is matched in.
func commandForms(tokens []string, home string) []string {
	tokens = normalizeTokens(tokens)
	if len(tokens) == 0 {
		return nil
	}
	forms := [][]string{tokens, canonical(tokens, home)}
	for _, g := range gitVariants(tokens) {
		forms = append(forms, g, canonical(g, home))
	}
	var out []string
	for _, f := range forms {
		out = append(out, strings.Join(f, " "))
	}
	return dedupe(out)
}

// patternForms normalises a policy pattern for one stage.
func patternForms(p, home string) []string {
	tokens := normalizeTokens(strings.Fields(p))
	if len(tokens) == 0 {
		return nil
	}
	return dedupe([]string{strings.Join(tokens, " "), strings.Join(canonical(tokens, home), " ")})
}

// formsMatch reports whether any pattern form matches any subject form;
// dynamic is true when every match relied on runtime-only parts.
func formsMatch(patterns, subjects []string) (matched, dynamic bool) {
	for _, p := range patterns {
		for _, sub := range subjects {
			if globMatchString(p, sub) {
				if !strings.ContainsRune(sub, dynAny) {
					return true, false
				}
				matched, dynamic = true, true
			}
		}
	}
	return matched, dynamic
}

// matchCommand checks one simple command (at one wrapper level).
func (s *shellEval) matchCommand(nameAlt string, args []cmdArg) {
	if isDynamic(nameAlt) {
		return
	}
	var subjects []string
	for _, argv := range argvVariants(args) {
		subjects = append(subjects, commandForms(argv, s.req.Home)...)
	}
	applyPatterns(s.e.policy, s.c, s.sec.work, s.req.Home, subjects, nil)
}

// applyPatterns matches single-command patterns (stages == nil) or pipeline
// patterns (stages != nil).
func applyPatterns(p *policy.Policy, c *collector, work *budget, home string, subjects []string, stages [][]string) {
	cost := (len(p.Commands.Deny) + len(p.Commands.Ask)) * (len(subjects) + 2*len(stages) + 1)
	if !work.spend(cost) {
		return
	}
	check := func(list []string, rule string, decision Decision) bool {
		for _, pat := range list {
			segs := splitPipePattern(pat)
			if len(segs) == 0 {
				continue
			}
			var matched, dynamic bool
			if stages == nil {
				if len(segs) != 1 {
					continue
				}
				matched, dynamic = formsMatch(patternForms(segs[0], home), subjects)
			} else {
				if len(segs) < 2 {
					continue
				}
				matched, dynamic = matchStages(segs, stages, home)
			}
			if !matched {
				continue
			}
			d := decision
			if dynamic {
				d = Ask
			}
			c.add(d, rule+":"+pat, commandReason(pat, decision, dynamic))
			return true
		}
		return false
	}
	if !check(p.Commands.Deny, RuleCommandDeny, Deny) {
		check(p.Commands.Ask, RuleCommandAsk, Ask)
	}
}

func splitPipePattern(p string) []string {
	var out []string
	for _, seg := range strings.Split(p, "|") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			return nil
		}
		out = append(out, seg)
	}
	return out
}

func matchStages(segs []string, stages [][]string, home string) (matched, dynamic bool) {
	for start := 0; start+len(segs) <= len(stages); start++ {
		ok, dyn := true, false
		for j, seg := range segs {
			m, d := formsMatch(patternForms(seg, home), stages[start+j])
			if !m {
				ok = false
				break
			}
			dyn = dyn || d
		}
		if ok {
			if !dyn {
				return true, false
			}
			matched, dynamic = true, true
		}
	}
	return matched, dynamic
}

func commandReason(pat string, decision Decision, dynamic bool) string {
	switch {
	case dynamic && decision == Deny:
		return fmt.Sprintf("this command contains a value only known at runtime and could expand to a command blocked by commands.deny %q in .agentleash.yaml; the user must confirm it. Prefer literal arguments.", pat)
	case decision == Deny:
		return fmt.Sprintf("this command is blocked by commands.deny %q in .agentleash.yaml. Do not try to run it another way; if it is really needed, ask the user to run it themselves.", pat)
	default:
		return fmt.Sprintf("this command matches commands.ask %q in .agentleash.yaml and needs the user's confirmation.", pat)
	}
}

// matchPipeline matches '|' patterns against a whole pipeline.
func (s *shellEval) matchPipeline(b *syntax.BinaryCmd) {
	var stmts []*syntax.Stmt
	var flatten func(st *syntax.Stmt)
	flatten = func(st *syntax.Stmt) {
		if bc, ok := st.Cmd.(*syntax.BinaryCmd); ok && (bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll) {
			s.pipeSeen[bc] = true
			flatten(bc.X)
			flatten(bc.Y)
			return
		}
		stmts = append(stmts, st)
	}
	s.pipeSeen[b] = true
	flatten(b.X)
	flatten(b.Y)
	stages := make([][]string, len(stmts))
	for i, st := range stmts {
		call, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			stages[i] = []string{string(dynAny) + "\x02"} // compound stage: never matches a literal pattern
			continue
		}
		args := make([]cmdArg, len(call.Args))
		for k, w := range call.Args {
			args[k] = cmdArg{alts: s.wordAlts(w, modePattern)}
		}
		for _, argv := range argvVariants(args) {
			for _, level := range unwrapLevels(argv) {
				stages[i] = append(stages[i], commandForms(level, s.req.Home)...)
			}
		}
	}
	applyPatterns(s.e.policy, s.c, s.sec.work, s.req.Home, nil, stages)
}

// unwrapLevels returns argv and the argvs of the commands it wraps (sudo,
// env, nohup, timeout, ...), without side effects.
func unwrapLevels(argv []string) [][]string {
	out := [][]string{argv}
	for depth := 0; depth < 8 && len(argv) > 0; depth++ {
		name := cmdBase(argv[0])
		args := argv[1:]
		i := 0
		if name == "env" {
			for i < len(args) && (strings.HasPrefix(args[i], "-") || (strings.IndexByte(args[i], '=') > 0 && isIdent(args[i][:strings.IndexByte(args[i], '=')]))) {
				if args[i] == "-u" || args[i] == "-C" {
					i++
				}
				i++
			}
		} else {
			spec, ok := wrapSpecs[name]
			if !ok {
				break
			}
			for i < len(args) && strings.HasPrefix(args[i], "-") && args[i] != "-" {
				if args[i] == "--" {
					i++
					break
				}
				if spec.long[args[i]] || (len(args[i]) == 2 && strings.ContainsRune(spec.short, rune(args[i][1]))) {
					i++
				}
				i++
			}
			i += spec.positional
		}
		if i >= len(args) {
			break
		}
		argv = args[i:]
		out = append(out, argv)
	}
	return out
}
