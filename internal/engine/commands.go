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
//   - A path argument that is the filesystem root, the home directory or an
//     ancestor of the home directory (also through a glob matching every
//     entry, a relative path resolved against the working directory, or
//     ~/..) is also spelled "/" or "~"; rm operands are matched one by one;
//     dd operands are reordered (if= first, of= last).
//   - git: global options (-C dir, -c k=v, --git-dir=...) are removed,
//     aliases (-c alias.x=..., git config alias.x ... in the same script) are
//     expanded, and `git push` with -f, --mirror, an abbreviated --force or a
//     +refspec (and `git send-pack --force`) is also matched as
//     `git push --force`; abbreviated `git reset --ha` is `--hard`.
//   - A pattern containing '|' matches consecutive pipeline stages, each
//     stage matched as above (with wrappers stripped). A stage that runs
//     code from stdin (sh, sudo -s, pwsh, python with no program, ...) is
//     also matched as `sh` and `bash`. Process substitution (`python3
//     <(curl ...)`) and download-then-run in the same script (`curl -o f
//     ...; sh f`) are matched as the equivalent pipeline.
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
		if len(alts) == 1 {
			// No branching: extend every variant in place (each variant
			// owns its slice), so long commands stay linear.
			t := subjectText(alts[0])
			for i := range out {
				out[i] = append(out[i], t)
			}
			continue
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

// rmLongOpts are GNU rm's long options; getopt accepts any unambiguous
// prefix (--rec = --recursive, --f = --force).
var rmLongOpts = []string{"--force", "--interactive", "--one-file-system", "--no-preserve-root",
	"--preserve-root", "--recursive", "--dir", "--verbose", "--help", "--version"}

// expandLong spells an abbreviated long option (--rec, --inter=never) in
// full when it is an exact or unambiguous prefix of one of opts, as GNU
// getopt_long does. Anything else is returned unchanged.
func expandLong(t string, opts []string) string {
	name, val, hasVal := strings.Cut(t, "=")
	if len(name) < 3 || !strings.HasPrefix(name, "--") {
		return t
	}
	hit := ""
	for _, o := range opts {
		if o == name {
			hit = o
			break
		}
		if strings.HasPrefix(o, name) {
			if hit != "" {
				return t // ambiguous: the program rejects it
			}
			hit = o
		}
	}
	if hit == "" {
		return t
	}
	if hasVal {
		return hit + "=" + val
	}
	return hit
}

// isAbbrev reports whether t is full or a prefix of it with at least min
// characters (git and getopt accept abbreviated long options).
func isAbbrev(t, full string, minLen int) bool {
	return len(t) >= minLen && strings.HasPrefix(full, t)
}

// canonical merges short-flag clusters, drops "--", cleans paths and spells
// the home directory "~" and drive roots "/". For rm, -R/--recursive and
// --force (or an unambiguous abbreviation) are folded into -r/-f, options
// that do not change what is deleted are dropped and empty operands are
// removed, so `rm --rec --for --no-preserve-root /` canonicalises like
// `rm -rf /`.
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
		case isRm && t == "":
			continue // rm "" only prints an error
		case isRm && strings.HasPrefix(t, "--"):
			if l, ok := rmLong[expandLong(t, rmLongOpts)]; ok {
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
			rest = append(rest, homeRoot(cleanArg(strings.ReplaceAll(t, `\`, "/")), home))
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
	if (t[0] == '~' || t[0] == '$') && hasDotDot(t) {
		// path.Clean("~/..") is ".": "~" and "$HOME" are not directory names
		// that ".." cancels. dangerTarget resolves such paths.
		return t
	}
	c := path.Clean(t)
	if strings.HasSuffix(t, "/") && c != "/" {
		c += "/"
	}
	return c
}

func hasDotDot(t string) bool {
	for _, seg := range strings.Split(t, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

var driveArgRe = regexp.MustCompile(`^[A-Za-z]:(/(.*))?$`)

// homeRoot rewrites the home directory (literal path, ~, ~user of the same
// user, $HOME, Git Bash /c/Users/u) to "~" and a Windows drive root to "/",
// so destructive patterns written for `rm -rf ~` / `rm -rf /` also cover
// `rm -rf "$HOME"`, `rm -rf /home/u/` and `Remove-Item -Recurse -Force C:\`.
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
		if user := path.Base(lh); user != "" && user != "/" && strings.HasPrefix(lt, "~"+user) {
			// ~user is the home directory when user is the current user.
			if r := lt[1+len(user):]; r == "" || r == "/" {
				return "~"
			} else if r[0] == '/' {
				return "~" + t[1+len(user):]
			}
		}
		if strings.TrimSuffix(lt, "/") == lh {
			return "~"
		}
		if strings.HasPrefix(lt, lh+"/") {
			return "~/" + t[len(h)+1:]
		}
		if driveRe.MatchString(lh) {
			// Git Bash / Cygwin / WSL spellings of a Windows home.
			mh := mapDrivePrefixes(lh)
			mt := mapDrivePrefixes(lt)
			if strings.TrimSuffix(mt, "/") == mh {
				return "~"
			}
			if strings.HasPrefix(mt, mh+"/") {
				return "~/" + t[len(t)-(len(mt)-len(mh)-1):]
			}
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

// cmdCtx is what command normalisation knows about the request.
type cmdCtx struct {
	home    string   // Request.Home as given
	homeInt string   // home in internal syntax ("" when unknown)
	bases   []string // possible working directories (internal); nil when unknown
	// gitAliases are aliases defined in the same script
	// (`git config alias.x 'push -f'`); nil when none can be.
	gitAliases *gitAliasSet
	// work is the request's budget (nil: unbounded, e.g. PowerShell).
	work *budget
}

func plainCtx(home string) cmdCtx {
	return cmdCtx{home: home, homeInt: normalizeAbs(home)}
}

func (s *shellEval) cmdCtx() cmdCtx {
	ctx := cmdCtx{home: s.req.Home, homeInt: s.sec.home, gitAliases: s.gitAliases, work: s.sec.work}
	if ctx.homeInt == "" {
		ctx.homeInt = normalizeAbs(s.req.Home)
	}
	if !s.sec.basesUnknown {
		ctx.bases = s.sec.bases
	}
	return ctx
}

var driveRootRe = regexp.MustCompile(`^[a-z]:/?$`)

// unknownHome stands for the home directory when Request.Home is unknown.
const unknownHome = "/\x02/\x02home"

// matchesAll reports whether a path segment is a glob that matches every
// (non-hidden) entry of its directory: *, **, ?*, *?* ...
func matchesAll(seg string) bool {
	if !strings.Contains(seg, "*") {
		return false
	}
	return strings.Trim(seg, "*?") == ""
}

// splitLast splits a path into its directory and last segment, ignoring
// trailing slashes. The directory of a single relative segment is ".".
func splitLast(t string) (dir, last string) {
	s := strings.TrimRight(t, "/")
	if s == "" {
		return "/", ""
	}
	i := strings.LastIndexByte(s, '/')
	switch {
	case i < 0:
		return ".", s
	case i == 0:
		return "/", s[1:]
	}
	return s[:i], s[i+1:]
}

// dangerTarget returns "/" when the path argument t (canonical text) is the
// filesystem or a drive root, "~" when it is the home directory or one of
// its ancestors, and "" otherwise. A trailing glob that matches everything
// (/*, ~/*) counts as its directory, ~/.. is resolved against the home, and
// a relative path against every possible working directory (cd targets of
// the same script included).
func (ctx cmdCtx) dangerTarget(t string) string {
	if t == "" || strings.ContainsAny(t, "\x00\x01") {
		return ""
	}
	t = strings.ReplaceAll(t, `\`, "/")
	for {
		dir, last := splitLast(t)
		if !matchesAll(last) {
			break
		}
		t = dir
	}
	if strings.ContainsAny(t, "*?[") {
		return ""
	}
	home := ctx.homeInt
	if home == "" {
		home = unknownHome
	}
	windows := driveRe.MatchString(home)
	l := strings.ToLower(t)
	var cands []string
	switch {
	case l == "~" || strings.HasPrefix(l, "~/"):
		cands = []string{home + l[1:]}
	case strings.HasPrefix(l, "~"):
		return "" // another user's home (~user of the same user is "~" already)
	case strings.HasPrefix(l, "$"):
		return ""
	case strings.HasPrefix(l, "/") || driveRe.MatchString(l):
		cands = []string{l}
		if windows && strings.HasPrefix(l, "/") {
			// homeRoot spells C:/x as /x; Git Bash spells it /c/x.
			cands = append(cands, mapDrivePrefixes(l), home[:2]+l)
		}
	default:
		for _, b := range ctx.bases {
			cands = append(cands, b+"/"+l)
		}
	}
	verdict := ""
	for _, c := range cands {
		r := cleanInternal(c)
		switch {
		case r == "/" || driveRootRe.MatchString(r):
			return "/"
		case r == home || strings.HasPrefix(home, strings.TrimSuffix(r, "/")+"/"):
			verdict = "~"
		}
	}
	return verdict
}

// dangerForm spells root/home(-ancestor) arguments "/" and "~"; nil when
// nothing changed.
func (ctx cmdCtx) dangerForm(c []string) []string {
	out := []string{c[0]}
	changed := false
	for _, t := range c[1:] {
		if !strings.HasPrefix(t, "-") {
			if d := ctx.dangerTarget(t); d != "" && d != t {
				t = d
				changed = true
			}
		}
		out = append(out, t)
	}
	if !changed {
		return nil
	}
	return out
}

// rmOperandForms returns `rm FLAGS OP` for every operand of a multi-operand
// rm: each operand is deleted independently (rm -rf ./build / is rm -rf /).
func rmOperandForms(c []string) [][]string {
	var flags, ops []string
	for _, t := range c[1:] {
		if strings.HasPrefix(t, "-") && t != "-" {
			flags = append(flags, t)
		} else {
			ops = append(ops, t)
		}
	}
	if len(ops) < 2 {
		return nil
	}
	var out [][]string
	for _, op := range ops {
		out = append(out, append(append([]string{"rm"}, flags...), op))
	}
	return out
}

// ddForm reorders dd's order-free operands: if= first (if=/dev/stdin when
// absent), of= last, so `dd * of=/dev/*` matches `dd of=/dev/sda if=x`.
func ddForm(c []string) []string {
	var ifs, mid, ofs []string
	for _, t := range c[1:] {
		switch {
		case strings.HasPrefix(t, "if="):
			ifs = append(ifs, t)
		case strings.HasPrefix(t, "of="):
			ofs = append(ofs, t)
		default:
			mid = append(mid, t)
		}
	}
	if len(ofs) == 0 {
		return nil
	}
	if len(ifs) == 0 {
		ifs = []string{"if=/dev/stdin"}
	}
	out := append([]string{"dd"}, ifs...)
	out = append(out, mid...)
	return append(out, ofs...)
}

var gitGlobalWithValue = set("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path", "--super-prefix")

// Git alias limits. Exceeding one fails closed: the request is denied as
// too complex (or, without a work budget, every git pattern matches as a
// runtime value, i.e. ask).
const (
	maxGitAliasValues = 8  // values recorded for one alias name
	maxGitAliasNames  = 64 // alias names defined in one request
	maxGitExpansions  = 32 // git or shell commands one call may expand to
)

// gitAliasSet holds git aliases (lower-case name -> values). Values
// starting with '!' are shell aliases.
type gitAliasSet struct {
	byName   map[string][]string
	overflow bool
	// shellDone records the shell alias commands already analysed.
	shellDone map[string]bool
}

func newGitAliasSet() *gitAliasSet {
	return &gitAliasSet{byName: map[string][]string{}, shellDone: map[string]bool{}}
}

// add records alias.NAME=VALUE (other keys are ignored).
func (a *gitAliasSet) add(key, val string) {
	if a == nil {
		return
	}
	key = strings.ToLower(key)
	if !strings.HasPrefix(key, "alias.") || len(key) == len("alias.") {
		return
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	name := key[len("alias."):]
	vals, known := a.byName[name]
	if containsStr(vals, val) {
		return
	}
	if len(vals) >= maxGitAliasValues || (!known && len(a.byName) >= maxGitAliasNames) {
		a.overflow = true
		return
	}
	a.byName[name] = append(vals, val)
}

func (a *gitAliasSet) values(name string) []string {
	if a == nil {
		return nil
	}
	return a.byName[name]
}

func (a *gitAliasSet) overflowed() bool { return a != nil && a.overflow }

// gitStrip removes git's global options; inline `-c alias.x=v` definitions
// are added to aliases when it is not nil.
func gitStrip(tokens []string, aliases *gitAliasSet) []string {
	i := 1
	for i < len(tokens) && strings.HasPrefix(tokens[i], "-") {
		if gitGlobalWithValue[tokens[i]] {
			if tokens[i] == "-c" && i+1 < len(tokens) {
				if k, v, ok := strings.Cut(tokens[i+1], "="); ok {
					aliases.add(k, v)
				}
			}
			i += 2
			continue
		}
		i++
	}
	if i > len(tokens) {
		i = len(tokens)
	}
	return append([]string{"git"}, tokens[i:]...)
}

// gitVariants strips git global options and spells force pushes out. The
// first element is always the stripped command.
func gitVariants(tokens []string) [][]string {
	v, _ := gitVariantsAliases(tokens, nil, nil)
	return v
}

// gitVariantsAliases is gitVariants with alias expansion (inline
// `-c alias.x=...` and aliases defined in the same script). ok is false
// when a limit was exceeded and some expansions are missing.
func gitVariantsAliases(tokens []string, script *gitAliasSet, work *budget) (out [][]string, ok bool) {
	cmds, _, ok := gitExpand(tokens, script, work)
	for _, c := range cmds {
		out = append(out, c)
		out = append(out, gitForceVariants(c)...)
	}
	return out, ok
}

// gitExpand strips git's global options and expands aliases the way git
// does: a plain alias replaces the subcommand (and may name another
// alias); a shell alias ('!cmd') runs `cmd ARGS...` with the call's
// remaining arguments appended. It returns the git commands and the shell
// commands the call may run; ok is false when a limit was exceeded.
func gitExpand(tokens []string, script *gitAliasSet, work *budget) (cmds [][]string, shellCmds []string, ok bool) {
	if len(tokens) == 0 || tokens[0] != "git" {
		return nil, nil, true
	}
	inline := newGitAliasSet()
	stripped := gitStrip(tokens, inline)
	cmds = [][]string{stripped}
	seen := map[string]bool{strings.Join(stripped, "\x00"): true}
	ok = true
	for k := 0; k < len(cmds) && ok; k++ {
		cur := cmds[k]
		if len(cur) < 2 {
			continue
		}
		name := strings.ToLower(cur[1])
		vals := append(append([]string(nil), inline.values(name)...), script.values(name)...)
		for _, v := range vals {
			if !work.spend(len(cur) + 1) {
				return cmds, shellCmds, false
			}
			if strings.HasPrefix(v, "!") {
				sc := v[1:] + shellArgs(cur[2:])
				if !containsStr(shellCmds, sc) {
					shellCmds = append(shellCmds, sc)
				}
			} else {
				exp := gitStrip(append(append([]string{"git"}, strings.Fields(v)...), cur[2:]...), inline)
				key := strings.Join(exp, "\x00")
				if seen[key] {
					continue
				}
				seen[key] = true
				cmds = append(cmds, exp)
			}
			if len(cmds)+len(shellCmds) > maxGitExpansions {
				ok = false
				break
			}
		}
	}
	return cmds, shellCmds, ok && !inline.overflow
}

// shellArgs renders arguments appended to a shell alias as shell words:
// metacharacters are escaped, glob characters stay active (git receives
// arguments the calling shell already expanded), and a runtime value
// becomes an unknown variable.
func shellArgs(args []string) string {
	var b strings.Builder
	for _, a := range args {
		b.WriteByte(' ')
		if strings.ContainsAny(a, "\x00\x01") {
			b.WriteString(`"${__agentleash_runtime_arg}"`)
			continue
		}
		if a == "" {
			b.WriteString("''")
			continue
		}
		for _, r := range a {
			if strings.ContainsRune(" \t\n'\"\\$`;&|<>(){}!#", r) {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// gitForceVariants returns `git push --force ARGS` for forced pushes (-f,
// --force or an abbreviation, --mirror, +refspec, send-pack --force) and
// `git reset --hard ...` for an abbreviated --hard.
func gitForceVariants(c []string) [][]string {
	if len(c) < 2 {
		return nil
	}
	switch c[1] {
	case "push", "send-pack":
		force := false
		var args []string
		for _, t := range c[2:] {
			name, _, _ := strings.Cut(t, "=")
			switch {
			case strings.HasPrefix(t, "+") && len(t) > 1:
				force = true
				args = append(args, t[1:])
			case t == "-f" || (len(t) > 1 && t[0] == '-' && t[1] != '-' && allLetters(t[1:]) && strings.ContainsRune(t, 'f')):
				force = true
			case isAbbrev(name, "--force", 3) || isAbbrev(name, "--mirror", 3):
				force = true
			default:
				args = append(args, t)
			}
		}
		if force {
			return [][]string{append([]string{"git", "push", "--force"}, args...)}
		}
	case "reset":
		changed := false
		out := []string{"git", "reset"}
		for _, t := range c[2:] {
			if t != "--hard" && isAbbrev(t, "--hard", 3) {
				t = "--hard"
				changed = true
			}
			out = append(out, t)
		}
		if changed {
			return [][]string{out}
		}
	}
	return nil
}

// recordGitConfigAlias records `git config [--global] alias.x VALUE` (and
// `git config set alias.x VALUE`) into aliases.
func recordGitConfigAlias(argv []string, aliases *gitAliasSet) {
	if len(argv) < 2 || cmdBase(argv[0]) != "git" {
		return
	}
	c := gitStrip(argv, aliases)
	if len(c) < 2 || c[1] != "config" {
		return
	}
	var ops []string
	for i := 2; i < len(c); i++ {
		t := c[i]
		switch {
		case t == "--file" || t == "-f" || t == "--blob" || t == "--type" || t == "--default" || t == "--comment" || t == "--value":
			i++
		case strings.HasPrefix(t, "-"):
		case t == "set" && len(ops) == 0:
		default:
			ops = append(ops, t)
		}
	}
	if len(ops) >= 2 {
		aliases.add(ops[0], ops[1])
	}
}

// commandForms returns every textual form a simple command is matched in.
func commandForms(tokens []string, home string) []string {
	return commandFormsCtx(tokens, plainCtx(home))
}

func commandFormsCtx(tokens []string, ctx cmdCtx) []string {
	tokens = normalizeTokens(tokens)
	if len(tokens) == 0 {
		return nil
	}
	forms := [][]string{tokens}
	addCanon := func(c []string) {
		forms = append(forms, c)
		d := ctx.dangerForm(c)
		if d != nil {
			forms = append(forms, d)
		} else {
			d = c
		}
		switch c[0] {
		case "rm":
			forms = append(forms, rmOperandForms(d)...)
		case "dd":
			if f := ddForm(c); f != nil {
				forms = append(forms, f)
			}
		}
	}
	addCanon(canonical(tokens, ctx.home))
	variants, ok := gitVariantsAliases(tokens, ctx.gitAliases, ctx.work)
	for _, g := range variants {
		forms = append(forms, g)
		addCanon(canonical(g, ctx.home))
	}
	var out []string
	for _, f := range forms {
		out = append(out, strings.Join(f, " "))
	}
	if len(variants) > 0 && (!ok || ctx.gitAliases.overflowed()) {
		ctx.giveUp()
		// Without a budget to exhaust, a runtime-valued form makes every
		// git pattern match (ask) instead of silently missing expansions.
		out = append(out, "git "+string(dynAny))
	}
	ctx.work.spend(len(out))
	return dedupe(out)
}

// giveUp fails the request closed as too complex (the work budget is
// exhausted, so Evaluate returns too-complex).
func (ctx cmdCtx) giveUp() {
	if ctx.work != nil {
		ctx.work.spend(ctx.work.left + 1)
	}
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
	ctx := s.cmdCtx()
	argvs := argvVariants(args)
	var subjects []string
	for _, argv := range argvs {
		subjects = append(subjects, commandFormsCtx(argv, ctx)...)
	}
	applyPatterns(s.e.policy, s.c, s.sec.work, s.req.Home, subjects, nil)
	for _, argv := range argvs {
		s.gitShellAliases(argv)
	}
}

// gitShellAliases analyses the shell commands that `!` git aliases run
// when argv invokes them (`git -c alias.p='!cat .env' p`, or an alias set
// by `git config` in the same script), with the call's arguments appended
// as git does. Every rule applies to them, as to `sh -c`.
func (s *shellEval) gitShellAliases(argv []string) {
	if len(argv) < 2 || cmdBase(argv[0]) != "git" {
		return
	}
	_, shellCmds, _ := gitExpand(argv, s.gitAliases, s.sec.work)
	for _, sc := range shellCmds {
		if s.gitAliases.shellDone[sc] {
			continue
		}
		s.gitAliases.shellDone[sc] = true
		s.recurseText(sc, false)
	}
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

// compoundStage never matches a literal pattern stage.
var compoundStage = []string{string(dynAny) + "\x02"}

// flattenPipe returns the stages of a pipeline statement and marks the
// pipelines it walks as seen.
func (s *shellEval) flattenPipe(st *syntax.Stmt, out []*syntax.Stmt) []*syntax.Stmt {
	if bc, ok := st.Cmd.(*syntax.BinaryCmd); ok && (bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll) {
		s.pipeSeen[bc] = true
		out = s.flattenPipe(bc.X, out)
		return s.flattenPipe(bc.Y, out)
	}
	return append(out, st)
}

// callArgv evaluates the argument words of a call.
func (s *shellEval) callArgv(call *syntax.CallExpr) [][]string {
	args := make([]cmdArg, len(call.Args))
	for k, w := range call.Args {
		args[k] = cmdArg{alts: s.wordAlts(w, modePattern)}
	}
	return argvVariants(args)
}

// stageForms returns the forms one pipeline stage is matched in.
func (s *shellEval) stageForms(st *syntax.Stmt) []string {
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return compoundStage
	}
	var out []string
	for _, argv := range s.callArgv(call) {
		out = append(out, s.argvStageForms(argv)...)
	}
	return dedupe(out)
}

// argvStageForms returns the forms of argv as a pipeline stage: every
// wrapper level, plus `sh` and `bash` when the stage runs code from stdin.
func (s *shellEval) argvStageForms(argv []string) []string {
	ctx := s.cmdCtx()
	var out []string
	for _, level := range unwrapLevels(argv) {
		out = append(out, commandFormsCtx(level, ctx)...)
		if stdinCodeRunner(level) {
			out = append(out, "sh", "bash")
		}
	}
	return dedupe(out)
}

// matchPipeline matches '|' patterns against a whole pipeline.
func (s *shellEval) matchPipeline(b *syntax.BinaryCmd) {
	s.pipeSeen[b] = true
	stmts := s.flattenPipe(b.X, nil)
	stmts = s.flattenPipe(b.Y, stmts)
	stages := make([][]string, len(stmts))
	for i, st := range stmts {
		stages[i] = s.stageForms(st)
	}
	applyPatterns(s.e.policy, s.c, s.sec.work, s.req.Home, nil, stages)
}

var stdinPaths = set("-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0")

// stdinCodeRunner reports whether argv (one wrapper level) executes code
// read from stdin: a shell without a script or with -s, -, /dev/stdin;
// sudo -s/-i and su without a command; pwsh without a script or with
// -Command -; an interpreter without a program.
func stdinCodeRunner(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	for _, a := range argv {
		if strings.IndexByte(a, dynAny) >= 0 {
			return false
		}
	}
	name := cmdBase(argv[0])
	args := argv[1:]
	switch {
	case shells[name] || name == "source" || name == ".":
		for i := 0; i < len(args); i++ {
			t := args[i]
			switch {
			case t == "-":
				return true
			case t == "--":
				return i+1 >= len(args) || stdinPaths[args[i+1]]
			case t == "--rcfile" || t == "--init-file" || t == "--init-command":
				i++
			case strings.HasPrefix(t, "--"):
			case len(t) > 1 && (t[0] == '-' || t[0] == '+'):
				if strings.ContainsRune(t[1:], 'c') {
					return false
				}
				if strings.ContainsRune(t[1:], 's') {
					return true
				}
				if strings.ContainsAny(t[1:], "oO") {
					i++
				}
			default:
				return stdinPaths[t]
			}
		}
		return name != "source" && name != "."
	case name == "pwsh" || name == "powershell":
		for i := 0; i < len(args); i++ {
			l := strings.ToLower(args[i])
			switch {
			case l == "-":
				return true
			case isAbbrev(l, "-command", 2) || isAbbrev(l, "-file", 2):
				return i+1 < len(args) && args[i+1] == "-"
			case isAbbrev(l, "-executionpolicy", 3) || l == "-ep" || isAbbrev(l, "-workingdirectory", 3) || l == "-wd" ||
				isAbbrev(l, "-outputformat", 3) || l == "-of" || isAbbrev(l, "-inputformat", 3) || l == "-if" ||
				isAbbrev(l, "-windowstyle", 3) || isAbbrev(l, "-settingsfile", 3) || isAbbrev(l, "-configurationname", 4):
				i++
			case strings.HasPrefix(l, "-"):
			default:
				return false // a script file or command text
			}
		}
		return true
	case name == "sudo" || name == "doas":
		shell := false
		for i := 0; i < len(args); i++ {
			t := args[i]
			switch {
			case t == "--shell" || t == "--login":
				shell = true
			case strings.HasPrefix(t, "--"):
				if !strings.Contains(t, "=") && wrapSpecs["sudo"].long[t] {
					i++
				}
			case len(t) > 1 && t[0] == '-':
				for j, r := range t[1:] {
					if r == 's' || r == 'i' {
						shell = true
					}
					if strings.ContainsRune("ugCDhprtTU", r) {
						if j == len(t)-2 {
							i++
						}
						break
					}
				}
			default:
				return false // runs a command (matched at the next level)
			}
		}
		return shell
	case name == "su":
		for i := 0; i < len(args); i++ {
			t := args[i]
			switch {
			case t == "--command" || strings.HasPrefix(t, "--command="):
				return false
			case t == "-s" || t == "--shell" || t == "-g" || t == "--group" || t == "-G" || t == "--supp-group":
				i++
			case len(t) > 1 && t[0] == '-' && t[1] != '-' && strings.ContainsRune(t, 'c'):
				return false
			}
		}
		return true
	case stdinInterpreters[name]:
		for _, t := range args {
			if !stdinPaths[t] {
				return false
			}
		}
		return true
	}
	return false
}

// scriptOperand returns the script file a shell, interpreter or source
// runs (first operand), or "" when it runs inline code or stdin.
func scriptOperand(argv []string) string {
	name := cmdBase(argv[0])
	if !shells[name] && !stdinInterpreters[name] && name != "source" && name != "." && name != "pwsh" && name != "powershell" {
		return ""
	}
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		switch {
		case t == "--":
			if i+1 < len(argv) {
				return argv[i+1]
			}
			return ""
		case strings.HasPrefix(t, "-") && t != "-":
			l := strings.ToLower(t)
			if (name == "pwsh" || name == "powershell") && isAbbrev(l, "-file", 2) && i+1 < len(argv) {
				return argv[i+1]
			}
			if !strings.HasPrefix(t, "--") && strings.ContainsAny(t[1:], "ceEmrp") {
				return "" // inline code or module
			}
		default:
			return t
		}
	}
	return ""
}

// downloadTargets returns the files curl/wget write (-o F, -O, wget's
// default remote name).
func downloadTargets(argv []string) []string {
	name := cmdBase(argv[0])
	if name != "curl" && name != "wget" {
		return nil
	}
	outLetter := byte('o')
	if name == "wget" {
		outLetter = 'O'
	}
	var outs, urls []string
	remoteName := name == "wget"
	prefix := ""
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		next := func() string {
			if i+1 < len(argv) {
				i++
				return argv[i]
			}
			return ""
		}
		switch {
		case strings.Contains(t, "://"):
			urls = append(urls, t)
		case name == "curl" && (t == "--output" || t == "-o"):
			outs = append(outs, next())
		case name == "curl" && strings.HasPrefix(t, "--output="):
			outs = append(outs, t[len("--output="):])
		case name == "curl" && (t == "--remote-name" || t == "--remote-name-all"):
			remoteName = true
		case name == "wget" && (t == "--output-document" || t == "-O"):
			outs = append(outs, next())
			remoteName = false
		case name == "wget" && strings.HasPrefix(t, "--output-document="):
			outs = append(outs, t[len("--output-document="):])
			remoteName = false
		case name == "wget" && (t == "--directory-prefix" || t == "-P"):
			prefix = next()
		case name == "wget" && strings.HasPrefix(t, "--directory-prefix="):
			prefix = t[len("--directory-prefix="):]
		case len(t) > 1 && t[0] == '-' && t[1] != '-':
			if j := strings.IndexByte(t, outLetter); j > 0 {
				v := t[j+1:]
				if v == "" {
					v = next()
				}
				outs = append(outs, v)
				if name == "wget" {
					remoteName = false
				}
			} else if name == "curl" && strings.ContainsRune(t, 'O') {
				remoteName = true
			}
		}
	}
	if remoteName {
		for _, u := range urls {
			u, _, _ = strings.Cut(u, "?")
			u, _, _ = strings.Cut(u, "#")
			if b := path.Base(u); b != "" && b != "/" && b != "." && !strings.Contains(b, ":") {
				if prefix != "" {
					b = prefix + "/" + b
				}
				outs = append(outs, b)
			}
		}
	}
	var res []string
	for _, o := range outs {
		if o != "" && o != "-" && !strings.ContainsAny(o, "\x00\x01") {
			res = append(res, path.Clean(o))
		}
	}
	return res
}

// commandPrepass runs before the statements of a script are visited. It
// records git aliases defined in the script and matches '|' patterns
// against pipelines that are not written with '|': a process substitution
// run as a script (`python3 <(curl ...)` is `curl ... | python3`) and a
// file downloaded then run in the same script (`curl -o f URL && sh f` is
// `curl ... | sh`).
func (s *shellEval) commandPrepass(root syntax.Node) {
	type runner struct {
		key   string
		forms []string
	}
	downloads := false
	var runs []runner
	var indirect [][][]string
	s.walk(root, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		argvs := s.callArgv(call)
		for _, argv := range argvs {
			for _, level := range unwrapLevels(argv) {
				if len(level) == 0 {
					continue
				}
				recordGitConfigAlias(level, s.gitAliases)
				if len(downloadTargets(level)) > 0 {
					downloads = true
				}
				if op := scriptOperand(level); op != "" {
					runs = append(runs, runner{key: path.Clean(op), forms: []string{cmdBase(level[0]), "sh", "bash"}})
				} else if strings.Contains(level[0], "/") {
					runs = append(runs, runner{key: path.Clean(level[0]), forms: []string{"sh", "bash"}})
				}
			}
		}
		// Process substitution as the script operand.
		for k := 1; k < len(call.Args); k++ {
			w := call.Args[k]
			if len(w.Parts) != 1 {
				continue
			}
			ps, ok := w.Parts[0].(*syntax.ProcSubst)
			if !ok || ps.Op != syntax.CmdIn || len(ps.Stmts) != 1 {
				continue
			}
			var inner [][]string
			for _, st := range s.flattenPipe(ps.Stmts[0], nil) {
				inner = append(inner, s.stageForms(st))
			}
			var runForms []string
			for _, argv := range argvs {
				if k >= len(argv) {
					continue
				}
				rest := append(append([]string(nil), argv[:k]...), argv[k+1:]...)
				opsOnly := true
				for _, t := range argv[1:k] {
					if !strings.HasPrefix(t, "-") {
						opsOnly = false
					}
				}
				if opsOnly {
					for _, level := range unwrapLevels(rest) {
						if stdinCodeRunner(level) {
							runForms = append(runForms, s.argvStageForms(rest)...)
							break
						}
					}
				}
			}
			if len(runForms) > 0 {
				indirect = append(indirect, append(inner, dedupe(runForms)))
			}
		}
		return true
	})
	// Download-then-run: the downloader's forms are computed only when a
	// later command runs the downloaded file.
	if downloads && len(runs) > 0 {
		dlForms := map[string][]string{}
		s.walk(root, func(n syntax.Node) bool {
			call, ok := n.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			for _, argv := range s.callArgv(call) {
				for _, level := range unwrapLevels(argv) {
					if len(level) == 0 {
						continue
					}
					for _, k := range downloadTargets(level) {
						dlForms[k] = append(dlForms[k], s.argvStageForms(argv)...)
					}
				}
			}
			return true
		})
		for _, r := range runs {
			if f, ok := dlForms[r.key]; ok {
				indirect = append(indirect, [][]string{dedupe(f), r.forms})
			}
		}
	}
	for _, stages := range indirect {
		applyPatterns(s.e.policy, s.c, s.sec.work, s.req.Home, nil, stages)
	}
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
