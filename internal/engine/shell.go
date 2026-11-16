package engine

import (
	"fmt"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// shellEval analyses one bash script (and, recursively, the scripts it
// embeds through sh -c, eval, xargs, find -exec, ...).
type shellEval struct {
	e     *Engine
	req   Request
	sec   *secretSet
	c     *collector
	depth int

	ignoreParseErrors bool

	vars      map[string][]varValue
	resolving map[string]bool
	stdin     map[*syntax.Stmt]*stdinInfo
	pipeSeen  map[*syntax.BinaryCmd]bool
	memo      map[wordKey][]string
	prodMemo  map[*syntax.Stmt]*stdinInfo
	globstar  bool
	// gitAliases are git aliases defined in the script (commands.go).
	gitAliases *gitAliasSet
	// written are the files the script writes (written.go).
	written *writtenFiles
}

func newShellEval(e *Engine, sec *secretSet, c *collector, depth int) *shellEval {
	return &shellEval{
		e: e, sec: sec, c: c, depth: depth,
		vars:      map[string][]varValue{},
		resolving: map[string]bool{},
		stdin:     map[*syntax.Stmt]*stdinInfo{},
		pipeSeen:  map[*syntax.BinaryCmd]bool{},
		memo:      map[wordKey][]string{},
		prodMemo:  map[*syntax.Stmt]*stdinInfo{},

		gitAliases: newGitAliasSet(),
		written:    newWrittenFiles(),
	}
}

// walk is syntax.Walk charged against the request's work budget.
func (s *shellEval) walk(root syntax.Node, f func(syntax.Node) bool) {
	syntax.Walk(root, func(n syntax.Node) bool {
		if n != nil && !s.sec.work.spend(1) {
			return false
		}
		return f(n)
	})
}

func (s *shellEval) withReq(req Request) *shellEval {
	s.req = req
	return s
}

// child creates an evaluator for an embedded script. Variables are shared
// (flow-insensitive, conservative).
func (s *shellEval) child() *shellEval {
	ch := newShellEval(s.e, s.sec, s.c, s.depth+1)
	ch.req = s.req
	ch.vars = s.vars
	ch.gitAliases = s.gitAliases
	ch.written = s.written
	return ch
}

var dotglobRe = regexp.MustCompile(`(?i)dotglob|glob_?dots|globignore`)

// run analyses bash text and reports whether it parsed.
func (s *shellEval) run(src string) bool {
	if s.depth > maxDepth {
		s.c.deny(RuleNesting, "the command nests shells/eval too deeply to analyse; blocked to be safe. Run the inner command directly.")
		return true
	}
	if !s.sec.work.spend(len(src)/64 + 1) {
		return true
	}
	if dotglobRe.MatchString(src) {
		s.sec.dotglob = true
	}
	s.globstar = s.globstar || strings.Contains(src, "globstar")
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		if !s.ignoreParseErrors {
			s.c.deny(RuleParseError, "could not parse the shell command, so it was blocked to be safe. Rewrite it as simpler POSIX/bash syntax (no unbalanced quotes or brackets).")
		}
		return false
	}
	if tooComplex(f) {
		s.c.deny(RuleTooComplex, tooComplexReason)
		return true
	}
	s.collect(f)
	s.memo = map[wordKey][]string{}
	s.commandPrepass(f)
	// Values computed while variables were still being collected (or before
	// stdin producers are known) may be incomplete.
	s.memo = map[wordKey][]string{}
	s.prodMemo = map[*syntax.Stmt]*stdinInfo{}
	s.collectWrites(f)
	s.visit(f)
	// After visit: writes made inside nested shells (sh -c '... > f') are
	// known too.
	s.checkWrittenRuns(f)
	return true
}

// collect records variable assignments and possible working directories.
func (s *shellEval) collect(root syntax.Node) {
	var cdTargets []*syntax.Word
	var links [][2]*syntax.Word
	s.walk(root, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Assign:
			if x.Name == nil {
				return true
			}
			name := x.Name.Value
			switch {
			case x.Append || x.Array != nil || x.Index != nil:
				s.vars[name] = append(s.vars[name], varValue{})
				if x.Array != nil {
					for _, el := range x.Array.Elems {
						if el.Value != nil {
							s.vars[name] = append(s.vars[name], varValue{word: el.Value})
						}
					}
				}
			case x.Value != nil:
				s.vars[name] = append(s.vars[name], varValue{word: x.Value})
			case x.Naked:
				// `export NAME` / `local NAME`: value comes from elsewhere.
				if _, ok := s.vars[name]; !ok {
					s.vars[name] = []varValue{{}}
				}
			default:
				s.vars[name] = append(s.vars[name], varValue{word: &syntax.Word{}})
			}
		case *syntax.ForClause:
			if wi, ok := x.Loop.(*syntax.WordIter); ok && wi.Name != nil {
				if wi.InPos.IsValid() || len(wi.Items) > 0 {
					for _, it := range wi.Items {
						s.vars[wi.Name.Value] = append(s.vars[wi.Name.Value], varValue{word: it, pattern: true})
					}
				} else {
					s.vars[wi.Name.Value] = append(s.vars[wi.Name.Value], varValue{})
				}
			}
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				return true
			}
			name, _ := staticText(s.wordAltsNoVars(x.Args[0]))
			name = cmdBase(name)
			switch name {
			case "cd", "pushd":
				if len(x.Args) == 1 {
					cdTargets = append(cdTargets, &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: "~"}}})
				}
				for _, a := range x.Args[1:] {
					t, ok := staticText(s.wordAltsNoVars(a))
					if ok && strings.HasPrefix(t, "-") && t != "-" {
						continue
					}
					cdTargets = append(cdTargets, a)
				}
			case "ln", "cp", "mount", "bindfs":
				links = append(links, s.linkPairs(name, x.Args[1:])...)
			case "read", "mapfile", "readarray", "getopts", "printf", "select":
				for _, a := range x.Args[1:] {
					if t, ok := staticText(s.wordAltsNoVars(a)); ok && isIdent(t) {
						s.vars[t] = append(s.vars[t], varValue{})
					}
				}
			}
			for i, a := range x.Args[1:] {
				t, ok := staticText(s.wordAltsNoVars(a))
				if !ok {
					continue
				}
				switch {
				case (t == "-C" || t == "--directory" || t == "--chdir" || t == "-D") && i+2 < len(x.Args):
					cdTargets = append(cdTargets, x.Args[i+2])
				case strings.HasPrefix(t, "--directory=") || strings.HasPrefix(t, "--chdir="):
					cdTargets = append(cdTargets, &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: t[strings.IndexByte(t, '=')+1:]}}})
				}
			}
		}
		return true
	})
	s.addBases(cdTargets)
	for _, l := range links {
		for _, t := range s.wordAlts(l[0], modePattern) {
			for _, k := range s.wordAlts(l[1], modePattern) {
				s.sec.addAlias(t, k)
			}
		}
	}
}

func litWord(t string) *syntax.Word {
	return &syntax.Word{Parts: []syntax.WordPart{&syntax.SglQuoted{Value: t}}}
}

// linkPairs extracts (target, link) pairs from ln, cp -s, mount --bind and
// bindfs so later paths through the link can be resolved to the target.
func (s *shellEval) linkPairs(name string, args []*syntax.Word) [][2]*syntax.Word {
	var operands []*syntax.Word
	linkish := name == "ln" || name == "bindfs"
	targetDir := ""
	for i := 0; i < len(args); i++ {
		t, ok := staticText(s.wordAltsNoVars(args[i]))
		switch {
		case !ok || !strings.HasPrefix(t, "-") || t == "-":
			operands = append(operands, args[i])
		case t == "-t" && i+1 < len(args):
			targetDir, _ = staticText(s.wordAltsNoVars(args[i+1]))
			i++
		case strings.HasPrefix(t, "--target-directory="):
			targetDir = strings.TrimPrefix(t, "--target-directory=")
		case name == "cp" && (t == "--symbolic-link" || (!strings.HasPrefix(t, "--") && strings.ContainsRune(t, 's'))):
			linkish = true
		case name == "mount" && (t == "--bind" || t == "--rbind" || t == "-B" || t == "-R"):
			linkish = true
		case name == "mount" && t == "-o" && i+1 < len(args):
			if v, _ := staticText(s.wordAltsNoVars(args[i+1])); strings.Contains(v, "bind") {
				linkish = true
			}
			i++
		}
	}
	if !linkish || len(operands) == 0 {
		return nil
	}
	base := func(w *syntax.Word) string {
		t, _ := staticText(s.wordAltsNoVars(w))
		t = strings.TrimSuffix(t, "/")
		if i := strings.LastIndexByte(t, '/'); i >= 0 {
			t = t[i+1:]
		}
		return t
	}
	var out [][2]*syntax.Word
	switch {
	case targetDir != "":
		for _, o := range operands {
			out = append(out, [2]*syntax.Word{o, litWord(targetDir + "/" + base(o))})
		}
	case len(operands) == 1 && name == "ln":
		out = append(out, [2]*syntax.Word{operands[0], litWord(base(operands[0]))})
	case len(operands) == 2:
		out = append(out, [2]*syntax.Word{operands[0], operands[1]})
		if dir, ok := staticText(s.wordAltsNoVars(operands[1])); ok {
			// LINK may be an existing directory: the link is created inside.
			out = append(out, [2]*syntax.Word{operands[0], litWord(dir + "/" + base(operands[0]))})
		}
	default:
		last := operands[len(operands)-1]
		dir, _ := staticText(s.wordAltsNoVars(last))
		for _, o := range operands[:len(operands)-1] {
			out = append(out, [2]*syntax.Word{o, litWord(dir + "/" + base(o))})
		}
	}
	return out
}

// wordAltsNoVars evaluates a word before variables are fully collected.
func (s *shellEval) wordAltsNoVars(w *syntax.Word) []string {
	return s.wordAlts(w, modePattern)
}

func isIdent(t string) bool {
	if t == "" {
		return false
	}
	for i, r := range t {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// addBases adds every directory a `cd` may switch to.
func (s *shellEval) addBases(targets []*syntax.Word) {
	for _, t := range targets {
		if s.sec.basesUnknown {
			return // already "anywhere": more targets add nothing
		}
		for _, alt := range s.wordAlts(t, modePattern) {
			s.sec.addBase(alt)
		}
	}
}

func containsStr(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func (s *shellEval) visit(root syntax.Node) {
	s.walk(root, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Stmt:
			s.visitStmt(x)
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				s.stdin[x.Y] = s.producer(x.X)
				if !s.pipeSeen[x] {
					s.matchPipeline(x)
				}
			}
		case *syntax.ParamExp:
			s.checkParam(x)
		case *syntax.CmdSubst:
			s.checkSubst(x)
		case *syntax.ProcSubst:
			s.checkSubst(x)
		case *syntax.DeclClause:
			s.checkDecl(x)
		case *syntax.ArithmExp:
			s.checkArith(x.X)
		case *syntax.ArithmCmd:
			s.checkArith(x.X)
		case *syntax.FuncDecl:
			s.checkForkBomb(x)
		case *syntax.ArrayExpr:
			// Array elements often become argv later ("${x[@]}").
			for _, el := range x.Elems {
				if el.Value != nil {
					s.checkArg("", cmdArg{alts: s.wordAlts(el.Value, modePattern)})
				}
			}
		case *syntax.LetClause:
			for _, e := range x.Exprs {
				s.checkArith(e)
			}
		}
		return true
	})
}

func (s *shellEval) visitStmt(st *syntax.Stmt) {
	for _, r := range st.Redirs {
		s.checkRedirect(r)
	}
	if call, ok := st.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
		for _, a := range call.Assigns {
			s.checkAssign(a, true)
		}
		words := braceFields(call.Args)
		args := make([]cmdArg, len(words))
		splits := false
		for i, w := range words {
			args[i] = cmdArg{alts: s.wordAlts(w, modePattern)}
			splits = splits || unquotedExpansion(w)
		}
		stdin := s.stmtStdin(st)
		s.processCommand(args, stdin)
		if splits {
			// Unquoted expansions are word-split at runtime (with a
			// possibly custom IFS): `c=cat_.env; IFS=_; $c`, `cat${IFS}.env`.
			if alt := s.splitArgs(words, args); alt != nil {
				s.processCommand(alt, stdin)
			}
		}
	} else if call, ok := st.Cmd.(*syntax.CallExpr); ok {
		for _, a := range call.Assigns {
			s.checkAssign(a, false)
		}
	}
}

// braceFields performs brace expansion the way bash does: one word becomes
// several fields (`{cat,.env}` is the command `cat .env`).
func braceFields(in []*syntax.Word) []*syntax.Word {
	var out []*syntax.Word
	for _, w := range in {
		clone := &syntax.Word{Parts: append([]syntax.WordPart(nil), w.Parts...)}
		if !syntax.SplitBraces(clone) {
			out = append(out, w)
			continue
		}
		n := 0
		for bw, err := range expand.BracesSeq(nil, clone) {
			if err != nil || n >= maxAlts {
				// Too many fields: keep the original word too, whose
				// evaluation degrades to "runtime value" (fail closed).
				out = append(out, w)
				break
			}
			out = append(out, bw)
			n++
		}
	}
	return out
}

// commandVars hold a command line or a file that a program runs/loads.
var commandVars = set("PAGER", "GIT_PAGER", "MANPAGER", "SYSTEMD_PAGER", "GIT_EDITOR", "EDITOR", "VISUAL",
	"SUDO_EDITOR", "GIT_SEQUENCE_EDITOR", "FCEDIT", "GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND", "GIT_SSH",
	"GIT_ASKPASS", "SSH_ASKPASS", "LESSOPEN", "LESSCLOSE", "BASH_ENV", "ENV", "PROMPT_COMMAND",
	"NODE_OPTIONS", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT")

// checkAssign analyses an assignment value. Prefix assignments
// (`VAR=value cmd`) are path-checked; command-carrying variables (PAGER,
// GIT_EXTERNAL_DIFF, LESSOPEN, BASH_ENV, ...) are re-parsed as commands
// wherever they are assigned.
func (s *shellEval) checkAssign(a *syntax.Assign, prefix bool) {
	if a.Name == nil || a.Value == nil {
		return
	}
	s.checkAssignValue(a.Name.Value, s.wordAlts(a.Value, modePattern), prefix)
}

func (s *shellEval) checkAssignValue(name string, alts []string, prefix bool) {
	upper := strings.ToUpper(name)
	cmdVar := commandVars[upper] || strings.HasPrefix(upper, "GIT_CONFIG_VALUE")
	for _, alt := range alts {
		if cmdVar {
			if isDynamic(alt) {
				s.c.deny(RuleDynamicShell, fmt.Sprintf("%s holds a command or file that a program will run, and its value is only known at runtime; blocked to be safe.", name))
				continue
			}
			ch := s.child()
			ch.ignoreParseErrors = true
			ch.run(strings.TrimLeft(strings.TrimSpace(plain(alt)), "|!"))
		}
		if !prefix && !cmdVar && !strings.HasPrefix(strings.ToLower(name), "npm_config_") {
			continue
		}
		// Assignment values are not globbed: check the literal text.
		for _, cand := range argCandidates(escapeLit(plain(alt))) {
			if m, ok := s.sec.checkPath(cand); ok && !m.glob {
				s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "passing (via "+name+")", s.sec))
			}
		}
	}
}

func unquotedExpansion(w *syntax.Word) bool {
	for _, p := range w.Parts {
		switch p.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst:
			return true
		}
	}
	return false
}

// splitArgs re-splits arguments that contain unquoted expansions on IFS
// characters (default whitespace plus any IFS value assigned in the script).
func (s *shellEval) splitArgs(words []*syntax.Word, args []cmdArg) []cmdArg {
	ifs := " \t\n"
	for _, v := range s.varAlts("IFS") {
		if !isDynamic(v.text) {
			ifs += v.text
		}
	}
	var out []cmdArg
	changed := false
	for i, a := range args {
		if !unquotedExpansion(words[i]) || len(a.alts) != 1 {
			out = append(out, a)
			continue
		}
		fields := strings.FieldsFunc(a.alts[0], func(r rune) bool { return strings.ContainsRune(ifs, r) })
		if len(fields) <= 1 {
			out = append(out, a)
			continue
		}
		changed = true
		for _, f := range fields {
			out = append(out, cmdArg{alts: []string{f}})
		}
	}
	if !changed {
		return nil
	}
	return out
}

// checkRedirect applies the path rules to redirection targets.
func (s *shellEval) checkRedirect(r *syntax.Redirect) {
	if r.Word == nil {
		return
	}
	var input bool
	switch r.Op {
	case syntax.RdrIn, syntax.RdrInOut:
		input = true
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrAllClob:
	case syntax.DplIn, syntax.DplOut:
		if t, ok := staticText(s.wordAlts(r.Word, modePattern)); ok && (t == "-" || isDigits(t)) {
			return
		}
		input = r.Op == syntax.DplIn
	default:
		return // heredocs and here-strings are data; their expansions are walked
	}
	verb := "writing to"
	if input {
		verb = "reading"
	}
	alts := append([]string(nil), s.wordAlts(r.Word, modePattern)...) // copy: memoised
	for _, a := range alts {
		if w, ok := winPathVariant(a); ok {
			alts = append(alts, w) // `cat < 'C:\proj\.env'` under Git Bash
		}
	}
	for _, alt := range alts {
		m, ok := s.sec.checkPath(alt)
		if !ok {
			continue
		}
		if isDynamic(alt) {
			if input {
				s.c.deny(RuleDynamicPath, fmt.Sprintf("the input redirection %q is built at runtime and could read a secret file (secrets.files: %q). Use a literal, non-secret path.", display(plain(alt)), m.pattern))
			}
			continue
		}
		s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, verb, s.sec))
	}
}

func isDigits(t string) bool {
	if t == "" {
		return false
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// checkParam denies expansions of secret environment variables.
func (s *shellEval) checkParam(pe *syntax.ParamExp) {
	if pe.Param == nil {
		return
	}
	name := pe.Param.Value
	if pe.Names != 0 {
		return // ${!prefix*} lists names, not values
	}
	if pe.Exp != nil && (pe.Exp.Op == syntax.AlternateUnset || pe.Exp.Op == syntax.AlternateUnsetOrNull) {
		return // ${X:+word} only reveals whether X is set
	}
	if pe.IsSet {
		return
	}
	if pe.Excl {
		for _, v := range s.varAlts(name) {
			t := plain(v.text)
			if isDynamic(v.text) || !isIdent(t) {
				s.c.deny(RuleEnvExposure, fmt.Sprintf("indirect expansion ${!%s} reads a variable whose name is only known at runtime and could expose a secret environment variable. Reference non-secret variables by name instead.", name))
				return
			}
			s.checkEnvName(t)
		}
		return
	}
	s.checkEnvName(name)
}

func (s *shellEval) checkEnvName(name string) {
	if g, ok := s.sec.envMatch(name); ok {
		s.c.deny(RuleSecretEnv+":"+g, envNameReason(name, g))
	}
}

func envNameReason(name, glob string) string {
	return fmt.Sprintf("the value of environment variable %s must not be exposed: it matches secrets.env %q in .agentleash.yaml. To check it is set without printing it, use [ -n \"${%s:+x}\" ]; otherwise ask the user.", name, glob, name)
}

const envDumpReason = "printing the whole environment is blocked by .agentleash.yaml because it contains secret variables (secrets.env). Print the specific non-secret variables you need instead, e.g. `echo \"$PATH\"` or `printenv HOME`."

// checkDecl handles export/declare/typeset/local/readonly.
func (s *shellEval) checkDecl(d *syntax.DeclClause) {
	variant := ""
	if d.Variant != nil {
		variant = d.Variant.Value
	}
	flags := ""
	var names []string
	assigns := 0
	for _, a := range d.Args {
		if a.Name != nil && !a.Naked {
			assigns++
		}
		if a.Naked && a.Name == nil && a.Value != nil {
			t, ok := staticText(s.wordAlts(a.Value, modePattern))
			if !ok {
				names = append(names, string(dynAny))
				continue
			}
			if strings.HasPrefix(t, "-") || strings.HasPrefix(t, "+") {
				flags += t[1:]
				continue
			}
			names = append(names, t)
			continue
		}
		if a.Name != nil {
			if a.Naked {
				names = append(names, a.Name.Value)
			}
			s.checkAssign(a, false)
			if strings.Contains(flags, "n") && a.Value != nil {
				for _, alt := range s.wordAlts(a.Value, modeRaw) {
					if isDynamic(alt) {
						s.c.deny(RuleEnvExposure, "a nameref (declare -n) to a variable chosen at runtime could expose a secret environment variable.")
						continue
					}
					s.checkEnvName(alt)
				}
			}
		}
	}
	if variant == "local" || variant == "nameref" {
		return
	}
	if strings.ContainsAny(flags, "fF") {
		return // functions only
	}
	if len(names) == 0 && assigns == 0 {
		s.c.deny(RuleEnvExposure, envDumpReason)
		return
	}
	if strings.Contains(flags, "p") {
		for _, n := range names {
			if isDynamic(n) {
				s.c.deny(RuleEnvExposure, envDumpReason)
				continue
			}
			s.checkEnvName(n)
		}
	}
}

// checkForkBomb detects a function that calls itself in a background job
// or a pipeline (`:(){ :|:& };:`, `bomb(){ bomb | bomb & }; bomb`). Command
// patterns cannot see it after parsing, so it is recognised structurally
// and always denied; the rule names the policy pattern when one exists.
func (s *shellEval) checkForkBomb(fd *syntax.FuncDecl) {
	if fd.Name == nil || fd.Body == nil {
		return
	}
	name := fd.Name.Value
	callsSelf := func(n syntax.Node) bool {
		found := false
		s.walk(n, func(n syntax.Node) bool {
			if call, ok := n.(*syntax.CallExpr); ok && len(call.Args) > 0 {
				if t, ok := staticText(s.wordAlts(call.Args[0], modePattern)); ok && t == name {
					found = true
				}
			}
			return !found
		})
		return found
	}
	bomb := false
	s.walk(fd.Body, func(n syntax.Node) bool {
		st, ok := n.(*syntax.Stmt)
		if !ok || bomb {
			return !bomb
		}
		bc, isBin := st.Cmd.(*syntax.BinaryCmd)
		if (st.Background || (isBin && (bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll))) && callsSelf(st) {
			bomb = true
		}
		return true
	})
	if !bomb {
		return
	}
	rule := "command-deny:fork-bomb"
	for _, p := range s.e.policy.Commands.Deny {
		if strings.Contains(strings.ReplaceAll(p, " ", ""), "(){") {
			rule = RuleCommandDeny + ":" + p
			break
		}
	}
	s.c.deny(rule, fmt.Sprintf("function %q calls itself in the background or in a pipeline: this is a fork bomb that would exhaust the machine, so it is blocked.", name))
}

// checkArith flags secret variables referenced by bare name in arithmetic.
func (s *shellEval) checkArith(x syntax.ArithmExpr) {
	if x == nil {
		return
	}
	s.walk(x, func(n syntax.Node) bool {
		if w, ok := n.(*syntax.Word); ok && len(w.Parts) == 1 {
			if l, ok := w.Parts[0].(*syntax.Lit); ok && isIdent(l.Value) {
				s.checkEnvName(l.Value)
			}
		}
		return true
	})
}

// checkSubst denies command substitutions that decode data at runtime: the
// classic way to smuggle a secret path or command past static analysis.
func (s *shellEval) checkSubst(n syntax.Node) {
	if s.containsDecode(n) {
		s.c.deny(RuleObfuscation, "the command builds part of itself by decoding data at runtime (base64/xxd/printf escapes/rev inside $(...)). This hides what is executed, so it is blocked. Write the command in plain text.")
	}
}

func (s *shellEval) containsDecode(n syntax.Node) bool {
	found := false
	s.walk(n, func(n syntax.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			var texts []string
			for _, a := range call.Args {
				texts = append(texts, firstAlt(s.wordAlts(a, modeRaw)))
			}
			if isDecodeCmd(texts) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func firstAlt(alts []string) string {
	if len(alts) == 0 {
		return ""
	}
	return alts[0]
}

var printfEscapeRe = regexp.MustCompile(`\\(x[0-9a-fA-F]|[0-7]{1,3}|u[0-9a-fA-F])`)

// isDecodeCmd recognises commands whose purpose is to decode/de-obfuscate.
func isDecodeCmd(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	name := cmdBase(argv[0])
	args := argv[1:]
	has := func(flags ...string) bool {
		for _, a := range args {
			for _, f := range flags {
				if a == f || (strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a[1:], f[1:])) {
					return true
				}
			}
		}
		return false
	}
	switch name {
	case "base64", "base32", "basenc", "gbase64":
		return has("-d", "--decode", "-D")
	case "xxd":
		return has("-r", "-revert")
	case "openssl":
		return has("-d", "-base64", "-a", "base64")
	case "uudecode", "rev", "recode":
		return true
	case "printf":
		return len(args) > 0 && printfEscapeRe.MatchString(strings.Join(args, " "))
	case "echo":
		return has("-e") && printfEscapeRe.MatchString(strings.Join(args, " "))
	}
	return false
}

// stdin description for commands that read code or arguments from stdin.
type stdinKind uint8

const (
	stdinStatic  stdinKind = iota // texts known
	stdinGlob                     // file names matching globs (find output)
	stdinUnknown                  // anything
	stdinFile                     // redirected from a file (contents unknown, a script on disk)
)

type stdinInfo struct {
	kind   stdinKind
	texts  []string // static texts, or globs (internal syntax) for stdinGlob
	decode bool     // produced by a decoding pipeline
	path   string   // stdinFile: the redirected file, for reasons
}

func (s *shellEval) stmtStdin(st *syntax.Stmt) *stdinInfo {
	for _, r := range st.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			if r.Hdoc == nil {
				return &stdinInfo{kind: stdinStatic, texts: []string{""}}
			}
			return s.staticInfo(s.wordAlts(r.Hdoc, modeRaw))
		case syntax.WordHdoc:
			return s.staticInfo(s.wordAlts(r.Word, modeRaw))
		case syntax.RdrIn:
			return &stdinInfo{kind: stdinFile, path: plain(firstAlt(s.wordAlts(r.Word, modeRaw)))}
		}
	}
	return s.stdin[st]
}

func (s *shellEval) staticInfo(alts []string) *stdinInfo {
	for _, a := range alts {
		if isDynamic(a) {
			return &stdinInfo{kind: stdinUnknown}
		}
	}
	return &stdinInfo{kind: stdinStatic, texts: alts}
}

// producer describes what a pipeline stage writes to stdout.
func (s *shellEval) producer(st *syntax.Stmt) *stdinInfo {
	if v, ok := s.prodMemo[st]; ok {
		return v
	}
	v := s.producerUncached(st)
	s.prodMemo[st] = v
	return v
}

func (s *shellEval) producerUncached(st *syntax.Stmt) *stdinInfo {
	switch x := st.Cmd.(type) {
	case *syntax.BinaryCmd:
		if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
			info := s.producer(x.Y)
			if info == nil {
				info = &stdinInfo{kind: stdinUnknown}
			}
			out := *info
			out.decode = out.decode || s.containsDecode(x.X)
			return &out
		}
	case *syntax.CallExpr:
		if len(x.Args) == 0 {
			break
		}
		var argv [][]string
		for _, a := range x.Args {
			argv = append(argv, s.wordAlts(a, modePattern))
		}
		name, ok := staticText(argv[0])
		if !ok {
			break
		}
		name = cmdBase(name)
		var texts []string
		for _, a := range x.Args {
			texts = append(texts, firstAlt(s.wordAlts(a, modeRaw)))
		}
		decode := isDecodeCmd(texts)
		switch name {
		case "echo", "printf":
			var parts []string
			escapes := name == "printf"
			for i, a := range x.Args[1:] {
				alts := s.wordAlts(a, modeRaw)
				if len(alts) != 1 || strings.ContainsAny(alts[0], string([]rune{dynAny, dynStar})) {
					return &stdinInfo{kind: stdinUnknown, decode: decode}
				}
				t := alts[0]
				if name == "echo" && i == 0 && strings.HasPrefix(t, "-") && len(t) > 1 && strings.Trim(t[1:], "neE") == "" {
					escapes = strings.Contains(t, "e")
					continue
				}
				parts = append(parts, t)
			}
			text := strings.Join(parts, " ")
			if name == "printf" && len(parts) > 0 {
				text = parts[0]
				if strings.Contains(text, "%") {
					text = strings.Join(parts[1:], "\n")
				}
			}
			if escapes {
				text = ansiC(text)
			}
			return &stdinInfo{kind: stdinStatic, texts: []string{text}, decode: decode}
		case "cat":
			if len(x.Args) == 1 {
				if info := s.stmtStdin(st); info != nil && info.kind == stdinStatic {
					return info
				}
			}
		case "find":
			return &stdinInfo{kind: stdinGlob, texts: s.findOutputs(argv)}
		case "git":
			if globs := gitLsFilesOutputs(argv); globs != nil {
				return &stdinInfo{kind: stdinGlob, texts: globs}
			}
		}
		return &stdinInfo{kind: stdinUnknown, decode: decode}
	}
	return &stdinInfo{kind: stdinUnknown, decode: s.containsDecode(st)}
}
