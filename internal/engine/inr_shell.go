package engine

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// inrCollectAcc accumulates the cd targets and link pairs found by collect.
type inrCollectAcc struct {
	cdTargets []*syntax.Word
	links     [][2]*syntax.Word
}

// inrCollectAssign records the values a variable assignment may give.
func (s *shellEval) inrCollectAssign(x *syntax.Assign) {
	if x.Name == nil {
		return
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
}

// inrCollectFor records the values a for-loop variable may take.
func (s *shellEval) inrCollectFor(x *syntax.ForClause) {
	wi, ok := x.Loop.(*syntax.WordIter)
	if !ok || wi.Name == nil {
		return
	}
	if wi.InPos.IsValid() || len(wi.Items) > 0 {
		for _, it := range wi.Items {
			s.vars[wi.Name.Value] = append(s.vars[wi.Name.Value], varValue{word: it, pattern: true})
		}
	} else {
		s.vars[wi.Name.Value] = append(s.vars[wi.Name.Value], varValue{})
	}
}

// inrCollectCall records the cd targets, links and variables of a command.
func (s *shellEval) inrCollectCall(x *syntax.CallExpr, acc *inrCollectAcc) {
	if len(x.Args) == 0 {
		return
	}
	name, _ := staticText(s.wordAltsNoVars(x.Args[0]))
	name = cmdBase(name)
	switch name {
	case "cd", "pushd":
		acc.cdTargets = append(acc.cdTargets, s.inrCdTargets(x.Args)...)
	case "ln", "cp", "mount", "bindfs":
		acc.links = append(acc.links, s.linkPairs(name, x.Args[1:])...)
	case "read", "mapfile", "readarray", "getopts", "printf", "select":
		s.inrCollectReadVars(x.Args[1:])
	}
	acc.cdTargets = append(acc.cdTargets, s.inrChdirOptTargets(x.Args)...)
}

// inrCdTargets returns the directories a cd/pushd command line may switch to.
func (s *shellEval) inrCdTargets(args []*syntax.Word) []*syntax.Word {
	var out []*syntax.Word
	if len(args) == 1 {
		out = append(out, &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: "~"}}})
	}
	for _, a := range args[1:] {
		t, ok := staticText(s.wordAltsNoVars(a))
		if ok && strings.HasPrefix(t, "-") && t != "-" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// inrCollectReadVars records the variables set by read-like builtins.
func (s *shellEval) inrCollectReadVars(args []*syntax.Word) {
	for _, a := range args {
		if t, ok := staticText(s.wordAltsNoVars(a)); ok && isIdent(t) {
			s.vars[t] = append(s.vars[t], varValue{})
		}
	}
}

// inrChdirOptTargets returns the directories given to -C/--directory style
// options of any command.
func (s *shellEval) inrChdirOptTargets(args []*syntax.Word) []*syntax.Word {
	var out []*syntax.Word
	for i, a := range args[1:] {
		t, ok := staticText(s.wordAltsNoVars(a))
		if !ok {
			continue
		}
		switch {
		case (t == "-C" || t == "--directory" || t == "--chdir" || t == "-D") && i+2 < len(args):
			out = append(out, args[i+2])
		case strings.HasPrefix(t, "--directory=") || strings.HasPrefix(t, "--chdir="):
			out = append(out, &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: t[strings.IndexByte(t, '=')+1:]}}})
		}
	}
	return out
}

// inrAddLinkAliases registers every (target, link) pair as a path alias.
func (s *shellEval) inrAddLinkAliases(links [][2]*syntax.Word) {
	for _, l := range links {
		for _, t := range s.wordAlts(l[0], modePattern) {
			for _, k := range s.wordAlts(l[1], modePattern) {
				s.sec.addAlias(t, k)
			}
		}
	}
}

// inrDeclArgs parses the arguments of a declaration builtin: the option
// letters, the named variables and the number of assignments. Assignments
// are checked on the way.
func (s *shellEval) inrDeclArgs(args []*syntax.Assign) (flags string, names []string, assigns int) {
	for _, a := range args {
		if a.Name != nil && !a.Naked {
			assigns++
		}
		if a.Naked && a.Name == nil && a.Value != nil {
			t, ok := staticText(s.wordAlts(a.Value, modePattern))
			switch {
			case !ok:
				names = append(names, string(dynAny))
			case strings.HasPrefix(t, "-") || strings.HasPrefix(t, "+"):
				flags += t[1:]
			default:
				names = append(names, t)
			}
			continue
		}
		if a.Name != nil {
			if a.Naked {
				names = append(names, a.Name.Value)
			}
			s.checkAssign(a, false)
			if strings.Contains(flags, "n") && a.Value != nil {
				s.inrCheckNameref(a.Value)
			}
		}
	}
	return flags, names, assigns
}

// inrCheckNameref checks the variable a nameref (declare -n) points to.
func (s *shellEval) inrCheckNameref(w *syntax.Word) {
	for _, alt := range s.wordAlts(w, modeRaw) {
		if isDynamic(alt) {
			s.c.deny(RuleEnvExposure, "a nameref (declare -n) to a variable chosen at runtime could expose a secret environment variable.")
			continue
		}
		s.checkEnvName(alt)
	}
}

// inrCheckDeclPrint checks the variables printed by `declare -p NAME...`.
func (s *shellEval) inrCheckDeclPrint(names []string) {
	for _, n := range names {
		if isDynamic(n) {
			s.c.deny(RuleEnvExposure, envDumpReason)
			continue
		}
		s.checkEnvName(n)
	}
}

// inrCallProducer describes what a simple command writes to stdout; nil
// means the command name is unknown and the caller decides.
func (s *shellEval) inrCallProducer(st *syntax.Stmt, x *syntax.CallExpr) *stdinInfo {
	if len(x.Args) == 0 {
		return nil
	}
	var argv [][]string
	for _, a := range x.Args {
		argv = append(argv, s.wordAlts(a, modePattern))
	}
	name, ok := staticText(argv[0])
	if !ok {
		return nil
	}
	name = cmdBase(name)
	var texts []string
	for _, a := range x.Args {
		texts = append(texts, firstAlt(s.wordAlts(a, modeRaw)))
	}
	decode := isDecodeCmd(texts)
	switch name {
	case "echo", "printf":
		return s.inrEchoProducer(name, x.Args[1:], decode)
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

// inrEchoProducer describes the output of echo or printf with args.
func (s *shellEval) inrEchoProducer(name string, args []*syntax.Word, decode bool) *stdinInfo {
	var parts []string
	escapes := name == "printf"
	for i, a := range args {
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
	text := inrEchoText(name, parts)
	if escapes {
		text = ansiC(text)
	}
	return &stdinInfo{kind: stdinStatic, texts: []string{text}, decode: decode}
}

// inrEchoText joins the operands of echo, or applies printf's format
// approximation (the format, or the arguments when it has % specs).
func inrEchoText(name string, parts []string) string {
	text := strings.Join(parts, " ")
	if name == "printf" && len(parts) > 0 {
		text = parts[0]
		if strings.Contains(text, "%") {
			text = strings.Join(parts[1:], "\n")
		}
	}
	return text
}

// inrRedirWrites records the files written by st's output redirections.
func (s *shellEval) inrRedirWrites(st *syntax.Stmt, call *syntax.CallExpr, name string) {
	for _, r := range st.Redirs {
		if !writeOps[r.Op] || r.Word == nil {
			continue
		}
		key := writeKey(s.staticArg(r.Word))
		if key == "" || key == "/dev/null" {
			continue
		}
		if (r.N != nil && r.N.Value != "1") || call == nil {
			s.written.add(key, writeRec{dynamic: true})
			continue
		}
		if dl := s.downloadForms(st); dl != nil {
			s.written.add(key, writeRec{dynamic: true, download: dl})
			continue
		}
		s.written.add(key, s.contentRec(s.producer(st), echoNewline(name, call)))
	}
}

// inrTeeWrites records the files written by a tee command.
func (s *shellEval) inrTeeWrites(st *syntax.Stmt, call *syntax.CallExpr, teeIn map[*syntax.Stmt]*stdinInfo, teeDl map[*syntax.Stmt][]string) {
	info := teeIn[st]
	for _, r := range st.Redirs {
		if r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc || r.Op == syntax.WordHdoc {
			info = s.stmtStdin(st)
		}
	}
	for _, a := range call.Args[1:] {
		t := s.staticArg(a)
		if t == "" || strings.HasPrefix(t, "-") {
			continue
		}
		rec := s.contentRec(info, false)
		if dl := teeDl[st]; dl != nil && info == teeIn[st] {
			rec = writeRec{dynamic: true, download: dl}
		}
		s.written.add(writeKey(t), rec)
	}
}

// inrCopyWrites carries the recorded content of a file copied or moved by
// cp, mv or install to its destination.
func (s *shellEval) inrCopyWrites(call *syntax.CallExpr) {
	var ops []string
	for _, a := range call.Args[1:] {
		t := s.staticArg(a)
		if t == "" {
			return
		}
		if !strings.HasPrefix(t, "-") {
			ops = append(ops, t)
		}
	}
	if len(ops) != 2 {
		return
	}
	for _, k := range s.written.lookup(ops[0]) {
		for _, rec := range s.written.byKey[k] {
			s.written.add(writeKey(ops[1]), rec)
			s.written.add(writeKey(ops[1]+"/"+path.Base(k)), rec)
		}
	}
}

// inrStmtWrittenRuns analyses the written files that one statement runs.
func (s *shellEval) inrStmtWrittenRuns(st *syntax.Stmt) {
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	stdinFile := ""
	for _, r := range st.Redirs {
		if r.Op == syntax.RdrIn && r.Word != nil {
			stdinFile = s.staticArg(r.Word)
		}
	}
	for _, argv := range s.callArgv(call) {
		for _, level := range unwrapLevels(argv) {
			s.inrLevelWrittenRuns(level, stdinFile)
		}
	}
}

// inrLevelWrittenRuns analyses the written files run by one unwrapped
// command line, as a script operand, a direct path or its stdin.
func (s *shellEval) inrLevelWrittenRuns(level []string, stdinFile string) {
	if len(level) == 0 {
		return
	}
	name := cmdBase(level[0])
	lang := name
	if shells[name] || name == "source" || name == "." || name == "sudo" || name == "doas" || name == "su" {
		lang = "sh"
	}
	switch op := scriptOperand(level); {
	case op != "" && name != "pwsh" && name != "powershell":
		s.runWritten(level[0], op, lang)
	case op == "" && strings.Contains(level[0], "/"):
		s.runWritten(level[0], level[0], "")
	}
	if stdinFile != "" && stdinCodeRunner(level) {
		s.runWritten(level[0], stdinFile, lang)
	}
}
