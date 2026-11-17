package engine

import (
	"fmt"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// RuleProtected marks a call that would modify a write-protected file
// (agentleash's own configuration, or a protect.files entry).
const RuleProtected = "protected-file" // + ":" + pattern

// Self-protection (issue #17)
//
// Protected files are analysed with the same machinery as secrets: a second
// Engine whose secrets.files are the protected globs. Any reference it finds
// (literal, glob, directory, nested shell, interpreter literal, ...) is a
// "touch". Write tools and patch paths that touch a protected file are always
// denied. A shell command that touches one is allowed only when the whole
// command is provably read-only (readonly.go): a small allowlist of readers
// with literal arguments, no expansions and no output redirection. Anything
// else is denied: we cannot tell a read from a write in arbitrary code.

func newProtectEngine(p *policy.Policy, resolve func(string) (string, error)) *Engine {
	if p == nil {
		return nil
	}
	pp := &policy.Policy{Version: p.Version, Secrets: policy.Secrets{Files: p.ProtectedFiles()}}
	return &Engine{policy: pp, resolve: resolve, touch: true}
}

// protectedVerdict returns a deny verdict when req would modify a protected
// file. ok is false when the call does not need to be blocked for that.
func (e *Engine) protectedVerdict(req Request) (v Verdict, blocked bool) {
	if e == nil || e.protect == nil {
		return Verdict{}, false
	}
	defer func() {
		if r := recover(); r != nil {
			v, blocked = Verdict{Decision: Deny, Rule: RuleInternal, Reason: reasonPrefix + fmt.Sprintf("internal error while checking this call (%v); blocked to be safe.", r)}, true
		}
	}()
	var paths []string
	switch req.Tool {
	case ToolWrite, ToolShell:
		paths = req.Paths
	default:
		return Verdict{}, false
	}
	if len(paths) > 0 {
		if pat, hit := e.protectHit(Request{Tool: ToolWrite, Paths: paths, Cwd: req.Cwd, ProjectRoot: req.ProjectRoot, Home: req.Home}); hit {
			return protectDeny(pat), true
		}
	}
	if req.Tool != ToolShell {
		return Verdict{}, false
	}
	sreq := req
	sreq.Paths = nil
	pat, hit := e.protectHit(sreq)
	if !hit || readOnlyCommand(req.Command, req.Shell) {
		return Verdict{}, false
	}
	return protectDeny(pat), true
}

// protectHit reports whether req touches a protected file, and which
// pattern. Incomplete analysis counts as a touch (fail closed).
func (e *Engine) protectHit(req Request) (pattern string, hit bool) {
	c, exhausted := e.protect.analyse(req)
	dynamic := false
	for _, f := range c.findings {
		switch {
		case strings.HasPrefix(f.rule, RuleSecretFile+":"):
			return strings.TrimPrefix(f.rule, RuleSecretFile+":"), true
		case f.rule == RuleInternal:
			return "", true
		case f.rule == RuleDynamicPath:
			dynamic = true
		}
	}
	if exhausted {
		return "", true
	}
	if dynamic {
		return dynamicProtected, true
	}
	return "", false
}

func protectDeny(pattern string) Verdict {
	if pattern == "" {
		return Verdict{Decision: Deny, Rule: RuleTooComplex, Reason: reasonPrefix + tooComplexReason}
	}
	if pattern == dynamicProtected {
		// Ask, not deny: the paths are usually harmless ("$TMP"), and the
		// user can see what they are.
		return Verdict{Decision: Ask, Rule: RuleProtected + ":" + dynamicProtected, Reason: reasonPrefix +
			"this call changes files whose names are only known at runtime (a variable, a substitution or a list piped in), " +
			"and they could include files agentleash protects (its own configuration or protect.files); the user must confirm. Name the files literally to avoid this."}
	}
	src := "protect.files in .agentleash.yaml"
	for _, b := range policy.BuiltinProtected {
		if b == pattern {
			src = "agentleash's own configuration"
			break
		}
	}
	return Verdict{
		Decision: Deny,
		Rule:     RuleProtected + ":" + pattern,
		Reason: reasonPrefix + fmt.Sprintf("this call could modify %q, which is write-protected (%s). "+
			"You may read it with the Read tool or a plain read-only command (cat, head, grep, sed -n, git diff), "+
			"but only a human may change it: ask the user to make this change and do not try another way.",
			strings.TrimPrefix(pattern, "./"), src),
	}
}

// dynamicProtected stands for a runtime-built path in protect findings.
const dynamicProtected = "(runtime path)"

// destructiveCmds remove or move whole trees: in mention mode an ancestor of
// the project counts as touching every protected file inside it.
var destructiveCmds = set("rm", "rmdir", "mv", "unlink", "shred", "trash", "trash-put", "gio", "srm")

// writerCmds change the files they are given (mention mode, runtime paths).
var writerCmds = set("cp", "install", "ln", "chmod", "chown", "chgrp", "truncate", "tee", "touch", "sed", "dd", "rsync")

// psWriterCmds are PowerShell commands that change the paths they get,
// including from the pipeline.
var psWriterCmds = set("remove-item", "move-item", "rename-item", "copy-item", "set-content", "add-content",
	"clear-content", "out-file", "tee-object", "new-item", "set-item", "clear-item")

// agentleashWriters are agentleash subcommands that rewrite the policy or the
// agent settings without naming them.
var agentleashWriters = set("init", "apply")

// touchCommand flags commands that modify protected files implicitly.
func touchCommand(c *collector, argv []string) {
	if len(argv) < 2 || readerName(argv[0]) != "agentleash" {
		return
	}
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if agentleashWriters[strings.ToLower(a)] {
			c.deny(RuleSecretFile+":./"+policy.FileName, "agentleash init/apply rewrites the policy and the agent settings.")
		}
		return
	}
}

// ---------------------------------------------------------------------------
// Read-only proof

// maxProofDepth bounds nested "bash -c" proofs.
const maxProofDepth = 3

// readOnlyCommand reports whether the command provably modifies no file.
// It is deliberately narrow: false negatives only cost a denial of a read of
// a protected file.
func readOnlyCommand(src string, sh Shell) bool {
	switch sh {
	case ShellBash:
		return bashReadOnly(src, 0)
	case ShellPowerShell:
		return psReadOnly(src, 0)
	default:
		// Unknown dialect: both views must be read-only. cmd.exe
		// metacharacters (which neither parser models) are refused, and so
		// are quoted words with whitespace, which cmd.exe would split.
		return !strings.ContainsAny(src, "&^%") && bashReadOnlyOpts(src, 0, true) && psReadOnly(src, 0)
	}
}

func bashReadOnly(src string, depth int) bool { return bashReadOnlyOpts(src, depth, false) }

// proof carries per-command options of the bash proof.
type proof struct {
	depth int
	// splitWS: words must not contain whitespace (cmd.exe view of ShellAuto),
	// except the script of a nested "bash -c", which bash itself parses.
	splitWS bool
}

func bashReadOnlyOpts(src string, depth int, splitWS bool) bool {
	if depth > maxProofDepth {
		return false
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		return false
	}
	return stmtsReadOnly(f.Stmts, proof{depth: depth, splitWS: splitWS})
}

func stmtReadOnly(st *syntax.Stmt, pf proof) bool {
	if st == nil || st.Coprocess || st.Background {
		return false
	}
	for _, r := range st.Redirs {
		if !redirReadOnly(r) {
			return false
		}
	}
	switch c := st.Cmd.(type) {
	case nil:
		return true
	case *syntax.CallExpr:
		return callReadOnly(c, pf)
	case *syntax.BinaryCmd:
		return stmtReadOnly(c.X, pf) && stmtReadOnly(c.Y, pf)
	case *syntax.Block:
		return stmtsReadOnly(c.Stmts, pf)
	case *syntax.Subshell:
		return stmtsReadOnly(c.Stmts, pf)
	case *syntax.IfClause:
		for ic := c; ic != nil; ic = ic.Else {
			if !stmtsReadOnly(ic.Cond, pf) || !stmtsReadOnly(ic.Then, pf) {
				return false
			}
		}
		return true
	case *syntax.TestClause:
		return testReadOnly(c.X)
	}
	return false
}

func stmtsReadOnly(sts []*syntax.Stmt, pf proof) bool {
	for _, s := range sts {
		if !stmtReadOnly(s, pf) {
			return false
		}
	}
	return true
}

// testReadOnly accepts [[ ... ]] expressions made of literal words.
func testReadOnly(x syntax.TestExpr) bool {
	switch t := x.(type) {
	case *syntax.Word:
		_, ok := plainWord(t)
		return ok
	case *syntax.UnaryTest:
		return testReadOnly(t.X)
	case *syntax.BinaryTest:
		return testReadOnly(t.X) && testReadOnly(t.Y)
	case *syntax.ParenTest:
		return testReadOnly(t.X)
	}
	return false
}

func redirReadOnly(r *syntax.Redirect) bool {
	if r.Hdoc != nil {
		if _, ok := plainWord(r.Hdoc); !ok {
			return false
		}
	}
	w, ok := plainWord(r.Word)
	if !ok {
		return false
	}
	switch r.Op {
	case syntax.RdrIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		return true
	case syntax.DplOut, syntax.DplIn:
		return w == "-" || isDigits(w)
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll:
		return w == "/dev/null"
	}
	return false
}

// plainWord returns the value of a word made only of plain text: no
// expansions of any kind and no backslash escapes (which the allowlist checks
// below would otherwise read differently from the shell).
func plainWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			// Backslash escapes, brace expansion and globs change the
			// words bash passes, so the option checks below would read
			// something else ({-i,}, -dele?). "[" and "]" of test stay.
			if strings.ContainsAny(x.Value, "\\{}*?") ||
				(strings.ContainsAny(x.Value, "[]") && x.Value != "[" && x.Value != "]") {
				return "", false
			}
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			if x.Dollar {
				return "", false
			}
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				l, ok := q.(*syntax.Lit)
				if !ok || strings.ContainsRune(l.Value, '\\') {
					return "", false
				}
				b.WriteString(l.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// safeAssign are environment assignments that cannot make a reader write.
var safeAssignRe = regexp.MustCompile(`^(LANG|LC_[A-Z]+|NO_COLOR|TZ|TERM|COLUMNS)$`)

func callReadOnly(c *syntax.CallExpr, pf proof) bool {
	for _, a := range c.Assigns {
		if a.Append || a.Array != nil || a.Index != nil || a.Name == nil || !safeAssignRe.MatchString(a.Name.Value) {
			return false
		}
		if _, ok := plainWord(a.Value); !ok {
			return false
		}
	}
	if len(c.Args) == 0 {
		return true
	}
	argv := make([]string, len(c.Args))
	for i, w := range c.Args {
		s, ok := plainWord(w)
		if !ok {
			return false
		}
		argv[i] = s
	}
	if pf.splitWS {
		for i, a := range argv {
			if strings.ContainsAny(a, " \t\r\n") && (i < 2 || !shellScriptArg(argv, i)) {
				return false
			}
		}
	}
	return argvReadOnly(argv, pf.depth)
}

// shellScriptArg reports whether argv[i] is the script of "bash -c".
func shellScriptArg(argv []string, i int) bool {
	switch readerName(argv[0]) {
	case "bash", "sh", "zsh", "dash":
	default:
		return false
	}
	prev := argv[i-1]
	return strings.HasPrefix(prev, "-") && !strings.HasPrefix(prev, "--") && strings.Contains(prev, "c")
}

// plainReaders never write files, whatever their arguments.
var plainReaders = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "wc": true,
	"stat": true, "ls": true, "nl": true, "od": true, "hexdump": true, "cmp": true,
	"comm": true, "diff": true, "grep": true, "egrep": true, "fgrep": true,
	"md5sum": true, "sha1sum": true, "sha256sum": true, "sha512sum": true,
	"shasum": true, "cksum": true, "b2sum": true, "realpath": true, "readlink": true,
	"dirname": true, "basename": true, "test": true, "[": true, "true": true,
	"echo": true, "pwd": true, "cd": true, "jq": true, "type": true, "findstr": true,
}

// readerName normalises argv[0] (path, case, .exe) for the allowlists.
func readerName(s string) string {
	s = strings.ToLower(s)
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSuffix(s, ".exe")
}

func argvReadOnly(argv []string, depth int) bool {
	name, args := readerName(argv[0]), argv[1:]
	switch {
	case plainReaders[name]:
		return true
	case name == "rg":
		for _, a := range args {
			if strings.HasPrefix(a, "--pre") {
				return false
			}
		}
		return true
	case name == "find":
		for _, a := range args {
			switch a {
			case "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls":
				return false
			}
		}
		return true
	case name == "sed":
		return sedReadOnly(args)
	case name == "git":
		return gitReadOnly(args)
	case name == "bash" || name == "sh" || name == "zsh" || name == "dash":
		return nestedBashReadOnly(args, depth)
	}
	return false
}

// sedScriptRe accepts print-only scripts such as "1,200p", "$p" or "10q".
var sedScriptRe = regexp.MustCompile(`^` + sedCmd + `(;` + sedCmd + `)*$`)

// sedCmd is one print-only sed command: [addr[,addr]] [p|d|q|=]. A regex
// address may not contain "/", "\\" or a newline (no escaped delimiters).
const (
	sedAddr = `(\d+|\$|/[^/\\\n]*/I?)`
	sedCmd  = `\s*(` + sedAddr + `(\s*,\s*(` + sedAddr + `|\+\d+))?)?\s*[pdq=]?\s*`
)

func sedReadOnly(args []string) bool {
	var scripts []string
	explicit := false
	var operands []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			operands = append(operands, args[i+1:]...)
			i = len(args)
		case a == "-n" || a == "--quiet" || a == "--silent" || a == "-E" || a == "-r" ||
			a == "--regexp-extended" || a == "-u" || a == "-s" || a == "-z":
		case a == "-e" || a == "--expression":
			if i+1 >= len(args) {
				return false
			}
			scripts, explicit = append(scripts, args[i+1]), true
			i++
		case strings.HasPrefix(a, "--expression="):
			scripts, explicit = append(scripts, strings.TrimPrefix(a, "--expression=")), true
		case strings.HasPrefix(a, "--"):
			return false
		case strings.HasPrefix(a, "-") && len(a) > 1:
			flags := a[1:]
			if strings.HasSuffix(flags, "e") {
				if i+1 >= len(args) {
					return false
				}
				scripts, explicit = append(scripts, args[i+1]), true
				i++
				flags = strings.TrimSuffix(flags, "e")
			}
			if strings.Trim(flags, "nErsuz") != "" {
				return false
			}
		default:
			operands = append(operands, a)
		}
	}
	if !explicit {
		if len(operands) == 0 {
			return false
		}
		scripts = append(scripts, operands[0])
	}
	for _, s := range scripts {
		if !sedScriptRe.MatchString(s) {
			return false
		}
	}
	return true
}

// gitReadOnlySubs never touch the working tree.
var gitReadOnlySubs = map[string]bool{
	"status": true, "log": true, "show": true, "diff": true, "blame": true,
	"ls-files": true, "rev-parse": true, "cat-file": true, "add": true, "commit": true,
}

func gitReadOnly(args []string) bool {
	i := 0
	for i < len(args) {
		switch a := args[i]; a {
		case "--no-pager", "-P", "--no-optional-locks":
			i++
		case "-C":
			i += 2
		default:
			if strings.HasPrefix(a, "-") {
				return false // -c, --git-dir, --exec-path, ... can redirect git
			}
			if !gitReadOnlySubs[strings.ToLower(a)] {
				return false
			}
			for _, x := range args[i+1:] {
				if strings.HasPrefix(x, "--output") || strings.HasPrefix(x, "--ext-diff") || strings.HasPrefix(x, "-O") {
					return false
				}
			}
			return true
		}
	}
	return false
}

// nestedBashReadOnly proves "bash -c SCRIPT" / "bash -lc SCRIPT".
func nestedBashReadOnly(args []string, depth int) bool {
	hasC := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--login" || a == "--noprofile" || a == "--norc":
		case strings.HasPrefix(a, "-") && len(a) > 1 && !strings.HasPrefix(a, "--"):
			if strings.Trim(a[1:], "lce") != "" {
				return false
			}
			if strings.Contains(a, "c") {
				hasC = true
			}
		default:
			if !hasC {
				return false // a script file: unknown content
			}
			return bashReadOnly(a, depth+1)
		}
	}
	return false
}

// psReadOnlyCmds are PowerShell commands (after alias resolution) that only read.
var psReadOnlyCmds = map[string]bool{
	"get-content": true, "select-string": true, "get-childitem": true, "get-item": true,
	"test-path": true, "get-filehash": true, "format-hex": true, "measure-object": true,
	"select-object": true, "get-location": true, "set-location": true, "resolve-path": true,
	"write-output": true, "out-host": true, "format-list": true, "format-table": true,
	"convertfrom-json": true, "convertto-json": true, "sort-object": true, "where-object": true,
	"out-string": true,
}

func psReadOnly(src string, depth int) bool {
	if depth > maxProofDepth {
		return false
	}
	toks, ok := psTokenize(src)
	if !ok {
		return false
	}
	var stmt []string
	flush := func() bool {
		defer func() { stmt = stmt[:0] }()
		if len(stmt) == 0 {
			return true
		}
		name := psCmdName(stmt[0])
		if psReadOnlyCmds[name] {
			return true
		}
		argv := append([]string{name}, stmt[1:]...)
		return argvReadOnly(argv, depth)
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.op {
		case "":
			// A '"' inside an argument reaches native programs unescaped in
			// PowerShell 5.1, which then split it into more arguments.
			if len(t.subs) > 0 || strings.ContainsAny(t.text, "\x02\x03<>`$@(){}\"") ||
				strings.ContainsRune(t.text, dynAny) || strings.ContainsRune(t.text, dynStar) {
				return false
			}
			stmt = append(stmt, t.text)
		case ">":
			// Only "2>/dev/null" or "2>nul" (stderr to the null device).
			if n := len(stmt); n == 0 || stmt[n-1] != "2" || i+1 >= len(toks) || !toks[i+1].isWord() ||
				(toks[i+1].text != "/dev/null" && !strings.EqualFold(toks[i+1].text, "nul")) {
				return false
			}
			stmt = stmt[:len(stmt)-1]
			i++
		case ";", "|", "&&", "||":
			if !flush() {
				return false
			}
		default:
			return false
		}
	}
	return flush()
}
