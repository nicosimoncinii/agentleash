package engine

import (
	"fmt"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// PowerShell support (ShellPowerShell) — conservative, documented limits.
//
// There is no PowerShell parser for Go, so the engine uses a tokenizer that
// understands quoting ('..', "..", here-strings, backtick escapes), $var /
// ${var} / $env:NAME, $(...) sub-expressions (analysed recursively), comments,
// type literals ([IO.File]::ReadAllText) and statement separators. On these
// tokens it applies:
//
//   - the path rules to every word and string (Get-Content, gc, type, cat,
//     -Path, [IO.File]::ReadAllText('...'), Copy-Item, ...);
//   - adjacent string concatenation ('.e'+'nv', -join) before matching;
//   - env rules: $env:NAME, ${env:NAME}, env: drive listings (gci env:,
//     dir env:, Get-Item env:*), [Environment]::GetEnvironmentVariable(s),
//     %NAME% (cmd-style);
//   - deny for -EncodedCommand (any accepted prefix), iex/Invoke-Expression,
//     [scriptblock]::Create and & / . calls with content only known at
//     runtime, and for runtime-built paths given to file readers;
//   - deny for decode primitives (FromBase64String, [char], -bxor, -join of
//     char codes, reversed strings) combined with a file read or execution;
//   - recursion into powershell -Command, cmd /c, bash -c, Start-Process
//     argument strings;
//   - commands.deny/ask patterns per statement and per pipeline.
//
// Not covered: full expression semantics (method chains, splatting,
// variables assigned in loops or functions, [char] arithmetic), aliases
// defined at runtime (Set-Alias), modules and scripts on disk.

type psTok struct {
	op   string   // non-empty for operators
	text string   // word text; vars appear as \x02name\x03, $(...) as dynAny
	subs []string // $(...) sub-expressions to analyse
}

const (
	phStart = '\x02'
	phEnd   = '\x03'
)

func (t psTok) isWord() bool { return t.op == "" }

// psTokenize splits PowerShell (or cmd) text into tokens. ok is false when a
// quote or here-string is not terminated.
func psTokenize(src string) (toks []psTok, ok bool) {
	rs := []rune(src)
	var cur strings.Builder
	var subs []string
	inWord := false
	flush := func() {
		if inWord {
			toks = append(toks, psTok{text: cur.String(), subs: subs})
		}
		cur.Reset()
		subs = nil
		inWord = false
	}
	emit := func(op string) {
		flush()
		toks = append(toks, psTok{op: op})
	}
	// readVar reads a variable reference starting at rs[i]=='$' and returns
	// the placeholder text and the index after it.
	readVar := func(i int) (string, int) {
		if i+1 < len(rs) && rs[i+1] == '{' {
			j := i + 2
			for j < len(rs) && rs[j] != '}' {
				j++
			}
			name := string(rs[i+2 : min(j, len(rs))])
			return string(phStart) + strings.ToLower(name) + string(phEnd), min(j+1, len(rs))
		}
		j := i + 1
		for j < len(rs) && (isWordRune(rs[j]) || rs[j] == ':' || rs[j] == '?' || rs[j] == '$' || rs[j] == '^') {
			if rs[j] == ':' && (j+1 >= len(rs) || !isWordRune(rs[j+1])) {
				break
			}
			j++
			if j == i+2 && (rs[i+1] == '$' || rs[i+1] == '?' || rs[i+1] == '^') {
				break
			}
		}
		if j == i+1 {
			return "$", j
		}
		return string(phStart) + strings.ToLower(string(rs[i+1:j])) + string(phEnd), j
	}
	readParen := func(i int) (string, int, bool) {
		// rs[i] == '(' ; returns inner text and index after ')'
		depth := 0
		for j := i; j < len(rs); j++ {
			switch rs[j] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return string(rs[i+1 : j]), j + 1, true
				}
			case '\'':
				j++
				for j < len(rs) && rs[j] != '\'' {
					j++
				}
			case '"':
				for j++; j < len(rs) && rs[j] != '"'; j++ {
					if rs[j] == '`' {
						j++
					}
				}
			}
		}
		return "", len(rs), false
	}
	// readDQ reads a double-quoted body (after the opening quote) until the
	// closing quote (or "@ for here-strings).
	readDQ := func(i int, here bool) (int, bool) {
		for i < len(rs) {
			c := rs[i]
			switch {
			case here && c == '\n' && i+2 < len(rs) && rs[i+1] == '"' && rs[i+2] == '@':
				return i + 3, true
			case !here && c == '"':
				if i+1 < len(rs) && rs[i+1] == '"' {
					cur.WriteRune('"')
					i += 2
					continue
				}
				return i + 1, true
			case c == '`' && i+1 < len(rs):
				cur.WriteRune(rs[i+1])
				i += 2
			case c == '$' && i+1 < len(rs) && rs[i+1] == '(':
				inner, next, ok := readParen(i + 1)
				if !ok {
					return len(rs), false
				}
				subs = append(subs, inner)
				cur.WriteRune(dynAny)
				i = next
			case c == '$':
				ph, next := readVar(i)
				cur.WriteString(ph)
				i = next
			default:
				cur.WriteRune(c)
				i++
			}
		}
		return i, false
	}
	ok = true
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			flush()
			i++
		case c == '\n':
			emit(";")
			i++
		case c == '#' && !inWord:
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
		case c == '<' && i+1 < len(rs) && rs[i+1] == '#':
			end := strings.Index(string(rs[i:]), "#>")
			if end < 0 {
				return toks, false
			}
			i += len([]rune(string(rs[i:])[:end+2]))
		case c == '`':
			if i+1 < len(rs) {
				if rs[i+1] != '\n' {
					cur.WriteRune(rs[i+1])
					inWord = true
				}
				i += 2
			} else {
				i++
			}
		case c == '@' && i+1 < len(rs) && (rs[i+1] == '\'' || rs[i+1] == '"') && i+2 < len(rs) && (rs[i+2] == '\n' || rs[i+2] == '\r'):
			inWord = true
			if rs[i+1] == '\'' {
				end := strings.Index(string(rs[i+2:]), "\n'@")
				if end < 0 {
					return toks, false
				}
				body := string(rs[i+2:])[:end]
				cur.WriteString(strings.TrimLeft(body, "\r\n"))
				i += 2 + len([]rune(string(rs[i+2:])[:end+3]))
			} else {
				next, good := readDQ(i+3, true)
				if !good {
					return toks, false
				}
				i = next
			}
		case c == '\'':
			inWord = true
			j := i + 1
			closed := false
			for j < len(rs) {
				if rs[j] == '\'' {
					if j+1 < len(rs) && rs[j+1] == '\'' {
						cur.WriteRune('\'')
						j += 2
						continue
					}
					closed = true
					j++
					break
				}
				cur.WriteRune(rs[j])
				j++
			}
			if !closed {
				return toks, false
			}
			i = j
		case c == '"':
			inWord = true
			next, good := readDQ(i+1, false)
			if !good {
				return toks, false
			}
			i = next
		case c == '$' && i+1 < len(rs) && rs[i+1] == '(':
			inner, next, good := readParen(i + 1)
			if !good {
				return toks, false
			}
			inWord = true
			subs = append(subs, inner)
			cur.WriteRune(dynAny)
			i = next
		case c == '@' && i+1 < len(rs) && (rs[i+1] == '(' || rs[i+1] == '{'):
			emit(string(rs[i+1]))
			i += 2
		case c == '$':
			ph, next := readVar(i)
			inWord = true
			cur.WriteString(ph)
			i = next
		case c == '[' && !inWord:
			depth := 0
			j := i
			for ; j < len(rs); j++ {
				if rs[j] == '[' {
					depth++
				} else if rs[j] == ']' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			if j >= len(rs) {
				cur.WriteRune(c)
				inWord = true
				i++
				continue
			}
			inWord = true
			cur.WriteString(string(rs[i : j+1]))
			i = j + 1
		case c == '&' && i+1 < len(rs) && rs[i+1] == '&':
			emit("&&")
			i += 2
		case c == '|' && i+1 < len(rs) && rs[i+1] == '|':
			emit("||")
			i += 2
		case strings.ContainsRune("|;(){},&+", c):
			emit(string(c))
			i++
		case c == '>' || c == '<':
			emit(string(c))
			i++
			if i < len(rs) && rs[i] == '>' {
				i++
			}
		case c == '=' && !inWord:
			emit("=")
			i++
		default:
			inWord = true
			cur.WriteRune(c)
			i++
		}
	}
	flush()
	return toks, ok
}

func isWordRune(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

type pwshEval struct {
	e     *Engine
	req   Request
	sec   *secretSet
	c     *collector
	depth int
	vars  map[string][]string
	// restricted: ShellAuto after a clean bash parse; only PowerShell/cmd
	// specific statements are analysed (bash covered the rest).
	restricted bool
}

func newPwshEval(e *Engine, sec *secretSet, c *collector, depth int) *pwshEval {
	return &pwshEval{e: e, sec: sec, c: c, depth: depth, vars: map[string][]string{}}
}

var psAliases = map[string]string{
	"gc": "get-content", "cat": "get-content", "type": "get-content",
	"sls": "select-string", "cp": "copy-item", "copy": "copy-item", "cpi": "copy-item",
	"mv": "move-item", "move": "move-item", "mi": "move-item", "ii": "invoke-item",
	"iex": "invoke-expression", "icm": "invoke-command",
	"gci": "get-childitem", "ls": "get-childitem", "dir": "get-childitem",
	"gi": "get-item", "gp": "get-itemproperty", "echo": "write-output",
	"saps": "start-process", "start": "start-process", "ipcsv": "import-csv",
	"rm": "remove-item", "rd": "remove-item", "del": "remove-item", "ri": "remove-item", "rmdir": "remove-item", "erase": "remove-item",
	"sc": "set-content", "ac": "add-content", "ni": "new-item", "md": "new-item", "mkdir": "new-item",
	"sl": "set-location", "pushd": "push-location", "chdir": "set-location",
	"gv": "get-variable", "%": "foreach-object", "foreach": "foreach-object", "?": "where-object", "where": "where-object",
}

var psReaders = set("get-content", "select-string", "copy-item", "move-item", "import-csv", "import-clixml",
	"import-powershelldatafile", "invoke-item", "more", "get-filehash", "format-hex", "compress-archive",
	"out-printer", "send-mailmessage", "invoke-webrequest", "invoke-restmethod", "iwr", "irm", "curl", "wget",
	"findstr", "find", "certutil", "xcopy", "robocopy", "expand", "makecab", "tar", "notepad")

var psPrint = set("write-output", "write-host", "write-verbose", "write-debug", "write-information", "write-warning", "out-host")

var (
	readMethodRe   = regexp.MustCompile(`(?i)(io\.file\]::(read|open|copy)|streamreader|::readalltext|::readalllines|::readallbytes|::openread|::opentext|filestream|get-content)`)
	psDecodeRe     = regexp.MustCompile(`(?i)frombase64string|\[char\]|\[char\[\]\]|-bxor|\[convert\]::|::reverse|\[array\]::reverse|-join\s*\(?\s*\[char|getstring\s*\(|\.replace\(|-replace\b`)
	psSinkRe       = regexp.MustCompile(`(?i)\b(iex|invoke-expression|get-content|gc|type|cat|readall\w*|start-process|invoke-command|icm|select-string|sls|copy-item)\b|::read|::open|&\s*\(`)
	cmdPercentVar  = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]*)(?::[^%]*)?%`)
	cmdBangVar     = regexp.MustCompile(`!([A-Za-z_][A-Za-z0-9_]*)(?::[^!]*)?!`)
	envDriveRe     = regexp.MustCompile(`(?i)^env:[\\/]?(.*)$`)
	psPlaceholderR = regexp.MustCompile("\x02([^\x03]*)\x03")
)

type psStmt struct {
	toks      []psTok
	readerCtx bool // arguments of a file-reading method call
	pipeIn    bool // receives pipeline input
	prev      *psStmt
}

// run analyses PowerShell text and reports whether it tokenized.
func (p *pwshEval) run(src string) bool {
	if p.depth > maxDepth {
		p.c.deny(RuleNesting, "the command nests shells too deeply to analyse; blocked to be safe.")
		return true
	}
	if !p.sec.work.spend(len(src)/64 + 1) {
		return true
	}
	toks, ok := psTokenize(src)
	if !ok {
		return false
	}
	if psDecodeRe.MatchString(src) && psSinkRe.MatchString(src) {
		p.c.deny(RuleObfuscation, "the PowerShell command decodes data (FromBase64String, [char], -bxor, -replace, reversed arrays) and then reads files or executes code; this hides what it accesses, so it is blocked. Write paths and commands in plain text.")
	}
	p.collectVars(toks)
	stmts := p.split(toks)
	for _, st := range stmts {
		p.statement(st)
	}
	p.concatChecks(toks)
	p.envAPICalls(toks)
	p.pipelines(toks)
	for _, t := range toks {
		for _, sub := range t.subs {
			ch := newPwshEval(p.e, p.sec, p.c, p.depth+1)
			ch.req, ch.vars = p.req, p.vars
			if !ch.run(sub) {
				p.c.deny(RuleParseError, "could not tokenize a PowerShell sub-expression; blocked to be safe.")
			}
		}
	}
	return true
}

func (p *pwshEval) collectVars(toks []psTok) {
	for i := 0; i+2 < len(toks); i++ {
		if !toks[i].isWord() || toks[i+1].op != "=" {
			continue
		}
		m := psPlaceholderR.FindStringSubmatch(toks[i].text)
		if m == nil || m[0] != toks[i].text {
			continue
		}
		name := m[1]
		val := toks[i+2]
		end := i + 3
		if val.isWord() && (end >= len(toks) || toks[end].op == ";" || toks[end].op == "") {
			p.vars[name] = append(p.vars[name], val.text)
		} else {
			p.vars[name] = append(p.vars[name], string(dynAny))
		}
	}
}

func (p *pwshEval) split(toks []psTok) []*psStmt {
	var out []*psStmt
	cur := &psStmt{}
	var prev *psStmt
	push := func(next *psStmt) {
		if len(cur.toks) > 0 {
			cur.prev = prev
			out = append(out, cur)
			prev = cur
		}
		cur = next
	}
	for _, t := range toks {
		switch t.op {
		case "":
			cur.toks = append(cur.toks, t)
		case ";", "&&", "||", "{", "}", ")":
			push(&psStmt{})
		case "|":
			push(&psStmt{pipeIn: true})
		case "(":
			reader := cur.readerCtx
			if n := len(cur.toks); n > 0 && cur.toks[n-1].isWord() {
				last := cur.toks[n-1].text
				name := p.stmtName(cur)
				if readMethodRe.MatchString(last) || psReaders[name] {
					reader = true
				}
			}
			push(&psStmt{readerCtx: reader})
		default:
			cur.toks = append(cur.toks, t)
		}
	}
	push(nil)
	return out
}

func psCmdName(t string) string {
	n := cmdBase(t)
	if a, ok := psAliases[n]; ok {
		return a
	}
	return n
}

func (p *pwshEval) stmtName(st *psStmt) string {
	if st.readerCtx || len(st.toks) == 0 || !st.toks[0].isWord() {
		return ""
	}
	t := st.toks[0].text
	if strings.ContainsRune(t, phStart) || strings.ContainsRune(t, dynAny) {
		return ""
	}
	return psCmdName(t)
}

// resolve expands placeholders into alternatives (internal syntax).
func (p *pwshEval) resolve(text string, depth int) []string {
	parts := psPlaceholderR.FindAllStringSubmatchIndex(text, -1)
	if len(parts) == 0 {
		return []string{activeLitWin(text)}
	}
	alts := []string{""}
	last := 0
	for _, m := range parts {
		alts = product(alts, []string{activeLitWin(text[last:m[0]])})
		name := text[m[2]:m[3]]
		alts = product(alts, p.varValues(name, depth))
		last = m[1]
		if len(alts) > maxAlts {
			return []string{string(dynAny)}
		}
	}
	return product(alts, []string{activeLitWin(text[last:])})
}

func (p *pwshEval) varValues(name string, depth int) []string {
	switch name {
	case "home", "env:userprofile", "env:home":
		if p.req.Home != "" {
			return []string{activeLitWin(p.req.Home)}
		}
	case "pwd":
		if p.req.Cwd != "" {
			return []string{activeLitWin(p.req.Cwd)}
		}
	}
	vals, ok := p.vars[name]
	if !ok || depth > 4 {
		return []string{string(dynAny)}
	}
	var out []string
	for _, v := range vals {
		out = append(out, p.resolve(v, depth+1)...)
	}
	return out
}

func (p *pwshEval) statement(st *psStmt) {
	if !p.sec.work.spend(len(st.toks) + 1) {
		return
	}
	name := p.stmtName(st)
	toks := st.toks
	// Variable references: env names and dynamic calls.
	for _, t := range toks {
		for _, m := range psPlaceholderR.FindAllStringSubmatch(t.text, -1) {
			v := m[1]
			if strings.HasPrefix(v, "env:") {
				p.checkEnvName(strings.TrimPrefix(v, "env:"))
			}
		}
		p.checkPercentVars(t.text)
		lower := strings.ToLower(t.text)
		if strings.Contains(lower, "getenvironmentvariables") || strings.Contains(lower, "win32_environment") ||
			strings.HasSuffix(strings.ReplaceAll(lower, "/", `\`), `\environment`) || (name == "wmic" && lower == "environment") {
			// also reg query HKCU\Environment, wmic environment, Get-CimInstance Win32_Environment
			p.c.deny(RuleEnvExposure, envDumpReason)
		}
		if strings.Contains(lower, "scriptblock]::create") {
			p.c.deny(RuleDynamicShell, "[scriptblock]::Create builds code at runtime that cannot be checked; blocked to be safe.")
		}
	}
	if len(toks) > 1 && (toks[0].op == "&" || (toks[0].isWord() && toks[0].text == ".")) {
		inner := toks[1].text
		if strings.ContainsRune(inner, phStart) || strings.ContainsRune(inner, dynAny) {
			p.c.deny(RuleDynamicShell, "calling a command whose name is only known at runtime (& $x / . $x) cannot be checked; blocked to be safe. Call the command by name.")
		}
		name = psCmdName(inner)
		toks = toks[1:]
	}
	args := toks
	if name != "" {
		args = toks[1:]
	}
	if p.restricted && !psSpecific(name, st.readerCtx) {
		// ShellAuto with a clean bash parse: bash already analysed this
		// statement; only PowerShell/cmd-specific constructs count here.
		p.envDriveWords(args)
		if psLocation[name] {
			p.setLocation(args) // cmd: cd /d %USERPROFILE%.aws & type credentials
		}
		return
	}
	if name != "" {
		argv := []string{cmdBase(toks[0].text)}
		for _, a := range args {
			if a.isWord() {
				argv = append(argv, plain(subjectText(p.resolve(a.text, 0)[0])))
			}
		}
		checkCredentialPrint(p.c, argv)
	}
	switch {
	case psLocation[name]:
		p.setLocation(args)
	case interpreters[name]:
		p.nestedBash(name, args)
	}
	switch name {
	case "invoke-expression":
		p.evalLike(args, "Invoke-Expression")
	case "powershell", "pwsh", "powershell_ise":
		p.nestedPwsh(args)
	case "cmd":
		p.nestedCmd(args)
	case "bash", "sh", "wsl", "zsh", "dash":
		p.nestedBash(name, args)
	case "set", "set-item", "get-item", "get-childitem", "get-content", "remove-item":
		if name == "set" {
			p.cmdSet(args)
		}
	case "printenv", "env":
		if len(args) == 0 {
			p.c.deny(RuleEnvExposure, envDumpReason)
		}
	}
	words := p.envDriveWords(args)
	if name == "copy-item" || name == "move-item" {
		words = p.copyDest(name, words)
	}
	for _, t := range words {
		if !psLocation[name] {
			p.checkWord(name, t, st.readerCtx)
		}
	}
	if (psReaders[name] || name == "foreach-object") && st.pipeIn && st.prev != nil && !hasPathArg(args) {
		p.pipelineInput(st.prev)
	}
}

// envDriveWords handles env: drive words (gci env:, Get-Item env:X) and
// returns the remaining words.
func (p *pwshEval) envDriveWords(args []psTok) []psTok {
	var rest []psTok
	for _, t := range args {
		if !t.isWord() {
			continue
		}
		m := envDriveRe.FindStringSubmatch(strings.ToLower(t.text))
		switch {
		case m == nil:
			rest = append(rest, t)
		case m[1] == "" || strings.ContainsAny(m[1], "*?[") || strings.ContainsRune(m[1], phStart):
			p.c.deny(RuleEnvExposure, envDumpReason)
		default:
			p.checkEnvName(m[1])
		}
	}
	return rest
}

// copyDest: Copy-Item/Move-Item onto a secret path (Copy-Item .env.example
// .env) reads nothing secret and is asked; the destination is removed from
// the words still to check.
func (p *pwshEval) copyDest(name string, words []psTok) []psTok {
	dest := -1
	var positional []int
	for i := 0; i < len(words); i++ {
		low := strings.ToLower(words[i].text)
		switch {
		case low == "-destination" || low == "-dest":
			if i+1 < len(words) {
				dest = i + 1
			}
			i++
		case strings.HasPrefix(low, "-"):
			if low == "-path" || low == "-literalpath" || low == "-filter" || low == "-include" || low == "-exclude" {
				if low != "-path" && low != "-literalpath" {
					i++
				}
			}
		default:
			positional = append(positional, i)
		}
	}
	if dest < 0 && len(positional) >= 2 {
		dest = positional[1]
	}
	if dest < 0 {
		return words
	}
	for _, alt := range p.resolve(words[dest].text, 0) {
		if isDynamic(alt) || hasGlobMeta(alt) {
			return words
		}
		if m, ok := p.sec.checkPath(alt); ok && !m.glob {
			p.c.ask(RuleSecretFile+":"+m.pattern, fmt.Sprintf("`%s` would overwrite the secret file %q (secrets.files: %q in .agentleash.yaml); the user must confirm. Nothing secret is read.", name, display(plain(alt)), m.pattern))
			return append(append([]psTok(nil), words[:dest]...), words[dest+1:]...)
		}
	}
	return words
}

var psLocation = set("set-location", "push-location", "cd", "chdir")

var psMetadataCmds = set("get-childitem", "get-item", "test-path", "remove-item", "new-item", "rename-item",
	"resolve-path", "split-path", "join-path", "get-acl", "set-acl")

// setLocation records a cd/Set-Location/Push-Location target as a possible
// working directory (cmd's `cd /d X` too).
func (p *pwshEval) setLocation(args []psTok) {
	for i := 0; i < len(args); i++ {
		t := args[i]
		if !t.isWord() {
			continue
		}
		low := strings.ToLower(t.text)
		if low == "/d" || (strings.HasPrefix(low, "-") && low != "-") {
			if low == "-path" || low == "-literalpath" {
				continue // value follows
			}
			if strings.HasPrefix(low, "-") {
				i++ // -StackName X, etc.
			}
			continue
		}
		for _, alt := range p.resolve(t.text, 0) {
			p.sec.addBase(alt)
		}
		return
	}
	p.sec.addBase("~")
}

// pipelineInput checks what a content reader receives through the
// pipeline: a string ('.env' | gc) or the output of a listing
// (gci -Force | gc). Windows has no dotfile rule, so listings match
// hidden files too.
func (p *pwshEval) pipelineInput(prev *psStmt) {
	name := p.stmtName(prev)
	words := prev.toks
	switch {
	case name == "get-childitem" || name == "get-item" || name == "resolve-path":
		words = words[1:]
	case len(words) == 1 && words[0].isWord() && name != "" && !psKnownCommand(name):
		p.checkListed(words[0].text, "", false) // a bare value: '.env' | gc
		return
	default:
		return
	}
	var dirs, filters []string
	recurse := false
	for i := 0; i < len(words); i++ {
		t := words[i]
		if !t.isWord() {
			continue
		}
		low := strings.ToLower(t.text)
		switch {
		case low == "-filter" || low == "-include":
			if i+1 < len(words) {
				filters = append(filters, words[i+1].text)
				i++
			}
		case isPrefixParam(strings.TrimLeft(low, "-"), "recurse", 1) && strings.HasPrefix(low, "-"):
			recurse = true
		case low == "-path" || low == "-literalpath":
		case strings.HasPrefix(low, "-"):
		default:
			dirs = append(dirs, t.text)
		}
	}
	if len(dirs) == 0 {
		dirs = []string{""}
	}
	if len(filters) == 0 {
		filters = []string{"*"}
	}
	for _, d := range dirs {
		for _, f := range filters {
			p.checkListed(d, f, recurse)
		}
	}
}

func psKnownCommand(name string) bool {
	return psReaders[name] || readers[name] || interpreters[name] || strings.Contains(name, "-") || psLocation[name]
}

// checkListed denies when a listed path (dir + filter) could be a secret.
func (p *pwshEval) checkListed(dir, filter string, recurse bool) {
	winGlob := func(s string) string {
		return strings.NewReplacer("*", string(dynStar), "?", string(dynStar)).Replace(s)
	}
	for _, alt := range p.resolve(dir, 0) {
		var cands []string
		switch {
		case filter == "" && dir != "":
			cands = []string{winGlob(alt)}
		default:
			base := strings.TrimSuffix(winGlob(alt), "/")
			if base != "" {
				base += "/"
			}
			if recurse {
				base += "**/"
			}
			cands = []string{base + winGlob(activeLitWin(filter)), winGlob(alt)}
		}
		for _, c := range cands {
			if c == "" {
				continue
			}
			if m, ok := p.sec.checkPath(c); ok {
				m.glob, m.path = true, plain(c)
				p.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "reading files listed by", p.sec))
				return
			}
		}
	}
}

// psSpecific reports whether a statement uses PowerShell/cmd-only
// constructs that the bash pass cannot see.
func psSpecific(name string, readerCtx bool) bool {
	if readerCtx || name == "" {
		return readerCtx
	}
	switch name {
	case "type", "copy", "more", "findstr", "xcopy", "robocopy", "certutil", "cmd", "powershell", "pwsh",
		"set", "reg", "wmic", "invoke-expression":
		return true
	}
	return strings.Contains(name, "-")
}

// envAPICalls checks [Environment]::GetEnvironmentVariable('NAME').
func (p *pwshEval) envAPICalls(toks []psTok) {
	for i, t := range toks {
		low := strings.ToLower(t.text)
		if !t.isWord() || !strings.Contains(low, "getenvironmentvariable") || strings.Contains(low, "getenvironmentvariables") {
			continue
		}
		if i+2 >= len(toks) || toks[i+1].op != "(" || !toks[i+2].isWord() || (i+3 < len(toks) && toks[i+3].op == "+") {
			p.c.deny(RuleEnvExposure, "GetEnvironmentVariable with a name only known at runtime could expose a secret environment variable; name the variable literally.")
			continue
		}
		alts := p.resolve(toks[i+2].text, 0)
		for _, a := range alts {
			if isDynamic(a) {
				p.c.deny(RuleEnvExposure, "GetEnvironmentVariable with a name only known at runtime could expose a secret environment variable; name the variable literally.")
				break
			}
			p.checkEnvName(plain(a))
		}
	}
}

func hasPathArg(args []psTok) bool {
	for _, a := range args {
		if a.isWord() && !strings.HasPrefix(a.text, "-") {
			return true
		}
	}
	return false
}

// checkWord applies the path rules to one word.
func (p *pwshEval) checkWord(name string, t psTok, readerCtx bool) {
	if psPrint[name] || name == "test-path" || existenceOnly[name] {
		return
	}
	reader := readerCtx || psReaders[name] || readers[name]
	for _, alt := range p.resolve(t.text, 0) {
		dyn := isDynamic(alt)
		for _, cand := range argCandidates(alt) {
			m, ok := p.sec.checkPath(cand)
			if !ok {
				if reader && !dyn {
					if dm, ok := p.sec.dirHoldsSecret(cand); ok {
						p.c.deny(RuleSecretFile+":"+dm.pattern, dirReason(dm, "reading", p.sec))
					}
				}
				continue
			}
			switch {
			case m.builtin && !dyn:
				p.c.deny(RuleEnvExposure, secretFileReason(m, "reading", p.sec))
			case !m.glob && psMetadataCmds[name]:
				// Get-ChildItem ~/.ssh, Get-Item .env: names and attributes only.
			case !m.glob:
				p.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "reading", p.sec))
			case isDynamic(cand):
				// A statement starting with a variable is an expression,
				// not a command: only readers and glued fragments count.
				if !strings.ContainsAny(cand, " \t") && (reader || hasStatic(cand)) {
					p.c.deny(RuleDynamicPath, fmt.Sprintf("the path %q is built at runtime (variable or sub-expression) and could resolve to a secret file (secrets.files: %q). Use a literal, non-secret path.", display(plain(alt)), m.pattern))
				}
			case !reader && !interpreters[name] && name != "":
				// Globs only matter for commands that read files; PowerShell
				// syntax gives too little structure to treat others strictly.
			default:
				m.path = plain(cand)
				p.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "reading", p.sec))
			}
		}
		if !dyn {
			txt := plain(alt)
			if strings.ContainsAny(txt, " \t") {
				p.embedded(txt)
			}
		}
	}
}

func hasStatic(cand string) bool {
	for _, r := range cand {
		if r != dynAny && r != dynStar && r != '/' && r != '.' && r != '*' {
			return true
		}
	}
	return false
}

func (p *pwshEval) checkEnvName(name string) {
	if g, ok := p.sec.envMatch(name); ok {
		p.c.deny(RuleSecretEnv+":"+g, fmt.Sprintf("the value of environment variable %s must not be exposed: it matches secrets.env %q in .agentleash.yaml. To check it is set without printing it, use [bool]$env:%s; otherwise ask the user.", name, g, name))
	}
}

func (p *pwshEval) checkPercentVars(text string) {
	for _, re := range []*regexp.Regexp{cmdPercentVar, cmdBangVar} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			p.checkEnvName(m[1])
		}
	}
}

// embedded re-analyses a string argument that looks like a command line
// (Start-Process -ArgumentList '/c type .env', cmd strings, ...).
func (p *pwshEval) embedded(text string) {
	t := strings.TrimSpace(text)
	low := strings.ToLower(t)
	for _, pre := range []string{"/c ", "/k ", "-c ", "-command "} {
		if strings.HasPrefix(low, pre) {
			t = t[len(pre):]
			low = low[len(pre):]
		}
	}
	head := low
	if i := strings.IndexAny(low, " \t;|&"); i >= 0 {
		head = low[:i]
	}
	n := psCmdName(head)
	if !psEmbeddedHead(n) {
		return
	}
	ch := newPwshEval(p.e, p.sec, p.c, p.depth+1)
	ch.req, ch.vars = p.req, p.vars
	ch.run(t)
}

func psEmbeddedHead(n string) bool {
	switch n {
	case "get-childitem", "invoke-expression", "cmd", "powershell", "pwsh", "set":
		return true
	}
	return psReaders[n] || readers[n] || embeddedHeads[n]
}

func (p *pwshEval) evalLike(args []psTok, what string) {
	var words []psTok
	for _, a := range args {
		if a.isWord() {
			words = append(words, a)
		}
	}
	if len(words) != 1 {
		p.c.deny(RuleDynamicShell, fmt.Sprintf("%s of text that is only known at runtime cannot be checked; blocked to be safe. Run the command directly.", what))
		return
	}
	alts := p.resolve(words[0].text, 0)
	for _, alt := range alts {
		if isDynamic(alt) {
			p.c.deny(RuleDynamicShell, fmt.Sprintf("%s of text that is only known at runtime cannot be checked; blocked to be safe. Run the command directly.", what))
			return
		}
	}
	for _, alt := range alts {
		ch := newPwshEval(p.e, p.sec, p.c, p.depth+1)
		ch.req, ch.vars = p.req, p.vars
		if !ch.run(plain(alt)) {
			p.c.deny(RuleParseError, "could not tokenize the PowerShell text passed to "+what+"; blocked to be safe.")
		}
	}
}

func isPrefixParam(p, full string, minLen int) bool {
	return len(p) >= minLen && strings.HasPrefix(full, p)
}

func (p *pwshEval) nestedPwsh(args []psTok) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.isWord() {
			continue
		}
		low := strings.ToLower(a.text)
		if !strings.HasPrefix(low, "-") && !strings.HasPrefix(low, "/") {
			p.evalLike(args[i:], "powershell")
			p.evalJoined(args[i:])
			return
		}
		param := strings.TrimLeft(low, "-/")
		switch {
		case param == "e" || param == "ec" || isPrefixParam(param, "encodedcommand", 2) || isPrefixParam(param, "encodedarguments", 8):
			p.c.deny(RuleEncodedCmd, "powershell -EncodedCommand hides the command being run, so it is blocked. Pass the command as plain text with -Command.")
			return
		case param == "c" || isPrefixParam(param, "command", 2):
			p.evalJoined(args[i+1:])
			return
		case param == "f" || isPrefixParam(param, "file", 2):
			return
		case isPrefixParam(param, "executionpolicy", 2) || param == "ep" || isPrefixParam(param, "windowstyle", 1) ||
			isPrefixParam(param, "workingdirectory", 2) || isPrefixParam(param, "configurationname", 4) ||
			isPrefixParam(param, "outputformat", 1) || isPrefixParam(param, "inputformat", 2) || isPrefixParam(param, "settingsfile", 2) ||
			isPrefixParam(param, "custompipename", 2) || isPrefixParam(param, "psconsolefile", 3):
			i++
		}
	}
}

// evalJoined re-analyses the remaining tokens as one PowerShell command.
func (p *pwshEval) evalJoined(args []psTok) {
	var parts []string
	for _, a := range args {
		if !a.isWord() {
			parts = append(parts, a.op)
			continue
		}
		alts := p.resolve(a.text, 0)
		if len(alts) != 1 || isDynamic(alts[0]) {
			p.c.deny(RuleDynamicShell, "powershell -Command with text only known at runtime cannot be checked; blocked to be safe.")
			return
		}
		parts = append(parts, plain(alts[0]))
	}
	if len(parts) == 0 {
		return
	}
	ch := newPwshEval(p.e, p.sec, p.c, p.depth+1)
	ch.req, ch.vars = p.req, p.vars
	if !ch.run(strings.Join(parts, " ")) {
		p.c.deny(RuleParseError, "could not tokenize the nested PowerShell command; blocked to be safe.")
	}
}

func (p *pwshEval) nestedCmd(args []psTok) {
	for i, a := range args {
		if !a.isWord() {
			continue
		}
		low := strings.ToLower(a.text)
		if low == "/c" || low == "/k" || low == "/r" {
			var parts []string
			for _, b := range args[i+1:] {
				if b.isWord() {
					parts = append(parts, b.text)
				} else {
					parts = append(parts, b.op)
				}
			}
			evalCmdText(p.e, p.req, p.sec, p.c, p.depth+1, strings.Join(parts, " "), false)
			return
		}
	}
}

func (p *pwshEval) nestedBash(name string, args []psTok) {
	var parts []string
	if name != "wsl" {
		parts = append(parts, name)
	}
	for _, a := range args {
		if !a.isWord() {
			continue
		}
		alts := p.resolve(a.text, 0)
		if len(alts) != 1 || isDynamic(alts[0]) {
			parts = append(parts, `"$X"`)
			continue
		}
		t := plain(alts[0])
		if name == "wsl" && (t == "-e" || t == "--exec" || t == "--") {
			continue
		}
		parts = append(parts, "'"+strings.ReplaceAll(t, "'", `'\''`)+"'")
	}
	if len(parts) == 0 {
		return
	}
	sh := newShellEval(p.e, p.sec, p.c, p.depth+1).withReq(p.req)
	sh.run(strings.Join(parts, " "))
}

// cmdSet handles cmd's `set` (and PowerShell's `set` alias for Set-Variable,
// which with no arguments is harmless but treated like cmd to be safe).
func (p *pwshEval) cmdSet(args []psTok) {
	var words []string
	for _, a := range args {
		if a.isWord() {
			words = append(words, a.text)
		} else if a.op == "=" {
			return // assignment
		}
	}
	if len(words) == 0 {
		p.c.deny(RuleEnvExposure, envDumpReason)
		return
	}
	w := words[0]
	if !isIdent(w) {
		return // flags (/a, /p, -e), assignments, dynamic text
	}
	// `set PREFIX` prints every variable starting with PREFIX.
	for _, g := range p.sec.env {
		if globMatchString(g, strings.ToLower(w)+string(dynAny)) {
			p.c.deny(RuleEnvExposure, fmt.Sprintf("`set %s` prints every environment variable starting with %q, which could include secrets (secrets.env %q).", display(w), display(w), g))
			return
		}
	}
}

// concatChecks joins string pieces glued with + or -join and re-checks them.
func (p *pwshEval) concatChecks(toks []psTok) {
	for i := 0; i < len(toks); i++ {
		if !toks[i].isWord() {
			continue
		}
		joined := toks[i].text
		j := i
		for j+2 < len(toks) && toks[j+1].op == "+" && toks[j+2].isWord() {
			joined += toks[j+2].text
			j += 2
		}
		if j > i {
			p.checkWord("", psTok{text: joined}, false)
			i = j
		}
		if strings.EqualFold(toks[i].text, "-join") {
			var b strings.Builder
			for k := i + 1; k < len(toks) && toks[k].op != ")" && toks[k].op != ";"; k++ {
				if toks[k].isWord() {
					b.WriteString(strings.Trim(toks[k].text, "'\""))
				}
			}
			p.checkWord("", psTok{text: b.String()}, false)
		}
	}
}

// pipelines applies command patterns per statement and per pipeline.
func (p *pwshEval) pipelines(toks []psTok) {
	var stages [][]string
	var cur []string
	flushStage := func() {
		if len(cur) > 0 && strings.ContainsRune(cur[0], dynAny) {
			// expression or runtime-chosen command: like bash, not matched
			stages = append(stages, []string{"\x02"})
			cur = nil
			return
		}
		if len(cur) > 0 {
			forms := commandForms(cur, p.req.Home)
			if alias := psCmdName(cur[0]); alias != cmdBase(cur[0]) {
				forms = append(forms, commandForms(append([]string{alias}, cur[1:]...), p.req.Home)...)
			}
			if rmArgv := psRemoveAsRm(cur); rmArgv != nil {
				forms = append(forms, commandForms(rmArgv, p.req.Home)...)
			}
			applyPatterns(p.e.policy, p.c, p.sec.work, p.req.Home, forms, nil)
			stages = append(stages, forms)
		}
		cur = nil
	}
	flushPipe := func() {
		flushStage()
		if len(stages) > 1 {
			applyPatterns(p.e.policy, p.c, p.sec.work, p.req.Home, nil, stages)
		}
		stages = nil
	}
	for _, t := range toks {
		switch {
		case t.isWord():
			alts := p.resolve(t.text, 0)
			cur = append(cur, subjectText(alts[0]))
		case t.op == "|":
			flushStage()
		case t.op == ">" || t.op == "<" || t.op == "," || t.op == "+" || t.op == "=":
			cur = append(cur, t.op)
		default:
			flushPipe()
		}
	}
	flushPipe()
}

// psRemoveAsRm translates Remove-Item (and its aliases, and cmd's
// rd/rmdir /s /q) into an equivalent `rm -rf PATH` argv so that rm deny
// patterns also cover `Remove-Item -Recurse -Force ~` or `rd /s /q C:\`.
func psRemoveAsRm(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	name := psCmdName(argv[0])
	if name != "remove-item" {
		return nil
	}
	letters := ""
	var paths []string
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		low := strings.ToLower(t)
		switch {
		case low == "/s":
			letters += "r"
		case low == "/q":
			letters += "f"
		case strings.HasPrefix(low, "-") && len(low) > 1:
			p := strings.TrimLeft(low, "-")
			if j := strings.IndexByte(p, ':'); j >= 0 {
				p = p[:j] // -Recurse:$true
			}
			switch {
			case isPrefixParam(p, "recurse", 1):
				letters += "r"
			case isPrefixParam(p, "force", 2):
				letters += "f"
			case p == "path" || p == "literalpath" || p == "lp" || p == "pspath":
				if i+1 < len(argv) {
					paths = append(paths, argv[i+1])
					i++
				}
			case p == "filter" || p == "include" || p == "exclude" || p == "credential" || p == "stream":
				i++
			}
		default:
			paths = append(paths, t)
		}
	}
	out := []string{"rm"}
	if letters != "" {
		out = append(out, "-"+letters)
	}
	return append(out, paths...)
}

var (
	cmdHomeVars = strings.NewReplacer(
		"%HOMEDRIVE%%HOMEPATH%", "$env:USERPROFILE", "%USERPROFILE%", "$env:USERPROFILE",
		"%userprofile%", "$env:USERPROFILE", "%HOMEPATH%", "$env:USERPROFILE", "%homepath%", "$env:USERPROFILE",
		"%HOME%", "$env:USERPROFILE", "%CD%", "$pwd", "%cd%", "$pwd")
	cmdAmpRe = regexp.MustCompile(`&&?`)
)

// evalCmdText analyses cmd.exe syntax: ^ escapes are removed, then the
// PowerShell tokenizer and rules are reused (type/copy/more, %VAR%, set).
func evalCmdText(e *Engine, req Request, sec *secretSet, c *collector, depth int, src string, restricted bool) bool {
	clean := strings.ReplaceAll(src, "^", "")
	if strings.Count(clean, `"`)%2 == 1 {
		return false
	}
	// cmd has no single quotes or backtick escapes: neutralise them.
	clean = strings.ReplaceAll(clean, "'", "\x04")
	clean = strings.ReplaceAll(clean, "`", "\x05")
	// Home and cwd variables, and `&` as a command separator.
	clean = cmdHomeVars.Replace(clean)
	clean = cmdAmpRe.ReplaceAllString(clean, " ; ")
	pe := newPwshEval(e, sec, c, depth)
	pe.req = req
	pe.restricted = restricted
	toks, ok := psTokenize(clean)
	if !ok {
		return false
	}
	for k := range toks {
		toks[k].text = strings.NewReplacer("\x04", "'", "\x05", "`").Replace(toks[k].text)
	}
	pe.collectVars(toks)
	for _, st := range pe.split(toks) {
		pe.statement(st)
	}
	pe.pipelines(toks)
	return true
}

// lexicalCheck is the last line of defence when some dialects could not
// parse the command: it looks at raw tokens only.
//
// With envOnly (bash parsed cleanly, so bash covered paths and dumps), only
// PowerShell/cmd-specific env references are looked for.
func lexicalCheck(sec *secretSet, c *collector, src string, envOnly bool) {
	envRe := lexEnvRe
	if envOnly {
		envRe = lexWinEnvRe
	}
	for _, m := range envRe.FindAllStringSubmatch(src, -1) {
		name := m[1] + m[2]
		if g, ok := sec.envMatch(name); ok {
			c.deny(RuleSecretEnv+":"+g, envNameReason(name, g))
		}
	}
	if envOnly {
		return
	}
	for _, tok := range lexTokRe.FindAllString(src, -1) {
		t := strings.TrimPrefix(tok, "@")
		if m, ok := sec.checkPath(escapeLitWin(t)); ok {
			c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "reading", sec))
		}
		if strings.ContainsAny(t, "*?[") {
			if m, ok := sec.checkPath(activeLitWin(t)); ok {
				m.glob = true
				c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "reading", sec))
			}
		}
	}
	if lexDumpRe.MatchString(src) {
		c.deny(RuleEnvExposure, envDumpReason)
	}
	if lexEncRe.MatchString(src) && lexPwshRe.MatchString(src) {
		c.deny(RuleEncodedCmd, "powershell -EncodedCommand hides the command being run, so it is blocked. Pass the command as plain text.")
	}
}

var (
	lexTokRe    = regexp.MustCompile(`[^\s'"` + "`" + `;|&<>(){},]+`)
	lexEnvRe    = regexp.MustCompile(`(?i)\$\{?(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}?|%([A-Za-z_][A-Za-z0-9_]*)(?::[^%]*)?%`)
	lexWinEnvRe = regexp.MustCompile(`(?i)\$\{?env:([A-Za-z_][A-Za-z0-9_]*)\}?|%([A-Za-z_][A-Za-z0-9_]*)(?::[^%]*)?%`)
	lexDumpRe   = regexp.MustCompile(`(?i)(^|[\s;|&(])(printenv|env|set|export\s+-p|declare\s+-x)\s*($|[;|&)])|env:\s*($|[;|&)])|getenvironmentvariables`)
	lexEncRe    = regexp.MustCompile(`(?i)(^|\s)-(e|ec|enc\w*)\s`)
	lexPwshRe   = regexp.MustCompile(`(?i)\b(powershell|pwsh)\b`)
)

// blankHeredocs replaces here-document bodies with spaces (newlines kept):
// for ShellAuto they are data that bash already analysed, not PowerShell or
// cmd statements.
func blankHeredocs(src string) string {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		return src
	}
	b := []byte(src)
	syntax.Walk(f, func(n syntax.Node) bool {
		r, ok := n.(*syntax.Redirect)
		if !ok || r.Hdoc == nil {
			return true
		}
		start, end := int(r.Hdoc.Pos().Offset()), int(r.Hdoc.End().Offset())
		for i := start; i < end && i < len(b); i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
		return true
	})
	return string(b)
}
