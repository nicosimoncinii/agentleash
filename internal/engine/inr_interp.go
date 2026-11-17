package engine

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// inrJqValueOpts are the jq options that take two values (name and value).
var inrJqValueOpts = set("--arg", "--argjson", "--slurpfile", "--rawfile")

// inrInterpScan is the state of one scan over an interpreter's arguments,
// looking for inline code, a script operand or a stdin program.
type inrInterpScan struct {
	s          *shellEval
	name, fam  string
	flags      string
	words      map[string]bool
	valOpts    map[string]bool
	pythonLike bool
	args       []cmdArg
	i          int

	gotProgram, gotScript, readsStdin bool
	expectCode                        bool
	scriptFile                        bool // -f FILE for awk/sed/jq
	codes, tail                       []string
}

// newInrInterpScan prepares the scan of the arguments of interpreter name.
func newInrInterpScan(s *shellEval, name string, args []cmdArg) *inrInterpScan {
	fam := familyOf(name)
	flags := codeFlags[name]
	return &inrInterpScan{
		s:          s,
		name:       name,
		fam:        fam,
		flags:      flags,
		words:      codeOptWords[name],
		valOpts:    interpValueOpts[fam],
		pythonLike: flags == "c",
		args:       args,
	}
}

// scan records a literal inline program and checks it.
func (p *inrInterpScan) scan(code string) {
	p.gotProgram = true
	p.codes = append(p.codes, code)
	p.s.scanCode(p.name, code)
}

// scanArg records an inline program argument (possibly dynamic) and checks it.
func (p *inrInterpScan) scanArg(a cmdArg) {
	p.gotProgram = true
	for _, alt := range a.alts {
		if !isDynamic(alt) {
			p.codes = append(p.codes, plain(alt))
		}
	}
	p.s.scanCodeArg(p.name, a)
}

// run walks the arguments until the program or script is found.
func (p *inrInterpScan) run() {
	for p.i = 0; p.i < len(p.args); p.i++ {
		if p.step() {
			break
		}
	}
}

// step handles the argument at p.i and reports whether the scan stops.
func (p *inrInterpScan) step() bool {
	a := p.args[p.i]
	t, static := a.text()
	if p.expectCode {
		p.expectCode = false
		p.scanArg(a)
		return false
	}
	if !static {
		return p.dynamicArg(a)
	}
	if handled, stop := p.special(t); handled {
		return stop
	}
	if strings.HasPrefix(t, "--") {
		p.longOption(t)
		return false
	}
	if strings.HasPrefix(t, "-") && len(t) > 1 {
		p.shortOption(t)
		return false
	}
	return p.operand(t)
}

// dynamicArg handles an argument only known at runtime and reports whether
// the scan stops.
func (p *inrInterpScan) dynamicArg(a cmdArg) bool {
	if programFirst[p.name] && !p.gotProgram && !p.scriptFile {
		p.scanArg(a)
		return false
	}
	if !p.gotProgram {
		p.gotScript = true
	}
	return true
}

// special handles stdin, end-of-options, code-taking words and
// interpreter-specific options; handled is false for anything else.
func (p *inrInterpScan) special(t string) (handled, stop bool) {
	switch {
	case t == "-":
		p.readsStdin = true
		return true, true
	case t == "--":
		return true, false
	case p.name == "deno" && t == "eval" && !p.gotScript:
		p.expectCode = true
		return true, false
	case p.fam == "jq" && inrJqValueOpts[t]:
		p.i += 2
		return true, false
	case p.words[t]:
		p.expectCode = true
		return true, false
	}
	if eq := strings.IndexByte(t, '='); eq > 0 && p.words[t[:eq]] {
		p.scan(t[eq+1:])
		return true, false
	}
	return p.module(t)
}

// module handles php -i, perl -M/-m and python -m.
func (p *inrInterpScan) module(t string) (handled, stop bool) {
	switch {
	case p.name == "php" && (t == "-i" || t == "--info"):
		p.s.c.deny(RuleEnvExposure, "`php -i` (phpinfo) prints the whole environment, which contains secret variables (secrets.env). Use `php -v` or `php -m` instead.")
		return true, false
	case p.fam == "perl" && len(t) >= 2 && (strings.HasPrefix(t, "-M") || strings.HasPrefix(t, "-m")):
		mod := t[2:]
		if mod == "" && p.i+1 < len(p.args) {
			p.i++
			mod = p.args[p.i].textOr()
		}
		p.s.perlModule(mod, t[1] == 'M')
		return true, false
	case p.pythonLike && strings.HasPrefix(t, "-m"):
		mod := t[2:]
		if mod == "" && p.i+1 < len(p.args) {
			mod = p.args[p.i+1].textOr()
		}
		if strings.HasPrefix(mod, "dotenv") {
			p.s.implicitDotenv(p.name)
		}
		p.gotScript = true
		return true, true
	}
	return false, false
}

// longOption handles a --long option, with or without an inline value.
func (p *inrInterpScan) longOption(t string) {
	key := t
	if eq := strings.IndexByte(t, '='); eq > 0 {
		key = t[:eq]
		if codeLongFlags[key] {
			p.scan(t[eq+1:])
		}
		return
	}
	if codeLongFlags[key] {
		p.expectCode = true
		return
	}
	if p.valOpts[key] {
		if key == "--file" || key == "--from-file" {
			p.scriptFile = true
		}
		p.i++
	}
}

// shortOption handles a -x option or a cluster of short options.
func (p *inrInterpScan) shortOption(t string) {
	if p.valOpts[t] {
		if t == "-f" {
			p.scriptFile = true
		}
		p.i++
		return
	}
	if p.words != nil {
		return // no short-option clusters
	}
	letters := t[1:]
	for j, l := range letters {
		if p.flags != "" && strings.ContainsRune(p.flags, l) {
			if j == len(letters)-1 {
				p.expectCode = true
			} else {
				p.scan(letters[j+1:])
			}
			break
		}
	}
}

// operand handles a non-option argument and reports whether the scan stops.
func (p *inrInterpScan) operand(t string) bool {
	if programFirst[p.name] && !p.gotProgram && !p.scriptFile {
		p.scan(t)
		return false
	}
	if p.gotProgram {
		p.tail = append(p.tail, t)
		return false
	}
	if operandFree[p.name] {
		return false
	}
	if !programFirst[p.name] {
		p.gotScript = true
		return true
	}
	return false
}

// inrInterpStdin checks the program an interpreter reads from stdin.
func (s *shellEval) inrInterpStdin(name string, stdin *stdinInfo) {
	switch {
	case stdin == nil || stdin.kind == stdinFile:
		return
	case stdin.kind == stdinStatic && !stdin.decode:
		for _, t := range stdin.texts {
			s.scanCode(name, t)
		}
	default:
		s.c.deny(RuleDynamicShell, fmt.Sprintf("piping code that is only known at runtime into `%s` cannot be checked; blocked to be safe. Write the script to a file you can review, then run it.", name))
	}
}

// inrDigitNames maps the Unicode names of the decimal digits to the digits.
var inrDigitNames = map[string]string{"ZERO": "0", "ONE": "1", "TWO": "2", "THREE": "3", "FOUR": "4", "FIVE": "5", "SIX": "6", "SEVEN": "7", "EIGHT": "8", "NINE": "9"}

// inrNamedEsc decodes one \N{NAME} escape, or returns it unchanged.
func inrNamedEsc(m string) string {
	name := strings.ToUpper(namedEscRe.FindStringSubmatch(m)[1])
	if c, ok := namedChars[name]; ok {
		return c
	}
	if c, ok := inrNamedLetter(name); ok {
		return c
	}
	return m
}

// inrNamedLetter decodes the Unicode names of Latin letters and digits.
func inrNamedLetter(name string) (string, bool) {
	for _, p := range []string{"LATIN SMALL LETTER ", "LATIN CAPITAL LETTER ", "DIGIT "} {
		rest, ok := strings.CutPrefix(name, p)
		if !ok {
			continue
		}
		if p == "DIGIT " {
			if d, ok := inrDigitNames[rest]; ok {
				return d, true
			}
		} else if len(rest) == 1 {
			if p == "LATIN SMALL LETTER " {
				return strings.ToLower(rest), true
			}
			return rest, true
		}
	}
	return "", false
}

// inrBraceEsc decodes one \u{HEX} escape, or returns it unchanged.
func inrBraceEsc(m string) string {
	n, err := strconv.ParseUint(braceEscRe.FindStringSubmatch(m)[1], 16, 32)
	if err != nil || n > utf8.MaxRune {
		return m
	}
	return string(rune(n))
}

// inrLuaDec decodes one Lua decimal escape (\46), or returns it unchanged.
func inrLuaDec(m string) string {
	n, err := strconv.ParseUint(m[1:], 10, 8)
	if err != nil {
		return m
	}
	return string([]byte{byte(n)})
}

// inrScanEnvAccessors checks the environment accessors of lang in code. It
// returns false when the work budget ran out.
func (s *shellEval) inrScanEnvAccessors(lang, code string) bool {
	for _, acc := range envAccessors {
		if acc.langs != nil && !acc.langs[lang] {
			continue
		}
		for _, loc := range acc.re.FindAllStringIndex(code, -1) {
			if !s.sec.work.spend(1) {
				return false
			}
			name, verdict := envAccessName(acc, code[loc[1]:])
			s.envVerdict(lang, name, verdict)
			if verdict != envNamed {
				break // further matches of this accessor add nothing
			}
		}
	}
	return true
}

// inrScanPerlUseEnv checks `use Env` imports in perl code.
func (s *shellEval) inrScanPerlUseEnv(lang, code string) {
	for _, loc := range perlUseEnvRe.FindAllStringIndex(code, -1) {
		if !s.sec.work.spend(1) {
			return
		}
		list := perlImportList(code[loc[1]:])
		if strings.TrimSpace(list) == "" {
			s.envVerdict(lang, "", envDump)
			return // further matches cannot change the verdict
		}
		names := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		if !s.sec.work.spend(len(names)) {
			return
		}
		for _, n := range names {
			s.checkEnvName(strings.TrimLeft(n, "$@"))
		}
	}
}

// inrNodeProcessValue examines one `process` token at loc and reports
// whether it is used as a value. Property and key accesses are checked here.
func (s *shellEval) inrNodeProcessValue(lang, code, blank string, loc []int) bool {
	if loc[0] > 0 && blank[loc[0]-1] == '$' {
		return false // $process: another identifier
	}
	rest, brest := code[loc[1]:], blank[loc[1]:]
	if s.inrNodeProcessAccess(lang, rest, brest) {
		return false
	}
	trimmed := strings.TrimLeft(brest, " \t\r\n")
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "?.[") {
		s.envVerdict(lang, "", envDynamic)
		return false
	}
	before := strings.TrimRight(blank[max(0, loc[0]-processLookback):loc[0]], " \t\r\n")
	return inrProcessIsValue(before, trimmed)
}

// inrNodeProcessAccess checks process.prop and process['key'] accesses and
// reports whether the token was one.
func (s *shellEval) inrNodeProcessAccess(lang, rest, brest string) bool {
	if m := processPropRe.FindStringSubmatch(brest); m != nil {
		if processDumpProps[m[1]] {
			s.envVerdict(lang, "", envDump)
		}
		return true // process.env is an accessor of its own
	}
	if m := processKeyRe.FindStringSubmatch(rest); m != nil {
		switch {
		case m[2] == "env":
			name, v := envAccessName(envAccessor{bracket: true, attr: true}, rest[len(m[0]):])
			s.envVerdict(lang, name, v)
		case processDumpProps[m[2]]:
			s.envVerdict(lang, "", envDump)
		}
		return true
	}
	return false
}

// inrProcessIsValue classifies the context of a `process` token from the
// code before it and the (left-trimmed) code after it.
func inrProcessIsValue(before, trimmed string) bool {
	var next, prev byte
	if trimmed != "" {
		next = trimmed[0]
	}
	if before != "" {
		prev = before[len(before)-1]
	}
	switch {
	case next == '(':
		return false // a function named process
	case strings.HasSuffix(before, "..."):
		return true // spread: {...process}
	case prev == '.':
		return false // obj.process
	case next == ':' && prev != '?':
		return false // {process: 1}
	case next == '=' && !strings.HasPrefix(trimmed, "=="):
		return false // assignment to a local named process
	case prev == '=' || strings.HasSuffix(before, "=>"):
		// comparison: x == process
		return len(before) < 2 || !strings.ContainsRune("=!<>", rune(before[len(before)-2])) || strings.HasSuffix(before, "=>")
	case prev == '(' || prev == ',':
		return prev != '(' || !processCallbackRe.MatchString(before)
	case prev == '[':
		return true
	case processReturnRe.MatchString(before):
		return true
	}
	// a bare expression statement: node -p process
	return (prev == 0 || prev == ';' || prev == '{' || prev == '}' || prev == '\n') &&
		(next == 0 || next == ';' || next == '}' || next == ',')
}
