package engine

import (
	"fmt"
	"regexp"
	"strings"
)

// Interpreter one-liners (python -c, node -e, perl -e, awk/sed/jq programs,
// heredocs fed to interpreters) are scanned heuristically:
//
//   - string literals (and adjacent literals concatenated with + , . join)
//     and bare tokens are matched against the secret path rules;
//   - environment accessors (os.environ, process.env, ENV[...], $ENV{...},
//     ENVIRON[...], getenv(...), jq env/$ENV) must name a non-secret
//     variable with a string literal; dumps and runtime-chosen names are denied;
//   - code that both decodes data (base64, chr(), \x escapes, fromCharCode,
//     reversed strings) and opens files or executes code is denied as
//     obfuscation;
//   - string literals passed to system()/subprocess/exec are re-parsed as
//     shell commands.
//
// This is a best-effort scan, not a parser for each language.

// codeFlags lists, per interpreter, the short options whose value is code.
var codeFlags = map[string]string{
	"python": "c", "python2": "c", "python3": "c", "pypy": "c", "pypy3": "c", "py": "c",
	"node": "ep", "nodejs": "ep", "bun": "ep",
	"ruby": "e", "irb": "e", "perl": "eE", "php": "rRBE", "lua": "e", "luajit": "e",
	"rscript": "e", "r": "e", "osascript": "e", "julia": "eE", "groovy": "e",
	"sed": "e", "awk": "", "gawk": "e", "mawk": "", "nawk": "",
}

var codeLongFlags = set("--eval", "--print", "--command", "--expression", "--source", "--exec")

// programFirst interpreters take their program as the first operand.
var programFirst = set("awk", "gawk", "mawk", "nawk", "sed", "jq", "yq")

// stdinInterpreters read a program from stdin when given no script.
var stdinInterpreters = set("python", "python2", "python3", "pypy", "pypy3", "py", "node", "nodejs", "bun", "deno",
	"ruby", "perl", "php", "lua", "luajit", "rscript", "r", "osascript", "julia", "groovy", "tclsh", "wish")

// valueOpts are options (per program family) taking a separate non-code value.
var interpValueOpts = map[string]map[string]bool{
	"awk":  set("-F", "-v", "-f", "--file", "--assign", "--field-separator", "-i", "--include", "-l", "--load"),
	"sed":  set("-f", "--file", "-l", "--line-length"),
	"jq":   set("-f", "--from-file", "--indent", "-L"),
	"yq":   set("-f", "--from-file", "-I", "--indent", "-o", "--output-format", "-p", "--input-format"),
	"node": set("-r", "--require", "--import", "--loader", "--inspect-port", "--env-file"),
	"perl": set("-I", "-M", "-m"),
}

func familyOf(name string) string {
	switch name {
	case "gawk", "mawk", "nawk":
		return "awk"
	case "nodejs", "bun":
		return "node"
	}
	return name
}

func (s *shellEval) interpreterCommand(name string, args []cmdArg, stdin *stdinInfo) {
	fam := familyOf(name)
	flags := codeFlags[name]
	valOpts := interpValueOpts[fam]
	gotProgram, gotScript, readsStdin := false, false, false
	expectCode := false
	scriptFile := false // -f FILE for awk/sed/jq
	for i := 0; i < len(args); i++ {
		a := args[i]
		t, static := a.text()
		if expectCode {
			expectCode = false
			gotProgram = true
			s.scanCodeArg(name, a)
			continue
		}
		if !static {
			if programFirst[name] && !gotProgram && !scriptFile {
				gotProgram = true
				s.scanCodeArg(name, a)
				continue
			}
			if !gotProgram {
				gotScript = true
			}
			break
		}
		if t == "-" {
			readsStdin = true
			break
		}
		if t == "--" {
			continue
		}
		if name == "deno" && t == "eval" && !gotScript {
			expectCode = true
			continue
		}
		if fam == "jq" && (t == "--arg" || t == "--argjson" || t == "--slurpfile" || t == "--rawfile") {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "--") {
			key := t
			if eq := strings.IndexByte(t, '='); eq > 0 {
				key = t[:eq]
				if codeLongFlags[key] {
					gotProgram = true
					s.scanCode(name, t[eq+1:])
				}
				continue
			}
			if codeLongFlags[key] {
				expectCode = true
				continue
			}
			if valOpts[key] {
				if key == "--file" || key == "--from-file" {
					scriptFile = true
				}
				i++
			}
			continue
		}
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			if valOpts[t] {
				if t == "-f" {
					scriptFile = true
				}
				i++
				continue
			}
			letters := t[1:]
			handled := false
			for j, l := range letters {
				if flags != "" && strings.ContainsRune(flags, l) {
					handled = true
					if j == len(letters)-1 {
						expectCode = true
					} else {
						gotProgram = true
						s.scanCode(name, letters[j+1:])
					}
					break
				}
			}
			_ = handled
			continue
		}
		// Operand.
		if programFirst[name] && !gotProgram && !scriptFile {
			gotProgram = true
			s.scanCode(name, t)
			continue
		}
		if !gotProgram && !programFirst[name] {
			gotScript = true
			break
		}
	}
	if expectCode {
		return // option without value: runtime error
	}
	if !stdinInterpreters[name] || gotProgram || (gotScript && !readsStdin) {
		return
	}
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

func (s *shellEval) scanCodeArg(name string, a cmdArg) {
	for _, alt := range a.alts {
		if isDynamic(alt) {
			s.c.deny(RuleDynamicShell, fmt.Sprintf("inline code for `%s` is built at runtime and cannot be checked; blocked to be safe. Pass the code as a literal string.", name))
			continue
		}
		s.scanCode(name, plain(alt))
	}
}

var (
	stringLitRe  = regexp.MustCompile(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|` + "`(?:[^`\\\\]|\\\\.)*`")
	litSepRe     = regexp.MustCompile(`^(?:[\s+,.\[\]()]|join)*$`)
	codeTokRe    = regexp.MustCompile(`[^\s;|&<>(){}'"=,+` + "`" + `]+`)
	openPrimRe   = regexp.MustCompile(`(?i)\bopen\s*\(|read_text|read_bytes|readfile|file\.read|io\.read|file_get_contents|fopen|file\.open|\bpath\s*\(|readlines|slurp|getline|<\s*\$|get-content|\bopen\s+\w+\s*,|\bcat\b`)
	decodePrimRe = regexp.MustCompile(`(?i)b64decode|base64|fromhex|unhexlify|\bchr\s*\(|\\x[0-9a-f]{2}|\\[0-7]{3}|atob\s*\(|buffer\.from|fromcharcode|\[::-1\]|\breverse|\bdecode\s*\(|\bpack\s*\(|unpack|rot13|codecs|\bord\s*\(|\\u00[0-9a-f]{2}|\bsprintf\s*\(\s*['"]%c`)
	execPrimRe   = regexp.MustCompile(`(?i)\bexec\w*\s*\(|\beval\s*\(|\bsystem\s*\(|popen|subprocess|spawn|child_process|shell_exec|passthru|\bqx\s*[{(/]|` + "`" + `|\bos\.exec|\bruntime\.exec|%x\{`)
)

type envAccessor struct {
	re      *regexp.Regexp
	bracket bool // X["NAME"]
	call    bool // X.get("NAME") / getenv("NAME")
	attr    bool // X.NAME
	brace   bool // $ENV{NAME}
	langs   map[string]bool
}

var envAccessors = []envAccessor{
	{re: regexp.MustCompile(`\bos\.environb?\b`), bracket: true, call: true},
	{re: regexp.MustCompile(`(?:^|[^.\w])environb\b`), bracket: true, call: true},
	{re: regexp.MustCompile(`(?:^|[^.\w])environ\b`), bracket: true, call: true},
	{re: regexp.MustCompile(`\b(?:os\.|System\.|std::)?getenv\b`), call: true},
	{re: regexp.MustCompile(`\bprocess\.env\b`), bracket: true, attr: true},
	{re: regexp.MustCompile(`\bDeno\.env\b`), call: true},
	{re: regexp.MustCompile(`\bBun\.env\b`), bracket: true, attr: true},
	{re: regexp.MustCompile(`(?:^|[^\w$%@:.])ENV\b`), bracket: true, call: true},
	{re: regexp.MustCompile(`%ENV\b`)},
	{re: regexp.MustCompile(`\$ENV\b`), brace: true, bracket: true, attr: true},
	{re: regexp.MustCompile(`\bENVIRON\b`), bracket: true},
	{re: regexp.MustCompile(`\$_ENV\b|\$_SERVER\b`), bracket: true},
	{re: regexp.MustCompile(`(?:^|[^\w$.])env\b`), attr: true, bracket: true, langs: set("jq", "yq")},
}

var (
	envBracketRe = regexp.MustCompile(`^\s*\[\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)(['"]?)\s*\]`)
	envCallRe    = regexp.MustCompile(`^\s*(?:\.\s*(?:get|fetch|setdefault|pop|get_or)\s*)?\(\s*(['"])([A-Za-z_][A-Za-z0-9_]*)['"]\s*[),]`) // a lone literal: 'GIT'+'HUB_TOKEN' is dynamic
	envAttrRe    = regexp.MustCompile(`^\.([A-Za-z_][A-Za-z0-9_]*)`)
	envBraceRe   = regexp.MustCompile(`^\{\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*\}`)
	envOpenRe    = regexp.MustCompile(`^\s*(?:\[|\{|\(|\.\s*(?:get|fetch|setdefault|pop)\s*\()`)
	attrMethods  = set("keys", "values", "items", "entries", "copy", "to_h", "to_hash", "each", "map", "select", "toobject", "inspect", "to_a", "dump")
)

// scanCode applies the interpreter heuristics to one program text.
func (s *shellEval) scanCode(lang, code string) {
	if lang == "sed" {
		s.scanSed(code)
		return
	}
	s.scanEnvAccess(lang, code)

	lits := stringLitRe.FindAllStringIndex(code, -1)
	var texts []string
	joined := ""
	prevEnd := -1
	for _, l := range lits {
		lit := code[l[0]:l[1]]
		body := ansiC(lit[1 : len(lit)-1])
		texts = append(texts, body)
		if prevEnd >= 0 && litSepRe.MatchString(code[prevEnd:l[0]]) {
			joined += body
		} else {
			if joined != "" {
				texts = append(texts, joined)
			}
			joined = body
		}
		prevEnd = l[1]
	}
	if joined != "" {
		texts = append(texts, joined)
	}
	for _, t := range dedupe(texts) {
		s.checkCodePath(lang, t, true)
		for _, tok := range codeTokRe.FindAllString(t, -1) {
			s.checkCodePath(lang, tok, true)
		}
	}
	for _, tok := range bareTokens(lang, code) {
		s.checkCodePath(lang, tok, false)
	}

	hasDecode := decodePrimRe.MatchString(code)
	hasExec := execPrimRe.MatchString(code)
	if hasDecode && (hasExec || openPrimRe.MatchString(code)) {
		s.c.deny(RuleObfuscation, fmt.Sprintf("the `%s` code decodes data (base64, chr(), escapes, reversed strings) and then opens files or runs code; this hides what it accesses, so it is blocked. Write the paths and commands in plain text.", lang))
	}
	if hasExec {
		for _, t := range texts {
			s.recurseText(t, true)
		}
	}
}

// bareTokens returns the non-literal code tokens to path-check. jq/yq
// filters such as ".env" are field accesses, not paths (they can only read
// files through string literals, e.g. yq load(".env")).
func bareTokens(lang, code string) []string {
	if lang == "jq" || lang == "yq" {
		return nil
	}
	return codeTokRe.FindAllString(code, -1)
}

var (
	sedFileCmdRe = regexp.MustCompile(`(?m)(?:^|[;{}\s\d$/])[rRwW]\s+([^;}\n]+)`)
	sedExecCmdRe = regexp.MustCompile(`(?m)(?:^|[;{}\s\d$/])e\s+([^;}\n]+)`)
)

// scanSed checks only what sed can read or run: the file names of the
// r/R/w/W commands and the shell commands of the e command. Regexes and
// replacement text ("s/\.env/.env.local/") are data.
func (s *shellEval) scanSed(code string) {
	for _, m := range sedFileCmdRe.FindAllStringSubmatch(code, -1) {
		s.checkCodePath("sed", strings.TrimSpace(m[1]), true)
	}
	for _, m := range sedExecCmdRe.FindAllStringSubmatch(code, -1) {
		ch := s.child()
		ch.ignoreParseErrors = true
		ch.run(m[1])
	}
}

func (s *shellEval) checkCodePath(lang, tok string, inLiteral bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" || len(tok) > 4096 {
		return
	}
	if m, ok := s.sec.checkPath(escapeLit(tok)); ok {
		rule := RuleSecretFile + ":" + m.pattern
		if m.builtin {
			rule = RuleEnvExposure
		}
		s.c.deny(rule, secretFileReason(m, "reading (from "+lang+" code)", s.sec))
		return
	}
	if inLiteral && strings.ContainsAny(tok, "*?[") {
		if m, ok := s.sec.checkPath(activeLit(tok)); ok {
			m.glob = true
			s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "globbing (from "+lang+" code)", s.sec))
		}
	}
}

func (s *shellEval) scanEnvAccess(lang, code string) {
	for _, acc := range envAccessors {
		if acc.langs != nil && !acc.langs[lang] {
			continue
		}
		for _, loc := range acc.re.FindAllStringIndex(code, -1) {
			rest := code[loc[1]:]
			name, verdict := envAccessName(acc, rest)
			switch verdict {
			case envNamed:
				s.checkEnvName(name)
			case envDynamic:
				s.c.deny(RuleEnvExposure, fmt.Sprintf("the `%s` code reads an environment variable whose name is only known at runtime; it could expose a secret. Read specific non-secret variables by literal name.", lang))
			case envDump:
				s.c.deny(RuleEnvExposure, fmt.Sprintf("the `%s` code accesses the whole environment, which contains secret variables (secrets.env). Read specific non-secret variables by literal name instead.", lang))
			}
		}
	}
}

type envAccessKind uint8

const (
	envNamed envAccessKind = iota
	envDynamic
	envDump
)

func envAccessName(acc envAccessor, rest string) (string, envAccessKind) {
	if acc.bracket {
		if m := envBracketRe.FindStringSubmatch(rest); m != nil {
			if m[1] == "" && m[3] == "" && !acc.attr {
				// awk/ruby/python bare identifier inside []: a variable
				return "", envDynamic
			}
			return m[2], envNamed
		}
	}
	if acc.call {
		if m := envCallRe.FindStringSubmatch(rest); m != nil {
			return m[2], envNamed
		}
	}
	if acc.brace {
		if m := envBraceRe.FindStringSubmatch(rest); m != nil {
			return m[1], envNamed
		}
	}
	if acc.attr {
		if m := envAttrRe.FindStringSubmatch(rest); m != nil && !attrMethods[strings.ToLower(m[1])] {
			return m[1], envNamed
		}
	}
	if envOpenRe.MatchString(rest) {
		return "", envDynamic
	}
	return "", envDump
}
