package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Interpreter one-liners (python -c, node -e, perl -e, awk/sed/jq programs,
// heredocs fed to interpreters) are scanned heuristically:
//
//   - string literals (after decoding escapes, literal interpolation, slices
//     and %/format substitution), adjacent literals concatenated with + . join
//     (per argument, and across a comma-separated list), lists of byte values
//     and bare tokens are matched against the secret path rules;
//   - environment accessors (os.environ, process.env, ENV[...], $ENV{...},
//     ENVIRON[...], getenv(...), jq env/$ENV, ...) must name a non-secret
//     variable with a string literal; dumps and runtime-chosen names are
//     denied, and so are concatenated literals that spell an accessor;
//   - implicit loaders (dotenv, reading every file of a listed directory)
//     are treated as reads of the secret files they reach;
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

// codeOptWords lists, per interpreter, exact option words whose value is
// code. These interpreters have single-dash long options (erl -eval,
// ghc -Werror), so their options are never read as short-option clusters.
var codeOptWords = map[string]map[string]bool{
	"elixir": set("-e", "--eval"),
	"erl":    set("-eval"),
	"guile":  set("-c"),
	"racket": set("-e", "--eval"),
	"ghc":    set("-e"),
	"ghci":   set("-e"),
	"clisp":  set("-x"),
	"sbcl":   set("--eval"),
	"scala":  set("-e"),
	"nix":    set("--expr", "-E"),
}

var codeLongFlags = set("--eval", "--print", "--command", "--expression", "--source", "--exec")

// programFirst interpreters take their program as the first operand.
var programFirst = set("awk", "gawk", "mawk", "nawk", "sed", "jq", "yq")

// operandFree interpreters have no script operand: their operands are
// subcommands or option values (nix eval --expr, erl -pa dir -eval).
var operandFree = set("nix", "erl")

// stdinInterpreters read a program from stdin when given no script.
var stdinInterpreters = set("python", "python2", "python3", "pypy", "pypy3", "py", "node", "nodejs", "bun", "deno",
	"ruby", "perl", "php", "lua", "luajit", "rscript", "r", "osascript", "julia", "groovy", "tclsh", "wish",
	"jshell", "guile", "racket", "ghci", "clisp", "sbcl", "scala")

// valueOpts are options (per program family) taking a separate non-code value.
var interpValueOpts = map[string]map[string]bool{
	"awk":    set("-F", "-v", "-f", "--file", "--assign", "--field-separator", "-i", "--include", "-l", "--load"),
	"sed":    set("-f", "--file", "-l", "--line-length"),
	"jq":     set("-f", "--from-file", "--indent", "-L"),
	"yq":     set("-f", "--from-file", "-I", "--indent", "-o", "--output-format", "-p", "--input-format"),
	"node":   set("-r", "--require", "--import", "--loader", "--inspect-port", "--env-file"),
	"perl":   set("-I"),
	"racket": set("-l", "--lib", "-t", "--require", "-f", "--load"),
	"ghc":    set("-package", "-o", "-odir", "-hidir", "-outputdir"),
	"elixir": set("-r", "-pa", "-pz", "--erl", "--sname", "--name", "--cookie"),
	"guile":  set("-L", "-l", "-C", "-x"),
	"clisp":  set("-i", "-M", "-B", "-E", "-L"),
	"sbcl":   set("--load", "--core", "--dynamic-space-size", "--control-stack-size"),
}

func familyOf(name string) string {
	switch name {
	case "gawk", "mawk", "nawk":
		return "awk"
	case "nodejs", "bun":
		return "node"
	case "ghci":
		return "ghc"
	}
	return name
}

// argvRe spots programs that read their command-line operands.
var argvRe = regexp.MustCompile(`(?i)\bargv\b|commandArgs|\barg\s*\[|\$args\b|System\.argv`)

func (s *shellEval) interpreterCommand(name string, args []cmdArg, stdin *stdinInfo) {
	fam := familyOf(name)
	flags := codeFlags[name]
	words := codeOptWords[name]
	valOpts := interpValueOpts[fam]
	pythonLike := flags == "c"
	gotProgram, gotScript, readsStdin := false, false, false
	expectCode := false
	scriptFile := false // -f FILE for awk/sed/jq
	var codes, tail []string
	scan := func(code string) {
		gotProgram = true
		codes = append(codes, code)
		s.scanCode(name, code)
	}
	scanArg := func(a cmdArg) {
		gotProgram = true
		for _, alt := range a.alts {
			if !isDynamic(alt) {
				codes = append(codes, plain(alt))
			}
		}
		s.scanCodeArg(name, a)
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		t, static := a.text()
		if expectCode {
			expectCode = false
			scanArg(a)
			continue
		}
		if !static {
			if programFirst[name] && !gotProgram && !scriptFile {
				scanArg(a)
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
		if words[t] {
			expectCode = true
			continue
		}
		if eq := strings.IndexByte(t, '='); eq > 0 && words[t[:eq]] {
			scan(t[eq+1:])
			continue
		}
		if name == "php" && (t == "-i" || t == "--info") {
			s.c.deny(RuleEnvExposure, "`php -i` (phpinfo) prints the whole environment, which contains secret variables (secrets.env). Use `php -v` or `php -m` instead.")
			continue
		}
		if fam == "perl" && len(t) >= 2 && (strings.HasPrefix(t, "-M") || strings.HasPrefix(t, "-m")) {
			mod := t[2:]
			if mod == "" && i+1 < len(args) {
				i++
				mod = args[i].textOr()
			}
			s.perlModule(mod, t[1] == 'M')
			continue
		}
		if pythonLike && strings.HasPrefix(t, "-m") {
			mod := t[2:]
			if mod == "" && i+1 < len(args) {
				mod = args[i+1].textOr()
			}
			if strings.HasPrefix(mod, "dotenv") {
				s.implicitDotenv(name)
			}
			gotScript = true
			break
		}
		if strings.HasPrefix(t, "--") {
			key := t
			if eq := strings.IndexByte(t, '='); eq > 0 {
				key = t[:eq]
				if codeLongFlags[key] {
					scan(t[eq+1:])
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
			if words != nil {
				continue // no short-option clusters
			}
			letters := t[1:]
			for j, l := range letters {
				if flags != "" && strings.ContainsRune(flags, l) {
					if j == len(letters)-1 {
						expectCode = true
					} else {
						scan(letters[j+1:])
					}
					break
				}
			}
			continue
		}
		// Operand.
		if programFirst[name] && !gotProgram && !scriptFile {
			scan(t)
			continue
		}
		if gotProgram {
			tail = append(tail, t)
			continue
		}
		if operandFree[name] {
			continue
		}
		if !programFirst[name] {
			gotScript = true
			break
		}
	}
	s.checkArgvJoin(name, codes, tail)
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

// maxArgvJoin bounds how many adjacent operands are joined into one
// candidate path.
const maxArgvJoin = 4

// checkArgvJoin handles inline programs that read their operands
// (sys.argv[1]+sys.argv[2]): adjacent operands are joined and path-checked,
// so a secret path split across harmless operands (.e nv) is caught.
func (s *shellEval) checkArgvJoin(lang string, codes, tail []string) {
	if len(tail) < 2 {
		return
	}
	reads := false
	for _, c := range codes {
		if argvRe.MatchString(c) {
			reads = true
			break
		}
	}
	if !reads {
		return
	}
	for i := range tail {
		for j := i + 2; j <= len(tail) && j <= i+maxArgvJoin; j++ {
			s.checkCodePath(lang, strings.Join(tail[i:j], ""), true)
		}
	}
}

// perlModule handles perl -MModule / -mModule. Env.pm ties environment
// variables to plain Perl variables: -MEnv ties all of them, -MEnv=A,B the
// named ones.
func (s *shellEval) perlModule(mod string, importAll bool) {
	mod = strings.TrimPrefix(mod, "-")
	name, list, hasList := strings.Cut(mod, "=")
	if name != "Env" {
		return
	}
	if !hasList {
		if importAll {
			s.c.deny(RuleEnvExposure, "the `perl` code imports Env.pm, which ties every environment variable (including secrets.env) to a Perl variable. Read specific non-secret variables with $ENV{NAME} instead.")
		}
		return
	}
	for _, n := range strings.Split(list, ",") {
		s.checkEnvName(strings.TrimLeft(strings.TrimSpace(n), "$@"))
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
	stringLitRe = regexp.MustCompile(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|` + "`(?:[^`\\\\]|\\\\.)*`")
	// listSepRe joins literals across a comma-separated list
	// (''.join(['.e','nv'])); argSepRe joins them within one argument
	// (open('.e'+'nv','r')).
	listSepRe    = regexp.MustCompile(`^(?:[\s+,.\[\]()]|join)*$`)
	argSepRe     = regexp.MustCompile(`^(?:[\s+.\[\]()]|join)*$`)
	codeTokRe    = regexp.MustCompile(`[^\s;|&<>(){}\[\]'"=,+` + "`" + `]+`)
	openPrimRe   = regexp.MustCompile(`(?i)\bopen\s*\(|read_text|read_bytes|readfile|file\.read|io\.read|file_get_contents|fopen|file\.open|\bpath\s*\(|readlines|slurp|getline|<\s*\$|get-content|\bopen\s+\w+\s*,|\bcat\b|createreadstream`)
	decodePrimRe = regexp.MustCompile(`(?i)b64decode|base64|fromhex|unhexlify|\bchr\s*\(|\\x[0-9a-f]{2}|\\[0-7]{3}|atob\s*\(|buffer\.from|fromcharcode|\[::-1\]|\breverse|\bdecode\s*\(|\bpack\s*\(|unpack|rot13|codecs|\bord\s*\(|\\u00[0-9a-f]{2}|\\u\{[0-9a-f]+\}|\\N\{|\bsprintf\s*\(\s*['"]%c`)
	// readPrimRe: primitives that read file contents (stricter than
	// openPrimRe: Path(...) alone or listing into a command does not count).
	readPrimRe = regexp.MustCompile(`(?i)\bopen\s*\(|read_text|read_bytes|readfile|file\.read|io\.read|file_get_contents|fopen|file\.open|readlines|slurp|getline|<\s*\$|\bopen\s+\w+\s*,|\bcat\b|createreadstream`)
	luaDecRe   = regexp.MustCompile(`\\\d{1,3}`)
	execPrimRe = regexp.MustCompile(`(?i)\bexec\w*\s*\(|\beval\s*\(|\bsystem\s*\(|popen|subprocess|spawn|child_process|shell_exec|passthru|\bqx\s*[{(/]|` + "`" + `|\bos\.exec|\bruntime\.exec|%x\{`)
)

type envAccessor struct {
	re      *regexp.Regexp
	bracket bool // X["NAME"]
	call    bool // X.get("NAME") / getenv("NAME") / getenv "NAME"
	attr    bool // X.NAME
	brace   bool // $ENV{NAME}
	paren   bool // $env(NAME) (Tcl)
	langs   map[string]bool
}

var envAccessors = []envAccessor{
	// environ/environb in any spelling: os., posix., nt., o. (alias),
	// __import__('os')., sys.modules['os']., from os import environ.
	{re: regexp.MustCompile(`\benvironb?\b`), bracket: true, call: true},
	{re: regexp.MustCompile(`\b(?:os\.|System\.|std::)?getenvb?\b`), call: true},
	{re: regexp.MustCompile(`\b(?:getEnv|lookupEnv|get_env|getEnvironment|getEnvironmentVariables?)\b`), call: true},
	{re: regexp.MustCompile(`\bprocess\.env\b`), bracket: true, attr: true},
	{re: regexp.MustCompile(`\bDeno\.env\b`), call: true},
	{re: regexp.MustCompile(`\bBun\.env\b`), bracket: true, attr: true},
	{re: regexp.MustCompile(`\bsys\.env\b`), call: true},
	{re: regexp.MustCompile(`(?:^|[^\w$%@:.])ENV\b`), bracket: true, call: true},
	{re: regexp.MustCompile(`%ENV\b`)},
	{re: regexp.MustCompile(`\$ENV\b`), brace: true, bracket: true, attr: true},
	{re: regexp.MustCompile(`\bENVIRON\b`), bracket: true},
	{re: regexp.MustCompile(`\$_ENV\b|\$_SERVER\b`), bracket: true},
	{re: regexp.MustCompile(`(?:^|[^\w$.])env\b`), attr: true, bracket: true, langs: set("jq", "yq")},
	{re: regexp.MustCompile(`\$(?:::)?env\b`), paren: true, langs: set("tclsh", "wish")},
}

// envDumpRes are whole-environment dumps with no accessor syntax to follow.
var envDumpRes = []*regexp.Regexp{
	regexp.MustCompile(`\bphpinfo\s*\(`),
	regexp.MustCompile(`\bconst_get\s*\(?\s*:?\s*['"]?ENV\b`),
	regexp.MustCompile(`\barray\s+get\s+(?:::)?env\b`),
}

// envAccessorWords are accessor names; a concatenated literal spelling one
// ($f="get"."env"; getattr(os,'envi'+'ron')) hides an environment access.
var envAccessorWords = set("environ", "environb", "getenv", "getenvb", "get_env", "phpinfo", "env", "process", "printenv", "getenvironment")

var (
	envBracketRe = regexp.MustCompile(`^\s*\[\s*b?(['"]?)([A-Za-z_][A-Za-z0-9_]*)(['"]?)\s*\]`)
	envCallRe    = regexp.MustCompile(`^\s*(?:\.\s*(?:get|fetch|setdefault|pop|get_or)\s*)?(?:\(\s*|\s)b?(['"])([A-Za-z_][A-Za-z0-9_]*)['"]\s*[),]`) // a lone literal: 'GIT'+'HUB_TOKEN' is dynamic
	envSpaceRe   = regexp.MustCompile(`^\s+b?(['"])([A-Za-z_][A-Za-z0-9_]*)['"]`)                                                                    // Lisp/Haskell/nix: getenv "NAME"
	envAttrRe    = regexp.MustCompile(`^\.([A-Za-z_][A-Za-z0-9_]*)`)
	envBraceRe   = regexp.MustCompile(`^\{\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*\}`)
	envParenRe   = regexp.MustCompile(`^\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)`)
	envOpenRe    = regexp.MustCompile(`^\s*(?:\[|\{|\(|\.\s*(?:get|fetch|setdefault|pop)\s*\()`)
	attrMethods  = set("keys", "values", "items", "entries", "copy", "to_h", "to_hash", "each", "map", "select", "toobject", "inspect", "to_a", "dump")
	perlUseEnvRe = regexp.MustCompile(`\buse\s+Env\b`)
)

// scanCode applies the interpreter heuristics to one program text.
func (s *shellEval) scanCode(lang, code string) {
	if lang == "sed" {
		s.scanSed(code)
		return
	}
	// Every scan below is linear in the code, but runs a dozen regex passes
	// over it: programs beyond maxCodeScan are denied as too complex, and
	// the rest are charged up front and per hit.
	if len(code) > maxCodeScan {
		s.c.deny(RuleTooComplex, tooComplexReason)
		return
	}
	if !s.sec.work.spend(len(code)/64 + 1) {
		return
	}
	if nodeLangs[lang] {
		code = requireProcessRe.ReplaceAllString(code, "process")
		s.scanNodeProcess(lang, code)
	}
	s.scanEnvAccess(lang, code)

	texts, built := codeLiterals(lang, code)
	if !s.sec.work.spend(len(texts) + len(built)) {
		return
	}
	for _, b := range built {
		if envAccessorWords[strings.ToLower(strings.TrimSpace(b))] {
			s.c.deny(RuleEnvExposure, fmt.Sprintf("the `%s` code builds the name of an environment accessor (%q) from pieces; this hides an environment read and is blocked. Read specific non-secret variables by literal name.", lang, b))
		}
	}
	for _, t := range texts {
		s.checkCodePath(lang, t, true)
		for _, tok := range codeTokRe.FindAllString(t, -1) {
			s.checkCodePath(lang, tok, true)
		}
	}
	for _, tok := range bareTokens(lang, code) {
		s.checkCodePath(lang, tok, false)
	}
	// Cheap substring gates keep the rarely matching regexes off the hot path.
	lower := strings.ToLower(code)
	if familyOf(lang) != "awk" && lang != "jq" && lang != "yq" && strings.Contains(lower, "dotenv") &&
		dotenvRe.MatchString(code) && !namesEnvFile(texts) {
		s.implicitDotenv(lang)
	}

	hasExec := execPrimRe.MatchString(code)
	hasDecode := decodePrimRe.MatchString(code) || ((lang == "lua" || lang == "luajit") && luaDecRe.MatchString(code))
	if hasDecode && (hasExec || openPrimRe.MatchString(code)) {
		s.c.deny(RuleObfuscation, fmt.Sprintf("the `%s` code decodes data (base64, chr(), escapes, reversed strings) and then opens files or runs code; this hides what it accesses, so it is blocked. Write the paths and commands in plain text.", lang))
	}
	if strings.Contains(lower, "dir") || strings.Contains(lower, "walk") || strings.Contains(lower, "glob") {
		if dirListRe.MatchString(code) && readPrimRe.MatchString(code) {
			s.scanDirReads(lang, code)
		}
	}
	if hasExec {
		for _, t := range texts {
			s.recurseText(t, true)
		}
	}
}

// codeLiterals returns the decoded string literals of a program plus the
// texts derived from them (slices, format substitution, concatenations,
// byte lists). built holds the concatenations of two or more literals.
func codeLiterals(lang, code string) (texts, built []string) {
	locs := stringLitRe.FindAllStringIndex(code, -1)
	bodies := make([]string, len(locs))
	for i, l := range locs {
		lit := code[l[0]:l[1]]
		bodies[i] = decodeLit(lang, lit[1:len(lit)-1])
	}
	for i := range locs {
		texts = append(texts, bodies[i])
		texts = append(texts, derivedTexts(code, locs, bodies, i)...)
	}
	for _, sep := range []*regexp.Regexp{argSepRe, listSepRe} {
		var joined strings.Builder
		n := 0
		flush := func() {
			if n > 1 {
				texts = append(texts, joined.String())
				built = append(built, joined.String())
			}
		}
		for i, l := range locs {
			if i > 0 && sep.MatchString(code[locs[i-1][1]:l[0]]) {
				joined.WriteString(bodies[i])
				n++
				continue
			}
			flush()
			joined.Reset()
			joined.WriteString(bodies[i])
			n = 1
		}
		flush()
	}
	texts = append(texts, byteListTexts(code)...)
	return dedupe(texts), dedupe(built)
}

var (
	litInterpRe = regexp.MustCompile(`[#$]\{\s*(['"])([^'"]*)['"]\s*\}`) // Ruby #{"x"}, JS ${'x'}
	namedEscRe  = regexp.MustCompile(`\\N\{([A-Za-z0-9 -]+)\}`)
	braceEscRe  = regexp.MustCompile(`\\u\{([0-9A-Fa-f]{1,6})\}`)
	// namedChars are the Unicode names of characters that matter in paths.
	namedChars = map[string]string{
		"FULL STOP": ".", "SOLIDUS": "/", "REVERSE SOLIDUS": `\`, "TILDE": "~", "LOW LINE": "_",
		"HYPHEN-MINUS": "-", "ASTERISK": "*", "QUESTION MARK": "?", "COLON": ":", "SPACE": " ",
	}
)

// decodeLit decodes the escapes of a literal body: language-specific forms
// (\N{NAME}, \u{HEX}, Lua decimal \46) first, then the common C escapes.
func decodeLit(lang, body string) string {
	body = litInterpRe.ReplaceAllString(body, "$2")
	if !strings.Contains(body, `\`) {
		return body
	}
	body = namedEscRe.ReplaceAllStringFunc(body, func(m string) string {
		name := strings.ToUpper(namedEscRe.FindStringSubmatch(m)[1])
		if c, ok := namedChars[name]; ok {
			return c
		}
		for _, p := range []string{"LATIN SMALL LETTER ", "LATIN CAPITAL LETTER ", "DIGIT "} {
			if rest, ok := strings.CutPrefix(name, p); ok {
				if p == "DIGIT " {
					digits := map[string]string{"ZERO": "0", "ONE": "1", "TWO": "2", "THREE": "3", "FOUR": "4", "FIVE": "5", "SIX": "6", "SEVEN": "7", "EIGHT": "8", "NINE": "9"}
					if d, ok := digits[rest]; ok {
						return d
					}
				} else if len(rest) == 1 {
					if p == "LATIN SMALL LETTER " {
						return strings.ToLower(rest)
					}
					return rest
				}
			}
		}
		return m
	})
	body = braceEscRe.ReplaceAllStringFunc(body, func(m string) string {
		n, err := strconv.ParseUint(braceEscRe.FindStringSubmatch(m)[1], 16, 32)
		if err != nil || n > utf8.MaxRune {
			return m
		}
		return string(rune(n))
	})
	if lang == "lua" || lang == "luajit" {
		body = luaDecRe.ReplaceAllStringFunc(body, func(m string) string {
			n, err := strconv.ParseUint(m[1:], 10, 8)
			if err != nil {
				return m
			}
			return string([]byte{byte(n)})
		})
	}
	return ansiC(body)
}

var (
	pySliceRe   = regexp.MustCompile(`^\[\s*(-?\d*)\s*:\s*(-?\d*)\s*(?::\s*(-1)\s*)?\]`)
	jsSliceRe   = regexp.MustCompile(`^\s*\.\s*(slice|substring|substr)\s*\(\s*(-?\d+)\s*(?:,\s*(-?\d+)\s*)?\)`)
	percentGap  = regexp.MustCompile(`^\s*%\s*\(?\s*$`)
	formatGap   = regexp.MustCompile(`^\s*\.\s*format\s*\(\s*$`)
	argGap      = regexp.MustCompile(`^\s*,\s*$`)
	percentSpec = regexp.MustCompile(`%[-#0 +]*\d*(?:\.\d+)?[srad]`)
	formatSpec  = regexp.MustCompile(`\{(\d*)(?:![rsa])?(?::[^{}]*)?\}`)
)

// maxCodeScan bounds the size of one interpreter program that is scanned;
// a larger program is denied as too complex.
const maxCodeScan = 64 << 10

// maxFormatArgs bounds the literal arguments substituted into one %/format
// template (keeps the scan linear).
const maxFormatArgs = 16

// derivedTexts applies slices and %/format substitution to literal i.
func derivedTexts(code string, locs [][]int, bodies []string, i int) []string {
	body := bodies[i]
	rest := code[locs[i][1]:]
	var out []string
	if m := pySliceRe.FindStringSubmatch(rest); m != nil {
		out = append(out, pySlice(body, m[1], m[2], m[3] != ""))
	}
	if m := jsSliceRe.FindStringSubmatch(rest); m != nil {
		out = append(out, jsSlice(body, m[1], m[2], m[3]))
	}
	if i+1 < len(locs) {
		gap := code[locs[i][1]:locs[i+1][0]]
		isPercent, isFormat := percentGap.MatchString(gap), formatGap.MatchString(gap)
		if !isPercent && !isFormat {
			return out
		}
		var args []string
		for j := i + 1; j < len(locs) && len(args) < maxFormatArgs; j++ {
			if j > i+1 && !argGap.MatchString(code[locs[j-1][1]:locs[j][0]]) {
				break
			}
			args = append(args, bodies[j])
		}
		switch {
		case isPercent:
			k := 0
			out = append(out, percentSpec.ReplaceAllStringFunc(body, func(m string) string {
				if k < len(args) {
					k++
					return args[k-1]
				}
				return m
			}))
		case isFormat:
			k := 0
			out = append(out, formatSpec.ReplaceAllStringFunc(body, func(m string) string {
				idx := formatSpec.FindStringSubmatch(m)[1]
				n := k
				if idx != "" {
					n, _ = strconv.Atoi(idx)
				} else {
					k++
				}
				if n < len(args) {
					return args[n]
				}
				return m
			}))
		}
	}
	return out
}

func clampIndex(v string, n, def int) int {
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	if i < 0 {
		i += n
	}
	return max(0, min(i, n))
}

func pySlice(s, a, b string, reverse bool) string {
	start, end := clampIndex(a, len(s), 0), clampIndex(b, len(s), len(s))
	if start > end {
		return ""
	}
	out := s[start:end]
	if reverse {
		r := []byte(out)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		out = string(r)
	}
	return out
}

func jsSlice(s, fn, a, b string) string {
	start := clampIndex(a, len(s), 0)
	switch fn {
	case "substr":
		if b == "" {
			return s[start:]
		}
		n, _ := strconv.Atoi(b)
		return s[start:min(len(s), start+max(0, n))]
	default:
		end := clampIndex(b, len(s), len(s))
		if start > end {
			if fn == "substring" {
				start, end = end, start
			} else {
				return ""
			}
		}
		return s[start:end]
	}
}

var byteListRe = regexp.MustCompile(`(?:\[|fromCharCode\s*\(|\bpack\s*\(\s*['"]C\*['"]\s*,)\s*(\d{1,3}(?:\s*,\s*\d{1,3})+)\s*[\])]`)

// byteListTexts decodes lists of printable byte values
// (bytes([46,101,110,118]), String.fromCharCode(46,101,...)).
func byteListTexts(code string) []string {
	var out []string
	for _, m := range byteListRe.FindAllStringSubmatch(code, -1) {
		var b strings.Builder
		ok := true
		for _, f := range strings.Split(m[1], ",") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil || n < 32 || n > 126 {
				ok = false
				break
			}
			b.WriteByte(byte(n))
		}
		if ok {
			out = append(out, b.String())
		}
	}
	return out
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

var (
	dotenvRe = regexp.MustCompile(`(?i)\bimport\s+dotenv\b|\bfrom\s+dotenv\b|['"` + "`" + `]dotenv(?:/config)?['"` + "`" + `]|dotenv_values|load_dotenv|find_dotenv|\bdotenv\s*\.`)
	// envFileLitRe: a literal naming an env file explicitly
	// (load_dotenv('.env.example')); the literal itself is path-checked.
	envFileLitRe = regexp.MustCompile(`(?i)(?:^|[/\\])\.env\b|\.env$`)
)

func namesEnvFile(texts []string) bool {
	for _, t := range texts {
		if envFileLitRe.MatchString(t) {
			return true
		}
	}
	return false
}

// implicitDotenv handles dotenv libraries (python-dotenv, node dotenv,
// python -m dotenv): without an explicit path they read ./.env.
func (s *shellEval) implicitDotenv(lang string) {
	if m, ok := s.sec.checkPath(escapeLit(".env")); ok {
		s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "loading (dotenv in "+lang+" code)", s.sec))
	}
}

var (
	dirListRe = regexp.MustCompile(`(?i)(?:\blistdir|\bscandir|\breaddir(?:sync)?|\biterdir|\bopendir|\bos\.walk|\.rglob|\bDir\.(?:entries|children|each_child|foreach|glob))\s*\(`)
	cwdArgs   = set("", ".", "./", "os.curdir", "os.getcwd()", "process.cwd()", "Dir.pwd", "__dirname", "Path.cwd()", "pathlib.Path.cwd()", "getcwd()", "~", "/", "..", "../")
	simpleLit = regexp.MustCompile(`^\s*(['"])([^'"]*)['"]\s*$`)
)

// scanDirReads denies code that lists a directory that may hold secrets
// (the cwd, home, root, or a runtime-chosen one) and reads or runs what it
// finds: [open(f).read() for f in os.listdir('.')] reads ./.env without
// naming it. Listing a specific subdirectory literal is allowed.
func (s *shellEval) scanDirReads(lang, code string) {
	for _, loc := range dirListRe.FindAllStringIndex(code, -1) {
		if !s.sec.work.spend(maxArgScan/64 + 1) {
			return
		}
		arg, ok := parenArg(code, loc[1]-1)
		if !ok {
			arg = "(unknown)" // unbalanced or too long: not provably a subdirectory
		}
		arg = strings.TrimSpace(arg)
		if arg == "" {
			// pathlib.Path('.').iterdir(): the receiver names the directory.
			if recv, ok := receiverArg(code, loc[0]); ok {
				arg = strings.TrimSpace(recv)
			}
		}
		if first, _, found := strings.Cut(arg, ","); found {
			arg = strings.TrimSpace(first)
		}
		if m := simpleLit.FindStringSubmatch(arg); m != nil {
			arg = m[2]
			if !cwdArgs[strings.TrimSpace(arg)] {
				continue // a named subdirectory
			}
		}
		if m, ok := s.sec.checkPath(activeLit(".*")); ok {
			m.glob = true
			m.path = "every file in " + displayDir(arg)
			s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "reading (from "+lang+" code)", s.sec))
			return
		}
	}
}

func displayDir(arg string) string {
	if arg == "" {
		return "the current directory"
	}
	return arg
}

// maxArgScan bounds how far parenArg/receiverArg look for a matching
// parenthesis, so repeated calls stay linear overall.
const maxArgScan = 512

// parenArg returns the text between the '(' at open and its matching ')'.
func parenArg(code string, open int) (string, bool) {
	depth := 0
	for i := open; i < len(code) && i < open+maxArgScan; i++ {
		switch code[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return code[open+1 : i], true
			}
		}
	}
	return "", false
}

// receiverArg returns the argument of the call just before a method call:
// for "Path('.').iterdir(" at start (the '.'), it returns "'.'".
func receiverArg(code string, start int) (string, bool) {
	i := start - 1
	for i >= 0 && i > start-maxArgScan && (code[i] == ' ' || code[i] == '.') {
		i--
	}
	if i < 0 || code[i] != ')' {
		return "", false
	}
	depth := 0
	for j := i; j >= 0 && j > i-maxArgScan; j-- {
		switch code[j] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return code[j+1 : i], true
			}
		}
	}
	return "", false
}

func (s *shellEval) scanEnvAccess(lang, code string) {
	for _, acc := range envAccessors {
		if acc.langs != nil && !acc.langs[lang] {
			continue
		}
		for _, loc := range acc.re.FindAllStringIndex(code, -1) {
			if !s.sec.work.spend(1) {
				return
			}
			name, verdict := envAccessName(acc, code[loc[1]:])
			s.envVerdict(lang, name, verdict)
			if verdict != envNamed {
				break // further matches of this accessor add nothing
			}
		}
	}
	for _, re := range envDumpRes {
		if re.MatchString(code) {
			s.envVerdict(lang, "", envDump)
		}
	}
	if lang == "perl" {
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
}

// maxImportList bounds the import list read after `use Env`.
const maxImportList = 512

// perlImportList returns the import list after `use Env`: qw(A B), qw/A B/
// or a quoted string. An empty result means everything is imported.
func perlImportList(rest string) string {
	rest = strings.TrimLeft(rest[:min(len(rest), maxImportList+8)], " \t\r\n")
	var closer byte
	switch {
	case strings.HasPrefix(rest, "qw"):
		rest = strings.TrimLeft(rest[2:], " \t")
		if rest == "" {
			return ""
		}
		switch rest[0] {
		case '(':
			closer = ')'
		case '/':
			closer = '/'
		default:
			return ""
		}
	case rest != "" && (rest[0] == '\'' || rest[0] == '"'):
		closer = rest[0]
	default:
		return ""
	}
	end := strings.IndexByte(rest[1:], closer)
	if end < 0 {
		return ""
	}
	return rest[1 : 1+end]
}

func (s *shellEval) envVerdict(lang, name string, verdict envAccessKind) {
	switch verdict {
	case envNamed:
		s.checkEnvName(name)
	case envDynamic:
		s.c.deny(RuleEnvExposure, fmt.Sprintf("the `%s` code reads an environment variable whose name is only known at runtime; it could expose a secret. Read specific non-secret variables by literal name.", lang))
	case envDump:
		s.c.deny(RuleEnvExposure, fmt.Sprintf("the `%s` code accesses the whole environment, which contains secret variables (secrets.env). Read specific non-secret variables by literal name instead.", lang))
	}
}

var (
	nodeLangs        = set("node", "nodejs", "bun", "deno")
	requireProcessRe = regexp.MustCompile(`\b(?:require|import)\s*\(\s*['"` + "`" + `](?:node:)?process['"` + "`" + `]\s*\)`)
	processRe        = regexp.MustCompile(`\bprocess\b`)
	processPropRe    = regexp.MustCompile(`^\s*\??\.\s*([A-Za-z_$][\w$]*)`)
	processKeyRe     = regexp.MustCompile(`^\s*(?:\?\.)?\[\s*(['"` + "`" + `])([\w$]*)['"` + "`" + `]\s*\]`)
	// processCallbackRe: process handed to an array/promise callback slot
	// ([1,2].forEach(process)) is called, not read; it only throws.
	processCallbackRe = regexp.MustCompile(`\b(?:forEach|map|filter|some|every|find|findIndex|findLast|reduce|reduceRight|flatMap|then|catch|finally)\s*\(\s*$`)
	processReturnRe   = regexp.MustCompile(`\b(?:return|yield|await)\s*$`)
	// processDumpProps expose the whole environment.
	processDumpProps = set("report", "binding", "_linkedBinding")
)

// processLookback bounds how much code before a `process` token is examined.
const processLookback = 32

// scanNodeProcess handles the JavaScript process object beyond the literal
// process.env accessor: process['env'], process.report, and process used as
// a value: an alias (p=process), destructuring ({env}=process), a spread,
// an argument (console.log(process)), a returned value, or a bare
// expression statement (node -p process). Property names (obj.process,
// {process: 1}), calls of a function named process, comments and other
// expression contexts (typeof process) are fine.
func (s *shellEval) scanNodeProcess(lang, code string) {
	blank := blankJSComments(blankLiterals(code))
	for _, loc := range processRe.FindAllStringIndex(blank, -1) {
		if !s.sec.work.spend(1) {
			return
		}
		if loc[0] > 0 && blank[loc[0]-1] == '$' {
			continue // $process: another identifier
		}
		rest, brest := code[loc[1]:], blank[loc[1]:]
		if m := processPropRe.FindStringSubmatch(brest); m != nil {
			if processDumpProps[m[1]] {
				s.envVerdict(lang, "", envDump)
			}
			continue // process.env is an accessor of its own
		}
		if m := processKeyRe.FindStringSubmatch(rest); m != nil {
			switch {
			case m[2] == "env":
				name, v := envAccessName(envAccessor{bracket: true, attr: true}, rest[len(m[0]):])
				s.envVerdict(lang, name, v)
			case processDumpProps[m[2]]:
				s.envVerdict(lang, "", envDump)
			}
			continue
		}
		trimmed := strings.TrimLeft(brest, " \t\r\n")
		before := strings.TrimRight(blank[max(0, loc[0]-processLookback):loc[0]], " \t\r\n")
		var next, prev byte
		if trimmed != "" {
			next = trimmed[0]
		}
		if before != "" {
			prev = before[len(before)-1]
		}
		switch {
		case strings.HasPrefix(trimmed, "["), strings.HasPrefix(trimmed, "?.["):
			s.envVerdict(lang, "", envDynamic)
			continue
		case next == '(':
			continue // a function named process
		case strings.HasSuffix(before, "..."):
			// spread: {...process}
		case prev == '.':
			continue // obj.process
		case next == ':' && prev != '?':
			continue // {process: 1}
		case next == '=' && !strings.HasPrefix(trimmed, "=="):
			continue // assignment to a local named process
		case prev == '=' || strings.HasSuffix(before, "=>"):
			if len(before) >= 2 && strings.ContainsRune("=!<>", rune(before[len(before)-2])) && !strings.HasSuffix(before, "=>") {
				continue // comparison: x == process
			}
		case prev == '(' || prev == ',':
			if prev == '(' && processCallbackRe.MatchString(before) {
				continue
			}
		case prev == '[':
		case processReturnRe.MatchString(before):
		case (prev == 0 || prev == ';' || prev == '{' || prev == '}' || prev == '\n') &&
			(next == 0 || next == ';' || next == '}' || next == ','):
			// a bare expression statement: node -p process
		default:
			continue
		}
		s.c.deny(RuleEnvExposure, fmt.Sprintf("the `%s` code uses the `process` object as a value (alias, destructuring, spread or argument), which exposes process.env with all secret variables (secrets.env). Read specific non-secret variables as process.env.NAME instead.", lang))
		return
	}
}

// blankJSComments replaces // and /* */ comments with spaces (same length).
// String literals must already be blanked.
func blankJSComments(code string) string {
	b := []byte(code)
	for i := 0; i+1 < len(b); i++ {
		if b[i] != '/' {
			continue
		}
		switch b[i+1] {
		case '/':
			for ; i < len(b) && b[i] != '\n'; i++ {
				b[i] = ' '
			}
		case '*':
			b[i], b[i+1] = ' ', ' '
			for i += 2; i < len(b); i++ {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					b[i], b[i+1] = ' ', ' '
					i++
					break
				}
				b[i] = ' '
			}
		}
	}
	return string(b)
}

// blankLiterals replaces the content of string literals with spaces (same
// length), keeping ${...} interpolations of template literals.
func blankLiterals(code string) string {
	b := []byte(code)
	for _, l := range stringLitRe.FindAllStringIndex(code, -1) {
		tmpl := code[l[0]] == '`'
		depth := 0
		for i := l[0] + 1; i < l[1]-1; i++ {
			if tmpl {
				if depth == 0 && code[i] == '$' && i+1 < l[1]-1 && code[i+1] == '{' {
					depth = 1
					i++
					continue
				}
				if depth > 0 {
					switch code[i] {
					case '{':
						depth++
					case '}':
						depth--
					}
					continue
				}
			}
			b[i] = ' '
		}
	}
	return string(b)
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
		if m := envSpaceRe.FindStringSubmatch(rest); m != nil {
			return m[2], envNamed
		}
	}
	if acc.brace {
		if m := envBraceRe.FindStringSubmatch(rest); m != nil {
			return m[1], envNamed
		}
	}
	if acc.paren {
		if m := envParenRe.FindStringSubmatch(rest); m != nil {
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
