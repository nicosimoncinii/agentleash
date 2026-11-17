package engine

import (
	"fmt"
	"regexp"
	"strings"
)

// Argument roles: some arguments are data (a grep pattern, a sed script,
// a jq filter), some are write-only destinations, and some git subcommands
// only touch metadata. These refine the conservative "any argument" rule.

// gitMetadata reports git subcommands that never print file content:
// check-ignore, ls-files, rm --cached, update-index --assume-unchanged.
func gitMetadata(args []cmdArg) bool {
	texts := []string{"git"}
	for _, a := range args {
		texts = append(texts, a.textOr())
	}
	sub := gitVariants(texts)[0][1:]
	if len(sub) == 0 {
		return false
	}
	switch sub[0] {
	case "check-ignore", "ls-files":
		return true
	case "rm":
		return containsStr(sub, "--cached")
	case "update-index":
		return containsStr(sub, "--assume-unchanged") || containsStr(sub, "--skip-worktree") ||
			containsStr(sub, "--no-assume-unchanged") || containsStr(sub, "--no-skip-worktree")
	}
	return false
}

var (
	patternFirst = set("grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "mawk", "nawk", "jq", "yq")
	// options whose separate value is data (pattern/script)
	dataValueOpts = set("-e", "--regexp", "--expression")
	// options whose separate value is a file holding the pattern/script
	fileValueOpts = set("-f", "--file", "--from-file")
	// options taking a separate (non-path) value; skipped when looking for
	// the positional pattern
	valueOpts = set("-A", "-B", "-C", "-m", "-d", "-D", "-t", "-T", "-j", "-M", "-F", "-v", "--type",
		"--type-not", "--max-count", "--context", "--after-context", "--before-context", "--max-depth",
		"--color", "--colors", "--sort", "--threads", "--indent", "-l", "--line-length")
	// jq options taking two values (name and value/file)
	jqPairOpts = set("--arg", "--argjson", "--slurpfile", "--rawfile")
)

// dataFiltered drops the pattern/script/filter argument of grep-like tools,
// sed, awk and jq: it is data, not a path ("grep -n '.env' src/x.ts").
// Files given with -f are kept.
func dataFiltered(name string, args []cmdArg) []cmdArg {
	if !patternFirst[name] {
		return args
	}
	out := make([]cmdArg, 0, len(args))
	patternSeen := exrHasExplicitPattern(name, args)
	for i := 0; i < len(args); i++ {
		a := args[i]
		t, ok := a.text()
		if l, attached := clusterValueOpt(name, t); ok && l != 0 {
			out, i = exrKeepClusterValue(out, args, i, l, attached)
			continue
		}
		if ok {
			var handled bool
			if out, i, handled = exrKeepOption(name, out, args, i, t); handled {
				continue
			}
		}
		if !patternSeen {
			patternSeen = true // the pattern / script / filter
			continue
		}
		out = append(out, a)
	}
	return out
}

// exrHasExplicitPattern reports whether the pattern/script is given with an
// option (-e, -f, --regexp=, --expression=, or -e/-f inside a cluster), so
// that no operand is the pattern.
func exrHasExplicitPattern(name string, args []cmdArg) bool {
	for _, a := range args {
		t, ok := a.text()
		if ok && (dataValueOpts[t] || fileValueOpts[t] || strings.HasPrefix(t, "--regexp=") || strings.HasPrefix(t, "--expression=")) {
			return true
		}
		if l, _ := clusterValueOpt(name, t); ok && l != 0 {
			return true
		}
	}
	return false
}

// exrKeepClusterValue handles -hf FILE, -ie PATTERN, -hfFILE: the cluster
// ends with (or carries) the value of -f (a file, kept) or -e (data,
// dropped). It returns the new output and the index of the last argument
// consumed.
func exrKeepClusterValue(out, args []cmdArg, i int, l byte, attached string) ([]cmdArg, int) {
	out = append(out, args[i])
	switch {
	case attached != "" && l == 'f':
		out = append(out, litArg(attached))
	case attached == "" && i+1 < len(args):
		if l == 'f' {
			out = append(out, args[i+1])
		}
		i++
	}
	return out, i
}

// exrKeepOption keeps an option word t (at index i) and any path value it
// takes, dropping data values. handled is false when t is not an option.
func exrKeepOption(name string, out, args []cmdArg, i int, t string) ([]cmdArg, int, bool) {
	a := args[i]
	switch {
	case dataValueOpts[t]:
		out = append(out, a)
		i++ // the value is a pattern/script: data
	case jqPairOpts[t] && (name == "jq" || name == "yq"):
		out = append(out, a)
		if (t == "--slurpfile" || t == "--rawfile") && i+2 < len(args) {
			out = append(out, args[i+2]) // the file
		}
		i += 2
	case fileValueOpts[t] || valueOpts[t]:
		out = append(out, a)
		if i+1 < len(args) {
			out = append(out, args[i+1])
			i++
		}
	case strings.HasPrefix(t, "-") && t != "-":
		out = append(out, a)
	default:
		return out, i, false
	}
	return out, i, true
}

// clusterFileOpt are the tools whose short -f takes a pattern/script file
// (ag/ack use -f for something else).
var clusterFileOpt = set("grep", "egrep", "fgrep", "rg", "sed", "awk", "gawk", "mawk", "nawk", "jq", "yq")

// clusterValueOpt finds -e or -f inside a short-option cluster of two or
// more letters ("-hf", "-ie", "-hfFILE"). It returns the letter and the value
// attached after it ("" when the value is the next argument), or 0.
func clusterValueOpt(name, t string) (byte, string) {
	if !clusterFileOpt[name] || len(t) < 3 || t[0] != '-' || t[1] == '-' {
		return 0, ""
	}
	for i := 1; i < len(t); i++ {
		c := t[i]
		if !isAlpha(c) {
			return 0, ""
		}
		if c == 'e' || c == 'f' {
			if i == 1 && len(t) > 2 {
				return 0, "" // -fFILE / -ePATTERN: handled by the attached-value rule
			}
			return c, t[i+1:]
		}
	}
	return 0, ""
}

// sedScripts returns the script texts of a sed command line: -e/--expression
// values, or the first operand when none is given (-f files are path-checked
// as arguments).
func sedScripts(args []cmdArg) []string {
	var scripts []string
	explicit := false // -e or -f given: operands are input files
	first := ""
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		if !ok {
			continue
		}
		l, attached := clusterValueOpt("sed", t)
		switch {
		case t == "-e" || t == "--expression" || (l == 'e' && attached == ""):
			explicit = true
			if i+1 < len(args) {
				scripts = append(scripts, args[i+1].textOr())
				i++
			}
		case l == 'e':
			explicit = true
			scripts = append(scripts, attached)
		case strings.HasPrefix(t, "--expression="):
			explicit = true
			scripts = append(scripts, strings.TrimPrefix(t, "--expression="))
		case strings.HasPrefix(t, "-e") && len(t) > 2:
			explicit = true
			scripts = append(scripts, t[2:])
		case t == "-f" || t == "--file" || (l == 'f' && attached == ""):
			explicit = true
			i++
		case t == "-l" || t == "--line-length":
			i++
		case strings.HasPrefix(t, "-") && t != "-":
			explicit = explicit || strings.HasPrefix(t, "-f") || strings.HasPrefix(t, "--file=") || l == 'f'
		case first == "":
			first = t
		}
	}
	if !explicit && first != "" {
		scripts = append(scripts, first)
	}
	return scripts
}

// sedExecTexts finds `s/regex/replacement/FLAGS` commands with the GNU `e`
// flag, which runs the pattern space as a shell command after the
// substitution. It returns the replacements and whether one of them is built
// from the input (& or \N), i.e. only known at runtime.
func sedExecTexts(script string) (texts []string, dynamic bool) {
	for i := 0; i+1 < len(script); i++ {
		if script[i] != 's' || (i > 0 && !strings.ContainsRune(";{}\n \t0123456789$/!,", rune(script[i-1]))) {
			continue
		}
		d := script[i+1]
		if isAlpha(d) || (d >= '0' && d <= '9') || d == '\\' || d == '\n' || d == ' ' {
			continue
		}
		var parts []string
		j := i + 2
		start := j
		for j < len(script) && len(parts) < 2 {
			switch script[j] {
			case '\\':
				j++
			case d:
				parts = append(parts, script[start:j])
				start = j + 1
			}
			j++
		}
		if len(parts) < 2 {
			return texts, dynamic
		}
		exec := false
		for ; j < len(script) && strings.IndexByte("gpiImMe0123456789", script[j]) >= 0; j++ {
			exec = exec || script[j] == 'e'
		}
		if exec {
			repl := strings.ReplaceAll(parts[1], `\`+string(d), string(d))
			texts = append(texts, repl)
			if strings.Contains(repl, "&") || sedBackrefRe.MatchString(repl) {
				dynamic = true
			}
		}
		i = j - 1
	}
	return texts, dynamic
}

var sedBackrefRe = regexp.MustCompile(`\\[0-9]`)

// sedSubstExec re-parses the commands run by the s///e flag.
func (s *shellEval) sedSubstExec(args []cmdArg) {
	for _, script := range sedScripts(args) {
		texts, dynamic := sedExecTexts(script)
		if dynamic {
			s.c.deny(RuleDynamicShell, "the sed `s///e` flag runs a command built from the input text (& or \\1), which is only known at runtime; blocked to be safe.")
		}
		for _, t := range texts {
			ch := s.child()
			ch.ignoreParseErrors = true
			ch.run(t)
		}
	}
}

var (
	sqliteValueOpts = set("-separator", "-newline", "-nullvalue", "-vfs", "-maxsize", "-mmap", "-pagecache",
		"-lookaside", "-heap", "-init", "-escape")
	sqliteReadFileRe = regexp.MustCompile(`(?i)\breadfile\s*\(\s*(?:'([^']*)'\s*\)|"([^"]*)"\s*\))?`)
	sqliteFileDots   = set(".read", ".import", ".open", ".restore", ".load", ".backup", ".save", ".output", ".once", ".clone")
)

// sqliteCommand analyses what sqlite3 runs besides the database file: SQL
// and dot-commands given as operands, with -cmd, or on static stdin.
// readfile('PATH') and .read/.import/... file names are path-checked,
// .shell/.system and '|cmd' file names are re-parsed as shell commands.
func (s *shellEval) sqliteCommand(args []cmdArg, stdin *stdinInfo) {
	var texts []string
	dbSeen := false
	for i := 0; i < len(args); i++ {
		t := args[i].textOr()
		switch {
		case t == "-cmd" || t == "--cmd":
			if i+1 < len(args) {
				texts = append(texts, args[i+1].textOr())
				i++
			}
		case sqliteValueOpts[strings.TrimPrefix(t, "-")] || sqliteValueOpts[t]:
			i++
		case strings.HasPrefix(t, "-"):
		case !dbSeen:
			dbSeen = true
		default:
			texts = append(texts, t)
		}
	}
	if stdin != nil && stdin.kind == stdinStatic {
		texts = append(texts, stdin.texts...)
	}
	for _, text := range texts {
		s.sqliteText(text)
	}
}

func (s *shellEval) sqliteText(text string) {
	for _, m := range sqliteReadFileRe.FindAllStringSubmatch(text, -1) {
		p := m[1] + m[2]
		if p == "" {
			s.c.deny(RuleDynamicPath, "sqlite3 readfile() of a value only known at runtime could read a secret file; pass a literal, non-secret path.")
			continue
		}
		s.checkArg("sqlite3", litArg(p))
	}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 || !strings.HasPrefix(f[0], ".") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimSpace(line)[len(f[0]):])
		switch {
		case f[0] == ".shell" || f[0] == ".system":
			ch := s.child()
			ch.ignoreParseErrors = true
			ch.run(rest)
		case sqliteFileDots[f[0]] && len(f) > 1:
			if arg := strings.Trim(rest, `'"`); strings.HasPrefix(arg, "|") {
				// .read '|cmd', .output '|cmd': the command is run by a shell
				s.recurseText(arg[1:], false)
				continue
			}
			for _, a := range f[1:] {
				if a = strings.Trim(a, `'"`); !strings.HasPrefix(a, "-") {
					s.checkArg("sqlite3", litArg(a))
					break
				}
			}
		}
	}
}

var copyCmds = set("cp", "mv", "install")

// checkCopyDest handles the destination of cp/mv/install. Copying a
// non-secret file ONTO a secret path (cp .env.example .env) reads nothing
// secret: it is asked, not denied. Returns the remaining arguments.
func (s *shellEval) checkCopyDest(name string, args []cmdArg) []cmdArg {
	destIdx := -1
	var positional []int
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		switch {
		case ok && (t == "-t" || t == "--target-directory") && i+1 < len(args):
			destIdx = i + 1
			i++
		case ok && strings.HasPrefix(t, "--target-directory="):
			return args // rare; keep the conservative rule
		case ok && strings.HasPrefix(t, "-") && t != "-":
		default:
			positional = append(positional, i)
		}
	}
	if destIdx < 0 {
		if len(positional) < 2 {
			return args
		}
		destIdx = positional[len(positional)-1]
	}
	dest := args[destIdx]
	if t, ok := dest.text(); ok {
		lit := escapeLit(t)
		if m, ok := s.sec.checkPath(lit); ok && !m.glob {
			s.c.ask(RuleSecretFile+":"+m.pattern, fmt.Sprintf("`%s` would overwrite the secret file %q (secrets.files: %q in .agentleash.yaml); the user must confirm. Nothing secret is read.", name, display(t), m.pattern))
			return append(append([]cmdArg(nil), args[:destIdx]...), args[destIdx+1:]...)
		}
		if m, ok := s.sec.dirHoldsSecret(lit); ok {
			s.c.ask(RuleSecretFile+":"+m.pattern, fmt.Sprintf("`%s` would write into %q, a directory holding secret files (secrets.files: %q); the user must confirm.", name, display(t), m.pattern))
			return append(append([]cmdArg(nil), args[:destIdx]...), args[destIdx+1:]...)
		}
	}
	return args
}
