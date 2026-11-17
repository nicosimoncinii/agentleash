package engine

import (
	"fmt"
	"regexp"
	"strings"
)

// cmdArg is one argument of a simple command, as evaluated alternatives.
type cmdArg struct {
	alts []string
}

func litArg(t string) cmdArg { return cmdArg{alts: []string{escapeLit(t)}} }

func dynArg() cmdArg { return cmdArg{alts: []string{string(dynAny)}} }

func (a cmdArg) text() (string, bool) { return staticText(a.alts) }

// textOr returns the static text or the display form of the first alt.
func (a cmdArg) textOr() string {
	if t, ok := a.text(); ok {
		return t
	}
	return plain(firstAlt(a.alts))
}

func (a cmdArg) hasDynamic() bool {
	for _, alt := range a.alts {
		if isDynamic(alt) {
			return true
		}
	}
	return false
}

// processCommand analyses a simple command. It is re-entered for the inner
// command of every wrapper (sudo, env, xargs, find -exec, ...).
func (s *shellEval) processCommand(args []cmdArg, stdin *stdinInfo) {
	if len(args) == 0 || !s.sec.work.spend(1) {
		return
	}
	if s.depth > maxDepth {
		s.c.deny(RuleNesting, "the command nests wrappers too deeply to analyse; blocked to be safe.")
		return
	}
	names := args[0].alts
	if len(names) > 8 {
		names = []string{string(dynAny)}
	}
	for _, n := range names {
		s.processNamed(n, args, stdin)
	}
}

func (s *shellEval) processNamed(nameAlt string, args []cmdArg, stdin *stdinInfo) {
	dynamicName := isDynamic(nameAlt) || (hasGlobMeta(nameAlt) && nameAlt != "[")
	name := ""
	if !dynamicName {
		name = cmdBase(plain(nameAlt))
	}
	s.matchCommand(nameAlt, args)
	if dynamicName {
		// Unknown program ($SHELL, "$EDITOR", ...): treat it like a reader,
		// and like a shell if it is given -c TEXT.
		s.checkArgs("", args[1:])
		// The name word itself can hide a path when a static fragment is
		// glued to the runtime part (cat${IFS}.env); a bare $CMD cannot.
		for _, cand := range argCandidates(nameAlt) {
			if m, ok := s.sec.checkPath(cand); ok && hasStatic(cand) {
				s.c.deny(RuleDynamicPath, fmt.Sprintf("the command word %q is built at runtime and could resolve to a secret file (secrets.files: %q). Write the command and its arguments literally.", display(plain(nameAlt)), m.pattern))
			}
		}
		for i, a := range args[1:] {
			if t, ok := a.text(); ok && t == "-c" && i+2 < len(args) {
				s.evalString(args[i+2:i+3], "-c")
			}
		}
		return
	}
	rest := args[1:]
	s.stdinScript(name, rest, stdin)
	argv := []string{name}
	for _, a := range rest {
		argv = append(argv, a.textOr())
	}
	checkCredentialPrint(s.c, argv)
	if s.sec.touch {
		touchCommand(s.c, argv)
	}
	if s.req.InteractiveStdin && stdin == nil {
		checkInteractive(s.c, argv)
	}
	if inner, own, ok := s.unwrap(name, rest, stdin); ok {
		s.checkArgs(name, own)
		if inner != nil {
			s.processCommand(inner, stdin)
		}
		return
	}
	switch {
	case shells[name]:
		s.shellCommand(name, rest, stdin)
		return
	case name == "busybox" || name == "toybox":
		s.processCommand(rest, stdin)
		return
	case name == "eval":
		s.evalString(rest, "eval")
		return
	case name == "alias":
		for _, a := range rest {
			t := a.textOr()
			if i := strings.IndexByte(t, '='); i > 0 {
				s.recurseText(t[i+1:], false)
			}
		}
		return
	case name == "trap":
		if len(rest) > 0 {
			s.evalString(rest[:1], "trap")
		}
		return
	case name == "pwsh" || name == "powershell" || name == "cmd":
		s.checkArgs(name, rest)
		var parts []string
		for _, a := range rest {
			parts = append(parts, quotePS(a.textOr()))
		}
		pe := newPwshEval(s.e, s.sec, s.c, s.depth+1)
		pe.req = s.req
		pe.run(name + " " + strings.Join(parts, " "))
		return
	case name == "find":
		s.findCommand(rest, stdin)
		return
	case name == "xargs":
		s.xargsCommand(rest, stdin)
		return
	case name == "docker" || name == "podman" || name == "nerdctl":
		s.containerEnv(rest)
		s.composeConfig(name, rest)
	case name == "docker-compose" || name == "podman-compose":
		s.composeConfig(name, rest)
	case name == "printenv":
		s.printenvCommand(rest)
		return
	case name == "set":
		if len(rest) == 0 {
			s.c.deny(RuleEnvExposure, envDumpReason)
		}
		return
	case name == "ps":
		for _, a := range rest {
			t := a.textOr()
			if !strings.HasPrefix(t, "-") && strings.ContainsRune(t, 'e') {
				s.c.deny(RuleEnvExposure, "`ps` with the BSD `e` option prints the environment of processes, which contains secrets. Use `ps aux` without `e`.")
				return
			}
			if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsRune(t, 'E') {
				s.c.deny(RuleEnvExposure, "`ps -E` prints the environment of processes, which contains secrets. Use `ps -ef` or `ps aux` instead.")
				return
			}
		}
	case name == "systemctl" || name == "tmux" || name == "launchctl":
		for _, a := range rest {
			t := a.textOr()
			if t == "show-environment" || t == "showenv" || (name == "launchctl" && t == "export") {
				s.c.deny(RuleEnvExposure, envDumpReason)
				return
			}
		}
		if name == "launchctl" && len(rest) > 0 && rest[0].textOr() == "getenv" {
			s.printenvCommand(rest[1:]) // launchctl getenv NAME prints one variable
			return
		}
	case name == "source" || name == ".":
		if len(rest) > 0 {
			if rest[0].hasDynamic() || strings.HasPrefix(rest[0].textOr(), "/dev/fd/") {
				s.c.deny(RuleDynamicShell, "sourcing a script whose content or path is only known at runtime cannot be checked; blocked to be safe.")
			}
			if t := rest[0].textOr(); (t == "/dev/stdin" || t == "-") && (stdin == nil || stdin.kind != stdinStatic) {
				s.c.deny(RuleDynamicShell, "sourcing code from stdin cannot be checked; blocked to be safe.")
			} else if stdin != nil && stdin.kind == stdinStatic && (t == "/dev/stdin" || t == "-") {
				for _, txt := range stdin.texts {
					s.recurseText(txt, false)
				}
			}
		}
	}
	if interpreters[name] {
		if len(rest) > 1 && rest[0].textOr() == "-m" && rest[1].textOr() == "dotenv" {
			// python -m dotenv list: the python-dotenv CLI
			s.processCommand(append([]cmdArg{litArg("dotenv")}, rest[2:]...), stdin)
		}
		s.interpreterCommand(name, rest, stdin)
	}
	checkName := name
	if name == "git" && !s.sec.touch && gitMetadata(rest) {
		checkName = "git-metadata"
	}
	argsToCheck := rest
	if !s.sec.touch {
		argsToCheck = dataFiltered(name, rest)
	}
	if copyCmds[name] {
		argsToCheck = s.checkCopyDest(name, argsToCheck)
	}
	s.checkArgsRoles(name, checkName, argsToCheck)
	if readsFileList(name, rest) {
		s.checkFileList(name, stdin)
	}
	if name == "sed" {
		s.sedSubstExec(rest)
	}
	if name == "sqlite3" {
		s.sqliteCommand(rest, stdin)
	}
	if recursiveCopiers[name] {
		s.checkRecursiveCopy(name, rest)
	}
	if searchers[name] {
		s.checkRecursiveSearch(name, rest)
	}
	if name == "rg" {
		s.checkUnrestrictedSearch(rest)
	}
	for _, g := range toolGlobs(name, rest) {
		s.checkToolGlob(name, g)
	}
}

var (
	toolGlobOpts   = set("--include", "--glob", "-g", "--iglob", "-G", "--file-search-regex")
	gitContentCmds = set("log", "diff", "show", "grep", "archive", "blame", "whatchanged", "format-patch", "difftool")
)

// toolGlobs returns the filename globs a tool expands itself: grep/rg/ag
// --include/--glob/-g/--iglob values and git pathspecs. Unlike shell globs,
// these match dotfiles ('*' matches ".env").
func toolGlobs(name string, args []cmdArg) []string {
	var out []string
	switch {
	case searchers[name]:
		for i, a := range args {
			t, ok := a.text()
			if !ok {
				continue
			}
			if eq := strings.IndexByte(t, '='); eq > 0 && toolGlobOpts[t[:eq]] {
				out = append(out, t[eq+1:])
			} else if toolGlobOpts[t] && i+1 < len(args) {
				if v, ok := args[i+1].text(); ok {
					out = append(out, v)
				}
			}
		}
	case name == "git":
		texts := make([]string, 0, len(args)+1)
		texts = append(texts, "git")
		for _, a := range args {
			t, _ := a.text()
			texts = append(texts, t)
		}
		stripped := gitVariants(texts)[0][1:]
		if len(stripped) == 0 || !gitContentCmds[stripped[0]] {
			return nil
		}
		afterDashes := false
		for _, t := range stripped[1:] {
			switch {
			case t == "--":
				afterDashes = true
			case afterDashes || strings.HasPrefix(t, ":(") || (!strings.HasPrefix(t, "-") && strings.ContainsAny(t, "*?[")):
				out = append(out, t)
			}
		}
	}
	return out
}

var pathspecMagic = regexp.MustCompile(`^:(\([^)]*\)|[/!^]+)`)

// checkToolGlob denies a tool-evaluated glob that could match a secret.
func (s *shellEval) checkToolGlob(name, g string) {
	g = pathspecMagic.ReplaceAllString(g, "")
	if g == "" {
		return
	}
	glob := strings.NewReplacer("*", string(dynStar), "?", string(dynStar)).Replace(escapeGlobExceptWild(g))
	cands := []string{glob}
	if strings.ContainsRune(glob, dynStar) {
		cands = append(cands, "**/"+strings.TrimPrefix(glob, "./")) // git and grep wildcards cross directories
	}
	for _, cand := range cands {
		if m, ok := s.sec.checkPath(cand); ok {
			m.glob, m.path = true, g
			s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "letting `"+name+"` expand", s.sec))
			return
		}
	}
}

// escapeGlobExceptWild escapes characters special to the internal syntax
// except the wildcards a tool will expand itself.
func escapeGlobExceptWild(g string) string {
	return strings.NewReplacer(`\`, `\\`, "]", `\]`).Replace(g)
}

var (
	searchers = set("grep", "egrep", "fgrep", "rg", "ag", "ack")
	identRe   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)

// checkRecursiveSearch asks before a recursive search for a secret variable
// name over a directory that contains the project root or home: it would
// print the matching line of .env with the value.
func (s *shellEval) checkRecursiveSearch(name string, args []cmdArg) {
	recursive := name != "grep" && name != "egrep" && name != "fgrep"
	hiddenToo := name == "grep" || name == "egrep" || name == "fgrep" || name == "ack"
	var pattern string
	var dirs []cmdArg
	explicitPattern := false
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		if !ok {
			continue
		}
		switch {
		case t == "-e" || t == "--regexp":
			if i+1 < len(args) {
				pattern, _ = args[i+1].text()
				explicitPattern = true
				i++
			}
			continue
		case strings.HasPrefix(t, "--exclude") || t == "-g" || strings.HasPrefix(t, "--glob") || strings.HasPrefix(t, "--iglob"):
			return // the agent is already excluding files
		case t == "--recursive" || t == "--dereference-recursive":
			recursive = true
			continue
		case t == "--hidden" || t == "--no-ignore" || strings.HasPrefix(t, "-uu"):
			hiddenToo = true
			continue
		case strings.HasPrefix(t, "--"):
			continue
		case strings.HasPrefix(t, "-") && len(t) > 1:
			if strings.ContainsAny(t[1:], "rR") && (name == "grep" || name == "egrep" || name == "fgrep") {
				recursive = true
			}
			continue
		}
		if pattern == "" && !explicitPattern {
			pattern = t
			explicitPattern = true
			continue
		}
		dirs = append(dirs, args[i])
	}
	if !recursive || !hiddenToo || pattern == "" {
		return
	}
	glob := ""
	for _, tok := range identRe.FindAllString(pattern, -1) {
		if g, ok := s.sec.envMatch(tok); ok {
			glob = g
			break
		}
	}
	if glob == "" {
		return
	}
	if len(dirs) == 0 {
		dirs = []cmdArg{litArg(".")}
	}
	for _, d := range dirs {
		for _, alt := range d.alts {
			if m, ok := s.sec.containsSecretRoot(alt); ok {
				s.c.ask(RuleSecretSearch, fmt.Sprintf("a recursive `%s` for %q over %q would also print matching lines from secret files such as %q (the variable values). Exclude them (e.g. --exclude='.env*') or search only source directories.", name, display(pattern), display(plain(alt)), m.pattern))
				return
			}
		}
	}
}

// stdinScripts are programs that execute shell text read from stdin.
var stdinScripts = set("at", "batch", "crontab")

// stdinScript analyses stdin text that a command will execute or read as a
// script: `at`, `batch`, `crontab -`, and any command given /dev/stdin or
// "-f -" (make -f /dev/stdin).
func (s *shellEval) stdinScript(name string, args []cmdArg, stdin *stdinInfo) {
	readsStdin := stdinScripts[name] && (name != "crontab" || len(args) == 0 || hasArg(args, "-"))
	if hasArg(args, "/dev/stdin") || (hasArg(args, "-") && !readsStdin && hasArg(args, "-f")) {
		readsStdin = true
	}
	if !readsStdin || stdin == nil || stdin.kind == stdinFile {
		return
	}
	if stdin.kind != stdinStatic || stdin.decode {
		if stdinScripts[name] {
			s.c.deny(RuleDynamicShell, fmt.Sprintf("`%s` would execute text that is only known at runtime; blocked to be safe.", name))
		}
		return
	}
	for _, t := range stdin.texts {
		for _, line := range strings.Split(t, "\n") {
			ch := s.child()
			ch.ignoreParseErrors = true
			ch.run(strings.TrimSpace(line))
		}
	}
}

func hasArg(args []cmdArg, want string) bool {
	for _, a := range args {
		if t, ok := a.text(); ok && t == want {
			return true
		}
	}
	return false
}

// checkArgs applies the conservative path rule to every argument and
// re-parses arguments that look like embedded shell commands.
func (s *shellEval) checkArgs(name string, args []cmdArg) {
	for _, a := range args {
		s.checkArg(name, a)
	}
}

func (s *shellEval) checkArg(name string, a cmdArg) { s.checkArgDir(name, a, true) }

// checkArgNoDir is checkArg for a subcommand word (git config, npm config):
// it is not a path, so the directory-holding-secrets rule does not apply.
func (s *shellEval) checkArgNoDir(name string, a cmdArg) { s.checkArgDir(name, a, false) }

func (s *shellEval) checkArgDir(name string, a cmdArg, dirRule bool) {
	if printOnly[name] || existenceOnly[name] {
		return
	}
	for _, alt := range a.alts {
		dyn := isDynamic(alt)
		for _, cand := range argCandidates(alt) {
			m, ok := s.sec.checkPath(cand)
			if !ok {
				if dirRule && !dyn && (s.sec.touch || !metadataOnly[name]) && !dirNavigation[name] {
					// A directory holding secrets (rsync -a ~/.ssh/ ...).
					// Mention mode: removing or moving an ancestor of the
					// project (rm -rf ., rm -rf ..) also counts.
					if dm, ok := s.sec.dirHolds(cand, s.sec.touch && destructiveCmds[name]); ok {
						s.c.deny(RuleSecretFile+":"+dm.pattern, dirReason(dm, verbFor(name), s.sec))
					}
				}
				continue
			}
			switch {
			case m.builtin && !dyn:
				s.c.deny(RuleEnvExposure, secretFileReason(m, verbFor(name), s.sec))
			case !m.glob && metadataOnly[name] && !s.sec.touch:
				// ls -l .env, touch .env, chmod 600 .env: no content is read.
			case !m.glob:
				s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, verbFor(name), s.sec))
			case isDynamic(cand):
				if s.dynamicSuspicious(name, cand) {
					s.c.deny(RuleDynamicPath, fmt.Sprintf("the argument %q to %s is built at runtime (variable or command substitution) and could resolve to a secret file (secrets.files: %q). Use a literal, non-secret path.", display(plain(alt)), cmdDisplay(name), m.pattern))
				}
			case (metadataOnly[name] || globBenign[name]) && !s.sec.touch:
			default:
				m.path = plain(cand)
				s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, verbFor(name), s.sec))
			}
		}
		if !dyn && !interpreters[name] {
			embedded := argCandidates(alt)
			if i := strings.IndexByte(alt, '='); i > 0 {
				embedded = append(embedded, alt[i+1:]) // --exec='cat .env', core.pager=...
			}
			for _, cand := range embedded {
				t := strings.TrimSpace(plain(cand))
				if !strings.ContainsAny(t, " \t\n;|&") {
					continue
				}
				s.recurseText(strings.TrimLeft(t, "!:"), true)
				if readers[name] {
					// Editors/readers given a command string (vim -c ':r .env'):
					// any literal secret path inside it counts.
					for _, tok := range strings.Fields(t) {
						if m, ok := s.sec.checkPath(escapeLit(tok)); ok && !m.glob {
							s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, verbFor(name), s.sec))
						}
					}
				}
			}
		}
	}
}

func cmdDisplay(name string) string {
	if name == "" {
		return "a runtime-chosen command"
	}
	return "`" + name + "`"
}

// dynamicSuspicious decides whether a runtime-built argument that could
// match a secret should be denied.
func (s *shellEval) dynamicSuspicious(name, cand string) bool {
	if strings.ContainsAny(cand, " \t\n") {
		return false // prose / header values ("Authorization: Bearer $T"), not a path
	}
	if name == "" || readers[name] || interpreters[name] || shells[name] {
		return true
	}
	if s.sec.touch && (destructiveCmds[name] || writerCmds[name]) {
		return true // mention mode: rm "$F", xargs rm
	}
	if benignDynamic[name] {
		return false
	}
	// Other commands: suspicious only if a static fragment is glued to the
	// dynamic part (e.g. ${X}env, $(...)/.ssh/id_rsa).
	return hasStatic(cand)
}

// argCandidates extracts the path-like pieces of an argument:
// the whole word, the value after '=', pieces split on ':' and ',',
// curl-style @file and attached short-option values (-f.env).
func argCandidates(alt string) []string {
	out := []string{alt}
	if w, ok := winPathVariant(alt); ok {
		out = append(out, w)
	}
	add := func(s string) {
		if s != "" && !containsStr(out, s) {
			out = append(out, s)
		}
	}
	// --grep=.env, --format=%H are data unless optionValue says "path";
	// only the value of such options is split further.
	split := alt
	if v, ok := optionValue(alt); ok {
		add(v)
		split = v
	} else if strings.HasPrefix(alt, "--") && strings.IndexByte(alt, '=') > 0 {
		split = ""
	}
	for _, sep := range []byte{':', ','} {
		if strings.IndexByte(split, sep) >= 0 {
			for _, p := range splitOn(split, sep) {
				add(p)
				if i := strings.IndexByte(p, '='); i >= 0 {
					add(p[i+1:])
				}
			}
		}
	}
	// Worklist: a piece found here is split again, so "-sd@.env" gives
	// "@.env" and then ".env".
	for i := 0; i < len(out) && i < 32; i++ {
		c := out[i]
		if strings.HasPrefix(c, "@") {
			add(c[1:])
		}
		if len(c) > 2 && c[0] == '-' && c[1] != '-' && isAlpha(c[1]) {
			add(c[2:])
			// value attached after a short-option cluster: -sd@.env, -xf.env
			k := 1
			for k < len(c) && isAlpha(c[k]) {
				k++
			}
			if k > 2 && k < len(c) {
				add(c[k:])
			}
		}
		if strings.HasPrefix(c, "<") || strings.HasPrefix(c, ">") {
			add(strings.TrimLeft(c, "<>"))
		}
		// name@file (curl --data-urlencode, httpie f@file, f:=@file)
		if j := strings.IndexByte(c, '@'); j > 0 && !strings.HasPrefix(c, "-") {
			add(c[j+1:])
		}
	}
	return out
}

var winPathRe = regexp.MustCompile(`^(?:[A-Za-z]:[\\/]|\.\.?\\|\\\\[^\\])`)

// winPathVariant: in bash a backslash is an ordinary character, but Git
// Bash on Windows (Claude Code's Bash tool) passes `cat 'C:\proj\.env'` to a
// program that reads C:\proj\.env. A path-role argument that looks like a
// Windows path is therefore also checked with `\` as a separator: a drive
// prefix (C:\, C:/), .\ or ..\, a UNC \\host\ prefix, or a backslash used
// between segments (sub\.env). A leading lone backslash (`\.env`, a regex
// escape) does not count; grep/sed patterns are data and never get here.
func winPathVariant(alt string) (string, bool) {
	if isDynamic(alt) {
		return "", false
	}
	t := unescapeKeepDyn(alt)
	if !strings.Contains(t, `\`) {
		return "", false
	}
	if !winPathRe.MatchString(t) && strings.HasPrefix(t, `\`) {
		return "", false
	}
	return escapeLitWin(t), true
}

// pathOptions take a file path as their value (--opt=PATH).
var pathOptions = set("--file", "--env-file", "--from-env-file", "--from-file", "--input", "--in", "--config",
	"--rcfile", "--init-file", "--key", "--cert", "--cacert", "--ca-file", "--keyfile", "--certfile",
	"--private-key", "--identity", "--identity-file", "--password-file", "--secret-file", "--data-binary",
	"--data", "--data-urlencode", "--upload-file", "--arg-file", "--include-file", "--path", "--source",
	"--src", "--target", "--output", "--out", "--log-file", "--kubeconfig", "--credentials", "--netrc-file",
	"--settings", "--userconfig", "--globalconfig", "--dotenv", "--envfile", "--secrets", "--json-file",
	"--keystore", "--truststore", "--token-file", "--pem", "--read", "--load", "--require", "--import",
	"--post-file", "--body-file", "--files0-from")

// optionValue returns the value of KEY=VALUE that may be a path: always for
// plain words (dd if=.env, VAR=.env), for --options only when the option
// takes a path or the value looks like one (has a '/' or starts with '~').
func optionValue(alt string) (string, bool) {
	i := strings.IndexByte(alt, '=')
	if i < 0 {
		return "", false
	}
	key, val := alt[:i], alt[i+1:]
	if !strings.HasPrefix(key, "-") {
		return val, true
	}
	if pathOptions[strings.ToLower(key)] || strings.Contains(val, "/") || strings.HasPrefix(val, "~") || strings.HasPrefix(val, "@") {
		return val, true
	}
	return "", false
}

func isAlpha(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// recurseText re-parses a string as a shell command. When onlyIfShellish is
// set, the text is only analysed if its first word is a command we know
// can read files or the environment (avoids flagging prose).
func (s *shellEval) recurseText(text string, onlyIfShellish bool) {
	if strings.TrimSpace(text) == "" {
		return
	}
	if onlyIfShellish {
		t := strings.TrimLeft(strings.TrimSpace(text), "!({ ")
		head := t
		if i := strings.IndexAny(t, " \t\n;|&"); i >= 0 {
			head = t[:i]
		}
		if !embeddedHeads[cmdBase(head)] {
			return
		}
	}
	ch := s.child()
	ch.ignoreParseErrors = onlyIfShellish
	ch.run(text)
}

// evalString handles eval-like commands that join and re-parse their args.
func (s *shellEval) evalString(args []cmdArg, what string) {
	var alts []string
	alts = append(alts, "")
	for i, a := range args {
		sep := " "
		if i == 0 {
			sep = ""
		}
		var next []string
		for _, x := range alts {
			for _, y := range a.alts {
				next = append(next, x+sep+y)
			}
		}
		alts = next
		if len(alts) > maxAlts {
			alts = []string{string(dynAny)}
		}
	}
	for _, alt := range alts {
		if isDynamic(alt) {
			s.c.deny(RuleDynamicShell, fmt.Sprintf("`%s` of text that is only known at runtime cannot be checked; blocked to be safe. Run the command directly instead.", what))
			continue
		}
		s.recurseText(plain(alt), false)
	}
}

// shellCommand handles sh/bash/zsh ... -c STRING, scripts and stdin.
func (s *shellEval) shellCommand(name string, args []cmdArg, stdin *stdinInfo) {
	cmdIdx := -1
	scriptIdx := -1
	readsStdin := false
	var own []cmdArg
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		if !ok {
			if cmdIdx == -2 {
				cmdIdx = i
				break
			}
			scriptIdx = i
			break
		}
		if cmdIdx == -2 {
			cmdIdx = i
			break
		}
		if t == "--" || t == "-" {
			if t == "-" {
				readsStdin = true
			}
			if i+1 < len(args) {
				scriptIdx = i + 1
			}
			break
		}
		if strings.HasPrefix(t, "--") {
			own = append(own, args[i])
			if (t == "--rcfile" || t == "--init-file" || t == "--init-command") && i+1 < len(args) {
				own = append(own, args[i+1])
				i++
			}
			continue
		}
		if strings.HasPrefix(t, "-") || strings.HasPrefix(t, "+") {
			flags := t[1:]
			if strings.ContainsRune(flags, 's') {
				readsStdin = true
			}
			if strings.ContainsAny(flags, "oO") && i+1 < len(args) {
				if v, _ := args[i+1].text(); strings.Contains(strings.ToLower(v), "glob") {
					s.sec.dotglob = true
				}
				i++
			}
			if strings.ContainsRune(flags, 'c') {
				cmdIdx = -2
			}
			continue
		}
		scriptIdx = i
		break
	}
	s.checkArgs(name, own)
	switch {
	case cmdIdx >= 0:
		s.evalString(args[cmdIdx:cmdIdx+1], name+" -c")
		return
	case cmdIdx == -2:
		return // `bash -c` without a string: syntax error at runtime
	case scriptIdx >= 0 && !readsStdin:
		if procSubstArg(args[scriptIdx]) {
			s.c.deny(RuleDynamicShell, fmt.Sprintf("running `%s` on a process substitution executes code that cannot be checked; blocked to be safe.", name))
			return
		}
		s.checkArgs(name, args[scriptIdx:])
		return
	}
	s.checkArgs(name, args)
	if stdin == nil || stdin.kind == stdinFile {
		return // interactive shell, or a script file on disk
	}
	if stdin.kind == stdinStatic && !stdin.decode {
		for _, t := range stdin.texts {
			s.recurseText(t, false)
		}
		return
	}
	s.c.deny(RuleDynamicShell, fmt.Sprintf("piping text that is only known at runtime into `%s` executes code that cannot be checked; blocked to be safe. Download or write the script to a file, review it, then run it.", name))
}

func procSubstArg(a cmdArg) bool {
	for _, alt := range a.alts {
		if strings.HasPrefix(plain(alt), "/dev/fd/") {
			return true
		}
	}
	return false
}

func (s *shellEval) printenvCommand(args []cmdArg) {
	var names []cmdArg
	for _, a := range args {
		if t, ok := a.text(); ok && strings.HasPrefix(t, "-") {
			continue
		}
		names = append(names, a)
	}
	if len(names) == 0 {
		s.c.deny(RuleEnvExposure, envDumpReason)
		return
	}
	for _, a := range names {
		if a.hasDynamic() {
			s.c.deny(RuleEnvExposure, "printenv of a variable chosen at runtime could expose a secret environment variable; name the variable explicitly.")
			continue
		}
		for _, alt := range a.alts {
			s.checkEnvName(plain(alt))
		}
	}
}

// checkRecursiveCopy asks before copying/archiving a directory that holds
// the project root, the home directory or an anchored secret location.
func (s *shellEval) checkRecursiveCopy(name string, args []cmdArg) {
	recursive := name == "rsync" || name == "7z" || name == "7za"
	for _, a := range args {
		t, ok := a.text()
		if !ok {
			continue
		}
		switch {
		case name == "tar" && !strings.HasPrefix(t, "--") && strings.ContainsAny(strings.TrimPrefix(t, "-"), "cru") && !strings.ContainsAny(t, "./"):
			recursive = true
		case name == "tar" && (t == "--create" || t == "--append"):
			recursive = true
		case (name == "cp" || name == "zip" || name == "scp") && strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsAny(t, "rRa"):
			recursive = true
		case name == "diff" && (t == "-x" || t == "-X" || strings.HasPrefix(t, "--exclude")):
			return // the agent is already excluding files
		case name == "diff" && strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsRune(t, 'r'):
			recursive = true
		case t == "--recursive" || t == "--archive":
			recursive = true
		}
	}
	if !recursive {
		return
	}
	for _, a := range args {
		for _, alt := range a.alts {
			t := plain(alt)
			if strings.HasPrefix(t, "-") || isDynamic(alt) {
				continue
			}
			if m, ok := s.sec.containsSecretRoot(alt); ok && name == "diff" {
				s.c.ask(RuleSecretDir, fmt.Sprintf("`diff -r` over %q would print the content of secret files (secrets.files: %q), e.g. with -N or when they differ. Compare only the directories you need, or exclude them (-x '.env*').", display(t), m.pattern))
				return
			} else if ok {
				s.c.ask(RuleSecretDir, fmt.Sprintf("`%s` would copy %q recursively, which includes secret files (secrets.files: %q). Exclude them explicitly or copy only the directories you need.", name, display(t), m.pattern))
				return
			}
		}
	}
}
