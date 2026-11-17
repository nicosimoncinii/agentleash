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
		s.exrDynamicName(nameAlt, args)
		return
	}
	rest := args[1:]
	s.exrCommonChecks(name, rest, stdin)
	if inner, own, ok := s.unwrap(name, rest, stdin); ok {
		s.checkArgs(name, own)
		if inner != nil {
			s.processCommand(inner, stdin)
		}
		return
	}
	if s.exrSpecialCommand(name, rest, stdin) {
		return
	}
	s.exrArgumentChecks(name, rest, stdin)
}

// exrDynamicName handles a command whose name is only known at runtime
// ($SHELL, "$EDITOR", ...): it is treated like a reader, and like a shell if
// it is given -c TEXT.
func (s *shellEval) exrDynamicName(nameAlt string, args []cmdArg) {
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
}

// exrCommonChecks runs the checks that apply to every named command before
// wrappers are unwrapped: stdin scripts, credential printing, mention-mode
// touches and interactive prompts.
func (s *shellEval) exrCommonChecks(name string, rest []cmdArg, stdin *stdinInfo) {
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
}

// exrSpecialCommand dispatches commands with dedicated handling (shells,
// eval, find, env dumpers, ...). It reports whether the analysis of the
// command is complete; false means the generic argument checks still apply.
func (s *shellEval) exrSpecialCommand(name string, rest []cmdArg, stdin *stdinInfo) bool {
	switch {
	case shells[name]:
		s.shellCommand(name, rest, stdin)
		return true
	case name == "busybox" || name == "toybox":
		s.processCommand(rest, stdin)
		return true
	case name == "eval":
		s.evalString(rest, "eval")
		return true
	case name == "alias":
		s.exrAliasCommand(rest)
		return true
	case name == "trap":
		if len(rest) > 0 {
			s.evalString(rest[:1], "trap")
		}
		return true
	case name == "pwsh" || name == "powershell" || name == "cmd":
		s.exrPwshCommand(name, rest)
		return true
	case name == "find":
		s.findCommand(rest, stdin)
		return true
	case name == "xargs":
		s.xargsCommand(rest, stdin)
		return true
	case name == "docker" || name == "podman" || name == "nerdctl":
		s.containerEnv(rest)
		s.composeConfig(name, rest)
	case name == "docker-compose" || name == "podman-compose":
		s.composeConfig(name, rest)
	case name == "printenv":
		s.printenvCommand(rest)
		return true
	case name == "set":
		if len(rest) == 0 {
			s.c.deny(RuleEnvExposure, envDumpReason)
		}
		return true
	case name == "ps":
		return s.exrPsCommand(rest)
	case name == "systemctl" || name == "tmux" || name == "launchctl":
		return s.exrEnvServiceCommand(name, rest)
	case name == "source" || name == ".":
		s.exrSourceCommand(rest, stdin)
	}
	return false
}

// exrAliasCommand analyses the value of every NAME=VALUE alias definition.
func (s *shellEval) exrAliasCommand(rest []cmdArg) {
	for _, a := range rest {
		t := a.textOr()
		if i := strings.IndexByte(t, '='); i > 0 {
			s.recurseText(t[i+1:], false)
		}
	}
}

// exrPwshCommand checks the arguments of pwsh/powershell/cmd and analyses
// the command line with the PowerShell evaluator.
func (s *shellEval) exrPwshCommand(name string, rest []cmdArg) {
	s.checkArgs(name, rest)
	var parts []string
	for _, a := range rest {
		parts = append(parts, quotePS(a.textOr()))
	}
	pe := newPwshEval(s.e, s.sec, s.c, s.depth+1)
	pe.req = s.req
	pe.run(name + " " + strings.Join(parts, " "))
}

// exrPsCommand denies ps options that print process environments. It
// reports whether it denied (the analysis of the command is then complete).
func (s *shellEval) exrPsCommand(rest []cmdArg) bool {
	for _, a := range rest {
		t := a.textOr()
		if !strings.HasPrefix(t, "-") && strings.ContainsRune(t, 'e') {
			s.c.deny(RuleEnvExposure, "`ps` with the BSD `e` option prints the environment of processes, which contains secrets. Use `ps aux` without `e`.")
			return true
		}
		if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsRune(t, 'E') {
			s.c.deny(RuleEnvExposure, "`ps -E` prints the environment of processes, which contains secrets. Use `ps -ef` or `ps aux` instead.")
			return true
		}
	}
	return false
}

// exrEnvServiceCommand handles systemctl/tmux/launchctl subcommands that
// dump or print environment variables. It reports whether the analysis of
// the command is complete.
func (s *shellEval) exrEnvServiceCommand(name string, rest []cmdArg) bool {
	for _, a := range rest {
		t := a.textOr()
		if t == "show-environment" || t == "showenv" || (name == "launchctl" && t == "export") {
			s.c.deny(RuleEnvExposure, envDumpReason)
			return true
		}
	}
	if name == "launchctl" && len(rest) > 0 && rest[0].textOr() == "getenv" {
		s.printenvCommand(rest[1:]) // launchctl getenv NAME prints one variable
		return true
	}
	return false
}

// exrSourceCommand checks `source`/`.`: a runtime-built script path or
// dynamic stdin is denied, static stdin text is analysed.
func (s *shellEval) exrSourceCommand(rest []cmdArg, stdin *stdinInfo) {
	if len(rest) == 0 {
		return
	}
	if rest[0].hasDynamic() || strings.HasPrefix(rest[0].textOr(), "/dev/fd/") {
		s.c.deny(RuleDynamicShell, "sourcing a script whose content or path is only known at runtime cannot be checked; blocked to be safe.")
	}
	t := rest[0].textOr()
	fromStdin := t == "/dev/stdin" || t == "-"
	staticStdin := stdin != nil && stdin.kind == stdinStatic
	if fromStdin && !staticStdin {
		s.c.deny(RuleDynamicShell, "sourcing code from stdin cannot be checked; blocked to be safe.")
	} else if staticStdin && fromStdin {
		for _, txt := range stdin.texts {
			s.recurseText(txt, false)
		}
	}
}

// exrArgumentChecks runs the generic per-command checks: interpreters and
// role-aware argument path checks, then the tool-specific rules.
func (s *shellEval) exrArgumentChecks(name string, rest []cmdArg, stdin *stdinInfo) {
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
	s.exrToolChecks(name, rest, stdin)
}

// exrToolChecks applies the tool-specific rules (file lists, sed, sqlite3,
// recursive copies and searches, tool-expanded globs) in a fixed order.
func (s *shellEval) exrToolChecks(name string, rest []cmdArg, stdin *stdinInfo) {
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
	sc, excluded := exrScanSearchArgs(name, args)
	if excluded || !sc.recursive || !sc.hiddenToo || sc.pattern == "" {
		return
	}
	if s.exrSecretEnvGlob(sc.pattern) == "" {
		return
	}
	dirs := sc.dirs
	if len(dirs) == 0 {
		dirs = []cmdArg{litArg(".")}
	}
	for _, d := range dirs {
		for _, alt := range d.alts {
			if m, ok := s.sec.containsSecretRoot(alt); ok {
				s.c.ask(RuleSecretSearch, fmt.Sprintf("a recursive `%s` for %q over %q would also print matching lines from secret files such as %q (the variable values). Exclude them (e.g. --exclude='.env*') or search only source directories.", name, display(sc.pattern), display(plain(alt)), m.pattern))
				return
			}
		}
	}
}

// exrSearchScan is the parsed command line of a grep-like search.
type exrSearchScan struct {
	name            string
	pattern         string
	dirs            []cmdArg
	explicitPattern bool
	recursive       bool
	hiddenToo       bool
}

// exrIsGrep reports whether name is one of the grep family.
func exrIsGrep(name string) bool {
	return name == "grep" || name == "egrep" || name == "fgrep"
}

// exrScanSearchArgs parses a search command line. excluded is true when the
// agent is already excluding files (--exclude, -g, --glob, --iglob).
func exrScanSearchArgs(name string, args []cmdArg) (sc exrSearchScan, excluded bool) {
	sc = exrSearchScan{name: name, recursive: !exrIsGrep(name), hiddenToo: exrIsGrep(name) || name == "ack"}
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		if !ok {
			continue
		}
		if t == "-e" || t == "--regexp" {
			if i+1 < len(args) {
				sc.pattern, _ = args[i+1].text()
				sc.explicitPattern = true
				i++
			}
			continue
		}
		handled, stop := sc.exrOption(t)
		if stop {
			return sc, true
		}
		if handled {
			continue
		}
		if sc.pattern == "" && !sc.explicitPattern {
			sc.pattern = t
			sc.explicitPattern = true
			continue
		}
		sc.dirs = append(sc.dirs, args[i])
	}
	return sc, false
}

// exrOption interprets an option word (other than -e/--regexp) of a search
// command. handled is false for operands; excluded is true for options that
// exclude files.
func (sc *exrSearchScan) exrOption(t string) (handled, excluded bool) {
	switch {
	case strings.HasPrefix(t, "--exclude") || t == "-g" || strings.HasPrefix(t, "--glob") || strings.HasPrefix(t, "--iglob"):
		return true, true // the agent is already excluding files
	case t == "--recursive" || t == "--dereference-recursive":
		sc.recursive = true
	case t == "--hidden" || t == "--no-ignore" || strings.HasPrefix(t, "-uu"):
		sc.hiddenToo = true
	case strings.HasPrefix(t, "--"):
	case strings.HasPrefix(t, "-") && len(t) > 1:
		if strings.ContainsAny(t[1:], "rR") && exrIsGrep(sc.name) {
			sc.recursive = true
		}
	default:
		return false, false
	}
	return true, false
}

// exrSecretEnvGlob returns the secret env pattern matched by the first
// matching identifier in a search pattern, or "".
func (s *shellEval) exrSecretEnvGlob(pattern string) string {
	for _, tok := range identRe.FindAllString(pattern, -1) {
		if g, ok := s.sec.envMatch(tok); ok {
			return g
		}
	}
	return ""
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
			s.exrCheckArgCandidate(name, alt, cand, dyn, dirRule)
		}
		if !dyn && !interpreters[name] {
			s.exrCheckEmbeddedCommands(name, alt)
		}
	}
}

// exrCheckArgCandidate applies the secret-path rules to one path-like
// candidate cand extracted from the argument alternative alt.
func (s *shellEval) exrCheckArgCandidate(name, alt, cand string, dyn, dirRule bool) {
	m, ok := s.sec.checkPath(cand)
	if !ok {
		if dirRule && !dyn && (s.sec.touch || !metadataOnly[name]) && !dirNavigation[name] {
			s.exrCheckSecretDir(name, cand)
		}
		return
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

// exrCheckSecretDir denies a directory holding secrets (rsync -a ~/.ssh/
// ...). Mention mode: removing or moving an ancestor of the project
// (rm -rf ., rm -rf ..) also counts.
func (s *shellEval) exrCheckSecretDir(name, cand string) {
	if dm, ok := s.sec.dirHolds(cand, s.sec.touch && destructiveCmds[name]); ok {
		s.c.deny(RuleSecretFile+":"+dm.pattern, dirReason(dm, verbFor(name), s.sec))
	}
}

// exrCheckEmbeddedCommands re-parses the pieces of an argument that look
// like shell commands (--exec='cat .env', core.pager=...).
func (s *shellEval) exrCheckEmbeddedCommands(name, alt string) {
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
			s.exrCheckCommandStringPaths(name, t)
		}
	}
}

// exrCheckCommandStringPaths denies literal secret paths inside a command
// string given to an editor or reader (vim -c ':r .env').
func (s *shellEval) exrCheckCommandStringPaths(name, t string) {
	for _, tok := range strings.Fields(t) {
		if m, ok := s.sec.checkPath(escapeLit(tok)); ok && !m.glob {
			s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, verbFor(name), s.sec))
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
	// --grep=.env, --format=%H are data unless optionValue says "path";
	// only the value of such options is split further.
	split := alt
	if v, ok := optionValue(alt); ok {
		exrAddCandidate(&out, v)
		split = v
	} else if strings.HasPrefix(alt, "--") && strings.IndexByte(alt, '=') > 0 {
		split = ""
	}
	exrAddSplitPieces(&out, split)
	// Worklist: a piece found here is split again, so "-sd@.env" gives
	// "@.env" and then ".env".
	for i := 0; i < len(out) && i < 32; i++ {
		exrExpandCandidate(&out, out[i])
	}
	return out
}

// exrAddCandidate appends a non-empty candidate that is not yet in out.
func exrAddCandidate(out *[]string, s string) {
	if s != "" && !containsStr(*out, s) {
		*out = append(*out, s)
	}
}

// exrAddSplitPieces adds the pieces of split on ':' and ',', and the value
// after '=' of each piece.
func exrAddSplitPieces(out *[]string, split string) {
	for _, sep := range []byte{':', ','} {
		if strings.IndexByte(split, sep) < 0 {
			continue
		}
		for _, p := range splitOn(split, sep) {
			exrAddCandidate(out, p)
			if i := strings.IndexByte(p, '='); i >= 0 {
				exrAddCandidate(out, p[i+1:])
			}
		}
	}
}

// exrExpandCandidate adds the path-like pieces hidden in candidate c:
// curl-style @file, attached short-option values, redirection prefixes and
// name@file.
func exrExpandCandidate(out *[]string, c string) {
	if strings.HasPrefix(c, "@") {
		exrAddCandidate(out, c[1:])
	}
	if len(c) > 2 && c[0] == '-' && c[1] != '-' && isAlpha(c[1]) {
		exrAddCandidate(out, c[2:])
		// value attached after a short-option cluster: -sd@.env, -xf.env
		k := 1
		for k < len(c) && isAlpha(c[k]) {
			k++
		}
		if k > 2 && k < len(c) {
			exrAddCandidate(out, c[k:])
		}
	}
	if strings.HasPrefix(c, "<") || strings.HasPrefix(c, ">") {
		exrAddCandidate(out, strings.TrimLeft(c, "<>"))
	}
	// name@file (curl --data-urlencode, httpie f@file, f:=@file)
	if j := strings.IndexByte(c, '@'); j > 0 && !strings.HasPrefix(c, "-") {
		exrAddCandidate(out, c[j+1:])
	}
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
	sc := s.exrScanShellArgs(args)
	s.checkArgs(name, sc.own)
	switch {
	case sc.cmdIdx >= 0:
		s.evalString(args[sc.cmdIdx:sc.cmdIdx+1], name+" -c")
		return
	case sc.cmdIdx == -2:
		return // `bash -c` without a string: syntax error at runtime
	case sc.scriptIdx >= 0 && !sc.readsStdin:
		if procSubstArg(args[sc.scriptIdx]) {
			s.c.deny(RuleDynamicShell, fmt.Sprintf("running `%s` on a process substitution executes code that cannot be checked; blocked to be safe.", name))
			return
		}
		s.checkArgs(name, args[sc.scriptIdx:])
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

// exrShellScan is the parsed command line of a shell invocation. cmdIdx is
// the index of the -c string, -1 when there is no -c, or -2 when -c was
// given without a string.
type exrShellScan struct {
	cmdIdx     int
	scriptIdx  int
	readsStdin bool
	own        []cmdArg
}

// exrScanShellArgs parses the options of a shell invocation up to the -c
// string, the script operand or "--"/"-".
func (s *shellEval) exrScanShellArgs(args []cmdArg) exrShellScan {
	sc := exrShellScan{cmdIdx: -1, scriptIdx: -1}
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		if sc.cmdIdx == -2 {
			sc.cmdIdx = i
			break
		}
		if !ok {
			sc.scriptIdx = i
			break
		}
		if t == "--" || t == "-" {
			sc.exrEndOfOptions(t, i, len(args))
			break
		}
		if strings.HasPrefix(t, "--") {
			i = sc.exrLongOption(args, i, t)
			continue
		}
		if strings.HasPrefix(t, "-") || strings.HasPrefix(t, "+") {
			i = s.exrShellShortFlags(&sc, args, i, t)
			continue
		}
		sc.scriptIdx = i
		break
	}
	return sc
}

// exrEndOfOptions records "--" or "-" at index i of n arguments: the next
// argument, if any, is the script, and "-" reads stdin.
func (sc *exrShellScan) exrEndOfOptions(t string, i, n int) {
	if t == "-" {
		sc.readsStdin = true
	}
	if i+1 < n {
		sc.scriptIdx = i + 1
	}
}

// exrLongOption records a long shell option (and the value of --rcfile,
// --init-file, --init-command) as the shell's own arguments. It returns the
// index of the last argument consumed.
func (sc *exrShellScan) exrLongOption(args []cmdArg, i int, t string) int {
	sc.own = append(sc.own, args[i])
	if (t == "--rcfile" || t == "--init-file" || t == "--init-command") && i+1 < len(args) {
		sc.own = append(sc.own, args[i+1])
		i++
	}
	return i
}

// exrShellShortFlags interprets a -xyz / +xyz flag cluster: s reads stdin,
// o/O take an option name (enabling dotglob for *glob*), c takes a command
// string. It returns the index of the last argument consumed.
func (s *shellEval) exrShellShortFlags(sc *exrShellScan, args []cmdArg, i int, t string) int {
	flags := t[1:]
	if strings.ContainsRune(flags, 's') {
		sc.readsStdin = true
	}
	if strings.ContainsAny(flags, "oO") && i+1 < len(args) {
		if v, _ := args[i+1].text(); strings.Contains(strings.ToLower(v), "glob") {
			s.sec.dotglob = true
		}
		i++
	}
	if strings.ContainsRune(flags, 'c') {
		sc.cmdIdx = -2
	}
	return i
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
