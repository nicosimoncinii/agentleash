package engine

import (
	"fmt"
	"strings"
)

// wrapSpec describes a command that runs another command given as its
// remaining arguments (sudo, nohup, timeout, ...).
type wrapSpec struct {
	short      string          // short options that take a value
	long       map[string]bool // long options that take a separate value
	positional int             // positional args before the inner command
	noExec     string          // short options meaning "no command is run"
}

var wrapSpecs = map[string]wrapSpec{
	"sudo":        {short: "ugCDhprtTU", long: set("--user", "--group", "--chdir", "--host", "--prompt", "--role", "--type", "--close-from", "--other-user", "--command-timeout"), noExec: "elvkK"},
	"doas":        {short: "uC"},
	"pkexec":      {long: set("--user")},
	"nohup":       {},
	"setsid":      {},
	"unbuffer":    {},
	"nocorrect":   {},
	"noglob":      {},
	"chronic":     {},
	"torsocks":    {},
	"proxychains": {short: "f"},
	"caffeinate":  {short: "wt"},
	"catchsegv":   {},
	"stdbuf":      {short: "ioe", long: set("--input", "--output", "--error")},
	"time":        {short: "fo", long: set("--format", "--output")},
	"nice":        {short: "n", long: set("--adjustment")},
	"ionice":      {short: "cnpPtu", long: set("--class", "--classdata", "--pid", "--pgid", "--uid")},
	"timeout":     {short: "sk", long: set("--signal", "--kill-after"), positional: 1},
	"command":     {noExec: "vV"},
	"builtin":     {},
	"exec":        {short: "a"},
	"chroot":      {long: set("--userspec", "--groups"), positional: 1},
	"strace":      {short: "oepsuEaIbXP"},
	"ltrace":      {short: "oepsuEaIn"},
	"firejail":    {},
	"systemd-run": {short: "pEu", long: set("--property", "--setenv", "--uid", "--gid", "--unit", "--working-directory")},
	"doppler":     {},
	"then":        {},
	"do":          {},
	"else":        {},
}

// unwrap returns the inner command of a wrapper. own are the wrapper's own
// arguments (still subject to the path rules). ok is false when name is not
// a wrapper.
func (s *shellEval) unwrap(name string, args []cmdArg, _ *stdinInfo) (inner, own []cmdArg, ok bool) {
	switch name {
	case "env":
		return s.unwrapEnv(args)
	case "dotenv", "dotenv-cli", "dotenvx", "direnv", "op", "doppler", "infisical", "envchain", "aws-vault", "chamber":
		if s.dotenvPrints(name, args) {
			return nil, args, true
		}
		if name == "dotenv-cli" {
			name = "dotenv"
		}
		return unwrapSecretRunner(name, args)
	case "su", "runuser", "script", "sg", "flock":
		return s.unwrapStringCmd(name, args)
	case "watch":
		return s.unwrapWatch(args)
	}
	if rs, ok := runnerSpecs[name]; ok {
		return s.unwrapRunner(name, rs, args)
	}
	spec, ok := wrapSpecs[name]
	if !ok {
		return nil, nil, false
	}
	i := 0
loop:
	for i < len(args) {
		t, static := args[i].text()
		switch {
		case !static:
			break loop
		case t == "--":
			i++
			break loop
		case !strings.HasPrefix(t, "-") || t == "-":
			break loop
		case strings.HasPrefix(t, "--"):
			if name == "sudo" && (t == "--edit" || t == "--list" || t == "--validate") {
				return nil, args, true
			}
			if !strings.Contains(t, "=") && spec.long[t] {
				i += 2
				continue
			}
			i++
		default:
			letters := t[1:]
			if spec.noExec != "" && strings.ContainsAny(letters, spec.noExec) {
				return nil, args, true
			}
			consumed := 1
			for j, l := range letters {
				if strings.ContainsRune(spec.short, l) {
					if j == len(letters)-1 {
						consumed = 2
					}
					break
				}
			}
			i += consumed
		}
	}
	i += spec.positional
	if i > len(args) {
		i = len(args)
	}
	if i < len(args) {
		inner = args[i:]
	}
	return inner, args[:i], true
}

// secretRunnerSubs are the subcommands of secret managers that run a
// command with secrets injected into its environment.
var secretRunnerSubs = set("run", "exec")

// unwrapSecretRunner handles dotenv, direnv exec, op run, doppler run,
// infisical run, aws-vault exec, ...: the inner command runs with secrets in
// its environment, so it is analysed like any other command (printenv in it
// is an env dump).
func unwrapSecretRunner(name string, args []cmdArg) (inner, own []cmdArg, ok bool) {
	for i, a := range args {
		if t, ok := a.text(); ok && t == "--" {
			return args[i+1:], args[:i], true
		}
	}
	i := 0
	if name == "dotenv" {
		// python-dotenv: dotenv [-f FILE] run CMD
		for i < len(args) {
			t, ok := args[i].text()
			if !ok || !strings.HasPrefix(t, "-") {
				break
			}
			if t == "-f" || t == "--file" || t == "-e" || t == "-v" || t == "-c" {
				i++
			}
			i++
		}
		if i < len(args) && args[i].textOr() == "run" {
			i++
		} else {
			i = 0
		}
	}
	if name != "dotenv" && name != "envchain" {
		// skip to the run/exec subcommand
		for i < len(args) {
			t, _ := args[i].text()
			i++
			if secretRunnerSubs[t] {
				break
			}
		}
		if name == "direnv" || name == "aws-vault" || name == "envchain" || name == "chamber" {
			i++ // direnv exec DIR, aws-vault exec PROFILE
		}
	}
	for i < len(args) {
		t, ok := args[i].text()
		if !ok || !strings.HasPrefix(t, "-") {
			break
		}
		i++
	}
	if i >= len(args) {
		return nil, args, true
	}
	return args[i:], args[:i], true
}

// containerEnv: `docker run -e NAME` (no value) forwards the variable from
// the host environment into the container.
func (s *shellEval) containerEnv(args []cmdArg) {
	for i, a := range args {
		t, ok := a.text()
		if !ok {
			continue
		}
		var v string
		switch {
		case (t == "-e" || t == "--env") && i+1 < len(args):
			v, _ = args[i+1].text()
		case strings.HasPrefix(t, "--env="):
			v = strings.TrimPrefix(t, "--env=")
		case strings.HasPrefix(t, "-e") && len(t) > 2 && !strings.HasPrefix(t, "--"):
			v = t[2:]
		default:
			continue
		}
		if v != "" && !strings.Contains(v, "=") {
			s.checkEnvName(v)
		}
	}
}

// unwrapEnv handles `env [opts] [NAME=VALUE...] [cmd args...]`. Without a
// command, env prints the environment.
func (s *shellEval) unwrapEnv(args []cmdArg) (inner, own []cmdArg, ok bool) {
	i := 0
	var split []cmdArg
	for i < len(args) {
		t, static := args[i].text()
		if !static {
			break
		}
		if t == "--" {
			i++
			break
		}
		if t == "-" || t == "-i" || t == "--ignore-environment" || t == "-0" || t == "--null" || t == "-v" || t == "--debug" {
			i++
			continue
		}
		if t == "-S" || t == "--split-string" {
			if i+1 < len(args) {
				split = append(split, args[i+1])
			}
			i += 2
			continue
		}
		if strings.HasPrefix(t, "--split-string=") {
			split = append(split, litArg(strings.TrimPrefix(t, "--split-string=")))
			i++
			continue
		}
		if strings.HasPrefix(t, "-S") && len(t) > 2 {
			split = append(split, litArg(t[2:]))
			i++
			continue
		}
		if t == "-u" || t == "--unset" || t == "-C" || t == "--chdir" || t == "-P" {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		if eq := strings.IndexByte(t, '='); eq > 0 && isIdent(t[:eq]) {
			s.checkAssignValue(t[:eq], []string{escapeLit(t[eq+1:])}, true)
			i++
			continue
		}
		break
	}
	if i > len(args) {
		i = len(args)
	}
	own = args[:i]
	if len(split) > 0 {
		s.evalString(append(split, args[i:]...), "env -S")
		return nil, own, true
	}
	if i >= len(args) {
		s.c.deny(RuleEnvExposure, envDumpReason)
		return nil, own, true
	}
	return args[i:], own, true
}

// unwrapStringCmd handles commands whose -c option is shell text.
func (s *shellEval) unwrapStringCmd(name string, args []cmdArg) (inner, own []cmdArg, ok bool) {
	for i, a := range args {
		t, static := a.text()
		if !static {
			continue
		}
		switch {
		case (t == "-c" || t == "--command") && i+1 < len(args):
			s.evalString(args[i+1:i+2], name+" -c")
			return nil, append(append([]cmdArg(nil), args[:i]...), args[i+2:]...), true
		case strings.HasPrefix(t, "--command="):
			s.recurseText(strings.TrimPrefix(t, "--command="), false)
			return nil, args, true
		}
	}
	switch name {
	case "sg":
		if len(args) > 1 {
			return args[1:], args[:1], true
		}
	case "flock":
		// flock [opts] FILE CMD...
		for i, a := range args {
			t, static := a.text()
			if static && strings.HasPrefix(t, "-") {
				continue
			}
			if i+1 < len(args) {
				return args[i+1:], args[:i+1], true
			}
			break
		}
	}
	return nil, args, true
}

// unwrapWatch handles `watch [opts] command...`: the command is joined and
// run through `sh -c` unless -x/--exec is given.
func (s *shellEval) unwrapWatch(args []cmdArg) (inner, own []cmdArg, ok bool) {
	i := 0
	exec := false
	for i < len(args) {
		t, static := args[i].text()
		if !static || !strings.HasPrefix(t, "-") {
			break
		}
		if t == "--" {
			i++
			break
		}
		if t == "-x" || t == "--exec" {
			exec = true
		}
		if t == "-n" || t == "--interval" || t == "-q" || t == "--equexit" {
			i += 2
			continue
		}
		i++
	}
	if i > len(args) {
		i = len(args)
	}
	if i >= len(args) {
		return nil, args, true
	}
	if exec {
		return args[i:], args[:i], true
	}
	s.evalString(args[i:], "watch")
	return nil, args[:i], true
}

// xargsCommand handles `producer | xargs [opts] cmd args`.
func (s *shellEval) xargsCommand(args []cmdArg, stdin *stdinInfo) {
	i := 0
	replace := ""
	fromFile := false
	var own []cmdArg
	for i < len(args) {
		t, static := args[i].text()
		if !static || !strings.HasPrefix(t, "-") || t == "-" {
			break
		}
		if t == "--" {
			i++
			break
		}
		switch {
		case t == "-I" && i+1 < len(args):
			replace, _ = args[i+1].text()
			own = append(own, args[i])
			i += 2
			continue
		case strings.HasPrefix(t, "-I"):
			replace = t[2:]
		case t == "-i" || t == "--replace":
			replace = "{}"
		case strings.HasPrefix(t, "-i"):
			replace = t[2:]
		case strings.HasPrefix(t, "--replace="):
			replace = strings.TrimPrefix(t, "--replace=")
		case t == "-a" || t == "--arg-file":
			fromFile = true
			own = append(own, args[i])
			if i+1 < len(args) {
				own = append(own, args[i+1])
			}
			i += 2
			continue
		case strings.HasPrefix(t, "--arg-file=") || (strings.HasPrefix(t, "-a") && len(t) > 2):
			fromFile = true
		case t == "-n" || t == "-L" || t == "-P" || t == "-s" || t == "-d" || t == "-E" || t == "--max-args" || t == "--max-procs" || t == "--delimiter" || t == "--max-lines" || t == "--max-chars" || t == "--eof":
			own = append(own, args[i])
			i += 2
			continue
		}
		own = append(own, args[i])
		i++
	}
	s.checkArgs("xargs", own)
	if i > len(args) {
		i = len(args)
	}
	inner := append([]cmdArg(nil), args[i:]...)
	if len(inner) == 0 {
		inner = []cmdArg{litArg("echo")}
	}
	var stdinArgs []cmdArg
	if fromFile {
		stdinArgs = []cmdArg{dynArg()}
	} else {
		stdinArgs = stdinWords(stdin)
	}
	if replace != "" {
		var all []string
		for _, sa := range stdinArgs {
			all = append(all, sa.alts...)
		}
		rep := escapeLit(replace)
		for k, a := range inner {
			var alts []string
			for _, alt := range a.alts {
				if !strings.Contains(alt, rep) {
					alts = append(alts, alt)
					continue
				}
				for _, v := range all {
					alts = append(alts, strings.ReplaceAll(alt, rep, v))
				}
			}
			inner[k] = cmdArg{alts: dedupe(alts)}
		}
		// The inner command may be a shell whose -c text embeds the
		// replacement: make sure it is still analysed.
	} else {
		inner = append(inner, stdinArgs...)
	}
	s.processCommand(inner, nil)
}

// stdinWords returns the words a pipeline producer writes, as arguments:
// static text split on whitespace, find/git ls-files globs, or a runtime
// value when the producer is unknown (ls, cat FILE, a decoder, a terminal).
func stdinWords(stdin *stdinInfo) []cmdArg {
	var out []cmdArg
	switch {
	case stdin == nil || stdin.kind == stdinUnknown || stdin.kind == stdinFile || stdin.decode:
		return []cmdArg{dynArg()}
	case stdin.kind == stdinGlob:
		return []cmdArg{{alts: stdin.texts}}
	}
	for _, t := range stdin.texts {
		for _, f := range strings.Fields(t) {
			out = append(out, litArg(strings.Trim(f, `"'`)))
		}
	}
	if len(out) > 64 {
		return []cmdArg{dynArg()}
	}
	return out
}

// cpioOutMode reports whether a cpio short-option cluster ("-o", "-vo",
// "-pdm") selects copy-out or pass-through mode. Letters after an option that
// takes a value (-H newc, -Ffile, ...) are that value, not options.
func cpioOutMode(t string) bool {
	for _, c := range t[1:] {
		switch {
		case c == 'o' || c == 'p':
			return true
		case strings.ContainsRune("HFOIMCERW", c):
			return false
		}
	}
	return false
}

// checkFileList checks the names an archiver reads from stdin. Static words
// and find/git ls-files globs are checked like xargs input; any other source
// (a file, an unknown producer, a terminal) is an opaque list and is denied
// with a reason that says where the list comes from.
func (s *shellEval) checkFileList(name string, stdin *stdinInfo) {
	if stdin != nil && !stdin.decode && (stdin.kind == stdinStatic || stdin.kind == stdinGlob) {
		s.checkArgs(name, stdinWords(stdin))
		return
	}
	src := "stdin"
	switch {
	case stdin != nil && stdin.kind == stdinFile && stdin.path != "":
		src = display(stdin.path)
	case stdin != nil && stdin.kind == stdinFile:
		src = "a redirected file"
	case stdin != nil:
		src = "the output of the previous pipeline command"
	}
	s.c.deny(RuleDynamicPath, fmt.Sprintf("`%s` reads the list of files to archive from %s, which agentleash cannot inspect; it could include secret files. Name the files on the command line, or produce the list with `find ... -name PATTERN` or `git ls-files PATHSPEC` in the same pipeline.", name, src))
}

// readsFileList reports whether an archiver takes the list of files to read
// from stdin: cpio -o/-p, tar -T -/--files-from=-, zip -@/--names-stdin.
func readsFileList(name string, args []cmdArg) bool {
	isStdin := func(t string) bool { return t == "-" || t == "/dev/stdin" }
	for i, a := range args {
		t, ok := a.text()
		if !ok {
			continue
		}
		next := ""
		if i+1 < len(args) {
			next, _ = args[i+1].text()
		}
		short := strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && len(t) > 1
		switch name {
		case "cpio":
			if t == "--create" || t == "--pass-through" || (short && cpioOutMode(t)) {
				return true
			}
		case "tar":
			if (t == "--files-from" || (short && strings.HasSuffix(t, "T"))) && isStdin(next) {
				return true
			}
			if t == "-T-" || (strings.HasPrefix(t, "--files-from=") && isStdin(strings.TrimPrefix(t, "--files-from="))) {
				return true
			}
		case "zip":
			if t == "--names-stdin" || (short && strings.Contains(t, "@")) {
				return true
			}
		}
	}
	return false
}

// findCommand handles find, including -exec/-execdir/-ok.
func (s *shellEval) findCommand(args []cmdArg, _ *stdinInfo) {
	argv := make([][]string, 0, len(args)+1)
	argv = append(argv, []string{"find"})
	for _, a := range args {
		argv = append(argv, a.alts)
	}
	outputs := s.findOutputs(argv)
	starts, _ := findStarts(args)
	s.checkArgs("find", starts)
	for i := 0; i < len(args); i++ {
		t, _ := args[i].text()
		switch t {
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			var inner []cmdArg
			for ; j < len(args); j++ {
				e, _ := args[j].text()
				if e == ";" || e == "+" {
					break
				}
				var alts []string
				for _, alt := range args[j].alts {
					if strings.Contains(alt, "{}") {
						for _, o := range outputs {
							alts = append(alts, strings.ReplaceAll(alt, "{}", o))
						}
						continue
					}
					alts = append(alts, alt)
				}
				inner = append(inner, cmdArg{alts: dedupe(alts)})
			}
			s.processCommand(inner, nil)
			i = j
		case "-delete":
			if s.sec.touch {
				// Mention mode: -delete removes every path find prints.
				s.checkArg("rm", cmdArg{alts: outputs})
			}
		case "-fprint", "-fprint0", "-fprintf", "-fls", "-files0-from":
			if i+1 < len(args) {
				s.checkArg("find", args[i+1])
				i++
			}
		}
	}
}

func findStarts(args []cmdArg) (starts []cmdArg, rest int) {
	i := 0
	for i < len(args) {
		t, static := args[i].text()
		if static && (t == "-H" || t == "-L" || t == "-P" || strings.HasPrefix(t, "-O")) {
			i++
			continue
		}
		if static && t == "-D" {
			i += 2
			continue
		}
		break
	}
	for i < len(args) {
		t, static := args[i].text()
		if static && (strings.HasPrefix(t, "-") || t == "(" || t == "!" || t == ",") {
			break
		}
		starts = append(starts, args[i])
		i++
	}
	return starts, i
}

// findOutputs approximates the paths find prints, as internal globs.
func (s *shellEval) findOutputs(argv [][]string) []string {
	args := make([]cmdArg, 0, len(argv))
	for _, a := range argv[1:] {
		args = append(args, cmdArg{alts: a})
	}
	starts, rest := findStarts(args)
	if len(starts) == 0 {
		starts = []cmdArg{litArg(".")}
	}
	var names []string
	for i := rest; i < len(args); i++ {
		t, _ := args[i].text()
		if i+1 >= len(args) {
			break
		}
		switch t {
		case "-name", "-iname":
			for _, v := range args[i+1].alts {
				names = append(names, findGlob(v))
			}
		case "-path", "-ipath", "-wholename", "-iwholename":
			for _, v := range args[i+1].alts {
				g := findGlob(v)
				if j := strings.LastIndexByte(g, '/'); j >= 0 {
					g = g[j+1:]
				}
				names = append(names, g)
			}
		case "-regex", "-iregex":
			names = append(names, string(dynStar))
		}
	}
	var out []string
	for _, st := range starts {
		for _, sa := range st.alts {
			base := strings.TrimSuffix(sa, "/")
			if len(names) == 0 {
				out = append(out, base+"/**")
				continue
			}
			for _, n := range names {
				out = append(out, base+"/**/"+n)
			}
		}
	}
	if len(out) > maxAlts {
		return []string{string(dynAny)}
	}
	return dedupe(out)
}

// gitLsFilesOutputs approximates `git ls-files PATHSPEC...`: tracked files
// matching each pathspec at any depth. Without a pathspec the output is
// unknown (nil).
func gitLsFilesOutputs(argv [][]string) []string {
	if len(argv) < 2 {
		return nil
	}
	if t, ok := staticText(argv[1]); !ok || t != "ls-files" {
		return nil
	}
	var out []string
	for _, a := range argv[2:] {
		t, ok := staticText(a)
		if !ok {
			return nil
		}
		if strings.HasPrefix(t, "-") || t == "--" {
			continue
		}
		g := findGlob(a[0])
		out = append(out, g, "**/"+g)
	}
	if len(out) == 0 || len(out) > maxAlts {
		return nil
	}
	return out
}

// findGlob converts a find -name pattern (already quoted by the shell, so
// its wildcards are escaped in internal syntax) into an active glob. find's
// '*' also matches leading dots, hence dynStar.
func findGlob(v string) string {
	p := plain(v)
	if isDynamic(v) {
		return string(dynStar)
	}
	p = strings.ReplaceAll(p, "*", string(dynStar))
	p = strings.ReplaceAll(p, "?", string(dynStar))
	return p
}

// quotePS quotes an argument for re-tokenisation by the PowerShell
// evaluator.
func quotePS(t string) string {
	if t == "" {
		return "''"
	}
	if strings.ContainsAny(t, " \t'\"") {
		return "'" + strings.ReplaceAll(t, "'", "''") + "'"
	}
	return t
}

// runnerSpec describes a package/project runner that executes another
// command: npx, pnpm dlx, poetry run, ... The inner command is analysed like
// any other (npx dotenv-cli -- printenv is an env dump).
type runnerSpec struct {
	subs       map[string]bool // subcommands that run a command (nil: none needed)
	value      map[string]bool // options taking a separate value (before or after the subcommand)
	call       map[string]bool // options whose value is a shell string (npx -c 'cmd')
	shell      map[string]bool // flags that run the joined command through a shell (pnpm dlx -c)
	positional int             // positional arguments before the command (envdir DIR)
}

var (
	npmValue  = set("-p", "--package", "-w", "--workspace", "--prefix", "--cache", "--registry", "--userconfig")
	pyRunOpts = set("-C", "--directory", "-P", "--project", "--env-file", "--with", "--with-requirements",
		"--python", "-p", "--package", "--extra", "--group", "--index", "--index-url", "--extra-index-url",
		"--from", "-e", "--env", "-f", "--procfile", "-d", "--root", "--app-root", "-n", "--name", "--prefix",
		"--spec", "--pip-args", "--venv")
	runnerSpecs = map[string]runnerSpec{
		"npx":     {value: npmValue, call: set("-c", "--call")},
		"pnpx":    {value: npmValue, call: set("-c", "--call")},
		"bunx":    {value: npmValue},
		"npm":     {subs: set("exec", "x"), value: npmValue, call: set("-c", "--call")},
		"pnpm":    {subs: set("dlx", "exec"), value: set("-C", "--dir", "--filter", "-F", "--package", "--workspace-dir"), shell: set("-c", "--shell-mode")},
		"yarn":    {subs: set("dlx", "exec"), value: npmValue},
		"bun":     {subs: set("x"), value: npmValue},
		"poetry":  {subs: set("run"), value: pyRunOpts},
		"pipenv":  {subs: set("run"), value: pyRunOpts},
		"pdm":     {subs: set("run"), value: pyRunOpts},
		"hatch":   {subs: set("run"), value: pyRunOpts},
		"uv":      {subs: set("run"), value: pyRunOpts},
		"uvx":     {value: pyRunOpts},
		"pipx":    {subs: set("run"), value: pyRunOpts},
		"conda":   {subs: set("run"), value: pyRunOpts},
		"foreman": {subs: set("run"), value: pyRunOpts},
		"honcho":  {subs: set("run"), value: pyRunOpts},
		"envdir":  {positional: 1},
	}
)

// unwrapRunner returns the command a runner executes. A runner used without
// a run subcommand (npm install, poetry add) is not a wrapper (ok=false).
func (s *shellEval) unwrapRunner(name string, rs runnerSpec, args []cmdArg) (inner, own []cmdArg, ok bool) {
	i := 0
	subSeen := rs.subs == nil
	shellMode := false
scan:
	for i < len(args) {
		t, static := args[i].text()
		switch {
		case !static:
			break scan
		case t == "--":
			i++
			if subSeen {
				break scan
			}
		case rs.call[t] && i+1 < len(args):
			s.evalString(args[i+1:i+2], name+" "+t)
			return nil, args, true
		case strings.HasPrefix(t, "--call=") && rs.call["--call"]:
			s.recurseText(strings.TrimPrefix(t, "--call="), false)
			return nil, args, true
		case rs.shell[t]:
			shellMode = true
			i++
		case rs.value[t]:
			i += 2
		case strings.HasPrefix(t, "-") && t != "-":
			i++
		case !subSeen:
			if !rs.subs[t] {
				return nil, nil, false
			}
			subSeen = true
			i++
		default:
			break scan
		}
	}
	if !subSeen {
		return nil, nil, false
	}
	i += rs.positional
	if i >= len(args) {
		return nil, args, true
	}
	if shellMode {
		s.evalString(args[i:], name+" -c")
		return nil, args[:i], true
	}
	return args[i:], args[:i], true
}

// implicitEnvFile denies a command that loads and prints a dotenv file
// without naming it on the command line (dotenv list, docker compose
// config). It reports whether file is secret under the policy (and denied).
func (s *shellEval) implicitEnvFile(cmd, file, advice string) bool {
	m, ok := s.sec.checkPath(escapeLit(file))
	if !ok || m.glob {
		return false
	}
	m.path = file
	s.c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, "`"+cmd+"` loading and printing", s.sec)+" "+advice)
	return true
}

// dotenvPrints handles the subcommands of dotenv CLIs that print values of
// ./.env (or of the file given with -f): python-dotenv `list`/`get`,
// dotenvx `get`/`decrypt --stdout`/`keypair`, dotenv-cli `-p NAME`.
// It reports whether the command was fully handled.
func (s *shellEval) dotenvPrints(name string, args []cmdArg) bool {
	if name != "dotenv" && name != "dotenv-cli" && name != "dotenvx" {
		return false
	}
	explicitFile := false
	sub := ""
scan:
	for i := 0; i < len(args); i++ {
		t := args[i].textOr()
		switch {
		case t == "--":
			break scan
		case t == "-f" || t == "--file" || t == "--env-file" || (name != "dotenvx" && t == "-e"):
			explicitFile = true // the file itself is path-checked as an argument
			i++
		case strings.HasPrefix(t, "--file=") || strings.HasPrefix(t, "--env-file="):
			explicitFile = true
		case t == "-p" && name != "dotenvx" && i+1 < len(args):
			// dotenv-cli -p NAME prints one variable loaded from .env
			s.printenvCommand(args[i+1 : i+2])
			s.checkArgs(name, args)
			return true
		case strings.HasPrefix(t, "-"):
			if name != "dotenvx" && (t == "-q" || t == "--quote" || t == "-v" || t == "-c") {
				i++
			}
		default:
			sub = t
			break scan
		}
	}
	file := ".env"
	switch {
	case name == "dotenvx" && sub == "keypair":
		file = ".env.keys"
	case name == "dotenvx" && sub == "decrypt" && hasArg(args, "--stdout"):
	case name == "dotenvx" && sub == "get":
	case name != "dotenvx" && (sub == "list" || sub == "get"):
	default:
		return false
	}
	if !explicitFile { // a file given with -f is path-checked as an argument
		s.implicitEnvFile(name+" "+sub, file, "Read .env.example for the variable names instead.")
	}
	s.checkArgs(name, args)
	return true
}

var (
	composeValueOpts   = set("-f", "--file", "-p", "--project-name", "--profile", "--env-file", "--project-directory", "--ansi", "--progress", "--parallel")
	composeConfigQuiet = set("-q", "--quiet", "--services", "--volumes", "--images", "--profiles", "--networks", "--hash", "--no-interpolate")
	// containerGlobalValueOpts are docker/podman/nerdctl global options that
	// take a separate value (docker --context prod compose config).
	containerGlobalValueOpts = set("-c", "--context", "-H", "--host", "--config", "-l", "--log-level",
		"--tlscacert", "--tlscert", "--tlskey", "--connection", "--url", "--identity", "--root", "--runroot",
		"--storage-driver", "--storage-opt", "--cgroup-manager", "--events-backend", "--runtime", "--tmpdir",
		"--module", "-n", "--namespace", "-a", "--address", "--snapshotter", "--data-root", "--cni-path",
		"--cni-netconfpath", "--hosts-dir")
)

// composeConfig: `docker compose config` (alias convert) loads ./.env, or
// the files given with --env-file instead, and prints the configuration with
// every variable interpolated. Listing flags (--services, --volumes, ...), -q
// and --no-interpolate print no values.
func (s *shellEval) composeConfig(name string, args []cmdArg) {
	i := 0
	if name == "docker" || name == "podman" || name == "nerdctl" {
		for i < len(args) && args[i].textOr() != "compose" {
			t := args[i].textOr()
			switch {
			case containerGlobalValueOpts[t]:
				i += 2
			case strings.HasPrefix(t, "-"):
				i++ // a flag, --opt=value or -Hvalue
			default:
				return // another docker subcommand
			}
		}
		i++
	}
	sub := ""
	var envFiles []string
	for ; i < len(args) && sub == ""; i++ {
		t := args[i].textOr()
		switch {
		case t == "--env-file" && i+1 < len(args):
			envFiles = append(envFiles, args[i+1].textOr())
			i++
		case strings.HasPrefix(t, "--env-file="):
			envFiles = append(envFiles, strings.TrimPrefix(t, "--env-file="))
		case composeValueOpts[t]:
			i++
		case strings.HasPrefix(t, "-"):
		default:
			sub = t
		}
	}
	if sub != "config" && sub != "convert" {
		return
	}
	for _, a := range args[i:] {
		if composeConfigQuiet[strings.SplitN(a.textOr(), "=", 2)[0]] {
			return
		}
	}
	if len(envFiles) == 0 {
		envFiles = []string{".env"} // Compose v2: --env-file replaces the default .env
	}
	advice := "Use `docker compose config -q` to validate, `--services`/`--volumes` to list, or `--no-interpolate` to see the file without values."
	secretFile := false
	for _, f := range envFiles {
		// A runtime-built --env-file is denied by the argument check.
		secretFile = s.implicitEnvFile(name+" compose "+sub, f, advice) || secretFile
	}
	if !secretFile && len(s.sec.env) > 0 {
		// Variables the compose file references are also taken from the
		// process environment, and we cannot see which ones.
		s.c.ask(RuleEnvExposure, "`"+name+" compose "+sub+"` interpolates variables from the environment into its output, which may include secret variables (secrets.env); the user must confirm. "+advice)
	}
}
