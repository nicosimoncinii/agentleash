package engine

import (
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
	case "dotenv", "dotenvx", "direnv", "op", "doppler", "infisical", "envchain", "aws-vault", "chamber":
		return unwrapSecretRunner(name, args)
	case "su", "runuser", "script", "sg", "flock":
		return s.unwrapStringCmd(name, args)
	case "watch":
		return s.unwrapWatch(args)
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
	switch {
	case fromFile || stdin == nil || stdin.kind == stdinUnknown || stdin.kind == stdinFile || stdin.decode:
		stdinArgs = []cmdArg{dynArg()}
	case stdin.kind == stdinGlob:
		stdinArgs = []cmdArg{{alts: stdin.texts}}
	default:
		for _, t := range stdin.texts {
			for _, f := range strings.Fields(t) {
				stdinArgs = append(stdinArgs, litArg(strings.Trim(f, `"'`)))
			}
		}
		if len(stdinArgs) > 64 {
			stdinArgs = []cmdArg{dynArg()}
		}
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
