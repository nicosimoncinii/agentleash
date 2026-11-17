package engine

import (
	"fmt"
	"strings"
)

// Interactive sessions (issue #18)
//
// Codex runs PreToolUse once for exec_command; text later sent to the
// process with write_stdin is never checked. A program that reads commands
// from that stdin (a shell, a REPL, a remote or container shell, a database
// shell, a debugger, an editor or pager with shell escapes) would therefore
// run unchecked commands. When Request.InteractiveStdin is set, such a
// program started with the session's stdin (not a pipe, file or here-doc)
// is denied.

// checkInteractive denies argv (one simple command, static words) when it
// would read commands from the inherited stdin.
func checkInteractive(c *collector, argv []string) {
	for _, level := range unwrapLevels(argv) {
		if what, ok := interactiveProgram(level); ok {
			c.deny(RuleInteractive, fmt.Sprintf("`%s` starts %s that reads commands typed later; Codex does not run hooks on input sent with write_stdin, so those commands could not be checked. "+
				"Run it non-interactively instead (a script file, -c/-e with the code, `ssh HOST CMD`, `psql -c SQL`).", display(strings.Join(level, " ")), what))
			return
		}
	}
}

func interactiveProgram(argv []string) (string, bool) {
	if len(argv) == 0 {
		return "", false
	}
	for _, a := range argv {
		if strings.IndexByte(a, dynAny) >= 0 {
			return "", false
		}
	}
	name := cmdBase(argv[0])
	args := argv[1:]
	if stdinCodeRunner(argv) {
		return "an interactive shell or interpreter", true
	}
	switch {
	case stdinInterpreters[name] || name == "irb" || name == "pry" || name == "iex" || name == "ghci":
		// python -i script.py, node -i, php -a: REPL after the program.
		for _, a := range args {
			if a == "-i" || a == "--interactive" || (name == "php" && a == "-a") {
				return "an interactive interpreter", true
			}
			if a == "--" || (!strings.HasPrefix(a, "-") && a != "") {
				break
			}
		}
		if name == "irb" || name == "pry" || (name == "iex" && !hasAny(args, "-e", "--eval")) {
			return "an interactive interpreter", true
		}
	case name == "wsl":
		if wslInteractive(args) {
			return "an interactive WSL shell", true
		}
	case name == "cmd":
		if !hasFold(args, "/c") {
			return "an interactive cmd.exe", true
		}
	case name == "ssh":
		if sshInteractive(args) {
			return "a remote shell", true
		}
	case name == "docker" || name == "podman" || name == "nerdctl":
		if containerInteractive(args, "-i", "--interactive") {
			return "an interactive container session", true
		}
	case name == "kubectl" || name == "oc":
		if containerInteractive(args, "-i", "--stdin") {
			return "an interactive pod session", true
		}
	case name == "psql":
		if !hasAnyPrefix(args, "-c", "--command", "-f", "--file", "-l", "--list", "-V", "--version", "--help") {
			return "a database shell", true
		}
	case name == "mysql" || name == "mariadb":
		if !hasAnyPrefix(args, "-e", "--execute", "-V", "--version", "--help") {
			return "a database shell", true
		}
	case name == "sqlite3":
		if operands(args) < 2 && !hasAnyPrefix(args, "-version", "--version", "-help", "--help", "-cmd") {
			return "a database shell", true
		}
	case name == "redis-cli" || name == "valkey-cli":
		if operands(args) == 0 && !hasAnyPrefix(args, "--version", "--help", "-v") {
			return "a database shell", true
		}
	case name == "mongosh" || name == "mongo":
		if !hasAnyPrefix(args, "--eval", "-f", "--file", "--version", "--help") && !hasScriptOperand(args, ".js") {
			return "a database shell", true
		}
	case name == "gdb" || name == "lldb":
		if !hasAnyPrefix(args, "-batch", "--batch", "-b", "--version", "-version") {
			return "an interactive debugger", true
		}
	case name == "sftp" || name == "ftp" || name == "telnet":
		if !hasAnyPrefix(args, "-b", "--version") {
			return "an interactive network client", true
		}
	case name == "vi" || name == "vim" || name == "nvim" || name == "view" || name == "ex" || name == "ed" || name == "nano" || name == "pico" || name == "micro":
		if !hasAnyPrefix(args, "--version", "-es", "-Es", "--headless") {
			return "an editor that can run shell commands", true
		}
	case name == "emacs":
		if !hasAnyPrefix(args, "--batch", "-batch", "--script", "--version") {
			return "an editor that can run shell commands", true
		}
	case name == "less" || name == "more" || name == "most" || name == "man":
		return "a pager that can run shell commands (!cmd)", true
	case name == "tmux" || name == "screen" || name == "script" || name == "expect":
		return "a terminal session that runs commands typed later", true
	}
	return "", false
}

func hasAny(args []string, opts ...string) bool {
	for _, a := range args {
		for _, o := range opts {
			if a == o {
				return true
			}
		}
	}
	return false
}

func hasFold(args []string, opt string) bool {
	for _, a := range args {
		if strings.EqualFold(a, opt) {
			return true
		}
	}
	return false
}

// hasAnyPrefix matches an option exactly, with "=value", or with an attached
// short value (-cSQL).
func hasAnyPrefix(args []string, opts ...string) bool {
	for _, a := range args {
		for _, o := range opts {
			if a == o || strings.HasPrefix(a, o+"=") || (len(o) == 2 && o[0] == '-' && strings.HasPrefix(a, o) && len(a) > 2 && a[1] != '-') {
				return true
			}
		}
	}
	return false
}

func operands(args []string) int {
	n := 0
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			n++
		}
	}
	return n
}

func hasScriptOperand(args []string, ext string) bool {
	for _, a := range args {
		if strings.HasSuffix(strings.ToLower(a), ext) {
			return true
		}
	}
	return false
}

// sshValueOpts take a separate value.
var sshValueOpts = "BbcDEeFIiJLlmOoPpQRSWw"

// sshInteractive reports an ssh invocation with no remote command.
func sshInteractive(args []string) bool {
	ops := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			ops += len(args) - i - 1
			i = len(args)
		case strings.HasPrefix(a, "-") && len(a) > 1:
			flags := a[1:]
			for j, r := range flags {
				if strings.ContainsRune(sshValueOpts, r) {
					if j == len(flags)-1 {
						i++
					}
					break
				}
				if r == 'V' || r == 'G' || r == 'O' || r == 'Q' {
					return false // version, config dump, control commands
				}
				if r == 'N' {
					return false // no remote command: port forwarding only
				}
			}
		default:
			ops++
		}
	}
	return ops == 1
}

// containerInteractive reports `docker exec|run|attach` and
// `kubectl exec|attach|run` with an interactive stdin flag, which keeps the
// container process reading the session's stdin.
func containerInteractive(args []string, short, long string) bool {
	sub := ""
	i := 0
	for ; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			sub = args[i]
			break
		}
	}
	switch sub {
	case "attach":
		return true
	case "exec", "run", "debug":
	default:
		return false
	}
	for _, a := range args[i+1:] {
		if a == "--" {
			break
		}
		if a == long || a == long+"=true" {
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a[1:], short[1:]) {
			return true
		}
	}
	return false
}

// wslInteractive reports wsl with no command to run (an interactive shell).
func wslInteractive(args []string) bool {
	for i := 0; i < len(args); i++ {
		switch a := strings.ToLower(args[i]); a {
		case "-d", "--distribution", "-u", "--user", "--cd", "--shell-type":
			i++
		case "--system", "--exec-shell":
		default:
			return false // a command, -e/--exec/--, or a management option
		}
	}
	return true
}
