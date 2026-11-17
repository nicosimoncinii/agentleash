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
	if stdinInterpreters[name] || psrREPLs[name] {
		return psrInterpreterSession(name, args)
	}
	if check, ok := psrInteractiveChecks[name]; ok {
		return check(args)
	}
	return "", false
}

// psrREPLs are interpreters, besides stdinInterpreters, that start a REPL.
var psrREPLs = set("irb", "pry", "iex", "ghci")

// psrInterpreterSession reports an interpreter that ends up in a REPL:
// python -i script.py, node -i, php -a, or irb/pry/iex without code.
func psrInterpreterSession(name string, args []string) (string, bool) {
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
	return "", false
}

// psrInteractiveCheck reports, from a program's arguments, whether it reads
// commands from stdin and what it starts.
type psrInteractiveCheck func(args []string) (string, bool)

// psrInteractiveChecks maps program names to their interactive-session check.
var psrInteractiveChecks = psrBuildInteractiveChecks()

// psrBuildInteractiveChecks builds psrInteractiveChecks.
func psrBuildInteractiveChecks() map[string]psrInteractiveCheck {
	m := map[string]psrInteractiveCheck{}
	add := func(check psrInteractiveCheck, names ...string) {
		for _, n := range names {
			m[n] = check
		}
	}
	add(psrWhen("an interactive WSL shell", wslInteractive), "wsl")
	add(psrWhen("an interactive cmd.exe", func(args []string) bool { return !hasFold(args, "/c") }), "cmd")
	add(psrWhen("a remote shell", sshInteractive), "ssh")
	add(psrWhen("an interactive container session", func(args []string) bool {
		return containerInteractive(args, "-i", "--interactive")
	}), "docker", "podman", "nerdctl")
	add(psrWhen("an interactive pod session", func(args []string) bool {
		return containerInteractive(args, "-i", "--stdin")
	}), "kubectl", "oc")
	add(psrUnless("a database shell", "-c", "--command", "-f", "--file", "-l", "--list", "-V", "--version", "--help"), "psql")
	add(psrUnless("a database shell", "-e", "--execute", "-V", "--version", "--help"), "mysql", "mariadb")
	add(psrWhen("a database shell", func(args []string) bool {
		return operands(args) < 2 && !hasAnyPrefix(args, "-version", "--version", "-help", "--help", "-cmd")
	}), "sqlite3")
	add(psrWhen("a database shell", func(args []string) bool {
		return operands(args) == 0 && !hasAnyPrefix(args, "--version", "--help", "-v")
	}), "redis-cli", "valkey-cli")
	add(psrWhen("a database shell", func(args []string) bool {
		return !hasAnyPrefix(args, "--eval", "-f", "--file", "--version", "--help") && !hasScriptOperand(args, ".js")
	}), "mongosh", "mongo")
	add(psrUnless("an interactive debugger", "-batch", "--batch", "-b", "--version", "-version"), "gdb", "lldb")
	add(psrUnless("an interactive network client", "-b", "--version"), "sftp", "ftp", "telnet")
	add(psrUnless("an editor that can run shell commands", "--version", "-es", "-Es", "--headless"),
		"vi", "vim", "nvim", "view", "ex", "ed", "nano", "pico", "micro")
	add(psrUnless("an editor that can run shell commands", "--batch", "-batch", "--script", "--version"), "emacs")
	add(psrWhen("a pager that can run shell commands (!cmd)", nil), "less", "more", "most", "man")
	add(psrWhen("a terminal session that runs commands typed later", nil), "tmux", "screen", "script", "expect")
	return m
}

// psrWhen returns a check reporting what when cond holds for the arguments
// (always when cond is nil).
func psrWhen(what string, cond func(args []string) bool) psrInteractiveCheck {
	return func(args []string) (string, bool) {
		if cond == nil || cond(args) {
			return what, true
		}
		return "", false
	}
}

// psrUnless returns a check reporting what unless one of the non-interactive
// options opts is given (see hasAnyPrefix).
func psrUnless(what string, opts ...string) psrInteractiveCheck {
	return psrWhen(what, func(args []string) bool { return !hasAnyPrefix(args, opts...) })
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
