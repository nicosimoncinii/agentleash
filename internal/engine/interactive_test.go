package engine

import "testing"

func TestInteractiveStdin(t *testing.T) {
	e := New(testPolicy())
	cases := []struct {
		cmd   string
		shell Shell
		want  Decision
	}{
		{"bash", ShellBash, Deny},
		{"bash -i", ShellBash, Deny},
		{"zsh -l", ShellBash, Deny},
		{"sh -s", ShellBash, Deny},
		{"sudo -s", ShellBash, Deny},
		{"sudo -i", ShellBash, Deny},
		{"python3", ShellBash, Deny},
		{"python3 -i app.py", ShellBash, Deny},
		{"node", ShellBash, Deny},
		{"env FOO=1 python3", ShellBash, Deny},
		{"irb", ShellBash, Deny},
		{"php -a", ShellBash, Deny},
		{"pwsh", ShellBash, Deny},
		{"ssh prod", ShellBash, Deny},
		{"ssh -p 2222 user@prod", ShellBash, Deny},
		{"docker exec -it web sh", ShellBash, Deny},
		{"docker run --rm -it ubuntu", ShellBash, Deny},
		{"kubectl exec -it pod -- bash", ShellBash, Deny},
		{"psql -h db app", ShellBash, Deny},
		{"mysql -u root", ShellBash, Deny},
		{"sqlite3 app.db", ShellBash, Deny},
		{"redis-cli", ShellBash, Deny},
		{"gdb ./a.out", ShellBash, Deny},
		{"vim notes.txt", ShellBash, Deny},
		{"less README.md", ShellBash, Deny},
		{"tmux", ShellBash, Deny},
		{"cd app && python3", ShellBash, Deny},
		{"bash -c 'python3'", ShellBash, Deny},
		{"pwsh", ShellPowerShell, Deny},
		{"python", ShellPowerShell, Deny},
		{"cmd", ShellPowerShell, Deny},
		{"cmd /k echo hi", ShellPowerShell, Deny},
		{"wsl", ShellPowerShell, Deny},
		{"wsl -d Ubuntu", ShellPowerShell, Deny},
		{"wsl -e ls", ShellPowerShell, Allow},
		{"bash", ShellAuto, Deny},
		// non-interactive forms
		{"bash build.sh", ShellBash, Allow},
		{"bash -c 'go test ./...'", ShellBash, Allow},
		{"python3 app.py", ShellBash, Allow},
		{"python3 -c 'print(1)'", ShellBash, Allow},
		{"python3 -m pytest", ShellBash, Allow},
		{"node server.js", ShellBash, Allow},
		{"ssh prod uptime", ShellBash, Allow},
		{"ssh -N -L 5432:db:5432 bastion", ShellBash, Allow},
		{"docker exec web ls", ShellBash, Allow},
		{"docker run --rm ubuntu echo hi", ShellBash, Allow},
		{"kubectl exec pod -- ls", ShellBash, Allow},
		{"kubectl get pods -it", ShellBash, Allow},
		{"psql -c 'select 1' app", ShellBash, Allow},
		{"mysql -e 'select 1'", ShellBash, Allow},
		{"sqlite3 app.db 'select 1'", ShellBash, Allow},
		{"redis-cli ping", ShellBash, Allow},
		{"gdb -batch -ex bt ./a.out", ShellBash, Allow},
		{"echo 'print(1)' | python3", ShellBash, Allow},
		{"python3 < script.py", ShellBash, Allow},
		{"python3 <<'EOF'\nprint(1)\nEOF", ShellBash, Allow},
		{"git log | less", ShellBash, Allow},
		{"cmd /c dir", ShellPowerShell, Allow},
		{"python app.py", ShellPowerShell, Allow},
		{"Get-Content x | python", ShellPowerShell, Allow},
	}
	for _, c := range cases {
		req := shellReq(c.cmd)
		req.Shell = c.shell
		req.InteractiveStdin = true
		v := e.Evaluate(req)
		if v.Decision != c.want {
			t.Errorf("%s %q = %s (%s: %s), want %s", c.shell, c.cmd, v.Decision, v.Rule, v.Reason, c.want)
		} else if c.want == Deny && v.Rule != RuleInteractive {
			t.Logf("%q denied by %s", c.cmd, v.Rule)
		}
	}
	// Without the flag (Claude Code, no write_stdin) nothing changes.
	for _, cmd := range []string{"python3", "ssh prod", "vim notes.txt"} {
		if v := e.Evaluate(shellReq(cmd)); v.Decision != Allow {
			t.Errorf("without InteractiveStdin %q = %s (%s)", cmd, v.Decision, v.Rule)
		}
	}
}
