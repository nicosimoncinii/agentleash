package engine

import (
	"errors"
	"strings"
	"testing"
)

func TestFileTools(t *testing.T) {
	e := New(testPolicy())
	cases := []struct {
		tool  ToolKind
		paths []string
		want  Decision
	}{
		{ToolRead, []string{"/home/u/proj/.env"}, Deny},
		{ToolRead, []string{".env"}, Deny},
		{ToolRead, []string{"/home/u/proj/.env.example"}, Allow},
		{ToolRead, []string{"/home/u/proj/.env.production"}, Deny},
		{ToolRead, []string{"/home/u/proj/src/main.go"}, Allow},
		{ToolRead, []string{"/home/u/proj/certs/server.pem"}, Deny},
		{ToolRead, []string{"/home/u/.aws/credentials"}, Deny},
		{ToolRead, []string{"/home/u/.aws/config"}, Allow},
		{ToolRead, []string{"/home/u/.ssh/known_hosts"}, Deny},
		{ToolRead, []string{"/home/u/proj/config/secrets.yml"}, Deny},
		{ToolRead, []string{"/home/u/proj/other/config/secrets.yml"}, Allow},
		{ToolRead, []string{"/home/u/proj/src/../.env"}, Deny},
		{ToolRead, []string{"/proc/self/environ"}, Deny},
		{ToolRead, []string{"/home/u/proj/README.md", "/home/u/proj/.env"}, Deny},
		{ToolRead, []string{"/home/u/proj/a*b"}, Allow}, // literal file name, not a glob
		{ToolWrite, []string{"/home/u/proj/.env"}, Deny},
		{ToolWrite, []string{"/home/u/proj/src/app.go"}, Allow},
		{ToolSearch, []string{"/home/u/proj"}, Allow},
		{ToolSearch, []string{"/home/u/proj", "**/*.go"}, Allow},
		{ToolSearch, []string{"/home/u/proj/src"}, Allow},
		{ToolSearch, []string{"/home/u/.ssh"}, Deny},
		{ToolSearch, []string{"/home/u/proj", "**/.env*"}, Deny},
		{ToolSearch, []string{"*.pem"}, Deny},
		{ToolSearch, []string{"/home/u/proj/.env"}, Deny},
		{ToolOther, []string{"/home/u/proj/.env"}, Allow},
	}
	for _, c := range cases {
		req := Request{Tool: c.tool, Paths: c.paths, Cwd: testRoot, ProjectRoot: testRoot, Home: testHome}
		v := e.Evaluate(req)
		if v.Decision != c.want {
			t.Errorf("%s %v = %s (%s), want %s", c.tool, c.paths, v.Decision, v.Reason, c.want)
		}
	}
}

func TestShellPathsFromAdapter(t *testing.T) {
	e := New(testPolicy())
	req := shellReq("apply_patch <<'EOF'\n*** Begin Patch\nEOF")
	req.Paths = []string{"/home/u/proj/.env"}
	if v := e.Evaluate(req); v.Decision != Deny || !strings.HasPrefix(v.Rule, RuleSecretFile) {
		t.Fatalf("shell with secret Paths: %+v", v)
	}
	req.Paths = []string{"/home/u/proj/src/a.go"}
	if v := e.Evaluate(req); v.Decision != Allow {
		t.Fatalf("shell with benign Paths: %+v", v)
	}
}

func TestWindowsPaths(t *testing.T) {
	e := New(testPolicy())
	win := func(tool ToolKind, cmd string, shell Shell, paths ...string) Request {
		return Request{Tool: tool, Command: cmd, Shell: shell, Paths: paths,
			Cwd: `C:\Users\u\proj`, ProjectRoot: `C:\Users\u\proj`, Home: `C:\Users\u`}
	}
	cases := []struct {
		req  Request
		want Decision
	}{
		{win(ToolRead, "", "", `C:\Users\u\proj\.env`), Deny},
		{win(ToolRead, "", "", `c:\users\U\PROJ\.ENV`), Deny},
		{win(ToolRead, "", "", `C:/Users/u/proj/config/secrets.yml`), Deny},
		{win(ToolRead, "", "", `C:\Users\u\proj\config\SECRETS.YML`), Deny},
		{win(ToolRead, "", "", `C:\Users\u\proj\src\main.go`), Allow},
		{win(ToolRead, "", "", `C:\Users\u\.aws\credentials`), Deny},
		{win(ToolRead, "", "", `C:\Users\u\proj\.env.`), Deny},
		{win(ToolRead, "", "", `C:\Users\u\proj\.env::$DATA`), Deny},
		{win(ToolRead, "", "", `C:\Users\u\proj\config\SECRET~1.YML`), Deny},
		{win(ToolRead, "", "", `\\?\C:\Users\u\proj\.env`), Deny},
		{win(ToolShell, "cat /c/Users/u/proj/config/secrets.yml", ShellBash), Deny},
		{win(ToolShell, "cat /mnt/c/Users/u/proj/config/secrets.yml", ShellBash), Deny},
		{win(ToolShell, "cat config/secrets.yml", ShellBash), Deny},
		{win(ToolShell, "cat ENV~1", ShellBash), Deny},
		{win(ToolShell, "git diff HEAD~1", ShellBash), Allow},
		{win(ToolShell, `Get-Content C:\Users\u\proj\.env`, ShellPowerShell), Deny},
		{win(ToolShell, `type config\secrets.yml`, ShellPowerShell), Deny},
		{win(ToolShell, `Get-Content $HOME\.aws\credentials`, ShellPowerShell), Deny},
		{win(ToolShell, `gc $env:USERPROFILE\.aws\credentials`, ShellPowerShell), Deny},
		{win(ToolShell, `Get-ChildItem C:\Users\u\proj`, ShellPowerShell), Allow},
	}
	for _, c := range cases {
		v := e.Evaluate(c.req)
		if v.Decision != c.want {
			t.Errorf("%s %q %v = %s (%s: %s), want %s", c.req.Tool, c.req.Command, c.req.Paths, v.Decision, v.Rule, v.Reason, c.want)
		}
	}
}

func TestSymlinkResolver(t *testing.T) {
	links := map[string]string{
		"/home/u/proj/notes.txt": "/home/u/proj/.env",
	}
	resolve := func(p string) (string, error) {
		if r, ok := links[p]; ok {
			return r, nil
		}
		return "", errors.New("not a link")
	}
	e := New(testPolicy(), WithSymlinkResolver(resolve))
	if v := e.Evaluate(shellReq("cat notes.txt")); v.Decision != Deny {
		t.Fatalf("symlink to .env: %+v", v)
	}
	if v := e.Evaluate(Request{Tool: ToolRead, Paths: []string{"/home/u/proj/notes.txt"}, Cwd: testRoot, ProjectRoot: testRoot, Home: testHome}); v.Decision != Deny {
		t.Fatalf("read symlink to .env: %+v", v)
	}
	if v := e.Evaluate(shellReq("cat README.md")); v.Decision != Allow {
		t.Fatalf("plain file: %+v", v)
	}
	// Without a resolver the engine never touches the filesystem.
	if v := New(testPolicy()).Evaluate(shellReq("cat notes.txt")); v.Decision != Allow {
		t.Fatalf("no resolver: %+v", v)
	}
}

func TestEmptyRequestContext(t *testing.T) {
	// No Cwd/ProjectRoot/Home: relative paths match anywhere, ~ is unknown.
	e := New(testPolicy())
	for _, c := range []struct {
		cmd  string
		want Decision
	}{
		{"cat config/secrets.yml", Deny},
		{"cat ~/.aws/credentials", Deny},
		{"cat .env", Deny},
		{"cat README.md", Allow},
	} {
		v := e.Evaluate(Request{Tool: ToolShell, Command: c.cmd})
		if v.Decision != c.want {
			t.Errorf("%q = %s (%s), want %s", c.cmd, v.Decision, v.Reason, c.want)
		}
	}
}

func TestRecursiveCopyAsks(t *testing.T) {
	runCases(t, ShellBash, []tc{
		{"tar czf /tmp/p.tgz .", Ask, "secret-dir-copy"},
		{"zip -r ../p.zip .", Ask, "secret-dir-copy"},
		{"cp -r ~ /tmp/home", Ask, "secret-dir-copy"},
		{"rsync -a ./ backup:/srv/p", Ask, "secret-dir-copy"},
		{"cp -r src build", Allow, ""},
		{"tar czf src.tgz src", Allow, ""},
	})
}

// rg with every ignore rule disabled searches gitignored secrets too.
func TestUnrestrictedRgAsks(t *testing.T) {
	runCases(t, ShellBash, []tc{
		{"rg -uu TODO", Ask, "secret-dir-copy"},
		{"rg -uuu foo .", Ask, "secret-dir-copy"},
		{"rg --hidden --no-ignore foo ~", Ask, "secret-dir-copy"},
		{"rg -u --hidden foo", Ask, "secret-dir-copy"},
		{"rg -u. foo", Ask, "secret-dir-copy"},
		{"rg -uu -n -A 3 foo /home/u", Ask, "secret-dir-copy"},
		{"rg --unrestricted --unrestricted -e foo", Ask, "secret-dir-copy"},
		{"rg -uu -m 5 foo", Ask, "secret-dir-copy"},
		{"rg TODO", Allow, ""},
		{"rg -u TODO", Allow, ""},
		{"rg --hidden TODO", Allow, ""},
		{"rg -uu TODO src/", Allow, ""},
		{"rg -uu -l TODO", Allow, ""},
		{"rg -uu --files", Allow, ""},
		{"rg -uu -tgo TODO", Allow, ""},
		{"rg -uu --glob '!.env*' TODO", Allow, ""},
		{"rg -uu -e foo src lib", Allow, ""},
	})
}

func TestCompilePatternSemantics(t *testing.T) {
	cases := []struct {
		pattern, anchor, home, want string
	}{
		{".env", "/proj", "/home/h", "**/.env"},
		{"**/*.pem", "/proj", "/home/h", "**/*.pem"},
		{"config/secrets.yml", "/proj", "/home/h", "/proj/config/secrets.yml"},
		{"./config/x", "/proj", "/home/h", "/proj/config/x"},
		{"secrets/", "/proj", "/home/h", "**/secrets"},
		{"~/.aws/credentials", "/proj", "/home/h", "/home/h/.aws/credentials"},
		{"~/.aws", "/proj", "", "**/.aws"},
		{"/etc/shadow", "/proj", "/home/h", "/etc/shadow"},
		{`C:\keys\*.pfx`, "/proj", "/home/h", "c:/keys/*.pfx"},
		{"config/x", "", "", "**/config/x"},
	}
	for _, c := range cases {
		cp, ok := compilePattern(c.pattern, c.anchor, c.home)
		if !ok || cp.path.raw != c.want {
			t.Errorf("compilePattern(%q) = %q, want %q", c.pattern, cp.path.raw, c.want)
		}
	}
	if _, ok := compilePattern("   ", "/proj", "/home/h"); ok {
		t.Error("blank pattern should be skipped")
	}
}
