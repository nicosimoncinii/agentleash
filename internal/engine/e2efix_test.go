package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// Regression tests for #22, #23 and #26 (found by the e2e suite), using the
// real default policy.

// #22: Git Bash on Windows reads backslash paths given to bash commands.
func TestIssue22WindowsPathsInBash(t *testing.T) {
	e := New(policy.Default())
	cases := []struct {
		cmd  string
		want Decision
	}{
		{`cat 'C:\proj\.env'`, Deny},
		{`cat "C:\\proj\\.env"`, Deny},
		{`cat C:\\proj\\.env`, Deny},
		{`cat 'C:/proj/.env'`, Deny},
		{`cat '.\.env'`, Deny},
		{`cat '..\proj\.env'`, Deny},
		{`cat '\\host\share\.env'`, Deny},
		{`cat 'sub\.env'`, Deny},
		{`cat 'config\secrets.yml'`, Deny},
		{`head -c 99 'D:\work\certs\server.pem'`, Deny},
		{`cat < 'C:\proj\.env'`, Deny},
		{`cat 'C:\proj\.env.example'`, Allow},
		{`cat 'C:\proj\README.md'`, Allow},
		// regexes and scripts are data, a leading lone backslash is an escape
		{`grep '\.env' src/main.go`, Allow},
		{`grep -rn "\.pem" src`, Allow},
		{`sed 's/\.env/x/' README.md`, Allow},
		{`rg '\.key\b' src`, Allow},
		{`echo 'C:\proj\.env' >> notes.txt`, Allow},
	}
	for _, c := range cases {
		if v := e.Evaluate(shellReq(c.cmd)); v.Decision != c.want {
			t.Errorf("%q = %s (%s), want %s", c.cmd, v.Decision, v.Rule, c.want)
		}
	}
}

// #23: a Glob rooted at the project must not "could match" ~/.ssh/**.
func TestIssue23GlobRootScoping(t *testing.T) {
	e := New(policy.Default())
	search := func(cwd string, paths ...string) Verdict {
		return e.Evaluate(Request{Tool: ToolSearch, Paths: paths, Cwd: cwd, ProjectRoot: testRoot, Home: testHome})
	}
	allow := [][]string{
		{"**/*.go"}, {"**/*.md"}, {"src/**/*.ts"}, {"*.go"}, {testRoot, "**/*.go"},
	}
	for _, p := range allow {
		if v := search(testRoot, p...); v.Decision != Allow {
			t.Errorf("Glob %v from the project = %s (%s), want allow", p, v.Decision, v.Rule)
		}
	}
	deny := [][]string{
		{"**/.env"}, {".env*"}, {"**/*.pem"}, {"**/id_rsa*"}, {"*.json"}, // *.json could be credentials.json
	}
	for _, p := range deny {
		if v := search(testRoot, p...); v.Decision != Deny {
			t.Errorf("Glob %v from the project = %s, want deny", p, v.Decision)
		}
	}
	// Searches rooted at or above home, or inside a secret dir, still see
	// home-anchored patterns.
	if v := search(testHome, "**/*"); v.Decision != Deny {
		t.Errorf("Glob **/* from home = %s, want deny (~/.ssh/**)", v.Decision)
	}
	if v := search(testHome+"/.ssh", "*"); v.Decision != Deny {
		t.Errorf("Glob * inside ~/.ssh = %s, want deny", v.Decision)
	}
	if v := search(testRoot, "~/.ssh/*"); v.Decision != Deny {
		t.Errorf("Glob ~/.ssh/* = %s, want deny", v.Decision)
	}
	if v := search(testRoot, "/home/u/**/*.go"); v.Decision != Deny {
		t.Errorf("absolute Glob over home = %s, want deny", v.Decision)
	}
}

// #26: with the injected resolver, an 8.3 short project path is
// canonicalised, so allow_files keep working.
func TestIssue26ShortNameCanonicalization(t *testing.T) {
	const short, long = `C:\Users\RUNNER~1\proj`, `C:\Users\runneradmin\proj`
	resolve := func(p string) (string, error) {
		q := strings.ReplaceAll(p, "/", `\`)
		low := strings.ToLower(q)
		for _, pre := range []string{strings.ToLower(short), strings.ToLower(long)} {
			if low == pre || strings.HasPrefix(low, pre+`\`) {
				return long + q[len(pre):], nil
			}
		}
		return "", errors.New("not found")
	}
	e := New(policy.Default(), WithSymlinkResolver(resolve))
	req := func(tool ToolKind, cmd string, paths ...string) Request {
		return Request{Tool: tool, Command: cmd, Shell: ShellBash, Paths: paths, Cwd: short, ProjectRoot: short, Home: `C:\Users\runneradmin`}
	}
	cases := []struct {
		req  Request
		want Decision
	}{
		{req(ToolRead, "", short+`\.env.example`), Allow},
		{req(ToolRead, "", short+`\.env`), Deny},
		{req(ToolRead, "", short+`\id_rsa`), Deny},
		{req(ToolShell, "cat .env.example"), Allow},
		{req(ToolShell, "cat .env"), Deny},
		{req(ToolRead, "", long+`\.env.example`), Allow},
		// without a resolver result (file does not exist), short names stay suspicious
		{req(ToolShell, `cat 'C:\Users\RUNNER~1\work\SECRE~1.YML'`), Deny},
	}
	for _, c := range cases {
		if v := e.Evaluate(c.req); v.Decision != c.want {
			t.Errorf("%s %q %v = %s (%s: %s), want %s", c.req.Tool, c.req.Command, c.req.Paths, v.Decision, v.Rule, v.Reason, c.want)
		}
	}
}
