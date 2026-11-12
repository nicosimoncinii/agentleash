package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// fakeDarwinFS simulates macOS: /var is a symlink to /private/var and only
// the listed paths exist (EvalSymlinks fails on anything else).
func fakeDarwinFS(existing ...string) func(string) (string, error) {
	exists := map[string]bool{"/": true, "/var": true, "/private": true, "/private/var": true}
	for _, e := range existing {
		exists[strings.ToLower(e)] = true
	}
	return func(p string) (string, error) {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
		canon := p
		if canon == "/var" || strings.HasPrefix(canon, "/var/") {
			canon = "/private" + canon
		}
		if !exists[strings.ToLower(canon)] {
			return "", errors.New("no such file or directory")
		}
		return canon, nil
	}
}

func TestResolveLongest(t *testing.T) {
	fs := fakeDarwinFS("/private/var/t", "/private/var/t/home", "/private/var/t/proj")
	cases := map[string]string{
		"/var/t/home":           "/private/var/t/home",
		"/var/t/home/.ssh":      "/private/var/t/home/.ssh", // .ssh does not exist
		"/var/t/home/.ssh/id_x": "/private/var/t/home/.ssh/id_x",
		"/private/var/t/proj":   "/private/var/t/proj",
	}
	for in, want := range cases {
		if got, ok := resolveLongest(fs, in); !ok || got != want {
			t.Errorf("resolveLongest(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := resolveLongest(nil, "/x"); ok {
		t.Error("nil resolver must not resolve")
	}
}

// A non-existent secret path under a symlinked parent must still match
// (macOS CI: Glob with path ~/.ssh when the fake home has no .ssh).
func TestSymlinkedParentNonExistentSecret(t *testing.T) {
	fs := fakeDarwinFS("/private/var/t", "/private/var/t/home", "/private/var/t/proj")
	e := New(policy.Default(), WithSymlinkResolver(fs))
	base := Request{Cwd: "/var/t/proj", ProjectRoot: "/var/t/proj", Home: "/var/t/home"}
	cases := []struct {
		tool  ToolKind
		cmd   string
		paths []string
		want  Decision
	}{
		{ToolSearch, "", []string{"/var/t/home/.ssh"}, Deny},
		{ToolSearch, "", []string{"/private/var/t/home/.ssh"}, Deny},
		{ToolRead, "", []string{"/var/t/home/.aws/credentials"}, Deny},
		{ToolShell, "cat ~/.ssh/id_ed25519", nil, Deny},
		{ToolShell, "cat /var/t/home/.ssh/config", nil, Deny},
		{ToolRead, "", []string{"/var/t/proj/.env"}, Deny},
		{ToolRead, "", []string{"/var/t/proj/README.md"}, Allow},
		{ToolSearch, "", []string{"/var/t/proj"}, Allow},
	}
	for _, c := range cases {
		req := base
		req.Tool, req.Command, req.Paths, req.Shell = c.tool, c.cmd, c.paths, ShellBash
		if v := e.Evaluate(req); v.Decision != c.want {
			t.Errorf("%s %q %v = %s (%s), want %s", c.tool, c.cmd, c.paths, v.Decision, v.Rule, c.want)
		}
	}
}
