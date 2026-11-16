package engine

import (
	"reflect"
	"strings"
	"testing"
)

func TestSedExecTexts(t *testing.T) {
	tests := []struct {
		script  string
		want    []string
		dynamic bool
	}{
		{"s/a/b/", nil, false},
		{"s/.*/cat .env/e", []string{"cat .env"}, false},
		{"1s/.*/printenv/e", []string{"printenv"}, false},
		{`s|x|cat a\|b|gep`, []string{"cat a|b"}, false},
		{`s/\(.*\)/\1/e`, []string{`\1`}, true},
		{"s/x/&/e", []string{"&"}, true},
		{"s/release/version/", nil, false},
		{"/start/,/end/p", nil, false},
		{"s/a/b/w out.txt", nil, false},
		{"s/a/b/; s/c/ls/e", []string{"ls"}, false},
	}
	for _, tt := range tests {
		got, dyn := sedExecTexts(tt.script)
		if !reflect.DeepEqual(got, tt.want) || dyn != tt.dynamic {
			t.Errorf("sedExecTexts(%q) = %q, %v; want %q, %v", tt.script, got, dyn, tt.want, tt.dynamic)
		}
	}
}

func TestClusterValueOpt(t *testing.T) {
	tests := []struct {
		name, arg string
		letter    byte
		attached  string
	}{
		{"grep", "-hf", 'f', ""},
		{"grep", "-ie", 'e', ""},
		{"grep", "-hfpat.txt", 'f', "pat.txt"},
		{"grep", "-f", 0, ""},
		{"grep", "-fpat", 0, ""},
		{"grep", "-rn", 0, ""},
		{"grep", "--file", 0, ""},
		{"ag", "-hf", 0, ""},
		{"sed", "-ne", 'e', ""},
	}
	for _, tt := range tests {
		l, a := clusterValueOpt(tt.name, tt.arg)
		if l != tt.letter || a != tt.attached {
			t.Errorf("clusterValueOpt(%q, %q) = %q, %q; want %q, %q", tt.name, tt.arg, l, a, tt.letter, tt.attached)
		}
	}
}

// A file list redirected from a file is opaque: the reason must say so,
// not talk about a "*" argument matching /proc/*/environ.
func TestFileListFromFileReason(t *testing.T) {
	e := New(testPolicy())
	for _, cmd := range []string{"cpio -o < list.txt > out.cpio", "tar cf out.tar -T - < list.txt", "zip out.zip -@ < list.txt"} {
		v := e.Evaluate(shellReq(cmd))
		if v.Decision != Deny || v.Rule != RuleDynamicPath || !strings.Contains(v.Reason, "list.txt") || strings.Contains(v.Reason, "environ") {
			t.Errorf("Evaluate(%q) = %s %q %q; want deny %s naming list.txt", cmd, v.Decision, v.Rule, v.Reason, RuleDynamicPath)
		}
	}
}

// docker compose config: a secret env file is denied; otherwise
// interpolation from the process environment is asked when the policy has
// secrets.env globs; --no-interpolate and listing flags are allowed.
func TestComposeConfigDecisions(t *testing.T) {
	// testPolicy has the anchored config/secrets.yml: the subcommand word
	// "config" must not count as the directory holding it (#34).
	p := testPolicy()
	e := New(p)
	cases := []tc{
		{"docker compose config", Deny, RuleSecretFile},
		{"docker compose --env-file .env.prod config", Deny, RuleSecretFile},
		{"docker compose --env-file .env.example config", Ask, RuleEnvExposure},
		{"docker --context dev compose --env-file .env.example convert", Ask, RuleEnvExposure},
		{"docker compose --env-file .env.example config --no-interpolate", Allow, ""},
		{"docker compose --env-file .env.example config -q", Allow, ""},
		{"docker compose --env-file .env.example config --services", Allow, ""},
	}
	for _, c := range cases {
		v := e.Evaluate(shellReq(c.cmd))
		if v.Decision != c.want || !strings.HasPrefix(v.Rule, c.rule) {
			t.Errorf("Evaluate(%q) = %s (%s: %s), want %s %s", c.cmd, v.Decision, v.Rule, v.Reason, c.want, c.rule)
		}
	}
	p.Secrets.Env = nil
	v := New(p).Evaluate(shellReq("docker compose --env-file .env.example config"))
	if v.Decision != Allow {
		t.Errorf("without secrets.env globs: got %s (%s: %s), want allow", v.Decision, v.Rule, v.Reason)
	}
}

func TestArgCandidatesAttachedValues(t *testing.T) {
	tests := []struct {
		arg  string
		want string
	}{
		{"-d@.env", ".env"},
		{"-sd@.env", ".env"},
		{"name@.env", ".env"},
		{"--post-file=.env", ".env"},
		{"--files0-from=.env", ".env"},
	}
	for _, tt := range tests {
		if got := argCandidates(escapeLit(tt.arg)); !containsStr(got, escapeLit(tt.want)) {
			t.Errorf("argCandidates(%q) = %q; want it to contain %q", tt.arg, got, tt.want)
		}
	}
}

// Issue #34: a subcommand word of a known CLI is not a path, so the
// directory-holding-secrets rule (config for config/secrets.yml) does not
// apply to it; the same word in a path role is still denied.
func TestSubcommandIsNotSecretDir(t *testing.T) {
	e := New(testPolicy())
	cases := []tc{
		{"git config user.name x", Allow, ""},
		{"git -C . config --get user.email", Allow, ""},
		{"npm config list", Allow, ""},
		{"pnpm config get registry", Allow, ""},
		{"yarn config get npmRegistryServer", Allow, ""},
		{"kubectl config view", Allow, ""},
		{"kubectl --context dev config use-context prod", Allow, ""},
		{"docker compose --env-file .env.example config --no-interpolate", Allow, ""},
		{"kubectl config view --raw", Deny, RuleCredential},
		{"cat config", Deny, RuleSecretFile},
		{"tar czf x.tgz config", Deny, RuleSecretFile},
		{"cp -r config /tmp", Deny, RuleSecretFile},
		{"git -C config status", Deny, RuleSecretFile},
		{"git --unknown-opt config status", Deny, RuleSecretFile},
		{"docker compose -f config up", Deny, RuleSecretFile},
		{"git diff --no-index config /tmp/x", Deny, RuleSecretFile},
		{"git config/secrets.yml", Deny, RuleSecretFile},
	}
	for _, c := range cases {
		v := e.Evaluate(shellReq(c.cmd))
		if v.Decision != c.want || !strings.HasPrefix(v.Rule, c.rule) {
			t.Errorf("Evaluate(%q) = %s (%s: %s), want %s %s", c.cmd, v.Decision, v.Rule, v.Reason, c.want, c.rule)
		}
	}
	for _, c := range []tc{
		{"kubectl config view", Allow, ""},
		{"git config user.name x", Allow, ""},
		{"docker compose -f config up", Deny, RuleSecretFile},
		{"Get-Content config", Deny, RuleSecretFile},
	} {
		for _, sh := range []Shell{ShellPowerShell, ShellAuto} {
			req := shellReq(c.cmd)
			req.Shell = sh
			v := e.Evaluate(req)
			if v.Decision != c.want || !strings.HasPrefix(v.Rule, c.rule) {
				t.Errorf("Evaluate(%s %q) = %s (%s: %s), want %s %s", sh, c.cmd, v.Decision, v.Rule, v.Reason, c.want, c.rule)
			}
		}
	}
}

func TestVerbArgs(t *testing.T) {
	args := func(ws ...string) []cmdArg {
		out := make([]cmdArg, len(ws))
		for i, w := range ws {
			out[i] = litArg(w)
		}
		return out
	}
	tests := []struct {
		name string
		args []string
		want []int
	}{
		{"git", []string{"config", "user.name", "x"}, []int{0}},
		{"git", []string{"-C", "config", "status"}, []int{2}},
		{"docker", []string{"--context", "dev", "compose", "-p", "x", "config"}, []int{2, 5}},
		{"docker", []string{"cp", "config", "c:/x"}, []int{0}},
		{"npm", []string{"config", "list"}, []int{0, 1}},
		{"git", []string{"--weird", "config"}, nil},
		{"git", []string{"./config"}, nil},
		{"cat", []string{"config"}, nil},
	}
	for _, tt := range tests {
		got := verbArgs(tt.name, args(tt.args...))
		if len(got) != len(tt.want) {
			t.Errorf("verbArgs(%s %q) = %v, want %v", tt.name, tt.args, got, tt.want)
			continue
		}
		for _, i := range tt.want {
			if !got[i] {
				t.Errorf("verbArgs(%s %q) = %v, want %v", tt.name, tt.args, got, tt.want)
			}
		}
	}
}
