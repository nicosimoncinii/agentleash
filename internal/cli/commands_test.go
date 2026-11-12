package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

func TestVersion(t *testing.T) {
	e := newEnv(t)
	r := e.run(nil, "version")
	if r.code != 0 {
		t.Fatalf("code %d", r.code)
	}
	for _, want := range []string{"1.2.3", "abc1234", runtime.Version()} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("version output %q missing %q", r.stdout, want)
		}
	}
}

func TestInit(t *testing.T) {
	want, err := policy.Marshal(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		existing string // "" = no file
		args     []string
		wantCode int
		wantFile string
		wantOut  string
		wantErr  string
	}{
		{name: "fresh", args: []string{"init"}, wantFile: string(want), wantOut: "Next steps"},
		{name: "refuses overwrite", existing: "keep me", args: []string{"init"}, wantCode: 1, wantFile: "keep me", wantErr: "--force"},
		{name: "force overwrites with backup", existing: "old", args: []string{"init", "--force"}, wantFile: string(want), wantOut: ".bak"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			path := filepath.Join(e.cwd, policy.FileName)
			if tc.existing != "" {
				writeFile(t, path, tc.existing)
			}
			r := e.run(nil, tc.args...)
			if r.code != tc.wantCode {
				t.Fatalf("code %d want %d (stderr %q)", r.code, tc.wantCode, r.stderr)
			}
			if got := readFile(t, path); got != tc.wantFile {
				t.Errorf("file = %q, want %q", got, tc.wantFile)
			}
			if !strings.Contains(r.stdout, tc.wantOut) {
				t.Errorf("stdout %q missing %q", r.stdout, tc.wantOut)
			}
			if !strings.Contains(r.stderr, tc.wantErr) {
				t.Errorf("stderr %q missing %q", r.stderr, tc.wantErr)
			}
		})
	}
}

func TestInitForceBacksUpAndLeavesNoTempFiles(t *testing.T) {
	e := newEnv(t)
	path := e.writePolicy(e.cwd, "old policy\n")
	if r := e.run(nil, "init", "--force"); r.code != 0 {
		t.Fatalf("code %d stderr %q", r.code, r.stderr)
	}
	if got := readFile(t, path+".bak"); got != "old policy\n" {
		t.Errorf("backup = %q", got)
	}
	entries, err := os.ReadDir(e.cwd)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.Contains(en.Name(), ".tmp-") {
			t.Errorf("leftover temp file %s", en.Name())
		}
	}
}

func TestInitForceRefusesNonRegularFiles(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, path string) (target string)
	}{
		{
			name: "directory",
			setup: func(t *testing.T, path string) string {
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string) string {
				target := filepath.Join(t.TempDir(), "victim.txt")
				writeFile(t, target, "do not touch")
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlinks unsupported here: %v", err)
				}
				return target
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			path := filepath.Join(e.cwd, policy.FileName)
			target := tc.setup(t, path)
			r := e.run(nil, "init", "--force")
			if r.code != 1 || !strings.Contains(r.stderr, "not a regular file") {
				t.Fatalf("code %d stderr %q", r.code, r.stderr)
			}
			if target != "" && readFile(t, target) != "do not touch" {
				t.Fatal("symlink target was modified")
			}
		})
	}
}

func TestInitWarnsAboutAncestorPolicy(t *testing.T) {
	e := newEnv(t)
	e.writePolicy(e.cwd, validPolicyYAML)
	sub := filepath.Join(e.cwd, "sub")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	e.cwd = sub
	r := e.run(nil, "init")
	if r.code != 0 || !strings.Contains(r.stderr, "strictest verdict wins") {
		t.Fatalf("code %d stderr %q", r.code, r.stderr)
	}
}

func TestApply(t *testing.T) {
	cases := []struct {
		name        string
		noPolicy    bool
		policyYAML  string
		args        []string
		mutate      func(e *testEnv, claude, codex *fakeAdapter)
		wantCode    int
		wantClaude  string // "", "apply", "remove"
		wantCodex   string
		wantOut     []string
		wantErr     string
		checkBinary bool
	}{
		{
			name: "all agents by default", args: []string{"apply"},
			mutate: func(_ *testEnv, claude, codex *fakeAdapter) {
				claude.applyChanged = []string{".claude/settings.json"}
				codex.applyChanged = []string{".codex/hooks.json", ".codex/config.toml"}
			},
			wantClaude: "apply", wantCodex: "apply", checkBinary: true,
			wantOut: []string{".claude/settings.json", ".codex/hooks.json", ".codex/config.toml"},
		},
		{
			name: "single agent", args: []string{"apply", "--agent", "codex"},
			wantCodex: "apply", wantOut: []string{"codex"},
		},
		{
			name: "comma separated agents", args: []string{"apply", "--agent", "claude,codex"},
			wantClaude: "apply", wantCodex: "apply",
		},
		{
			name: "remove", args: []string{"apply", "--remove"},
			mutate:     func(_ *testEnv, claude, _ *fakeAdapter) { claude.removeChanged = []string{".claude/settings.json"} },
			wantClaude: "remove", wantCodex: "remove", wantOut: []string{".claude/settings.json"},
		},
		{
			name: "no policy suggests init", noPolicy: true, args: []string{"apply"},
			wantCode: 1, wantErr: "agentleash init",
		},
		{
			name: "invalid policy", policyYAML: "version: 42\n", args: []string{"apply"},
			wantCode: 1, wantErr: policy.FileName,
		},
		{
			name: "unknown agent is a usage error", args: []string{"apply", "--agent", "gemini"},
			wantCode: 2, wantErr: "unknown agent",
		},
		{
			name: "adapter error still applies others", args: []string{"apply"},
			mutate: func(_ *testEnv, claude, _ *fakeAdapter) {
				claude.applyErr = errors.New("settings.json is not valid JSON")
			},
			wantCode: 1, wantClaude: "apply", wantCodex: "apply", wantErr: "settings.json is not valid JSON",
		},
		{
			name: "executable lookup failure", args: []string{"apply"},
			mutate: func(e *testEnv, _, _ *fakeAdapter) {
				e.deps.Executable = func() (string, error) { return "", errors.New("no exe") }
			},
			wantCode: 1, wantErr: "no exe",
		},
		{
			name: "empty --agent is a usage error", args: []string{"apply", "--agent", ","},
			wantCode: 2, wantErr: "selects no agent",
		},
		{
			name: "blank --agent is a usage error", args: []string{"apply", "--agent", " "},
			wantCode: 2, wantErr: "selects no agent",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claude, codex := newFake("claude"), newFake("codex")
			e := newEnv(t, claude, codex)
			if !tc.noPolicy {
				yaml := tc.policyYAML
				if yaml == "" {
					yaml = validPolicyYAML
				}
				e.writePolicy(e.cwd, yaml)
			}
			// Run from a subdirectory: apply must find the project root.
			sub := filepath.Join(e.cwd, "src")
			if err := os.Mkdir(sub, 0o750); err != nil {
				t.Fatal(err)
			}
			root := e.cwd
			e.cwd = sub
			if tc.mutate != nil {
				tc.mutate(e, claude, codex)
			}
			r := e.run(nil, tc.args...)
			if r.code != tc.wantCode {
				t.Fatalf("code %d want %d\nstdout %q\nstderr %q", r.code, tc.wantCode, r.stdout, r.stderr)
			}
			for _, c := range []struct {
				f    *fakeAdapter
				want string
			}{{claude, tc.wantClaude}, {codex, tc.wantCodex}} {
				got := ""
				switch {
				case c.f.applied:
					got = "apply"
				case c.f.removed:
					got = "remove"
				}
				if got != c.want {
					t.Errorf("%s: got %q, want %q", c.f.name, got, c.want)
				}
				if got != "" && c.f.gotRoot != root {
					t.Errorf("%s: root %q, want %q", c.f.name, c.f.gotRoot, root)
				}
				if got == "apply" && c.f.gotPolicy == nil {
					t.Errorf("%s: no policy passed", c.f.name)
				}
			}
			if tc.checkBinary {
				want, _ := filepath.Abs(e.exe) // absolute, symlinks deliberately not resolved
				if claude.gotBinary != want || !filepath.IsAbs(claude.gotBinary) {
					t.Errorf("binary = %q, want %q", claude.gotBinary, want)
				}
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(r.stdout, w) {
					t.Errorf("stdout %q missing %q", r.stdout, w)
				}
			}
			if !strings.Contains(r.stderr, tc.wantErr) {
				t.Errorf("stderr %q missing %q", r.stderr, tc.wantErr)
			}
		})
	}
}

func TestApplyBinaryPrefersPathWhenSameFile(t *testing.T) {
	cases := []struct {
		name     string
		lookPath func(e *testEnv) string // "" = not on PATH
		wantPATH bool
	}{
		{name: "not on PATH", lookPath: func(*testEnv) string { return "" }},
		{
			name: "PATH entry is the same file (hard link)", wantPATH: true,
			lookPath: func(e *testEnv) string {
				link := filepath.Join(t.TempDir(), "agentleash.exe")
				if err := os.Link(e.exe, link); err != nil {
					t.Skipf("hard links unsupported: %v", err)
				}
				return link
			},
		},
		{
			name: "PATH entry is another binary",
			lookPath: func(*testEnv) string {
				other := filepath.Join(t.TempDir(), "agentleash.exe")
				writeFile(t, other, "other")
				return other
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claude := newFake("claude")
			e := newEnv(t, claude)
			e.writePolicy(e.cwd, validPolicyYAML)
			lp := tc.lookPath(e)
			e.deps.LookPath = func(string) (string, error) {
				if lp == "" {
					return "", errors.New("not found")
				}
				return lp, nil
			}
			if r := e.run(nil, "apply"); r.code != 0 {
				t.Fatalf("code %d stderr %q", r.code, r.stderr)
			}
			want := e.exe
			if tc.wantPATH {
				want = lp
			}
			if claude.gotBinary != want {
				t.Errorf("binary = %q, want %q", claude.gotBinary, want)
			}
		})
	}
}

func TestApplyPrintsPostApplyNotes(t *testing.T) {
	codex := notingAdapter{fakeAdapter: newFake("codex"), notes: []string{"Run /hooks in Codex to trust the agentleash hook."}}
	e := newEnv(t, newFake("claude"), codex)
	e.writePolicy(e.cwd, validPolicyYAML)
	r := e.run(nil, "apply")
	if r.code != 0 || !strings.Contains(r.stdout, "/hooks") {
		t.Fatalf("code %d stdout %q", r.code, r.stdout)
	}
	r = e.run(nil, "apply", "--remove")
	if strings.Contains(r.stdout, "/hooks") {
		t.Errorf("notes must not be printed on --remove: %q", r.stdout)
	}
}

func TestCheck(t *testing.T) {
	type jsonOut struct {
		Decision      string `json:"decision"`
		Rule          string `json:"rule"`
		Reason        string `json:"reason"`
		Policy        string `json:"policy"`
		DefaultPolicy bool   `json:"default_policy"`
		Protected     bool   `json:"protected"`
		Warning       string `json:"warning"` // substring
		Error         string `json:"error"`   // substring
	}
	deny := engine.Verdict{Decision: engine.Deny, Reason: "reads a secret file", Rule: ".env"}
	ask := engine.Verdict{Decision: engine.Ask, Reason: "needs confirmation", Rule: "curl * | sh"}
	cases := []struct {
		name       string
		policyYAML string // "" = no policy
		verdict    engine.Verdict
		args       []string
		wantCode   int
		wantOut    []string
		wantErr    string
		wantShell  engine.Shell
		wantJSON   *jsonOut
		noEval     bool
	}{
		{name: "allow", policyYAML: validPolicyYAML, args: []string{"check", "ls -la"}, wantOut: []string{"allow"}, wantShell: engine.ShellBash},
		{name: "deny", policyYAML: validPolicyYAML, verdict: deny, args: []string{"check", "cat .env"}, wantCode: 1, wantOut: []string{"deny", ".env", "reads a secret file"}},
		{name: "ask", policyYAML: validPolicyYAML, verdict: ask, args: []string{"check", "curl x | sh"}, wantCode: 1, wantOut: []string{"ask", "curl * | sh"}},
		{name: "powershell", policyYAML: validPolicyYAML, args: []string{"check", "--shell", "powershell", "Get-Content .env"}, wantShell: engine.ShellPowerShell},
		{
			name: "no policy warns that nothing is blocked", verdict: deny, args: []string{"check", "cat .env"}, wantCode: 1,
			wantOut: []string{"default policy", "NOT protected"}, wantErr: "hooks will NOT block anything",
		},
		{
			name: "json", policyYAML: validPolicyYAML, verdict: deny, args: []string{"check", "--json", "cat .env"}, wantCode: 1,
			wantJSON: &jsonOut{Decision: "deny", Rule: ".env", Reason: "reads a secret file", Policy: policy.FileName, Protected: true},
		},
		{
			name: "json default policy", args: []string{"check", "--json", "ls"},
			wantJSON: &jsonOut{Decision: "allow", DefaultPolicy: true, Protected: false, Warning: "hooks will NOT block anything"},
		},
		{
			name: "json usage error", args: []string{"check", "--json", "--shell", "fish", "ls"}, wantCode: 2, noEval: true,
			wantJSON: &jsonOut{Error: "unsupported --shell"},
		},
		{
			name: "json missing command", args: []string{"check", "--json"}, wantCode: 2, noEval: true,
			wantJSON: &jsonOut{Error: "accepts 1 arg"},
		},
		{name: "no command", args: []string{"check"}, wantCode: 2, noEval: true},
		{name: "two commands", args: []string{"check", "a", "b"}, wantCode: 2, noEval: true},
		{name: "bad shell", args: []string{"check", "--shell", "fish", "ls"}, wantCode: 2, wantErr: "shell", noEval: true},
		{name: "bad flag", args: []string{"check", "--nope", "ls"}, wantCode: 2, noEval: true},
		{name: "invalid policy", policyYAML: "version: 7\n", args: []string{"check", "ls"}, wantCode: 2, wantErr: policy.FileName, noEval: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.policyYAML != "" {
				e.writePolicy(e.cwd, tc.policyYAML)
			}
			if tc.verdict.Decision != "" {
				v := tc.verdict
				e.eval = func(engine.Request) engine.Verdict { return v }
			}
			r := e.run(nil, tc.args...)
			if r.code != tc.wantCode {
				t.Fatalf("code %d want %d\nstdout %q\nstderr %q", r.code, tc.wantCode, r.stdout, r.stderr)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(r.stdout, w) {
					t.Errorf("stdout %q missing %q", r.stdout, w)
				}
			}
			if !strings.Contains(r.stderr, tc.wantErr) {
				t.Errorf("stderr %q missing %q", r.stderr, tc.wantErr)
			}
			if tc.noEval != (len(e.evalReqs) == 0) {
				t.Fatalf("engine calls = %d, noEval = %v", len(e.evalReqs), tc.noEval)
			}
			if len(e.evalReqs) == 1 {
				req := e.evalReqs[0]
				if req.Tool != engine.ToolShell || req.Cwd != e.cwd || req.ProjectRoot != e.cwd || req.Home != e.home {
					t.Errorf("unexpected request %+v", req)
				}
				if tc.wantShell != "" && req.Shell != tc.wantShell {
					t.Errorf("shell = %q, want %q", req.Shell, tc.wantShell)
				}
			}
			if tc.wantJSON != nil {
				var got jsonOut
				if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
					t.Fatalf("invalid JSON %q: %v", r.stdout, err)
				}
				if got.Decision != tc.wantJSON.Decision || got.Rule != tc.wantJSON.Rule || got.Reason != tc.wantJSON.Reason ||
					got.DefaultPolicy != tc.wantJSON.DefaultPolicy || !strings.HasSuffix(got.Policy, tc.wantJSON.Policy) ||
					got.Protected != tc.wantJSON.Protected || !strings.Contains(got.Warning, tc.wantJSON.Warning) ||
					!strings.Contains(got.Error, tc.wantJSON.Error) || (tc.wantJSON.Error == "") != (got.Error == "") {
					t.Errorf("json = %+v, want %+v", got, *tc.wantJSON)
				}
			}
		})
	}
}

func TestDoctor(t *testing.T) {
	claudeSettings := func(cmd string) string {
		b, _ := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{
			map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": cmd}}},
		}}})
		return string(b)
	}
	codexHooks := func(cmd string) string {
		b, _ := json.Marshal(map[string]any{"PreToolUse": []any{map[string]any{"type": "command", "command": cmd}}})
		return string(b)
	}
	cases := []struct {
		name     string
		setup    func(e *testEnv)
		wantCode int
		wantOut  []string
	}{
		{
			name:     "no policy",
			setup:    func(*testEnv) {},
			wantCode: 1, wantOut: []string{"✗", "agentleash init"},
		},
		{
			name: "all good",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"), claudeSettings(e.exe+" hook claude")) // .exe: marker matched loosely
				writeFile(t, filepath.Join(e.cwd, ".codex", "hooks.json"), codexHooks(`"`+e.exe+`" hook codex # agentleash hook`))
			},
			wantOut: []string{"✓", "policy is valid", "claude", "codex"},
		},
		{
			name: "plain marker form",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				bin := filepath.Join(filepath.Dir(e.exe), "agentleash")
				writeFile(t, bin, "bin")
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"), claudeSettings(bin+" hook claude"))
			},
			wantOut: []string{"✓"},
		},
		{
			name: "invalid policy",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, "version: 3\n")
			},
			wantCode: 1, wantOut: []string{"✗", "invalid"},
		},
		{
			name: "settings without our hook",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"), claudeSettings("prettier --check"))
			},
			wantCode: 1, wantOut: []string{"✗", "agentleash apply"},
		},
		{
			name: "hook binary missing",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"),
					claudeSettings(filepath.Join(e.home, "gone", "agentleash")+" hook claude"))
			},
			wantCode: 1, wantOut: []string{"✗", "not found"},
		},
		{
			name: "settings not JSON",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"), "{oops")
			},
			wantCode: 1, wantOut: []string{"✗"},
		},
		{
			name: "exec form with spaces in the binary path",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				bin := filepath.Join(t.TempDir(), "my tools", "agentleash.exe")
				writeFile(t, bin, "bin")
				b, _ := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{
					map[string]any{"matcher": "*", "hooks": []any{map[string]any{
						"type": "command", "command": bin, "args": []string{"hook", "claude"}, "onFailure": "block",
					}}},
				}}})
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"), string(b))
			},
			wantOut: []string{"✓ claude: hook installed", "my tools"},
		},
		{
			name: "exec form for another agent does not count",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				b, _ := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{
					map[string]any{"hooks": []any{map[string]any{"type": "command", "command": e.exe, "args": []string{"hook", "codex"}}}},
				}}})
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"), string(b))
			},
			wantCode: 1, wantOut: []string{"✗ claude: agentleash hook not installed"},
		},
		{
			name: "hook in settings.local.json",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.local.json"), claudeSettings(e.exe+" hook claude"))
			},
			wantOut: []string{"✓ claude: hook installed in " + filepath.Join(".claude", "settings.local.json")},
		},
		{
			name: "marker only in a non-command field does not count",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				b, _ := json.Marshal(map[string]any{"PreToolUse": []any{map[string]any{
					"type": "command", "command": "other-tool", "statusMessage": "agentleash hook: checking",
				}}})
				writeFile(t, filepath.Join(e.cwd, ".codex", "hooks.json"), string(b))
			},
			wantCode: 1, wantOut: []string{"✗ codex: agentleash hook not installed"},
		},
		{
			name: "hook binary does not run",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"), claudeSettings(e.exe+" hook claude"))
				e.deps.RunBinary = func(string, ...string) ([]byte, error) { return nil, errors.New("exec format error") }
			},
			wantCode: 1, wantOut: []string{"does not run"},
		},
		{
			name: "hook binary version differs",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
				writeFile(t, filepath.Join(e.cwd, ".claude", "settings.json"), claudeSettings(e.exe+" hook claude"))
				e.deps.RunBinary = func(string, ...string) ([]byte, error) { return []byte("agentleash 0.0.1 (commit x, go)"), nil }
			},
			wantOut: []string{"- hook binary reports", "0.0.1"},
		},
		{
			name: "no agent configured",
			setup: func(e *testEnv) {
				e.writePolicy(e.cwd, validPolicyYAML)
			},
			wantCode: 1, wantOut: []string{"no agent", "agentleash apply"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e)
			r := e.run(nil, "doctor")
			if r.code != tc.wantCode {
				t.Fatalf("code %d want %d\nstdout %s\nstderr %s", r.code, tc.wantCode, r.stdout, r.stderr)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(r.stdout, w) {
					t.Errorf("stdout missing %q:\n%s", w, r.stdout)
				}
			}
		})
	}
}

func TestHookBinaryFromCommand(t *testing.T) {
	cases := []struct{ cmd, want string }{
		{"/usr/local/bin/agentleash hook claude", "/usr/local/bin/agentleash"},
		{`"C:\Program Files\agentleash\agentleash.exe" hook codex`, `C:\Program Files\agentleash\agentleash.exe`},
		{`'/opt/my tools/agentleash' hook claude`, "/opt/my tools/agentleash"},
		{`C:\a b\agentleash.exe hook claude`, `C:\a b\agentleash.exe`},
		{"agentleash hook claude", "agentleash"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := hookBinary(tc.cmd); got != tc.want {
			t.Errorf("hookBinary(%q) = %q, want %q", tc.cmd, got, tc.want)
		}
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	e := newEnv(t)
	if r := e.run(nil, "frobnicate"); r.code != 2 {
		t.Fatalf("code %d", r.code)
	}
}
