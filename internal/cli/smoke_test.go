package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSmokeRealClaudeAdapterEngineAndDefaultPolicy runs init -> apply --agent claude ->
// hook with the REAL policy package, engine and Claude Code adapter in a temp project.
func TestSmokeRealClaudeAdapterEngineAndDefaultPolicy(t *testing.T) {
	project := t.TempDir()
	home := t.TempDir()
	exe := filepath.Join(t.TempDir(), "agentleash.exe")
	writeFile(t, exe, "binary")
	writeFile(t, filepath.Join(project, ".env"), "API_TOKEN=dummy-not-a-secret\n")

	run := func(stdin string, args ...string) result {
		t.Helper()
		deps := Deps{
			Getwd:       func() (string, error) { return project, nil },
			UserHomeDir: func() (string, error) { return home, nil },
			Executable:  func() (string, error) { return exe, nil },
			LookPath:    func(string) (string, error) { return "", errors.New("not on PATH") },
			Getenv:      func(string) string { return "" }, // ignore the real CLAUDE_PROJECT_DIR
			RunBinary: func(string, ...string) ([]byte, error) {
				return []byte("agentleash dev (commit none, go)"), nil
			},
			// Adapters, FindPolicy, LoadPolicy and NewEvaluator: real defaults.
		}
		var out, errb bytes.Buffer
		cmd := NewRootCmd(deps)
		cmd.SetIn(strings.NewReader(stdin))
		cmd.SetOut(&out)
		cmd.SetErr(&errb)
		cmd.SetArgs(args)
		code := Execute(cmd)
		return result{stdout: out.String(), stderr: errb.String(), code: code}
	}

	if r := run("", "init"); r.code != 0 {
		t.Fatalf("init: code %d stderr %q", r.code, r.stderr)
	}
	if r := run("", "apply", "--agent", "claude"); r.code != 0 {
		t.Fatalf("apply: code %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
	settings := readFile(t, filepath.Join(project, ".claude", "settings.json"))
	if !strings.Contains(settings, `"hook"`) || !strings.Contains(settings, "claude") {
		t.Fatalf("settings.json has no agentleash hook:\n%s", settings)
	}
	if r := run("", "doctor"); !strings.Contains(r.stdout, "✓ claude: hook installed") {
		t.Errorf("doctor does not see the exec-form hook (code %d):\n%s\nstderr: %s\nsettings: %s", r.code, r.stdout, r.stderr, settings)
	}

	bash := func(command string) string {
		b, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": project,
			"tool_input": map[string]any{"command": command},
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	r := run(bash("cat .env"), "hook", "claude")
	assertHookContract(t, r)
	blockedOut := r.code == 2 || strings.Contains(r.stdout, `"deny"`) || strings.Contains(r.stdout, `"ask"`)
	if !blockedOut {
		t.Fatalf("cat .env was not blocked: code %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
	if strings.Contains(r.stdout+r.stderr, "dummy-not-a-secret") {
		t.Fatal("secret value leaked")
	}

	r = run(bash("ls"), "hook", "claude")
	assertHookContract(t, r)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("ls: want exit 0 with empty stdout, got code %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}

	if _, err := os.Stat(filepath.Join(project, ".agentleash.yaml")); err != nil {
		t.Fatal(err)
	}
}
