// Package e2e runs end-to-end tests against the real agentleash binary: it builds
// cmd/agentleash once, installs it into throwaway projects with `init` and `apply`, and
// pipes realistic Claude Code and Codex PreToolUse payloads into `agentleash hook`.
//
// Run with: go test ./e2e/ -v
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// dummySecret is the value of the fixture .env. It must never appear in any output.
const dummySecret = "E2E_DUMMY_SECRET_VALUE"

// hookBudget is the maximum wall time of one hook call (process start included).
const hookBudget = 2 * time.Second

// binPath is the agentleash binary built by TestMain.
var binPath string

// homeDir is an isolated home directory shared by every subprocess.
var homeDir string

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	// A space in the path exercises quoting of the installed hook commands.
	tmp, err := os.MkdirTemp("", "agentleash e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: create temp dir:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	name := "agentleash"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binPath = filepath.Join(tmp, "bin dir", name)
	homeDir = filepath.Join(tmp, "home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: create home:", err)
		return 1
	}

	build := exec.Command("go", "build", "-o", binPath, "./cmd/agentleash")
	build.Dir = ".." // module root (go test runs in the package directory)
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: go build failed:", err)
		return 1
	}
	return m.Run()
}

// env is the environment of every subprocess: an isolated home and no agent project
// directory variables, so only the policies of the test project apply.
func env() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HOME", "USERPROFILE", "CLAUDE_PROJECT_DIR", "CODEX_PROJECT_DIR":
			continue
		}
		out = append(out, kv)
	}
	return append(out, "HOME="+homeDir, "USERPROFILE="+homeDir)
}

type result struct {
	stdout, stderr string
	code           int
	dur            time.Duration
}

// run executes name with args in dir, feeding stdin. It fails the test if the process
// cannot start or does not finish, and whenever the dummy secret appears in its output.
func run(t *testing.T, dir string, stdin []byte, name string, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env()
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	r := result{stdout: stdout.String(), stderr: stderr.String(), dur: time.Since(start)}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	case err != nil:
		t.Fatalf("run %s %v: %v", name, args, err)
	}
	if strings.Contains(r.stdout, dummySecret) || strings.Contains(r.stderr, dummySecret) {
		t.Errorf("%s %v leaked the dummy secret:\nstdout: %s\nstderr: %s", name, args, r.stdout, r.stderr)
	}
	return r
}

// agentleash runs the built binary in dir.
func agentleash(t *testing.T, dir string, stdin []byte, args ...string) result {
	t.Helper()
	return run(t, dir, stdin, binPath, args...)
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newProject creates a git repository with fixture files but no agentleash setup.
func newProject(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}
	dir := filepath.Join(longPath(t, t.TempDir()), "my project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if r := run(t, dir, nil, "git", "init", "-q"); r.code != 0 {
		t.Fatalf("git init: exit %d: %s", r.code, r.stderr)
	}
	writeFile(t, filepath.Join(dir, ".env"), "API_KEY="+dummySecret+"\n")
	writeFile(t, filepath.Join(dir, ".env.example"), "API_KEY=\n")
	writeFile(t, filepath.Join(dir, "src", "main.go"), "package main\n\nfunc main() {}\n")
	writeFile(t, filepath.Join(dir, "id_rsa"),
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"+dummySecret+"\n-----END OPENSSH PRIVATE KEY-----\n")
	return dir
}

// longPath expands Windows 8.3 short names (C:\Users\RUNNER~1\...) in an existing
// directory, as found in %TEMP% on GitHub's Windows runners. The short form is covered
// on its own by TestWindowsShortPathProject (see #26). Elsewhere the path is returned
// unchanged, so macOS keeps its /var -> /private/var symlink in the project path.
func longPath(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return dir
	}
	long, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return long
}

// setupProject creates a fixture project and runs `init` and `apply` in it.
func setupProject(t *testing.T) string {
	t.Helper()
	dir := newProject(t)
	if r := agentleash(t, dir, nil, "init"); r.code != 0 {
		t.Fatalf("init: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if r := agentleash(t, dir, nil, "apply"); r.code != 0 {
		t.Fatalf("apply: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	return dir
}

// hookHandler is a hook handler object as written into the agents' config files.
type hookHandler struct {
	Type           string   `json:"type"`
	Command        string   `json:"command"`
	CommandWindows string   `json:"commandWindows"`
	Args           []string `json:"args"`
	OnFailure      string   `json:"onFailure"`
}

// preToolUseHandlers returns every handler under hooks.PreToolUse[].hooks[] of a JSON file.
func preToolUseHandlers(t *testing.T, path string) []hookHandler {
	t.Helper()
	var doc struct {
		Hooks struct {
			PreToolUse []struct {
				Matcher string        `json:"matcher"`
				Hooks   []hookHandler `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(readFile(t, path), &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out []hookHandler
	for _, g := range doc.Hooks.PreToolUse {
		out = append(out, g.Hooks...)
	}
	return out
}

func sameFile(a, b string) bool {
	ia, err := os.Stat(a)
	if err != nil {
		return false
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ia, ib)
}

// claudeHook returns the agentleash handler installed in .claude/settings.json.
func claudeHook(t *testing.T, dir string) hookHandler {
	t.Helper()
	for _, h := range preToolUseHandlers(t, filepath.Join(dir, ".claude", "settings.json")) {
		if len(h.Args) == 2 && h.Args[0] == "hook" && h.Args[1] == "claude" {
			return h
		}
	}
	t.Fatalf(".claude/settings.json has no PreToolUse handler with args [hook claude]")
	return hookHandler{}
}

// codexHook returns the agentleash handler installed in .codex/hooks.json.
func codexHook(t *testing.T, dir string) hookHandler {
	t.Helper()
	for _, h := range preToolUseHandlers(t, filepath.Join(dir, ".codex", "hooks.json")) {
		if strings.HasSuffix(h.Command, " hook codex") {
			return h
		}
	}
	t.Fatalf(".codex/hooks.json has no agentleash PreToolUse handler")
	return hookHandler{}
}

func TestInitApplyDoctor(t *testing.T) {
	dir := setupProject(t)

	if _, err := os.Stat(filepath.Join(dir, ".agentleash.yaml")); err != nil {
		t.Fatalf("init did not write .agentleash.yaml: %v", err)
	}

	// Claude Code: exec-form handler whose command is the binary itself. The native
	// permission rule list is not asserted here (see the .env.* overlap fix in flight).
	h := claudeHook(t, dir)
	if h.Type != "command" {
		t.Errorf("claude hook type = %q, want command", h.Type)
	}
	if !filepath.IsAbs(h.Command) || !sameFile(h.Command, binPath) {
		t.Errorf("claude hook command = %q, want the built binary %q", h.Command, binPath)
	}
	if h.OnFailure != "block" {
		t.Errorf("claude hook onFailure = %q, want block", h.OnFailure)
	}

	// Codex: shell-form handler running `<binary> hook codex`.
	c := codexHook(t, dir)
	if !strings.Contains(c.Command, filepath.Base(filepath.Dir(binPath))) {
		t.Errorf("codex hook command %q does not reference the built binary %q", c.Command, binPath)
	}

	if r := agentleash(t, dir, nil, "doctor"); r.code != 0 {
		t.Fatalf("doctor: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
}

// hookResponse is the PreToolUse decision JSON both agents read from stdout.
type hookResponse struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// claudePayload builds a Claude Code PreToolUse stdin object.
func claudePayload(tool string, input map[string]any, cwd string) map[string]any {
	return map[string]any{
		"session_id":      "e2e-session-0001",
		"transcript_path": filepath.Join(cwd, ".e2e-transcript.jsonl"),
		"cwd":             cwd,
		"permission_mode": "default",
		"hook_event_name": "PreToolUse",
		"tool_name":       tool,
		"tool_input":      input,
		"tool_use_id":     "toolu_e2e_0001",
	}
}

// codexPayload builds a Codex PreToolUse stdin object (see internal/agents/codex).
func codexPayload(tool string, input map[string]any, cwd string) map[string]any {
	return map[string]any{
		"session_id":      "thr_e2e",
		"transcript_path": nil,
		"cwd":             cwd,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-5.5-codex",
		"permission_mode": "default",
		"turn_id":         "turn_1",
		"tool_name":       tool,
		"tool_use_id":     "call_e2e",
		"tool_input":      input,
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// hook pipes payload into `agentleash hook <agent>` run from dir and checks the time budget.
func hook(t *testing.T, dir, agent string, payload []byte) result {
	t.Helper()
	r := agentleash(t, dir, payload, "hook", agent)
	if r.dur > hookBudget {
		t.Errorf("hook %s took %v, want under %v", agent, r.dur, hookBudget)
	}
	return r
}

// assertDecision checks the hook outcome. want is "allow", "deny" or "ask".
// Codex cannot ask: an ask arrives as a deny whose reason explains it.
func assertDecision(t *testing.T, agent string, r result, want string) {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("exit %d, want 0\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if want == "allow" {
		if r.stdout != "" {
			t.Fatalf("allow must print nothing, got stdout: %s", r.stdout)
		}
		return
	}
	var resp hookResponse
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("stdout is not a hook response (%v): %q", err, r.stdout)
	}
	o := resp.HookSpecificOutput
	if o.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", o.HookEventName)
	}
	wantDecision := want
	if agent == "codex" {
		wantDecision = "deny"
	}
	if o.PermissionDecision != wantDecision {
		t.Errorf("permissionDecision = %q, want %q (reason: %s)", o.PermissionDecision, wantDecision, o.PermissionDecisionReason)
	}
	if strings.TrimSpace(o.PermissionDecisionReason) == "" {
		t.Errorf("empty permissionDecisionReason")
	}
	if agent == "codex" && want == "ask" && !strings.Contains(strings.ToLower(o.PermissionDecisionReason), "ask") {
		t.Errorf("codex ask→deny reason does not mention ask: %s", o.PermissionDecisionReason)
	}
}

// assertBlocked accepts either form of a block: exit 2 with a reason on stderr, or
// exit 0 with a deny/ask decision on stdout.
func assertBlocked(t *testing.T, r result) {
	t.Helper()
	switch r.code {
	case 2:
		if strings.TrimSpace(r.stderr) == "" {
			t.Fatalf("exit 2 with empty stderr (agents treat that as allow)")
		}
	case 0:
		var resp hookResponse
		if err := json.Unmarshal([]byte(r.stdout), &resp); err != nil {
			t.Fatalf("exit 0 without a decision JSON: %q", r.stdout)
		}
		if d := resp.HookSpecificOutput.PermissionDecision; d != "deny" && d != "ask" {
			t.Fatalf("permissionDecision = %q, want a block", d)
		}
	default:
		t.Fatalf("exit %d is not a block\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
}

type hookCase struct {
	name  string
	tool  string
	input func(dir string) map[string]any
	want  string // allow, deny, ask
	// os limits the case to one GOOS ("" = all).
	os string
	// skip marks a known product bug ("bug: ... — see #N").
	skip string
}

func cmdInput(c string) func(string) map[string]any {
	return func(string) map[string]any { return map[string]any{"command": c} }
}

func fileInput(field, rel string) func(string) map[string]any {
	return func(string) map[string]any { return map[string]any{field: rel} }
}

func absFileInput(field, rel string) func(string) map[string]any {
	return func(dir string) map[string]any {
		return map[string]any{field: filepath.Join(dir, filepath.FromSlash(rel))}
	}
}

func patchInput(lines ...string) func(string) map[string]any {
	return cmdInput(strings.Join(lines, "\n") + "\n")
}

func runHookCases(t *testing.T, agent string, cases []hookCase, payload func(string, map[string]any, string) map[string]any) {
	dir := setupProject(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.os != "" && tc.os != runtime.GOOS {
				t.Skipf("%s only", tc.os)
			}
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			r := hook(t, dir, agent, mustJSON(t, payload(tc.tool, tc.input(dir), dir)))
			assertDecision(t, agent, r, tc.want)
		})
	}
}

func TestClaudeHook(t *testing.T) {
	cases := []hookCase{
		{name: "Read .env", tool: "Read", input: absFileInput("file_path", ".env"), want: "deny"},
		{name: "Read relative .env", tool: "Read", input: fileInput("file_path", ".env"), want: "deny"},
		{name: "Read .env.example", tool: "Read", input: absFileInput("file_path", ".env.example"), want: "allow"},
		{name: "Read src/main.go", tool: "Read", input: absFileInput("file_path", "src/main.go"), want: "allow"},
		{name: "Read id_rsa", tool: "Read", input: absFileInput("file_path", "id_rsa"), want: "deny"},
		{name: "Bash cat .env", tool: "Bash", input: cmdInput("cat .env"), want: "deny"},
		{name: "Bash cat src/../.env", tool: "Bash", input: cmdInput("cat src/../.env"), want: "deny"},
		{name: "Bash bash -c cat .env", tool: "Bash", input: cmdInput(`bash -c "cat .env"`), want: "deny"},
		{name: "Bash base64 .env", tool: "Bash", input: cmdInput("base64 .env"), want: "deny"},
		{name: "Bash redirect from .env", tool: "Bash", input: cmdInput("wc -c < .env"), want: "deny"},
		{name: "Bash cp .env out", tool: "Bash", input: cmdInput("cp .env /tmp/leak.txt"), want: "deny"},
		{name: "Bash cat id_rsa", tool: "Bash", input: cmdInput("cat id_rsa"), want: "deny"},
		{name: "Bash echo GITHUB_TOKEN", tool: "Bash", input: cmdInput("echo $GITHUB_TOKEN"), want: "deny"},
		{name: "Bash printenv", tool: "Bash", input: cmdInput("printenv"), want: "deny"},
		{name: "Bash git push --force", tool: "Bash", input: cmdInput("git push --force origin main"), want: "deny"},
		{name: "Bash git reset --hard", tool: "Bash", input: cmdInput("git reset --hard"), want: "ask"},
		{name: "Bash cat .env.example", tool: "Bash", input: cmdInput("cat .env.example"), want: "allow"},
		{name: "Bash go test", tool: "Bash", input: cmdInput("go test ./..."), want: "allow"},
		{name: "Bash git status", tool: "Bash", input: cmdInput("git status"), want: "allow"},
		{name: "Bash ls -la", tool: "Bash", input: cmdInput("ls -la"), want: "allow"},
		{name: "Bash git log", tool: "Bash", input: cmdInput("git log --oneline -5"), want: "allow"},
		{
			name: "Bash cat absolute .env forward slashes", tool: "Bash", want: "deny",
			input: func(dir string) map[string]any {
				return map[string]any{"command": "cat '" + filepath.ToSlash(filepath.Join(dir, ".env")) + "'"}
			},
		},
		{
			name: "Bash cat absolute .env backslashes", tool: "Bash", want: "deny", os: "windows",
			input: func(dir string) map[string]any {
				return map[string]any{"command": "cat '" + filepath.Join(dir, ".env") + "'"}
			},
		},
		{
			name: "Grep in src", tool: "Grep", want: "allow",
			input: func(dir string) map[string]any {
				return map[string]any{"pattern": "func main", "path": filepath.Join(dir, "src")}
			},
		},
		{
			name: "Grep path .env", tool: "Grep", want: "deny",
			input: func(dir string) map[string]any {
				return map[string]any{"pattern": "API_KEY", "path": filepath.Join(dir, ".env")}
			},
		},
		{name: "Glob go files", tool: "Glob", input: fileInput("pattern", "**/*.go"), want: "allow"},
		{name: "Glob src go files", tool: "Glob", input: fileInput("pattern", "src/*.go"), want: "allow"},
		// Glob returns names only: its pattern is not checked, only its root.
		{name: "Glob json files", tool: "Glob", input: fileInput("pattern", "**/*.json"), want: "allow"},
		{name: "Glob .env* names", tool: "Glob", input: fileInput("pattern", ".env*"), want: "allow"},
		{name: "Glob in ~/.ssh", tool: "Glob", want: "deny", input: func(string) map[string]any {
			return map[string]any{"pattern": "*", "path": filepath.Join(homeDir, ".ssh")}
		}},
		// Grep reads contents: its glob filter is still checked.
		{name: "Grep glob .env*", tool: "Grep", want: "deny", input: func(string) map[string]any {
			return map[string]any{"pattern": "API_KEY", "glob": ".env*"}
		}},
		{name: "Write .env", tool: "Write", want: "deny", input: func(dir string) map[string]any {
			return map[string]any{"file_path": filepath.Join(dir, ".env"), "content": "API_KEY=x\n"}
		}},
		{name: "Write src/x.go", tool: "Write", want: "allow", input: func(dir string) map[string]any {
			return map[string]any{"file_path": filepath.Join(dir, "src", "x.go"), "content": "package main\n"}
		}},
		{name: "Edit .env", tool: "Edit", want: "deny", input: func(dir string) map[string]any {
			return map[string]any{"file_path": filepath.Join(dir, ".env"), "old_string": "A", "new_string": "B"}
		}},
		{name: "PowerShell Get-Content .env", tool: "PowerShell", input: cmdInput("Get-Content .env"), want: "deny"},
		{name: "PowerShell env var", tool: "PowerShell", input: cmdInput("Write-Output $env:GITHUB_TOKEN"), want: "deny"},
		{name: "PowerShell Get-ChildItem", tool: "PowerShell", input: cmdInput("Get-ChildItem src"), want: "allow"},
		{name: "uninspected tool", tool: "WebFetch", want: "allow", input: func(string) map[string]any {
			return map[string]any{"url": "https://example.com", "prompt": "summarise"}
		}},
	}
	runHookCases(t, "claude", cases, claudePayload)
}

func TestCodexHook(t *testing.T) {
	cases := []hookCase{
		{name: "Bash cat .env", tool: "Bash", input: cmdInput("cat .env"), want: "deny"},
		{name: "Bash cat src/../.env", tool: "Bash", input: cmdInput("cat src/../.env"), want: "deny"},
		{name: "Bash bash -c cat .env", tool: "Bash", input: cmdInput(`bash -c "cat .env"`), want: "deny"},
		{name: "Bash base64 .env", tool: "Bash", input: cmdInput("base64 .env"), want: "deny"},
		{name: "Bash cat id_rsa", tool: "Bash", input: cmdInput("cat id_rsa"), want: "deny"},
		{name: "Bash echo GITHUB_TOKEN", tool: "Bash", input: cmdInput("echo $GITHUB_TOKEN"), want: "deny"},
		{name: "Bash printenv", tool: "Bash", input: cmdInput("printenv"), want: "deny"},
		{name: "Bash git push --force", tool: "Bash", input: cmdInput("git push --force origin main"), want: "deny"},
		{name: "Bash git reset --hard", tool: "Bash", input: cmdInput("git reset --hard"), want: "ask"},
		{name: "Bash go test", tool: "Bash", input: cmdInput("go test ./..."), want: "allow"},
		{name: "Bash git status", tool: "Bash", input: cmdInput("git status"), want: "allow"},
		{name: "Bash ls -la", tool: "Bash", input: cmdInput("ls -la"), want: "allow"},
		{name: "Bash cat .env.example", tool: "Bash", input: cmdInput("cat .env.example"), want: "allow"},
		{name: "Bash rg in src", tool: "Bash", input: cmdInput("rg -n TODO src"), want: "allow"},
		{name: "PowerShell Get-Content .env", tool: "Bash", input: cmdInput("Get-Content .env"), want: "deny"},
		{name: "PowerShell env var", tool: "Bash", input: cmdInput("Write-Output $env:GITHUB_TOKEN"), want: "deny"},
		{name: "cmd type .env", tool: "Bash", input: cmdInput("type .env"), want: "deny"},
		{
			name: "Bash cat absolute .env forward slashes", tool: "Bash", want: "deny",
			input: func(dir string) map[string]any {
				return map[string]any{"command": "cat '" + filepath.ToSlash(filepath.Join(dir, ".env")) + "'"}
			},
		},
		{
			name: "Bash cat absolute .env backslashes", tool: "Bash", want: "deny", os: "windows",
			input: func(dir string) map[string]any {
				return map[string]any{"command": "cat '" + filepath.Join(dir, ".env") + "'"}
			},
		},
		{name: "exec_command cmd field", tool: "exec_command", input: func(string) map[string]any {
			return map[string]any{"cmd": "cat .env"}
		}, want: "deny"},
		{name: "argv bash -lc cat .env", tool: "Bash", input: func(string) map[string]any {
			return map[string]any{"command": []string{"bash", "-lc", "cat .env"}}
		}, want: "deny"},
		{name: "argv powershell Get-Content .env", tool: "Bash", input: func(string) map[string]any {
			return map[string]any{"command": []string{"powershell.exe", "-NoProfile", "-Command", "Get-Content .env"}}
		}, want: "deny"},
		{name: "argv git status", tool: "Bash", input: func(string) map[string]any {
			return map[string]any{"command": []string{"git", "status"}}
		}, want: "allow"},
		{name: "apply_patch add .env", tool: "apply_patch", want: "deny", input: patchInput(
			"*** Begin Patch", "*** Add File: .env", "+API_KEY=x", "*** End Patch")},
		{name: "apply_patch delete .env", tool: "apply_patch", want: "deny", input: patchInput(
			"*** Begin Patch", "*** Delete File: .env", "*** End Patch")},
		{name: "apply_patch absolute .env", tool: "apply_patch", want: "deny", input: func(dir string) map[string]any {
			return patchInput("*** Begin Patch", "*** Add File: "+filepath.Join(dir, ".env"), "+API_KEY=x", "*** End Patch")(dir)
		}},
		{name: "apply_patch update src/main.go", tool: "apply_patch", want: "allow", input: patchInput(
			"*** Begin Patch", "*** Update File: src/main.go", "@@", "-func main() {}", "+func main() { println(1) }", "*** End Patch")},
		{name: "apply_patch add src/x.go", tool: "apply_patch", want: "allow", input: patchInput(
			"*** Begin Patch", "*** Add File: src/x.go", "+package main", "*** End Patch")},
		{name: "Bash heredoc apply_patch moving .env", tool: "Bash", want: "deny", input: patchInput(
			"apply_patch <<'EOF'", "*** Begin Patch", "*** Update File: .env", "*** Move to: notes.txt",
			"@@", "-API_KEY=x", "+API_KEY=x", "*** End Patch", "EOF")},
		{name: "Bash heredoc apply_patch src/main.go", tool: "Bash", want: "allow", input: patchInput(
			"apply_patch <<'EOF'", "*** Begin Patch", "*** Update File: src/main.go",
			"@@", "-func main() {}", "+func main() { println(1) }", "*** End Patch", "EOF")},
		{name: "MCP tool", tool: "mcp__github__list_issues", want: "allow", input: func(string) map[string]any {
			return map[string]any{"repo": "example/example"}
		}},
	}
	runHookCases(t, "codex", cases, codexPayload)
}

// TestCodexHookViaShell runs the exact command line written into .codex/hooks.json
// through the shell Codex uses on POSIX systems (Windows uses cmd.exe; not covered).
func TestCodexHookViaShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell form only")
	}
	dir := setupProject(t)
	h := codexHook(t, dir)
	payload := mustJSON(t, codexPayload("Bash", map[string]any{"command": "cat .env"}, dir))
	r := run(t, dir, payload, "sh", "-c", h.Command)
	assertDecision(t, "codex", r, "deny")
	payload = mustJSON(t, codexPayload("Bash", map[string]any{"command": "git status"}, dir))
	assertDecision(t, "codex", run(t, dir, payload, "sh", "-c", h.Command), "allow")
}

// TestClaudeHookViaConfig runs the exact exec-form handler from .claude/settings.json.
func TestClaudeHookViaConfig(t *testing.T) {
	dir := setupProject(t)
	h := claudeHook(t, dir)
	payload := mustJSON(t, claudePayload("Bash", map[string]any{"command": "cat .env"}, dir))
	assertDecision(t, "claude", run(t, dir, payload, h.Command, h.Args...), "deny")
}

func TestHookFailClosed(t *testing.T) {
	dir := setupProject(t)
	for _, agent := range []string{"claude", "codex"} {
		payload := claudePayload
		if agent == "codex" {
			payload = codexPayload
		}
		t.Run(agent+"/garbage stdin", func(t *testing.T) {
			r := hook(t, dir, agent, []byte("this is {not json"))
			if r.code != 2 || strings.TrimSpace(r.stderr) == "" {
				t.Fatalf("exit %d, stderr %q; want exit 2 with a reason", r.code, r.stderr)
			}
		})
		t.Run(agent+"/empty stdin", func(t *testing.T) {
			assertBlocked(t, hook(t, dir, agent, nil))
		})
		t.Run(agent+"/no policy allows", func(t *testing.T) {
			bare := t.TempDir()
			writeFile(t, filepath.Join(bare, ".env"), "API_KEY="+dummySecret+"\n")
			r := hook(t, bare, agent, mustJSON(t, payload("Bash", map[string]any{"command": "cat .env"}, bare)))
			assertDecision(t, agent, r, "allow")
		})
		t.Run(agent+"/payload cwd outside project", func(t *testing.T) {
			outside := t.TempDir()
			secret := filepath.ToSlash(filepath.Join(dir, ".env"))
			r := hook(t, dir, agent, mustJSON(t, payload("Bash", map[string]any{"command": "cat '" + secret + "'"}, outside)))
			assertDecision(t, agent, r, "deny")
		})
	}

	t.Run("unknown agent", func(t *testing.T) {
		r := hook(t, dir, "gemini", mustJSON(t, claudePayload("Bash", map[string]any{"command": "ls"}, dir)))
		if r.code != 2 || strings.TrimSpace(r.stderr) == "" {
			t.Fatalf("exit %d, stderr %q; want exit 2 with a reason", r.code, r.stderr)
		}
	})
}

func TestHookInvalidPolicy(t *testing.T) {
	dir := setupProject(t)
	writeFile(t, filepath.Join(dir, ".agentleash.yaml"), "version: 99\nsecrets: [\n")
	for _, agent := range []string{"claude", "codex"} {
		payload := claudePayload
		if agent == "codex" {
			payload = codexPayload
		}
		t.Run(agent, func(t *testing.T) {
			r := hook(t, dir, agent, mustJSON(t, payload("Bash", map[string]any{"command": "ls"}, dir)))
			assertDecision(t, agent, r, "deny")
		})
	}
}

// agentFiles are the config files apply writes (relative to the project root).
var agentFiles = []string{
	filepath.Join(".claude", "settings.json"),
	filepath.Join(".claude", "agentleash-state.json"),
	filepath.Join(".codex", "hooks.json"),
	filepath.Join(".codex", "config.toml"),
}

// snapshot returns the content of every agent config file ("" if missing).
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range agentFiles {
		b, err := os.ReadFile(filepath.Join(dir, f))
		switch {
		case errors.Is(err, os.ErrNotExist):
			out[f] = ""
		case err != nil:
			t.Fatal(err)
		default:
			out[f] = string(b)
		}
	}
	return out
}

func TestApplyIdempotent(t *testing.T) {
	dir := setupProject(t)
	before := snapshot(t, dir)
	for _, f := range agentFiles {
		if before[f] == "" {
			t.Errorf("apply did not write %s", f)
		}
	}
	if r := agentleash(t, dir, nil, "apply"); r.code != 0 {
		t.Fatalf("second apply: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	after := snapshot(t, dir)
	for _, f := range agentFiles {
		if before[f] != after[f] {
			t.Errorf("%s changed on the second apply:\nbefore:\n%s\nafter:\n%s", f, before[f], after[f])
		}
	}
}

// jsonEqual reports whether a and b hold the same JSON value.
func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal([]byte(a), &va); err != nil {
		t.Fatalf("invalid JSON %q: %v", a, err)
	}
	if err := json.Unmarshal([]byte(b), &vb); err != nil {
		t.Fatalf("invalid JSON %q: %v", b, err)
	}
	return fmt.Sprint(va) == fmt.Sprint(vb)
}

func TestApplyRemove(t *testing.T) {
	dir := newProject(t)
	userClaude := `{"permissions":{"allow":["Bash(go test:*)"],"deny":["Read(./secrets/**)"]},"model":"opus"}`
	userCodex := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo user-hook"}]}]}}`
	writeFile(t, filepath.Join(dir, ".claude", "settings.json"), userClaude)
	writeFile(t, filepath.Join(dir, ".codex", "hooks.json"), userCodex)

	if r := agentleash(t, dir, nil, "init"); r.code != 0 {
		t.Fatalf("init: exit %d: %s", r.code, r.stderr)
	}
	if r := agentleash(t, dir, nil, "apply"); r.code != 0 {
		t.Fatalf("apply: exit %d: %s", r.code, r.stderr)
	}
	claudeHook(t, dir)
	codexHook(t, dir)

	if r := agentleash(t, dir, nil, "apply", "--remove"); r.code != 0 {
		t.Fatalf("apply --remove: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	got := snapshot(t, dir)
	if !jsonEqual(t, got[filepath.Join(".claude", "settings.json")], userClaude) {
		t.Errorf(".claude/settings.json not restored:\n%s", got[filepath.Join(".claude", "settings.json")])
	}
	if !jsonEqual(t, got[filepath.Join(".codex", "hooks.json")], userCodex) {
		t.Errorf(".codex/hooks.json not restored:\n%s", got[filepath.Join(".codex", "hooks.json")])
	}
	for f, content := range got {
		if strings.Contains(strings.ToLower(content), "agentleash") {
			t.Errorf("%s still mentions agentleash after remove:\n%s", f, content)
		}
	}
	// The Claude hook is gone, so doctor no longer finds a configured hook.
	if r := agentleash(t, dir, nil, "doctor"); r.code == 0 {
		t.Errorf("doctor exit 0 after remove, want a failure\n%s", r.stdout)
	}
}

func TestCheck(t *testing.T) {
	dir := setupProject(t)
	if r := agentleash(t, dir, nil, "check", "cat .env"); r.code != 1 {
		t.Errorf("check \"cat .env\": exit %d, want 1\n%s%s", r.code, r.stdout, r.stderr)
	}
	if r := agentleash(t, dir, nil, "check", "ls"); r.code != 0 {
		t.Errorf("check ls: exit %d, want 0\n%s%s", r.code, r.stdout, r.stderr)
	}
	for _, c := range []struct {
		cmd, want string
		code      int
	}{
		{"cat .env", "deny", 1},
		{"ls", "allow", 0},
	} {
		r := agentleash(t, dir, nil, "check", "--json", c.cmd)
		if r.code != c.code {
			t.Errorf("check --json %q: exit %d, want %d", c.cmd, r.code, c.code)
		}
		var res struct {
			Decision  string `json:"decision"`
			Rule      string `json:"rule"`
			Reason    string `json:"reason"`
			Protected bool   `json:"protected"`
		}
		if err := json.Unmarshal([]byte(r.stdout), &res); err != nil {
			t.Fatalf("check --json %q: invalid JSON (%v): %q", c.cmd, err, r.stdout)
		}
		if res.Decision != c.want || !res.Protected {
			t.Errorf("check --json %q = %+v, want decision %s, protected", c.cmd, res, c.want)
		}
		if c.want != "allow" && (res.Rule == "" || res.Reason == "") {
			t.Errorf("check --json %q: missing rule or reason: %+v", c.cmd, res)
		}
	}
}

// shortPath returns the 8.3 short form of an existing Windows directory, or "" if the
// volume does not provide one.
func shortPath(t *testing.T, dir string) string {
	t.Helper()
	r := run(t, dir, nil, "cmd", "/d", "/c", "for %I in (.) do @echo %~sI")
	if r.code != 0 {
		t.Fatalf("cmd: exit %d: %s", r.code, r.stderr)
	}
	s := strings.TrimSpace(r.stdout)
	if s == "" || !strings.Contains(s, "~") {
		return ""
	}
	return s
}

// TestWindowsShortPathProject sends payloads whose paths use the 8.3 short form of the
// project directory, as an agent started from such a directory would.
func TestWindowsShortPathProject(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	dir := setupProject(t) // ".../my project" gets a short alias (MYPROJ~1) when 8.3 names are on
	short := shortPath(t, dir)
	if short == "" {
		t.Skip("8.3 short names are disabled on this volume")
	}
	read := func(rel string) []byte {
		p := filepath.Join(short, filepath.FromSlash(rel))
		return mustJSON(t, claudePayload("Read", map[string]any{"file_path": p}, short))
	}
	assertDecision(t, "claude", hook(t, dir, "claude", read(".env")), "deny")
	assertDecision(t, "claude", hook(t, dir, "claude", read("id_rsa")), "deny")

	assertDecision(t, "claude", hook(t, dir, "claude", read(".env.example")), "allow")
	cat := mustJSON(t, codexPayload("Bash", map[string]any{"command": "cat .env.example"}, short))
	assertDecision(t, "codex", hook(t, dir, "codex", cat), "allow")
}
