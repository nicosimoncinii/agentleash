package codex

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/engine"
)

// payload builds a realistic Codex PreToolUse stdin object (see
// codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json).
func payload(t *testing.T, toolName string, toolInput any, cwd string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"session_id":      "thr_0193",
		"transcript_path": nil,
		"cwd":             cwd,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-5.5-codex",
		"permission_mode": "default",
		"turn_id":         "turn_7",
		"tool_name":       toolName,
		"tool_use_id":     "call_abc",
		"tool_input":      toolInput,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeHook(t *testing.T) {
	cwd := filepath.FromSlash("/work/proj")
	root := filepath.FromSlash("/work/proj")
	home := filepath.FromSlash("/home/dev")
	abs := func(p string) string { return filepath.Join(cwd, filepath.FromSlash(p)) }

	patch := strings.Join([]string{
		"*** Begin Patch",
		"*** Update File: src/app.go",
		"@@",
		"-old",
		"+new",
		"*** End Patch",
	}, "\n")

	tests := []struct {
		name string
		in   []byte
		want engine.Request
	}{
		{
			name: "Bash shell command",
			in:   payload(t, "Bash", map[string]any{"command": "cat .env | base64"}, cwd),
			want: engine.Request{Tool: engine.ToolShell, Command: "cat .env | base64", Shell: engine.ShellAuto},
		},
		{
			name: "exec_command tool name",
			in:   payload(t, "exec_command", map[string]any{"cmd": "printenv"}, cwd),
			want: engine.Request{Tool: engine.ToolShell, Command: "printenv", Shell: engine.ShellAuto},
		},
		{
			name: "argv array is joined with shell quoting",
			in:   payload(t, "Bash", map[string]any{"command": []string{"bash", "-lc", "cat .env && echo 'hi'"}}, cwd),
			want: engine.Request{Tool: engine.ToolShell, Command: `bash -lc 'cat .env && echo '\''hi'\'''`, Shell: engine.ShellAuto},
		},
		{
			// Codex intercepts this inside exec_command and applies the patch without a second
			// PreToolUse, so the patch paths must ride along on the shell request.
			name: "apply_patch heredoc through Bash carries patch paths",
			in: payload(t, "Bash", map[string]any{"command": "apply_patch <<'EOF'\n*** Begin Patch\n" +
				"*** Update File: .env\n*** Move to: notes.txt\n@@\n-A=1\n+A=1\n*** End Patch\nEOF\n"}, cwd),
			want: engine.Request{
				Tool:    engine.ToolShell,
				Command: "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: .env\n*** Move to: notes.txt\n@@\n-A=1\n+A=1\n*** End Patch\nEOF\n",
				Shell:   engine.ShellAuto,
				Paths:   []string{abs(".env"), abs("notes.txt")},
			},
		},
		{
			name: "cd dir && apply_patch resolves against cwd and the cd target",
			in: payload(t, "Bash", map[string]any{"command": "cd 'sub dir' && apply_patch <<'EOF'\n*** Begin Patch\n" +
				"*** Delete File: .env\n*** End Patch\nEOF"}, cwd),
			want: engine.Request{
				Tool:    engine.ToolShell,
				Command: "cd 'sub dir' && apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: .env\n*** End Patch\nEOF",
				Shell:   engine.ShellAuto,
				Paths:   []string{abs(".env"), abs("sub dir/.env")},
			},
		},
		{
			name: "apply_patch argv through Bash carries patch paths",
			in: payload(t, "Bash", map[string]any{"command": []string{"apply_patch",
				"*** Begin Patch\n*** Add File: secrets/id_rsa\n+k\n*** End Patch\n"}}, cwd),
			want: engine.Request{
				Tool:    engine.ToolShell,
				Command: "apply_patch '*** Begin Patch\n*** Add File: secrets/id_rsa\n+k\n*** End Patch\n'",
				Shell:   engine.ShellAuto,
				Paths:   []string{abs("secrets/id_rsa")},
			},
		},
		{
			name: "apply_patch tilde path is checked expanded and literal",
			in:   payload(t, "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Update File: ~/.aws/credentials\n*** End Patch"}, cwd),
			want: engine.Request{Tool: engine.ToolWrite, Paths: []string{
				filepath.Join(home, ".aws", "credentials"), abs("~/.aws/credentials"),
			}},
		},
		{
			name: "explicit bash shell field",
			in:   payload(t, "Bash", map[string]any{"command": "ls", "shell": "/bin/zsh"}, cwd),
			want: engine.Request{Tool: engine.ToolShell, Command: "ls", Shell: engine.ShellBash},
		},
		{
			name: "explicit powershell shell field",
			in:   payload(t, "Bash", map[string]any{"command": "Get-Content .env", "shell": "pwsh"}, cwd),
			want: engine.Request{Tool: engine.ToolShell, Command: "Get-Content .env", Shell: engine.ShellPowerShell},
		},
		{
			name: "powershell argv is unwrapped",
			in:   payload(t, "Bash", map[string]any{"command": []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-Command", "Get-Content .env"}}, cwd),
			want: engine.Request{Tool: engine.ToolShell, Command: "Get-Content .env", Shell: engine.ShellPowerShell},
		},
		{
			name: "apply_patch extracts paths",
			in:   payload(t, "apply_patch", map[string]any{"command": patch}, cwd),
			want: engine.Request{Tool: engine.ToolWrite, Paths: []string{abs("src/app.go")}},
		},
		{
			name: "mcp tool is other",
			in:   payload(t, "mcp__filesystem__read_file", map[string]any{"path": ".env"}, cwd),
			want: engine.Request{Tool: engine.ToolOther},
		},
		{
			name: "unknown local function tool is other",
			in:   payload(t, "update_plan", map[string]any{"plan": []any{}}, cwd),
			want: engine.Request{Tool: engine.ToolOther},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Adapter{}.DecodeHook(tt.in, root, home)
			if err != nil {
				t.Fatalf("DecodeHook: %v", err)
			}
			want := tt.want
			want.Cwd, want.ProjectRoot, want.Home = cwd, root, home
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got  %#v\nwant %#v", got, want)
			}
		})
	}
}

func TestDecodeHookErrors(t *testing.T) {
	cwd := filepath.FromSlash("/work/proj")
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"not json", []byte("cat .env")},
		{"json array", []byte(`[]`)},
		{"trailing garbage", append(payload(t, "Bash", map[string]any{"command": "ls"}, cwd), []byte(`{}`)...)},
		{"missing tool_name", []byte(`{"cwd":"/w","hook_event_name":"PreToolUse","tool_input":{"command":"ls"}}`)},
		{"wrong event", []byte(`{"cwd":"/w","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)},
		{"missing cwd", []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)},
		{"bash without command", payload(t, "Bash", map[string]any{}, cwd)},
		{"bash empty command", payload(t, "Bash", map[string]any{"command": "  "}, cwd)},
		{"bash command wrong type", payload(t, "Bash", map[string]any{"command": 42}, cwd)},
		{"bash tool_input not object", payload(t, "Bash", "ls", cwd)},
		{"argv with non-string", payload(t, "Bash", map[string]any{"command": []any{"ls", 1}}, cwd)},
		{"apply_patch without command", payload(t, "apply_patch", map[string]any{}, cwd)},
		{"apply_patch without file headers", payload(t, "apply_patch", map[string]any{"command": "*** Begin Patch\n*** End Patch"}, cwd)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := (Adapter{}).DecodeHook(tt.in, "/w", "/h"); err == nil {
				t.Fatalf("expected error, got %#v", got)
			}
		})
	}
}

type hookOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func TestEncodeVerdict(t *testing.T) {
	tests := []struct {
		name         string
		in           engine.Verdict
		wantEmpty    bool
		wantContains []string
	}{
		{name: "allow emits nothing", in: engine.Verdict{Decision: engine.Allow}, wantEmpty: true},
		{
			name:         "deny keeps reason",
			in:           engine.Verdict{Decision: engine.Deny, Reason: "reading .env is blocked; use .env.example", Rule: "secrets.files"},
			wantContains: []string{"reading .env is blocked; use .env.example"},
		},
		{
			name:         "deny with empty reason still has a reason",
			in:           engine.Verdict{Decision: engine.Deny},
			wantContains: []string{"agentleash"},
		},
		{
			name: "ask maps to deny with manual-run guidance",
			in:   engine.Verdict{Decision: engine.Ask, Reason: "piping curl into sh needs confirmation", Rule: "commands.ask"},
			wantContains: []string{
				"piping curl into sh needs confirmation",
				"cannot ask",
				"human must run the command manually",
				".agentleash.yaml",
			},
		},
		{
			name:         "unknown decision fails closed",
			in:           engine.Verdict{Decision: "maybe"},
			wantContains: []string{"agentleash"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, code := Adapter{}.EncodeVerdict(tt.in)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
			if tt.wantEmpty {
				if len(out) != 0 {
					t.Fatalf("stdout = %q, want empty", out)
				}
				return
			}
			var got hookOutput
			dec := json.NewDecoder(strings.NewReader(string(out)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("stdout %q is not the documented deny shape: %v", out, err)
			}
			h := got.HookSpecificOutput
			if h.HookEventName != "PreToolUse" || h.PermissionDecision != "deny" {
				t.Fatalf("got %+v", h)
			}
			if strings.TrimSpace(h.PermissionDecisionReason) == "" {
				t.Fatal("empty reason: Codex ignores a deny without a reason")
			}
			for _, s := range tt.wantContains {
				if !strings.Contains(h.PermissionDecisionReason, s) {
					t.Errorf("reason %q does not contain %q", h.PermissionDecisionReason, s)
				}
			}
		})
	}
}

func TestPostApplyNotes(t *testing.T) {
	notes := strings.Join(Adapter{}.PostApplyNotes(), "\n")
	for _, s := range []string{"/hooks", "trust", "guardrail", "not a sandbox"} {
		if !strings.Contains(notes, s) {
			t.Errorf("notes missing %q:\n%s", s, notes)
		}
	}
}
