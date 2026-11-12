package claude

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/engine"
)

const (
	testRoot = "/home/dev/proj"
	testHome = "/home/dev"
)

func TestName(t *testing.T) {
	if got := (Adapter{}).Name(); got != "claude" {
		t.Fatalf("Name() = %q, want claude", got)
	}
}

func TestDecodeHook(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    engine.Request
		wantErr string
	}{
		{
			name: "bash",
			payload: `{"session_id":"abc123","transcript_path":"/home/dev/.claude/projects/x.jsonl","cwd":"/home/dev/proj",
				"permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash",
				"tool_input":{"command":"cat .env | base64","description":"Show env","timeout":120000,"run_in_background":false},
				"tool_use_id":"toolu_01ABC"}`,
			want: engine.Request{Tool: engine.ToolShell, Command: "cat .env | base64", Shell: engine.ShellBash, Cwd: "/home/dev/proj"},
		},
		{
			name: "powershell",
			payload: `{"cwd":"C:\\Users\\dev\\proj","hook_event_name":"PreToolUse","tool_name":"PowerShell",
				"tool_input":{"command":"Get-Content .env","description":"Read env"}}`,
			want: engine.Request{Tool: engine.ToolShell, Command: "Get-Content .env", Shell: engine.ShellPowerShell, Cwd: `C:\Users\dev\proj`},
		},
		{
			name:    "read",
			payload: `{"cwd":"/home/dev/proj","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/home/dev/proj/.env","offset":10,"limit":50}}`,
			want:    engine.Request{Tool: engine.ToolRead, Paths: []string{"/home/dev/proj/.env"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "grep with path and glob",
			payload: `{"cwd":"/home/dev/proj","tool_name":"Grep","tool_input":{"pattern":"AWS_SECRET","path":"/home/dev/proj/config","glob":"*.env","output_mode":"content","-i":true}}`,
			want:    engine.Request{Tool: engine.ToolSearch, Paths: []string{"/home/dev/proj/config", "*.env"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "grep without path searches cwd",
			payload: `{"cwd":"/home/dev/proj","tool_name":"Grep","tool_input":{"pattern":"TODO"}}`,
			want:    engine.Request{Tool: engine.ToolSearch, Paths: []string{"/home/dev/proj"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "glob with path",
			payload: `{"cwd":"/home/dev/proj","tool_name":"Glob","tool_input":{"pattern":"**/.env*","path":"/home/dev/proj/svc"}}`,
			want:    engine.Request{Tool: engine.ToolSearch, Paths: []string{"/home/dev/proj/svc", "**/.env*"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "glob without path searches cwd",
			payload: `{"cwd":"/home/dev/proj","tool_name":"Glob","tool_input":{"pattern":"*.pem"}}`,
			want:    engine.Request{Tool: engine.ToolSearch, Paths: []string{"/home/dev/proj", "*.pem"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "edit",
			payload: `{"cwd":"/home/dev/proj","tool_name":"Edit","tool_input":{"file_path":"/home/dev/proj/main.go","old_string":"a","new_string":"b","replace_all":false}}`,
			want:    engine.Request{Tool: engine.ToolWrite, Paths: []string{"/home/dev/proj/main.go"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "multiedit",
			payload: `{"cwd":"/home/dev/proj","tool_name":"MultiEdit","tool_input":{"file_path":"/home/dev/proj/a.go","edits":[{"old_string":"a","new_string":"b"}]}}`,
			want:    engine.Request{Tool: engine.ToolWrite, Paths: []string{"/home/dev/proj/a.go"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "write",
			payload: `{"cwd":"/home/dev/proj","tool_name":"Write","tool_input":{"file_path":"/home/dev/proj/.env","content":"X=1"}}`,
			want:    engine.Request{Tool: engine.ToolWrite, Paths: []string{"/home/dev/proj/.env"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "notebook edit",
			payload: `{"cwd":"/home/dev/proj","tool_name":"NotebookEdit","tool_input":{"notebook_path":"/home/dev/proj/nb.ipynb","new_source":"print(1)","edit_mode":"replace"}}`,
			want:    engine.Request{Tool: engine.ToolWrite, Paths: []string{"/home/dev/proj/nb.ipynb"}, Cwd: "/home/dev/proj"},
		},
		{
			name:    "other tool",
			payload: `{"cwd":"/home/dev/proj","tool_name":"WebFetch","tool_input":{"url":"https://example.com","prompt":"summarise"}}`,
			want:    engine.Request{Tool: engine.ToolOther, Cwd: "/home/dev/proj"},
		},
		{
			name:    "mcp tool without tool_input",
			payload: `{"cwd":"/home/dev/proj","tool_name":"mcp__memory__create_entities"}`,
			want:    engine.Request{Tool: engine.ToolOther, Cwd: "/home/dev/proj"},
		},
		{name: "invalid json", payload: `{"tool_name":`, wantErr: "decode"},
		{name: "empty payload", payload: ``, wantErr: "decode"},
		{name: "not an object", payload: `[]`, wantErr: "decode"},
		{name: "missing tool_name", payload: `{"cwd":"/p","tool_input":{}}`, wantErr: "tool_name"},
		{name: "missing cwd", payload: `{"tool_name":"Bash","tool_input":{"command":"ls"}}`, wantErr: "cwd"},
		{name: "bash missing command", payload: `{"cwd":"/p","tool_name":"Bash","tool_input":{}}`, wantErr: "command"},
		{name: "bash empty command", payload: `{"cwd":"/p","tool_name":"Bash","tool_input":{"command":""}}`, wantErr: "command"},
		{name: "bash command wrong type", payload: `{"cwd":"/p","tool_name":"Bash","tool_input":{"command":["cat",".env"]}}`, wantErr: "command"},
		{name: "bash missing tool_input", payload: `{"cwd":"/p","tool_name":"Bash"}`, wantErr: "tool_input"},
		{name: "bash tool_input not object", payload: `{"cwd":"/p","tool_name":"Bash","tool_input":"cat .env"}`, wantErr: "tool_input"},
		{name: "read missing file_path", payload: `{"cwd":"/p","tool_name":"Read","tool_input":{"path":".env"}}`, wantErr: "file_path"},
		{name: "grep path wrong type", payload: `{"cwd":"/p","tool_name":"Grep","tool_input":{"pattern":"x","path":42}}`, wantErr: "path"},
		{name: "grep glob wrong type", payload: `{"cwd":"/p","tool_name":"Grep","tool_input":{"pattern":"x","glob":true}}`, wantErr: "glob"},
		{name: "glob missing pattern", payload: `{"cwd":"/p","tool_name":"Glob","tool_input":{"path":"/p"}}`, wantErr: "pattern"},
		{name: "notebook missing path", payload: `{"cwd":"/p","tool_name":"NotebookEdit","tool_input":{"file_path":"/p/nb.ipynb"}}`, wantErr: "notebook_path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Adapter{}.DecodeHook([]byte(tt.payload), testRoot, testHome)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("DecodeHook() = %+v, want error containing %q", got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DecodeHook() error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeHook() unexpected error: %v", err)
			}
			want := tt.want
			want.ProjectRoot, want.Home = testRoot, testHome
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("DecodeHook()\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestEncodeVerdict(t *testing.T) {
	tests := []struct {
		name     string
		verdict  engine.Verdict
		wantJSON string // empty means no stdout at all
	}{
		{
			name:     "allow defers to the normal permission flow",
			verdict:  engine.Verdict{Decision: engine.Allow},
			wantJSON: "",
		},
		{
			name:     "deny",
			verdict:  engine.Verdict{Decision: engine.Deny, Reason: "reading .env is blocked by agentleash; use .env.example", Rule: ".env"},
			wantJSON: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"reading .env is blocked by agentleash; use .env.example"}}`,
		},
		{
			name:     "ask",
			verdict:  engine.Verdict{Decision: engine.Ask, Reason: "curl piped to sh requires confirmation", Rule: "curl * | sh"},
			wantJSON: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"curl piped to sh requires confirmation"}}`,
		},
		{
			name:     "deny without reason gets a default reason",
			verdict:  engine.Verdict{Decision: engine.Deny},
			wantJSON: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"blocked by agentleash policy"}}`,
		},
		{
			name:     "unknown decision fails closed",
			verdict:  engine.Verdict{Decision: "maybe", Reason: "x"},
			wantJSON: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"agentleash: unknown decision \"maybe\"; blocking (fail closed)"}}`,
		},
		{
			name:     "html characters are not escaped",
			verdict:  engine.Verdict{Decision: engine.Deny, Reason: "a <b> & c"},
			wantJSON: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"a <b> & c"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, code := Adapter{}.EncodeVerdict(tt.verdict)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
			if tt.wantJSON == "" {
				if len(out) != 0 {
					t.Fatalf("stdout = %q, want empty", out)
				}
				return
			}
			if !json.Valid(out) {
				t.Fatalf("stdout is not valid JSON: %q", out)
			}
			if got := strings.TrimSpace(string(out)); got != tt.wantJSON {
				t.Fatalf("stdout\n got %s\nwant %s", got, tt.wantJSON)
			}
		})
	}
}
