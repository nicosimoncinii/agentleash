package agents

import "testing"

func TestIsAgentleashCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		agent   string
		want    bool
	}{
		// Exec form (what adapters install).
		{"exec unix", "/usr/local/bin/agentleash", []string{"hook", "claude"}, "claude", true},
		{"exec windows exe with spaces", `C:\Program Files\agentleash\agentleash.exe`, []string{"hook", "claude"}, "claude", true},
		{"exec upper-case exe", `C:\Tools\AgentLeash.EXE`, []string{"hook", "codex"}, "codex", true},
		{"exec forward slashes on windows", "C:/tools/agentleash.exe", []string{"hook", "claude"}, "claude", true},
		{"exec bare name", "agentleash", []string{"hook", "claude"}, "claude", true},
		{"exec any agent", "agentleash", []string{"hook", "codex"}, "", true},
		{"exec other agent", "agentleash", []string{"hook", "codex"}, "claude", false},
		{"exec other subcommand", "agentleash", []string{"check", "claude"}, "claude", false},
		{"exec other binary", "/usr/bin/my-agentleash", []string{"hook", "claude"}, "claude", false},
		{"exec too few args", "agentleash", []string{"hook"}, "claude", false},

		// Legacy shell form.
		{"shell plain", "agentleash hook claude", nil, "claude", true},
		{"shell path", "/usr/local/bin/agentleash hook claude", nil, "claude", true},
		{"shell double-quoted exe with spaces", `"C:\Program Files\agentleash\agentleash.exe" hook claude`, nil, "claude", true},
		{"shell single-quoted exe", `'C:\Users\simon\go\bin\agentleash.exe' hook claude`, nil, "claude", true},
		{"shell extra args", "agentleash hook claude --verbose", nil, "claude", true},
		{"shell other agent", "agentleash hook codex", nil, "claude", false},
		{"shell any agent", "agentleash hook codex", nil, "", true},
		{"shell echo mention", "echo 'not agentleash hook'", nil, "", false},
		{"shell echo mention with agent", "echo agentleash hook claude", nil, "claude", false},
		{"shell prefixed name", "my-agentleash hook x", nil, "", false},
		{"shell user script", `"$CLAUDE_PROJECT_DIR"/.claude/hooks/check.sh`, nil, "claude", false},
		{"shell check subcommand", "agentleash check 'rm -rf /'", nil, "", false},
		{"empty", "", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAgentleashCommand(tt.command, tt.args, tt.agent); got != tt.want {
				t.Fatalf("IsAgentleashCommand(%q, %q, %q) = %v, want %v", tt.command, tt.args, tt.agent, got, tt.want)
			}
		})
	}
}
