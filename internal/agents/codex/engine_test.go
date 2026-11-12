package codex

import (
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// TestDecodeThroughEngine feeds decoded Codex payloads to the real engine with the default
// policy, end to end: the apply_patch bypasses from the PR #16 review must be denied.
func TestDecodeThroughEngine(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	eng := engine.New(policy.Default())
	tests := []struct {
		name string
		tool string
		in   map[string]any
		want engine.Decision
	}{
		{"heredoc patch moving .env through Bash", "Bash", map[string]any{"command": "apply_patch <<'EOF'\n*** Begin Patch\n" +
			"*** Update File: .env\n*** Move to: notes.txt\n@@\n-A=1\n+A=1\n*** End Patch\nEOF\n"}, engine.Deny},
		{"indented Add File header", "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Add File: ok.txt\n+x\n  *** Add File: .env\n+S=1\n*** End Patch"}, engine.Deny},
		{"benign patch", "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Update File: src/main.go\n@@\n-a\n+b\n*** End Patch"}, engine.Allow},
		{"benign shell", "Bash", map[string]any{"command": "go test ./..."}, engine.Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := Adapter{}.DecodeHook(payload(t, tt.tool, tt.in, root), root, home)
			if err != nil {
				t.Fatal(err)
			}
			if v := eng.Evaluate(req); v.Decision != tt.want {
				t.Errorf("decision = %s (%s), want %s; paths %v", v.Decision, v.Reason, tt.want, req.Paths)
			}
		})
	}
}
