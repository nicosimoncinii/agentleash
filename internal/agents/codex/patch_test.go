package codex

import (
	"reflect"
	"testing"
)

func TestPatchPaths(t *testing.T) {
	tests := []struct {
		name  string
		patch string
		want  []string
	}{
		{
			name: "update add delete move",
			patch: "*** Begin Patch\n" +
				"*** Add File: docs/new.md\n" +
				"+hello\n" +
				"*** Update File: src/main.go\n" +
				"*** Move to: src/cmd/main.go\n" +
				"@@ func main() {\n" +
				"-\told()\n" +
				"+\tnew()\n" +
				"*** Delete File: .env\n" +
				"*** End Patch\n",
			want: []string{"docs/new.md", "src/main.go", "src/cmd/main.go", ".env"},
		},
		{
			name:  "CRLF and surrounding whitespace",
			patch: "*** Begin Patch\r\n*** Update File:   config/app.yaml  \r\n@@\r\n-a\r\n+b\r\n*** End Patch\r\n",
			want:  []string{"config/app.yaml"},
		},
		{
			name:  "paths with spaces and absolute paths",
			patch: "*** Begin Patch\n*** Add File: my notes/todo.txt\n+x\n*** Delete File: /home/dev/.aws/credentials\n*** End Patch",
			want:  []string{"my notes/todo.txt", "/home/dev/.aws/credentials"},
		},
		{
			name:  "heredoc invocation form",
			patch: "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: a.txt\n@@\n-x\n+y\n*** End Patch\nEOF\n",
			want:  []string{"a.txt"},
		},
		{
			name:  "duplicates are reported once",
			patch: "*** Begin Patch\n*** Update File: a.txt\n@@\n-x\n+y\n*** Update File: a.txt\n@@\n-y\n+z\n*** End Patch",
			want:  []string{"a.txt"},
		},
		{
			name: "added or removed lines that look like headers are not headers",
			patch: "*** Begin Patch\n*** Update File: a.txt\n@@\n" +
				"+*** Delete File: not-a-header\n" +
				"-*** Add File: also-not\n" +
				"*** End Patch",
			want: []string{"a.txt"},
		},
		{
			// Codex's streaming parser matches headers on line.trim() outside Update hunks.
			name:  "indented header inside an Add hunk",
			patch: "*** Begin Patch\n*** Add File: ok.txt\n+x\n  *** Add File: .env\n+S=1\n*** End Patch",
			want:  []string{"ok.txt", ".env"},
		},
		{
			name:  "tab-indented header after Begin Patch",
			patch: "*** Begin Patch\n\t*** Delete File: .env\n*** End Patch",
			want:  []string{".env"},
		},
		{
			name:  "indented header inside a Delete hunk",
			patch: "*** Begin Patch\n*** Delete File: old.txt\n   *** Update File: .env\n*** Move to: public.txt\n*** End Patch",
			want:  []string{"old.txt", ".env", "public.txt"},
		},
		{
			// Inside an Update hunk this is a context line for Codex; reporting it is a safe over-approximation.
			name:  "indented header inside an Update hunk is over-approximated",
			patch: "*** Begin Patch\n*** Update File: a.txt\n@@\n *** Add File: context-line\n*** End Patch",
			want:  []string{"a.txt", "context-line"},
		},
		{name: "no headers", patch: "*** Begin Patch\n*** End Patch", want: nil},
		{name: "empty header path", patch: "*** Begin Patch\n*** Update File:   \n*** End Patch", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := patchPaths(tt.patch)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
