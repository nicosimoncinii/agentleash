package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

// goldenBinary is a realistic Windows install path with spaces.
const goldenBinary = `C:\Program Files\agentleash\agentleash.exe`

func goldenPolicy() *policy.Policy {
	return &policy.Policy{
		Version: policy.CurrentVersion,
		Secrets: policy.Secrets{
			Files: []string{
				".env",
				".env.*",
				"**/*.pem",
				"./certs/*.key",
				"config/secrets.yml",
				"~/.aws/credentials",
				"/etc/ssl/private/**",
				`C:\Users\dev\.ssh\id_rsa`,
			},
			AllowFiles: []string{".env.example"},
		},
	}
}

// project creates a temp project, optionally seeding .claude/settings.json from testdata.
func project(t *testing.T, input string) string {
	t.Helper()
	root := t.TempDir()
	if input == "" {
		return root
	}
	writeSettings(t, root, readFile(t, filepath.Join("testdata", input)))
	return root
}

func writeSettings(t *testing.T, root string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath(root), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// golden compares got with testdata/name, rewriting it under -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want := bytes.ReplaceAll(readFile(t, path), []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch (run go test -update to accept)\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func rel(t *testing.T, root string, paths []string) []string {
	t.Helper()
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		r, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, filepath.ToSlash(r))
	}
	return out
}

func mustApply(t *testing.T, root string, p *policy.Policy) []string {
	t.Helper()
	changed, err := Adapter{}.Apply(root, p, goldenBinary)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return rel(t, root, changed)
}

func mustRemove(t *testing.T, root string) []string {
	t.Helper()
	changed, err := Adapter{}.Remove(root)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	return rel(t, root, changed)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(va, vb)
}

func denyList(t *testing.T, data []byte) []string {
	t.Helper()
	var s struct {
		Permissions struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return s.Permissions.Deny
}

type handler struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func preToolUse(t *testing.T, data []byte) [][]handler {
	t.Helper()
	var s struct {
		Hooks struct {
			PreToolUse []struct {
				Hooks []handler `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	var out [][]handler
	for _, g := range s.Hooks.PreToolUse {
		out = append(out, g.Hooks)
	}
	return out
}

var bothFiles = []string{".claude/settings.json", ".claude/" + stateFileName}

func TestApplyGolden(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "fresh", input: ""},
		{name: "existing", input: "existing/settings.input.json"},
		{name: "empty-file", input: "empty-file/settings.input.json"},
		// The user already denies .env.*: agentleash's block, including its
		// Read(!.env.example) carve-out, must come before every user rule.
		{name: "user-env-rule", input: "user-env-rule/settings.input.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := project(t, tt.input)
			changed := mustApply(t, root, goldenPolicy())
			if !slices.Equal(changed, bothFiles) {
				t.Fatalf("changed = %v, want %v", changed, bothFiles)
			}
			applied := readFile(t, settingsPath(root))
			golden(t, tt.name+"/settings.golden.json", applied)
			golden(t, tt.name+"/state.golden.json", readFile(t, statePath(root)))

			bak := settingsPath(root) + ".bak"
			if tt.input == "" {
				if exists(bak) {
					t.Fatal("backup written for a project without settings.json")
				}
			} else if !bytes.Equal(readFile(t, bak), readFile(t, filepath.Join("testdata", tt.input))) {
				t.Fatal("backup does not hold the original settings.json")
			}

			// Re-applying keeps the order and changes nothing.
			if again := mustApply(t, root, goldenPolicy()); len(again) != 0 {
				t.Fatalf("re-apply changed %v", again)
			}
			if !bytes.Equal(applied, readFile(t, settingsPath(root))) {
				t.Fatal("re-apply rewrote settings.json")
			}
		})
	}
}

func TestApplyBlockPrecedesUserRules(t *testing.T) {
	root := project(t, "user-env-rule/settings.input.json")
	mustApply(t, root, goldenPolicy())
	block, _, err := denyBlock(goldenPolicy(), root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(block, "Read(!.env.example)") || !slices.Contains(block, "Edit(!.env.example)") {
		t.Fatalf("block lacks the .env.example carve-outs: %q", block)
	}
	// Our block (negations included) first, then the user's rules in their order.
	want := append(slices.Clone(block), "Read(.env.*)", "Bash(rm -rf *)")
	if deny := denyList(t, readFile(t, settingsPath(root))); !slices.Equal(deny, want) {
		t.Fatalf("permissions.deny = %q, want %q", deny, want)
	}
	mustRemove(t, root)
	want = []string{"Read(.env.*)", "Bash(rm -rf *)"}
	if got := denyList(t, readFile(t, settingsPath(root))); !slices.Equal(got, want) {
		t.Fatalf("after Remove permissions.deny = %q, want %q", got, want)
	}
}

func TestApplySemanticNoOp(t *testing.T) {
	root := project(t, "existing/settings.input.json")
	mustApply(t, root, goldenPolicy())
	bak := readFile(t, settingsPath(root)+".bak")

	// Same JSON with CRLF line endings and 4-space indentation.
	var buf bytes.Buffer
	if err := json.Indent(&buf, readFile(t, settingsPath(root)), "", "    "); err != nil {
		t.Fatal(err)
	}
	reformatted := bytes.ReplaceAll(buf.Bytes(), []byte("\n"), []byte("\r\n"))
	writeSettings(t, root, reformatted)

	if changed := mustApply(t, root, goldenPolicy()); len(changed) != 0 {
		t.Fatalf("re-apply of a reformatted file changed %v", changed)
	}
	if !bytes.Equal(readFile(t, settingsPath(root)), reformatted) {
		t.Fatal("reformatted settings.json was rewritten")
	}
	if !bytes.Equal(readFile(t, settingsPath(root)+".bak"), bak) {
		t.Fatal(".bak was overwritten")
	}
}

func TestBackupKeepsPreAgentleashOriginal(t *testing.T) {
	root := project(t, "existing/settings.input.json")
	original := readFile(t, settingsPath(root))
	mustApply(t, root, goldenPolicy())

	smaller := goldenPolicy()
	smaller.Secrets.Files = []string{".env"}
	if changed := mustApply(t, root, smaller); len(changed) == 0 {
		t.Fatal("policy change was not applied")
	}
	mustRemove(t, root)
	if !bytes.Equal(readFile(t, settingsPath(root)+".bak"), original) {
		t.Fatal(".bak no longer holds the pre-agentleash original")
	}
}

func TestRemoveGolden(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "fresh", input: ""},
		{name: "existing", input: "existing/settings.input.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := project(t, tt.input)
			mustApply(t, root, goldenPolicy())

			changed := mustRemove(t, root)
			if !slices.Equal(changed, bothFiles) {
				t.Fatalf("changed = %v, want %v", changed, bothFiles)
			}
			got := readFile(t, settingsPath(root))
			golden(t, tt.name+"/removed.golden.json", got)
			if exists(statePath(root)) {
				t.Fatal("state file left behind")
			}
			want := []byte("{}")
			if tt.input != "" {
				want = readFile(t, filepath.Join("testdata", tt.input))
			}
			if !jsonEqual(t, got, want) {
				t.Fatalf("after remove settings differ in meaning from the original:\n%s", got)
			}

			if again := mustRemove(t, root); len(again) != 0 {
				t.Fatalf("second Remove changed %v", again)
			}
		})
	}
}

func TestApplyPolicyChangeDropsStaleRulesOnly(t *testing.T) {
	root := project(t, "existing/settings.input.json")
	mustApply(t, root, goldenPolicy())

	smaller := goldenPolicy()
	smaller.Secrets.Files = []string{".env", "**/*.pem"}
	if changed := mustApply(t, root, smaller); !slices.Equal(changed, bothFiles) {
		t.Fatalf("changed = %v, want %v", changed, bothFiles)
	}
	deny := denyList(t, readFile(t, settingsPath(root)))
	want := []string{
		"Read(.env)", "Read(*.pem)", "Edit(.env)", "Edit(*.pem)",
		"Read(.env)", "WebFetch(domain:evil.example)",
	}
	if !slices.Equal(deny, want) {
		t.Fatalf("permissions.deny = %q, want %q", deny, want)
	}

	// The user's own Read(.env) predates agentleash and must survive Remove.
	mustRemove(t, root)
	deny = denyList(t, readFile(t, settingsPath(root)))
	if want := []string{"Read(.env)", "WebFetch(domain:evil.example)"}; !slices.Equal(deny, want) {
		t.Fatalf("after Remove permissions.deny = %q, want %q", deny, want)
	}
}

func TestApplyUpdatesHookInPlace(t *testing.T) {
	root := project(t, "existing/settings.input.json")
	mustApply(t, root, goldenPolicy())
	if _, err := (Adapter{}).Apply(root, goldenPolicy(), "/usr/local/bin/agentleash"); err != nil {
		t.Fatal(err)
	}
	groups := preToolUse(t, readFile(t, settingsPath(root)))
	want := [][]handler{
		{{Command: `"$CLAUDE_PROJECT_DIR"/.claude/hooks/check.sh`}},
		{{Command: "/usr/local/bin/agentleash", Args: []string{"hook", "claude"}}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("PreToolUse = %+v, want %+v", groups, want)
	}
}

// Legacy shell-form hooks (including a double-quoted Windows .exe path with spaces,
// which does not contain HookMarker verbatim) are migrated to exec form in place and
// removed by Remove; a user's echo mentioning agentleash is left alone.
func TestLegacyShellFormHookMigrated(t *testing.T) {
	legacy, err := json.Marshal(`"C:\Program Files\agentleash\agentleash.exe" hook claude`)
	if err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[` +
		`{"matcher":"Bash","hooks":[{"type":"command","command":` + string(legacy) + `}]},` +
		`{"matcher":"Bash","hooks":[{"type":"command","command":"echo 'not agentleash hook'"}]}]}}`
	root := t.TempDir()
	writeSettings(t, root, []byte(settings))

	mustApply(t, root, goldenPolicy())
	groups := preToolUse(t, readFile(t, settingsPath(root)))
	want := [][]handler{
		{{Command: goldenBinary, Args: []string{"hook", "claude"}}},
		{{Command: "echo 'not agentleash hook'"}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("PreToolUse = %+v, want %+v", groups, want)
	}

	mustRemove(t, root)
	groups = preToolUse(t, readFile(t, settingsPath(root)))
	if want := [][]handler{{{Command: "echo 'not agentleash hook'"}}}; !reflect.DeepEqual(groups, want) {
		t.Fatalf("after Remove PreToolUse = %+v, want %+v", groups, want)
	}
}

func TestApplyErrors(t *testing.T) {
	bad := goldenPolicy()
	bad.Secrets.Files = []string{"~root/.ssh/id_rsa"}
	tests := []struct {
		name     string
		settings string
		policy   *policy.Policy
		binary   string
		wantErr  string
	}{
		{name: "invalid json", settings: `{"permissions": {`, policy: goldenPolicy(), binary: "agentleash", wantErr: "settings.json"},
		{name: "top level array", settings: `[]`, policy: goldenPolicy(), binary: "agentleash", wantErr: "object"},
		{name: "permissions not object", settings: `{"permissions": []}`, policy: goldenPolicy(), binary: "agentleash", wantErr: "permissions"},
		{name: "deny not array", settings: `{"permissions": {"deny": "Read(.env)"}}`, policy: goldenPolicy(), binary: "agentleash", wantErr: "permissions.deny"},
		{name: "hooks not object", settings: `{"hooks": []}`, policy: goldenPolicy(), binary: "agentleash", wantErr: "hooks"},
		{name: "PreToolUse not array", settings: `{"hooks": {"PreToolUse": {}}}`, policy: goldenPolicy(), binary: "agentleash", wantErr: "PreToolUse"},
		{name: "nil policy", settings: `{}`, policy: nil, binary: "agentleash", wantErr: "policy"},
		{name: "empty binary", settings: `{}`, policy: goldenPolicy(), binary: " ", wantErr: "binary"},
		{name: "bad glob", settings: `{}`, policy: bad, binary: "agentleash", wantErr: "~/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSettings(t, root, []byte(tt.settings))
			_, err := Adapter{}.Apply(root, tt.policy, tt.binary)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Apply error = %v, want it to contain %q", err, tt.wantErr)
			}
			if got := string(readFile(t, settingsPath(root))); got != tt.settings {
				t.Fatalf("settings.json modified on error: %s", got)
			}
			if exists(statePath(root)) || exists(settingsPath(root)+".bak") {
				t.Fatal("files written on error")
			}
		})
	}
}

func TestCorruptState(t *testing.T) {
	for _, content := range []string{`{not json`, `{"version": 99, "permissionsDeny": []}`} {
		root := project(t, "existing/settings.input.json")
		if err := os.WriteFile(statePath(root), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		before := readFile(t, settingsPath(root))
		for name, run := range map[string]func() error{
			"apply":  func() error { _, err := Adapter{}.Apply(root, goldenPolicy(), goldenBinary); return err },
			"remove": func() error { _, err := Adapter{}.Remove(root); return err },
		} {
			err := run()
			if err == nil || !strings.Contains(err.Error(), "delete it and re-run") {
				t.Fatalf("%s with state %q: error = %v, want recovery steps", name, content, err)
			}
		}
		if !bytes.Equal(before, readFile(t, settingsPath(root))) {
			t.Fatal("settings.json modified despite corrupt state")
		}
	}
}

func TestMissingStateWithHookWarns(t *testing.T) {
	root := project(t, "existing/settings.input.json")
	mustApply(t, root, goldenPolicy())
	if err := os.Remove(statePath(root)); err != nil {
		t.Fatal(err)
	}
	mustApply(t, root, goldenPolicy())
	notes := Adapter{}.PostApplyNotes()
	if len(notes) == 0 || !strings.Contains(notes[0], stateFileName+" was missing") || !strings.Contains(notes[0], "Read(.env.*)") {
		t.Fatalf("missing-state warning not reported: %q", notes)
	}

	// A normal apply clears the warning but keeps the standing notes.
	mustApply(t, root, goldenPolicy())
	notes = Adapter{}.PostApplyNotes()
	if !slices.Equal(notes, staticNotes) {
		t.Fatalf("notes = %q, want only the static notes", notes)
	}
}

func TestPostApplyNotes(t *testing.T) {
	mustApply(t, t.TempDir(), goldenPolicy())
	notes := strings.Join(Adapter{}.PostApplyNotes(), "\n")
	for _, want := range []string{"v2.1.295", "project root", "Commit .claude/" + stateFileName} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes missing %q:\n%s", want, notes)
		}
	}

	p := goldenPolicy()
	p.Secrets.Files = []string{"config/*.env"}
	p.Secrets.AllowFiles = []string{"config/sample.env"}
	mustApply(t, t.TempDir(), p)
	if notes := (Adapter{}).PostApplyNotes(); !strings.Contains(notes[0], `allow_files "config/sample.env" stays blocked`) {
		t.Fatalf("overlap warning missing: %q", notes)
	}
}

func TestRemoveWithoutInstall(t *testing.T) {
	root := t.TempDir()
	if changed := mustRemove(t, root); len(changed) != 0 {
		t.Fatalf("changed = %v", changed)
	}
	if exists(filepath.Join(root, ".claude")) {
		t.Fatal("Remove created .claude/")
	}

	for _, settings := range []string{
		string(readFile(t, filepath.Join("testdata", "existing", "settings.input.json"))),
		`{"permissions": {}, "hooks": {"PreToolUse": []}}`,
		`{"permissions": {"deny": []}}`,
	} {
		root = t.TempDir()
		writeSettings(t, root, []byte(settings))
		if changed := mustRemove(t, root); len(changed) != 0 {
			t.Fatalf("Remove on %s changed %v", settings, changed)
		}
	}
}

func TestResolveBinary(t *testing.T) {
	abs, err := filepath.Abs(filepath.Join("bin", "agentleash"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ in, want string }{
		{"agentleash", "agentleash"},
		{"/usr/local/bin/agentleash", "/usr/local/bin/agentleash"},
		{`C:\Program Files\agentleash\agentleash.exe`, `C:\Program Files\agentleash\agentleash.exe`},
		{"C:/tools/agentleash.exe", "C:/tools/agentleash.exe"},
		{"  agentleash  ", "agentleash"},
		{filepath.Join("bin", "agentleash"), abs},
	}
	for _, tt := range tests {
		got, err := resolveBinary(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("resolveBinary(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

// The real default policy must get native rules for every dotenv glob, with carve-outs
// for the template files, and warn only about overlaps that truly cannot be carved
// (keeping those native rules: fail closed).
func TestApplyDefaultPolicyGolden(t *testing.T) {
	userHomeDir = func() (string, error) { return "/home/dev", nil }
	t.Cleanup(func() { userHomeDir = os.UserHomeDir })

	root := t.TempDir()
	mustApply(t, root, policy.Default())
	settings := readFile(t, settingsPath(root))
	golden(t, "default-policy/settings.golden.json", settings)

	deny := denyList(t, settings)
	for _, want := range []string{
		"Read(.env)", "Read(.env.*)", "Read(.envrc)", "Read(!.env.example)", "Read(!.env.sample)",
		"Read(!.env.template)", "Read(!.env.dist)", "Read(!*.pub)", "Read(id_rsa*)",
		"Edit(.env.*)", "Edit(!.env.example)", "Read(~/.ssh/**)", "Edit(~/.ssh/**)",
	} {
		if !slices.Contains(deny, want) {
			t.Errorf("default policy: permissions.deny lacks %q", want)
		}
	}

	var warnings []string
	for _, n := range (Adapter{}).PostApplyNotes() {
		if !slices.Contains(staticNotes, n) {
			warnings = append(warnings, n)
		}
	}
	// ~/.ssh/** really overlaps ~/.ssh/*.pub; a home-anchored rule cannot be carved, so
	// the native rule is kept and the note says *.pub stays blocked natively.
	want := `allow_files "~/.ssh/*.pub" stays blocked by Claude Code's native rules Read(~/.ssh/**)/Edit(~/.ssh/**)`
	if len(warnings) != 1 || !strings.Contains(warnings[0], want) {
		t.Fatalf("default policy warnings = %q, want exactly one about %s", warnings, want)
	}
}
