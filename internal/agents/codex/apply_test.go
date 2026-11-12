package codex

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files under testdata/")

func testPolicy(env ...string) *policy.Policy {
	return &policy.Policy{
		Version: policy.CurrentVersion,
		Secrets: policy.Secrets{Files: []string{".env"}, Env: env},
	}
}

var defaultEnv = []string{"*_KEY", "*_SECRET*", "*_TOKEN", "*PASSWORD*"}

// Golden layout: testdata/<case>/before/ is copied to <root>/.codex/ (absent = fresh project);
// testdata/<case>/apply/ and testdata/<case>/remove/ hold the expected .codex/ contents.
func TestApplyRemoveGolden(t *testing.T) {
	tests := []struct {
		name   string
		binary string
		env    []string
		// files Apply / Remove must report as changed (relative to .codex/).
		applyChanged, removeChanged []string
	}{
		{
			name: "fresh", binary: "/usr/local/bin/agentleash", env: defaultEnv,
			applyChanged:  []string{"config.toml", "hooks.json"},
			removeChanged: []string{"config.toml", "hooks.json"},
		},
		{
			name: "windows-binary", binary: `C:\Program Files\agentleash\agentleash.exe`, env: defaultEnv,
			applyChanged:  []string{"config.toml", "hooks.json"},
			removeChanged: []string{"config.toml", "hooks.json"},
		},
		{
			name: "existing-user-config", binary: "/opt/my tools/agentleash", env: defaultEnv,
			applyChanged:  []string{"config.toml", "hooks.json"},
			removeChanged: []string{"config.toml", "hooks.json"},
		},
		{
			name: "legacy-exclude-array", binary: "/usr/local/bin/agentleash", env: defaultEnv,
			applyChanged:  []string{"config.toml", "hooks.json"},
			removeChanged: []string{"config.toml", "hooks.json"},
		},
		{
			name: "legacy-include-only", binary: "/usr/local/bin/agentleash", env: defaultEnv,
			applyChanged:  []string{"config.toml", "hooks.json"},
			removeChanged: []string{"config.toml", "hooks.json"},
		},
		{
			name: "stale-agentleash-entries", binary: "/usr/local/bin/agentleash", env: []string{"*_TOKEN", "DATABASE_URL"},
			applyChanged:  []string{"config.toml", "hooks.json"},
			removeChanged: []string{"config.toml", "hooks.json"},
		},
		{
			name: "no-env-globs", binary: "/usr/local/bin/agentleash", env: nil,
			applyChanged:  []string{"hooks.json"},
			removeChanged: []string{"hooks.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caseDir := filepath.Join("testdata", tt.name)
			root := t.TempDir()
			codexDir := filepath.Join(root, ".codex")
			before := readTree(t, filepath.Join(caseDir, "before"))
			writeTree(t, codexDir, before)
			p := testPolicy(tt.env...)

			changed, err := Adapter{}.Apply(root, p, tt.binary)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			assertChanged(t, codexDir, changed, tt.applyChanged)
			afterApply := readTree(t, codexDir)
			for name, data := range before {
				if bak, ok := afterApply[name+".bak"]; ok && !bytes.Equal(bak, data) {
					t.Errorf("%s.bak does not hold the original content", name)
				} else if !ok && !bytes.Equal(afterApply[name], data) {
					t.Errorf("%s was modified without a .bak backup", name)
				}
			}
			checkGolden(t, filepath.Join(caseDir, "apply"), withoutBackups(afterApply))

			// Re-applying is a no-op.
			changed, err = Adapter{}.Apply(root, p, tt.binary)
			if err != nil {
				t.Fatalf("second Apply: %v", err)
			}
			if len(changed) != 0 {
				t.Errorf("second Apply changed %v, want nothing", changed)
			}
			if again := readTree(t, codexDir); !reflect.DeepEqual(again, afterApply) {
				t.Error("second Apply modified files")
			}

			changed, err = Adapter{}.Remove(root)
			if err != nil {
				t.Fatalf("Remove: %v", err)
			}
			assertChanged(t, codexDir, changed, tt.removeChanged)
			checkGolden(t, filepath.Join(caseDir, "remove"), withoutBackups(readTree(t, codexDir)))

			// Removing again is a no-op.
			changed, err = Adapter{}.Remove(root)
			if err != nil {
				t.Fatalf("second Remove: %v", err)
			}
			if len(changed) != 0 {
				t.Errorf("second Remove changed %v, want nothing", changed)
			}
		})
	}
}

func TestApplyRejectsUnsafeConfig(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{"invalid hooks.json", map[string]string{"hooks.json": `{"hooks": {"PreToolUse": [`}},
		{"hooks.json not an object", map[string]string{"hooks.json": `[]`}},
		{"hooks not an object", map[string]string{"hooks.json": `{"hooks": []}`}},
		{"PreToolUse not an array", map[string]string{"hooks.json": `{"hooks": {"PreToolUse": {}}}`}},
		{"invalid config.toml", map[string]string{"config.toml": "model = \n"}},
		{"inline shell_environment_policy", map[string]string{"config.toml": "shell_environment_policy = { inherit = \"core\" }\n"}},
		{"dotted filters key", map[string]string{"config.toml": "shell_environment_policy.filters.AWS_X = \"exclude\"\n"}},
		{"unterminated managed block", map[string]string{"config.toml": tomlBegin + "\n[shell_environment_policy.filters]\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			codexDir := filepath.Join(root, ".codex")
			in := map[string][]byte{}
			for k, v := range tt.files {
				in[k] = []byte(v)
			}
			writeTree(t, codexDir, in)
			if _, err := (Adapter{}).Apply(root, testPolicy(defaultEnv...), "/bin/agentleash"); err == nil {
				t.Fatal("Apply succeeded, want error")
			}
			for k, v := range in {
				got, err := os.ReadFile(filepath.Join(codexDir, k))
				if err != nil || !bytes.Equal(got, v) {
					t.Errorf("%s was modified despite the error", k)
				}
			}
		})
	}
}

func TestStripRefusesUnsafeBlocks(t *testing.T) {
	ours := block([]string{`"*_KEY" = "exclude"`}, "\n")
	tests := map[string]string{
		// Markers inside a multi-line string: stripping would eat the user's string content.
		"genuine block inside multi-line string": "s = \"\"\"\n" + ours + "\n\"\"\"\n",
		"tampered block inside multi-line string": "s = \"\"\"\n" + tomlBegin + "\nhello\n" +
			strings.SplitAfter(ours, "\n")[2] + "\n\"\"\"\n",
		// The user added their own key inside our block: Remove/re-Apply would drop it.
		"user key added inside our block": "[shell_environment_policy.filters]\n" +
			strings.Replace(ours, "\n", "\n\"MY_DB_URL\" = \"exclude\"\n", 1) + "\n",
		"end marker without checksum":    "[shell_environment_policy.filters]\n" + tomlBegin + "\n\"*_KEY\" = \"exclude\"\n# <<< agentleash hook <<<\n",
		"begin marker not at line start": "x = 1 " + ours + "\n",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			for _, env := range [][]string{nil, defaultEnv} {
				root := t.TempDir()
				codexDir := filepath.Join(root, ".codex")
				writeTree(t, codexDir, map[string][]byte{"config.toml": []byte(in)})
				var err error
				if env == nil {
					_, err = Adapter{}.Remove(root)
				} else {
					_, err = Adapter{}.Apply(root, testPolicy(env...), "/bin/agentleash")
				}
				if err == nil {
					t.Fatalf("env=%v: want error", env)
				}
				if got, _ := os.ReadFile(filepath.Join(codexDir, "config.toml")); string(got) != in {
					t.Errorf("env=%v: config.toml modified despite error", env)
				}
			}
		})
	}
}

func TestFilterConflictWarnings(t *testing.T) {
	tests := []struct {
		name, in      string
		wantWarn      []string
		wantAdded     []string
		wantNotAdded  []string
		wantNoWarning bool
	}{
		{
			name:         "same key with include value blocks our exclude",
			in:           "[shell_environment_policy.filters]\n\"*_token\" = \"include\"\n",
			wantWarn:     []string{`"*_token" = "include"`, `*_TOKEN`},
			wantAdded:    []string{`"*_KEY"`},
			wantNotAdded: []string{`"*_TOKEN"`},
		},
		{
			name:      "include of a name our glob matches",
			in:        "[shell_environment_policy.filters]\n\"GITHUB_TOKEN\" = \"include\"\n",
			wantWarn:  []string{`GITHUB_TOKEN`, `*_TOKEN`},
			wantAdded: []string{`"*_TOKEN"`},
		},
		{
			name:     "legacy include_only entry matched by our glob",
			in:       "[shell_environment_policy]\ninclude_only = [\"PATH\", \"NPM_TOKEN\"]\n",
			wantWarn: []string{`NPM_TOKEN`, `*_TOKEN`},
		},
		{
			name:          "matching exclude is not a conflict",
			in:            "[shell_environment_policy.filters]\n\"*_Token\" = \"Exclude\"\n",
			wantNotAdded:  []string{`"*_TOKEN"`},
			wantNoWarning: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			codexDir := filepath.Join(root, ".codex")
			writeTree(t, codexDir, map[string][]byte{"config.toml": []byte(tt.in)})
			a := Adapter{}
			if _, err := a.Apply(root, testPolicy(defaultEnv...), "/bin/agentleash"); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(filepath.Join(codexDir, "config.toml"))
			for _, s := range tt.wantAdded {
				if !strings.Contains(string(got), s) {
					t.Errorf("config.toml lacks %s:\n%s", s, got)
				}
			}
			for _, s := range tt.wantNotAdded {
				if strings.Contains(string(got), s) {
					t.Errorf("config.toml should not contain %s:\n%s", s, got)
				}
			}
			notes := a.PostApplyNotes()
			var warnings []string
			for _, n := range notes {
				if strings.HasPrefix(n, "Warning:") {
					warnings = append(warnings, n)
				}
			}
			if tt.wantNoWarning && len(warnings) > 0 {
				t.Errorf("unexpected warnings: %q", warnings)
			}
			joined := strings.Join(warnings, "\n")
			for _, s := range tt.wantWarn {
				if !strings.Contains(joined, s) {
					t.Errorf("warnings %q do not mention %s", warnings, s)
				}
			}
		})
	}
}

func TestApplyRejectsCmdExpandedBinary(t *testing.T) {
	for _, bin := range []string{`C:\Users\a%USERNAME%b\agentleash.exe`, `C:\tools!\agentleash.exe`} {
		root := t.TempDir()
		if _, err := (Adapter{}).Apply(root, testPolicy(defaultEnv...), bin); err == nil {
			t.Errorf("Apply(%q) succeeded, want error", bin)
		}
		if _, err := os.Stat(filepath.Join(root, ".codex")); !os.IsNotExist(err) {
			t.Errorf("Apply(%q) wrote files despite the error", bin)
		}
	}
}

func TestEditConfigRoundTrip(t *testing.T) {
	inputs := map[string]string{
		"crlf with filters":   "# c\r\n[shell_environment_policy.filters]\r\n\"AWS_*\" = \"exclude\"\r\n",
		"crlf no trailing nl": "model = \"x\"\r\n[shell_environment_policy]\r\ninherit = \"core\"",
		"header at eof":       "[shell_environment_policy.filters]",
		"dotted root table":   "shell_environment_policy.inherit = \"core\"\n",
		"quoted header":       "[ \"shell_environment_policy\" . filters ] # c\n\"A\" = \"exclude\"\n",
		"dotted exclude":      "shell_environment_policy.exclude = [\"A\"]\n",
		"empty file":          "",
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			out, _, err := editConfig([]byte(in), defaultEnv)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			again, _, err := editConfig(out, defaultEnv)
			if err != nil || !bytes.Equal(again, out) {
				t.Fatalf("re-apply not idempotent (err %v):\n%q\n%q", err, out, again)
			}
			back, _, err := editConfig(out, nil)
			if err != nil {
				t.Fatalf("remove: %v", err)
			}
			// Remove restores the user's text, modulo trailing newlines and (for legacy
			// arrays) the line break after '['.
			norm := func(s string) string {
				return strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "[\n", "["), "\n")
			}
			if norm(string(back)) != norm(in) {
				t.Errorf("remove did not restore input:\n got %q\nwant %q", back, in)
			}
		})
	}
}

func TestHookCommandQuoting(t *testing.T) {
	tests := []struct {
		binary, posix, windows string
	}{
		{"agentleash", "agentleash hook codex", "agentleash hook codex"},
		{"/usr/local/bin/agentleash", "/usr/local/bin/agentleash hook codex", "/usr/local/bin/agentleash hook codex"},
		{"/opt/my tools/agentleash", "'/opt/my tools/agentleash' hook codex", `"/opt/my tools/agentleash" hook codex`},
		{"/opt/it's/agentleash", `'/opt/it'\''s/agentleash' hook codex`, `/opt/it's/agentleash hook codex`},
		{`C:\a&b\agentleash.exe`, `'C:\a&b\agentleash.exe' hook codex`, `"C:\a&b\agentleash.exe" hook codex`},
		{`C:\Program Files\agentleash\agentleash.exe`, `'C:\Program Files\agentleash\agentleash.exe' hook codex`, `"C:\Program Files\agentleash\agentleash.exe" hook codex`},
		{`C:\tools\agentleash.exe`, `'C:\tools\agentleash.exe' hook codex`, `C:\tools\agentleash.exe hook codex`},
	}
	for _, tt := range tests {
		if got := hookCommand(tt.binary); got != tt.posix {
			t.Errorf("hookCommand(%q) = %q, want %q", tt.binary, got, tt.posix)
		}
		if got := hookCommandWindows(tt.binary); got != tt.windows {
			t.Errorf("hookCommandWindows(%q) = %q, want %q", tt.binary, got, tt.windows)
		}
	}
}

func TestIsOurHandler(t *testing.T) {
	handler := func(kv ...string) *object {
		o := newObject()
		for i := 0; i < len(kv); i += 2 {
			o.set(kv[i], kv[i+1])
		}
		return o
	}
	tests := []struct {
		name string
		h    any
		want bool
	}{
		{"quoted windows path with spaces and .exe, no statusMessage",
			handler("type", "command", "command", `"C:\Program Files\agentleash\agentleash.exe" hook codex`), true},
		{"only commandWindows is quoted .exe",
			handler("type", "command", "command", "./x", "commandWindows", `"C:\Program Files\agentleash\agentleash.exe" hook codex`), true},
		{"single-quoted posix path", handler("type", "command", "command", `'/opt/my tools/agentleash' hook codex`), true},
		{"plain marker", handler("type", "command", "command", "agentleash hook codex"), true},
		{"marker only in statusMessage", handler("type", "command", "command", "/x/guard", "statusMessage", hookStatusMessage), true},
		{"user hook", handler("type", "command", "command", "./scripts/audit.sh"), false},
		{"user hook mentioning agentleash", handler("type", "command", "command", "agentleash check ls"), false},
		{"not an object", "agentleash hook codex", false},
	}
	for _, tt := range tests {
		if got := isOurHandler(tt.h); got != tt.want {
			t.Errorf("%s: isOurHandler = %v, want %v", tt.name, got, tt.want)
		}
	}

	// Apply over a hand-written quoted .exe entry replaces it instead of duplicating it.
	root := t.TempDir()
	codexDir := filepath.Join(root, ".codex")
	writeTree(t, codexDir, map[string][]byte{"hooks.json": []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[` +
		`{"type":"command","command":"\"C:\\Program Files\\agentleash\\agentleash.exe\" hook codex"}]}]}}`)})
	bin := `C:\Program Files\agentleash\agentleash.exe`
	if _, err := (Adapter{}).Apply(root, testPolicy(), bin); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(codexDir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), `"type": "command"`); n != 1 {
		t.Errorf("want exactly one handler after Apply, got %d:\n%s", n, data)
	}
	if _, err := (Adapter{}).Remove(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(codexDir, "hooks.json")); !os.IsNotExist(err) {
		t.Errorf("hooks.json should be deleted after Remove, stat err = %v", err)
	}
}

func assertChanged(t *testing.T, codexDir string, got, want []string) {
	t.Helper()
	var rel []string
	for _, p := range got {
		r, err := filepath.Rel(codexDir, p)
		if err != nil {
			t.Fatal(err)
		}
		rel = append(rel, filepath.ToSlash(r))
	}
	sort.Strings(rel)
	if !reflect.DeepEqual(rel, want) {
		t.Errorf("changed = %v, want %v", rel, want)
	}
}

func readTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return files
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = data
	}
	return files
}

func writeTree(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	if len(files) == 0 {
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func withoutBackups(files map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range files {
		if !strings.HasSuffix(k, ".bak") {
			out[k] = v
		}
	}
	return out
}

func checkGolden(t *testing.T, dir string, got map[string][]byte) {
	t.Helper()
	if *update {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		// Keep empty golden dirs in git.
		if len(got) == 0 {
			if err := os.WriteFile(filepath.Join(dir, ".keep"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		writeTree(t, dir, got)
		return
	}
	want := readTree(t, dir)
	delete(want, ".keep")
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("%s: missing file %s", dir, name)
		}
	}
	for name, data := range got {
		w, ok := want[name]
		if !ok {
			t.Errorf("%s: unexpected file %s:\n%s", dir, name, data)
			continue
		}
		// Golden files are compared with normalised line endings (git may check them out as CRLF).
		if normalize(w) != normalize(data) {
			t.Errorf("%s/%s mismatch (run go test -update)\n--- got ---\n%s\n--- want ---\n%s", dir, name, data, w)
		}
	}
}

func normalize(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }
