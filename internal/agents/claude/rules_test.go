package claude

import (
	"slices"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

func TestParseGlobRulePath(t *testing.T) {
	tests := []struct {
		glob    string
		want    string // rule path; empty with wantErr
		wantErr string
	}{
		{glob: ".env", want: ".env"},
		{glob: ".env.*", want: ".env.*"},
		{glob: "*.pem", want: "*.pem"},
		{glob: "**/*.pem", want: "*.pem"},
		{glob: "**/**/.env.*", want: ".env.*"},
		{glob: "**/config/*.yml", want: "**/config/*.yml"},
		{glob: "**/secrets/", want: "secrets/**"},
		{glob: "./.env", want: ".env"},
		{glob: "./certs/*.key", want: "/certs/*.key"},
		{glob: "config/secrets.yml", want: "/config/secrets.yml"},
		{glob: "secrets/", want: "secrets/**"},
		{glob: "config/certs/", want: "/config/certs/**"},
		{glob: `certs\*.key`, want: "/certs/*.key"},
		{glob: `.\certs\a.key`, want: "/certs/a.key"},
		{glob: "~/.aws/credentials", want: "~/.aws/credentials"},
		{glob: `~\.aws\credentials`, want: "~/.aws/credentials"},
		{glob: "~/.ssh/", want: "~/.ssh/**"},
		{glob: "/etc/ssl/private/**", want: "//etc/ssl/private/**"},
		{glob: `C:\Users\dev\.ssh\id_rsa`, want: "//c/Users/dev/.ssh/id_rsa"},
		{glob: "D:/keys/*.pem", want: "//d/keys/*.pem"},
		{glob: "  .env  ", want: ".env"},
		{glob: "", wantErr: "empty"},
		{glob: "~", wantErr: "~/"},
		{glob: "~root/.ssh/id_rsa", wantErr: "~/"},
		{glob: "./", wantErr: "names no file"},
	}
	for _, tt := range tests {
		g, err := parseGlob(tt.glob)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseGlob(%q) error = %v, want %q", tt.glob, err, tt.wantErr)
			}
			continue
		}
		if err != nil || g.rulePath() != tt.want {
			t.Errorf("parseGlob(%q).rulePath() = %q, %v; want %q", tt.glob, g.rulePath(), err, tt.want)
		}
	}
}

func TestParseGlobUNC(t *testing.T) {
	for _, s := range []string{`\\server\share\.env`, "//server/share/.env"} {
		g, err := parseGlob(s)
		if err != nil || g.anchor != anchorUNC {
			t.Errorf("parseGlob(%q) = %+v, %v; want UNC", s, g, err)
		}
	}
}

func TestDenyBlock(t *testing.T) {
	tests := []struct {
		name      string
		root      string // project root; defaults to testRoot (home is testHome)
		files     []string
		allow     []string
		want      []string
		wantNotes []string // substrings of the single expected note; nil: no note
	}{
		{
			name:  "bare secret carved by bare allow",
			files: []string{".env", ".env.*"},
			allow: []string{".env.example"},
			want: []string{
				"Read(.env)", "Read(.env.*)", "Read(!.env.example)",
				"Edit(.env)", "Edit(.env.*)", "Edit(!.env.example)",
			},
		},
		{
			name:  "allow with a directory is carved relative to cwd",
			files: []string{"*.env"},
			allow: []string{"config/sample.env", `docs\example.env`},
			want: []string{
				"Read(*.env)", "Read(!config/sample.env)", "Read(!docs/example.env)",
				"Edit(*.env)", "Edit(!config/sample.env)", "Edit(!docs/example.env)",
			},
		},
		{
			name:      "anchored secret overlapping an allow keeps its native rule",
			files:     []string{"config/*.env", ".env"},
			allow:     []string{"config/sample.env"},
			want:      []string{"Read(/config/*.env)", "Read(.env)", "Edit(/config/*.env)", "Edit(.env)"},
			wantNotes: []string{`allow_files "config/sample.env" stays blocked by Claude Code's native rules Read(/config/*.env)/Edit(/config/*.env) for secret "config/*.env", although the policy allows it: a "!" exception only reaches unanchored relative rules`},
		},
		{
			name:      "directory rule cannot be reopened",
			files:     []string{"secrets/"},
			allow:     []string{"secrets/public.txt"},
			want:      []string{"Read(secrets/**)", "Edit(secrets/**)"},
			wantNotes: []string{`allow_files "secrets/public.txt" stays blocked`, "cannot reopen files inside a blocked directory"},
		},
		{
			// gitignore also applies "secrets" to a directory, so the native rule
			// stays stricter than the policy here; no file-level overlap, no note.
			name:  "bare name and a file inside a same-named directory",
			files: []string{"secrets"},
			allow: []string{"secrets/public.txt"},
			want:  []string{"Read(secrets)", "Edit(secrets)"},
		},
		{
			name:      "home secret overlapping home allow",
			files:     []string{"~/.aws/*"},
			allow:     []string{"~/.aws/config"},
			want:      []string{"Read(~/.aws/*)", "Edit(~/.aws/*)"},
			wantNotes: []string{`allow_files "~/.aws/config" stays blocked`},
		},
		{
			name:  "project glob vs home allow outside the project",
			files: []string{"*.pem", ".env", ".env.*", ".envrc"},
			allow: []string{"~/certs/public.pem", "~/.ssh/*.pub"},
			want: []string{
				"Read(*.pem)", "Read(.env)", "Read(.env.*)", "Read(.envrc)",
				"Edit(*.pem)", "Edit(.env)", "Edit(.env.*)", "Edit(.envrc)",
			},
		},
		{
			name:      "project glob vs home allow when the project is the home directory",
			root:      testHome,
			files:     []string{"*.pem"},
			allow:     []string{"~/certs/public.pem"},
			want:      []string{"Read(*.pem)", "Edit(*.pem)"},
			wantNotes: []string{`allow_files "~/certs/public.pem" stays blocked`, `a "~/" or absolute allow entry cannot be carved out`},
		},
		{
			name:  "file names that can never match do not overlap",
			files: []string{".env", "**/*.pem", "**/id_rsa*"},
			allow: []string{"**/*.pub"},
			want: []string{
				"Read(.env)", "Read(*.pem)", "Read(id_rsa*)", "Read(!*.pub)",
				"Edit(.env)", "Edit(*.pem)", "Edit(id_rsa*)", "Edit(!*.pub)",
			},
		},
		{
			name:  "any-depth secret carved by any-depth allow",
			files: []string{"**/.env.*"},
			allow: []string{".env.example", "**/.env.sample"},
			want: []string{
				"Read(.env.*)", "Read(!.env.example)", "Read(!.env.sample)",
				"Edit(.env.*)", "Edit(!.env.example)", "Edit(!.env.sample)",
			},
		},
		{
			name:  "anchored allow inside an any-depth secret",
			files: []string{"**/config/*.yml"},
			allow: []string{"config/example.yml"},
			want: []string{
				"Read(**/config/*.yml)", "Read(!config/example.yml)",
				"Edit(**/config/*.yml)", "Edit(!config/example.yml)",
			},
		},
		{
			name:  "non-overlapping allow adds no negation",
			files: []string{"**/*.pem", "~/.aws/credentials"},
			allow: []string{".env.example"},
			want: []string{
				"Read(*.pem)", "Read(~/.aws/credentials)",
				"Edit(*.pem)", "Edit(~/.aws/credentials)",
			},
		},
		{
			name:      "UNC secret is left to the hook",
			files:     []string{`\\server\share\.env`, ".env"},
			want:      []string{"Read(.env)", "Edit(.env)"},
			wantNotes: []string{"network (UNC) path"},
		},
		{
			name:  "duplicates and negations in files are dropped",
			files: []string{".env", "./.env", "!.env.example"},
			want:  []string{"Read(.env)", "Edit(.env)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policy.Policy{Version: policy.CurrentVersion, Secrets: policy.Secrets{Files: tt.files, AllowFiles: tt.allow}}
			root := tt.root
			if root == "" {
				root = testRoot
			}
			block, notes, err := denyBlock(p, root, testHome)
			if err != nil {
				t.Fatal(err)
			}
			prot, err := protectRules(p)
			if err != nil {
				t.Fatal(err)
			}
			if want := append(slices.Clone(tt.want), prot...); !slices.Equal(block, want) {
				t.Errorf("block = %q, want %q", block, want)
			}
			if (len(notes) == 0) != (len(tt.wantNotes) == 0) || len(notes) > 1 {
				t.Fatalf("notes = %q, want one note containing %q", notes, tt.wantNotes)
			}
			for _, n := range tt.wantNotes {
				if !strings.Contains(notes[0], n) {
					t.Errorf("note = %q, want it to contain %q", notes[0], n)
				}
			}
		})
	}
}

func TestSegmentsIntersect(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{".env", ".env", true},
		{".env", "*.pub", false},
		{".env.*", "*.pub", true}, // ".env.pub"
		{".env.*", ".env.example", true},
		{".envrc", "*.pub", false},
		{"id_rsa*", "*.pub", true},
		{"*.pem", "*.pub", false},
		{"*.key", "*.pub", false},
		{"secrets.y*ml", "*.pub", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"[ab]x", "cx", true}, // classes are not modelled: conservative
		{"*", "", true},
		{"", "x", false},
	}
	for _, tt := range tests {
		if got := segmentsIntersect(tt.a, tt.b); got != tt.want {
			t.Errorf("segmentsIntersect(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
		if got := segmentsIntersect(tt.b, tt.a); got != tt.want {
			t.Errorf("segmentsIntersect(%q, %q) = %v, want %v (symmetry)", tt.b, tt.a, got, tt.want)
		}
	}
}

func TestPathsIntersect(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"p/**/.env", "p/**/.env.example", false},
		{"p/**/.env.*", "p/**/.env.example", true},
		{"p/**/.env.*", "h/.ssh/*.pub", false},
		{"p/config/*.yml", "p/**/config/a.yml", true},
		{"h/.ssh/**", "h/.ssh/*.pub", true},
		{"p/**/x", "q/x", false},
	}
	for _, tt := range tests {
		if got := pathsIntersect(strings.Split(tt.a, "/"), strings.Split(tt.b, "/")); got != tt.want {
			t.Errorf("pathsIntersect(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestProtectRules(t *testing.T) {
	p := &policy.Policy{Version: policy.CurrentVersion, Protect: policy.Protect{Files: []string{"Makefile", "ci/**"}}}
	got, err := protectRules(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Edit(/.agentleash.yaml)", "Edit(/.claude/settings.json)", "Edit(/.codex/config.toml)",
		"Edit(~/.claude/settings.json)", "Edit(~/.codex/hooks.json)"} {
		if !slices.Contains(got, want) {
			t.Errorf("protectRules missing %s: %q", want, got)
		}
	}
	if n := len(got); n != len(policy.BuiltinProtected)+2 {
		t.Errorf("protectRules = %d rules, want %d: %q", n, len(policy.BuiltinProtected)+2, got)
	}
}
