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
		{glob: "**/*.pem", want: "/**/*.pem"},
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
		files     []string
		allow     []string
		want      []string
		wantNotes []string // substrings, one per note
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
			name:      "anchored secret overlapping an allow gets no native rule",
			files:     []string{"config/*.env", ".env"},
			allow:     []string{"config/sample.env"},
			want:      []string{"Read(.env)", "Edit(.env)"},
			wantNotes: []string{`"config/*.env" overlaps allow_files "config/sample.env"`},
		},
		{
			name:      "directory rule cannot be reopened",
			files:     []string{"secrets/"},
			allow:     []string{"secrets/public.txt"},
			wantNotes: []string{`"secrets/" overlaps`},
		},
		{
			name:      "bare name matching a parent directory cannot be reopened",
			files:     []string{"secrets"},
			allow:     []string{"secrets/public.txt"},
			wantNotes: []string{`"secrets" overlaps`},
		},
		{
			name:      "home secret overlapping home allow",
			files:     []string{"~/.aws/*"},
			allow:     []string{"~/.aws/config"},
			wantNotes: []string{`"~/.aws/*" overlaps`},
		},
		{
			name:      "bare secret with a non-relative allow",
			files:     []string{"*.pem"},
			allow:     []string{"~/certs/public.pem"},
			wantNotes: []string{`"*.pem" overlaps`},
		},
		{
			name:  "non-overlapping allow adds no negation",
			files: []string{"**/*.pem", "~/.aws/credentials"},
			allow: []string{".env.example"},
			want: []string{
				"Read(/**/*.pem)", "Read(~/.aws/credentials)",
				"Edit(/**/*.pem)", "Edit(~/.aws/credentials)",
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
			block, notes, err := denyBlock(p)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(block, tt.want) {
				t.Errorf("block = %q, want %q", block, tt.want)
			}
			if len(notes) != len(tt.wantNotes) {
				t.Fatalf("notes = %q, want %d", notes, len(tt.wantNotes))
			}
			for i, n := range tt.wantNotes {
				if !strings.Contains(notes[i], n) {
					t.Errorf("note %d = %q, want it to contain %q", i, notes[i], n)
				}
			}
		})
	}
}
