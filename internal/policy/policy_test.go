package policy

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr []string // substrings that must all appear in the error; nil = no error
	}{
		{
			name: "minimal valid",
			yaml: "version: 1\n",
		},
		{
			name: "full valid",
			yaml: `version: 1
secrets:
  files: [".env", "**/*.pem", "~/.aws/credentials"]
  allow_files: [".env.example"]
  env: ["*_TOKEN"]
commands:
  deny: ["rm -rf /"]
  ask: ["curl * | sh"]
`,
		},
		{
			name:    "empty file",
			yaml:    "",
			wantErr: []string{"empty"},
		},
		{
			name:    "whitespace and comments only",
			yaml:    "  \n# just a comment\n\n",
			wantErr: []string{"empty"},
		},
		{
			name:    "unknown top-level field with line number",
			yaml:    "version: 1\nsecretz:\n  files: []\n",
			wantErr: []string{"line 2", "secretz"},
		},
		{
			name:    "unknown nested field with line number",
			yaml:    "version: 1\nsecrets:\n  files: []\n  allowfiles: []\n",
			wantErr: []string{"line 4", "allowfiles"},
		},
		{
			name:    "unknown commands field",
			yaml:    "version: 1\ncommands:\n  block: [x]\n",
			wantErr: []string{"line 3", "block"},
		},
		{
			name:    "wrong type",
			yaml:    "version: one\n",
			wantErr: []string{"line 1"},
		},
		{
			name:    "malformed yaml",
			yaml:    "version: 1\nsecrets: [\n",
			wantErr: []string{"parse policy"},
		},
		{
			name:    "multiple documents",
			yaml:    "version: 1\n---\nversion: 1\n",
			wantErr: []string{"single YAML document"},
		},
		{
			name:    "missing version",
			yaml:    "secrets:\n  files: [\".env\"]\n",
			wantErr: []string{"version", "missing"},
		},
		{
			name:    "validation error surfaces",
			yaml:    "version: 2\n",
			wantErr: []string{"version", "unsupported"},
		},
		{
			name:    "null list item (bare dash)",
			yaml:    "version: 1\nsecrets:\n  files:\n    - .env\n    -\n",
			wantErr: []string{"line 5", "secrets.files", "empty entry"},
		},
		{
			name:    "null list items (~ and null) all reported",
			yaml:    "version: 1\nsecrets:\n  env: [~]\ncommands:\n  deny:\n    - null\n",
			wantErr: []string{"line 3", "secrets.env", "line 6", "commands.deny"},
		},
		{
			name: "quoted null-looking strings are fine",
			yaml: "version: 1\ncommands:\n  ask: [\"null\", \"~\"]\n",
		},
		{
			name: "null list itself is fine",
			yaml: "version: 1\nsecrets:\n  files:\n",
		},
		{
			name:    "top-level not a mapping",
			yaml:    "- a\n- b\n",
			wantErr: []string{"parse policy"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(tt.yaml))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Parse() unexpected error: %v", err)
				}
				if p == nil {
					t.Fatal("Parse() returned nil policy")
				}
				return
			}
			assertErrContains(t, err, tt.wantErr...)
		})
	}
}

func TestValidate(t *testing.T) {
	valid := func() *Policy {
		return &Policy{
			Version: CurrentVersion,
			Secrets: Secrets{
				Files:      []string{".env", "**/*.pem", "~/.ssh/**", "/etc/shadow"},
				AllowFiles: []string{".env.example"},
				Env:        []string{"*_TOKEN"},
			},
			Commands: Commands{
				Deny: []string{"rm -rf /"},
				Ask:  []string{"curl * | sh"},
			},
		}
	}
	tests := []struct {
		name    string
		mutate  func(p *Policy)
		wantErr []string
	}{
		{name: "valid", mutate: func(*Policy) {}},
		{name: "empty lists are fine", mutate: func(p *Policy) { p.Secrets, p.Commands = Secrets{}, Commands{} }},
		{
			name:    "bad version",
			mutate:  func(p *Policy) { p.Version = 99 },
			wantErr: []string{"version: unsupported version 99"},
		},
		{
			name:    "missing version",
			mutate:  func(p *Policy) { p.Version = 0 },
			wantErr: []string{"version: missing"},
		},
		{
			name:    "empty file entry",
			mutate:  func(p *Policy) { p.Secrets.Files = append(p.Secrets.Files, "") },
			wantErr: []string{"secrets.files[4]", "empty"},
		},
		{
			name:    "whitespace-only env entry",
			mutate:  func(p *Policy) { p.Secrets.Env = []string{"   "} },
			wantErr: []string{"secrets.env[0]", "empty"},
		},
		{
			name:    "surrounding whitespace",
			mutate:  func(p *Policy) { p.Commands.Deny = []string{" rm -rf /"} },
			wantErr: []string{"commands.deny[0]", "whitespace"},
		},
		{
			name:    "invalid glob in files",
			mutate:  func(p *Policy) { p.Secrets.Files = []string{"secrets/[abc"} },
			wantErr: []string{"secrets.files[0]", "invalid glob"},
		},
		{
			name:    "invalid glob in later segment",
			mutate:  func(p *Policy) { p.Secrets.AllowFiles = []string{"a/**/b[/c"} },
			wantErr: []string{"secrets.allow_files[0]", "invalid glob"},
		},
		{
			name:    "invalid glob in env",
			mutate:  func(p *Policy) { p.Secrets.Env = []string{"[A-"} },
			wantErr: []string{"secrets.env[0]", "invalid glob"},
		},
		{
			// Command patterns are not path.Match globs (design §5): only * is special.
			name: "commands with path.Match-invalid syntax are fine",
			mutate: func(p *Policy) {
				p.Commands.Ask = []string{"rm [x", "echo a?b", "x | y"}
				p.Commands.Deny = []string{`rm -rf C:\`, `rm -rf /\*`}
			},
		},
		{
			name:    "leading ! in files",
			mutate:  func(p *Policy) { p.Secrets.Files = []string{"!.env.local"} },
			wantErr: []string{"secrets.files[0]", "negation is not supported", "allow_files"},
		},
		{
			name:    "leading ! in allow_files",
			mutate:  func(p *Policy) { p.Secrets.AllowFiles = []string{"!x"} },
			wantErr: []string{"secrets.allow_files[0]", "negation is not supported"},
		},
		{
			name:    "backslash in file glob",
			mutate:  func(p *Policy) { p.Secrets.Files = []string{`config\.env`} },
			wantErr: []string{"secrets.files[0]", "forward slashes"},
		},
		{
			name:    "tilde user form unsupported",
			mutate:  func(p *Policy) { p.Secrets.Files = []string{"~root/.ssh/id_rsa"} },
			wantErr: []string{"secrets.files[0]", "~/"},
		},
		{
			name:    "env with whitespace",
			mutate:  func(p *Policy) { p.Secrets.Env = []string{"MY TOKEN"} },
			wantErr: []string{"secrets.env[0]", "whitespace or '='"},
		},
		{
			name:    "env with equals",
			mutate:  func(p *Policy) { p.Secrets.Env = []string{"A=B"} },
			wantErr: []string{"secrets.env[0]", "whitespace or '='"},
		},
		{
			name:    "duplicate within list",
			mutate:  func(p *Policy) { p.Commands.Deny = []string{"rm -rf /", "x", "rm -rf /"} },
			wantErr: []string{`commands.deny[2]: duplicate of commands.deny[0] "rm -rf /"`},
		},
		{
			name: "same entry in different lists is fine",
			mutate: func(p *Policy) {
				p.Commands.Deny = []string{"npm publish*"}
				p.Commands.Ask = []string{"npm publish*"}
			},
		},
		{
			name: "all problems reported at once",
			mutate: func(p *Policy) {
				p.Version = 3
				p.Secrets.Files = []string{"", "[", ".env", ".env"}
				p.Commands.Ask = []string{"  "}
			},
			wantErr: []string{
				"version: unsupported",
				"secrets.files[0]",
				"secrets.files[1]",
				"secrets.files[3]: duplicate",
				"commands.ask[0]",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := valid()
			tt.mutate(p)
			err := p.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			assertErrContains(t, err, tt.wantErr...)
		})
	}
}

func TestValidateNil(t *testing.T) {
	var p *Policy
	assertErrContains(t, p.Validate(), "nil policy")
}

func TestDefault(t *testing.T) {
	d := Default()
	if err := d.Validate(); err != nil {
		t.Fatalf("Default() is invalid: %v", err)
	}
	if Default() == d || &Default().Secrets.Files[0] == &d.Secrets.Files[0] {
		t.Fatal("Default() must return a fresh copy each call")
	}
	// Superset of the design doc §5 example plus the issue #1 requirements.
	must := []struct {
		field string
		list  []string
		want  []string
	}{
		{"secrets.files", d.Secrets.Files, []string{
			".env", ".env.*", "**/.env", "**/.env.*", "**/*.pem", "**/*.key",
			"**/id_rsa*", "**/id_ed25519*", "**/*.p12", "**/*.pfx", "**/.npmrc",
			"**/.pypirc", "**/.netrc", "~/.aws/credentials", "~/.ssh/**",
			"~/.docker/config.json", "~/.kube/config", "**/credentials.json",
			"**/*.tfstate", "**/*.tfstate.*", "**/secrets.y*ml", ".envrc", "**/.envrc",
			"~/.npmrc", "~/.pypirc", "~/.netrc", "~/.git-credentials", "~/.config/gcloud/**",
			"~/.azure/**", "~/.pgpass", "~/.terraform.d/credentials.tfrc.json",
		}},
		{"secrets.allow_files", d.Secrets.AllowFiles, []string{
			".env.example", ".env.sample", ".env.template",
			"**/.env.example", "**/.env.sample", "**/.env.template", "**/*.pub",
		}},
		{"secrets.env", d.Secrets.Env, []string{
			"*_KEY", "*_SECRET*", "*_TOKEN", "*PASSWORD*", "*_API_KEY*", "GITHUB_TOKEN",
			"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
			"DATABASE_URL", "*_CONNECTION_STRING*",
		}},
		{"commands.deny", d.Commands.Deny, []string{
			"rm -rf /", "rm -rf ~", `rm -rf /\*`, "git push --force*", "git push -f*",
			"mkfs*", ":(){ :|:& };:", "chmod -R 777 /",
		}},
		{"commands.ask", d.Commands.Ask, []string{
			"curl * | sh", "curl * | bash", "wget * | sh", "git reset --hard*",
			"git clean -fd*", "npm publish*",
		}},
	}
	for _, m := range must {
		have := make(map[string]bool, len(m.list))
		for _, e := range m.list {
			have[e] = true
		}
		for _, w := range m.want {
			if !have[w] {
				t.Errorf("Default() %s is missing %q", m.field, w)
			}
		}
	}
}

// TestDefaultBehaviour guards Default() against false positives (harmless
// things blocked) and false negatives, using reference matchers that follow
// the semantics documented in docs/design.md §5. The engine owns the real
// matchers; these exist so policy edits cannot silently regress.
func TestDefaultBehaviour(t *testing.T) {
	d := Default()

	t.Run("files", func(t *testing.T) {
		tests := []struct {
			path    string // project-relative, or ~/...
			blocked bool
		}{
			{"README.md", false},
			{"src/main.go", false},
			{"src/env.ts", false},
			{"go.sum", false},
			{"package.json", false},
			{".env.example", false},
			{"config/.env.example", false},
			{".env.sample", false},
			{"deploy/id_rsa.pub", false},
			{"~/.ssh/id_ed25519.pub", false},
			{"docs/keys.md", false},
			{".env", true},
			{".env.local", true},
			{"apps/web/.env.production", true},
			{".envrc", true},
			{"infra/terraform.tfstate", true},
			{"infra/terraform.tfstate.backup", true},
			{"certs/server.key", true},
			{"deploy/id_rsa", true},
			{"config/secrets.yaml", true},
			{"~/.ssh/id_ed25519", true},
			{"~/.git-credentials", true},
			{"~/.config/gcloud/application_default_credentials.json", true},
			{"~/.aws/credentials", true},
			{"~/.pgpass", true},
		}
		for _, tt := range tests {
			got := anyGlob(d.Secrets.Files, tt.path) && !anyGlob(d.Secrets.AllowFiles, tt.path)
			if got != tt.blocked {
				t.Errorf("file %q blocked=%v, want %v", tt.path, got, tt.blocked)
			}
		}
	})

	t.Run("env", func(t *testing.T) {
		tests := []struct {
			name    string
			blocked bool
		}{
			{"PATH", false},
			{"HOME", false},
			{"GOPATH", false},
			{"NODE_ENV", false},
			{"CI", false},
			{"AWS_REGION", false},
			{"AWS_PROFILE", false},
			{"AWS_DEFAULT_REGION", false},
			{"AWS_ENDPOINT_URL", false},
			{"SSH_AUTH_SOCK", false},
			{"KEYBOARD_LAYOUT", false},
			{"AWS_ACCESS_KEY_ID", true},
			{"AWS_SECRET_ACCESS_KEY", true},
			{"AWS_SESSION_TOKEN", true},
			{"GITHUB_TOKEN", true},
			{"OPENAI_API_KEY", true},
			{"DB_PASSWORD", true},
			{"DATABASE_URL", true},
			{"AZURE_STORAGE_CONNECTION_STRING", true},
		}
		for _, tt := range tests {
			got := false
			for _, g := range d.Secrets.Env {
				if ok, _ := path.Match(g, tt.name); ok {
					got = true
				}
			}
			if got != tt.blocked {
				t.Errorf("env %q blocked=%v, want %v", tt.name, got, tt.blocked)
			}
		}
	})

	t.Run("commands", func(t *testing.T) {
		tests := []struct {
			cmd  string
			want string // "deny", "ask" or "" (allow)
		}{
			{"rm -rf node_modules", ""},
			{"rm -rf /tmp/build", ""},
			{"rm -rf ~/projects/old", ""},
			{"rm -rf ./dist", ""},
			{"git push", ""},
			{"git push origin feat/x", ""},
			{"git push --follow-tags", ""},
			{"git reset --soft HEAD~1", ""},
			{"git clean -n", ""},
			{"dd if=/dev/zero of=/dev/null bs=1M count=10", ""},
			{"curl -fsSL https://example.com/install.sh -o install.sh", ""},
			{"npm run build", ""},
			{"chmod 755 script.sh", ""},
			{"rm -rf /", "deny"},
			{"rm -rf /*", "deny"},
			{"rm -rf ~", "deny"},
			{"rm -fr ~/*", "deny"},
			{"rm -rf --no-preserve-root /", "deny"},
			{"git push --force", "deny"},
			{"git push origin feat/x --force", "deny"},
			{"git push -f origin main", "deny"},
			{"mkfs.ext4 /dev/sdb1", "deny"},
			{"dd if=/dev/zero of=/dev/sda", "deny"},
			{":(){ :|:& };:", "deny"},
			{"curl https://x/y | sh", "ask"},
			{"wget -qO- https://x/y | bash", "ask"},
			{"git reset --hard origin/main", "ask"},
			{"git clean -fdx", "ask"},
			{"git clean -xdf", "ask"},
			{"npm publish --access public", "ask"},
		}
		for _, tt := range tests {
			got := ""
			switch {
			case anyCmd(d.Commands.Deny, tt.cmd):
				got = "deny"
			case anyCmd(d.Commands.Ask, tt.cmd):
				got = "ask"
			}
			if got != tt.want {
				t.Errorf("command %q => %q, want %q", tt.cmd, got, tt.want)
			}
		}
	})
}

// anyGlob reports whether name matches any file glob: path.Match per "/"
// segment, with a "**" segment matching zero or more segments. Relative globs
// are anchored at the project root, so they never match "~/..." paths.
func anyGlob(globs []string, name string) bool {
	for _, g := range globs {
		if strings.HasPrefix(name, "~/") != strings.HasPrefix(g, "~/") {
			continue
		}
		if globMatch(strings.Split(g, "/"), strings.Split(name, "/")) {
			return true
		}
	}
	return false
}

func globMatch(pat, name []string) bool {
	if len(pat) == 0 {
		return len(name) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(name); i++ {
			if globMatch(pat[1:], name[i:]) {
				return true
			}
		}
		return false
	}
	if len(name) == 0 {
		return false
	}
	ok, _ := path.Match(pat[0], name[0])
	return ok && globMatch(pat[1:], name[1:])
}

// anyCmd reports whether cmd matches any command pattern: "*" matches any run
// of characters, `\*` is a literal star, and patterns containing " | " are
// matched stage by stage against the pipeline.
func anyCmd(patterns []string, cmd string) bool {
	for _, p := range patterns {
		ps, cs := []string{p}, []string{cmd}
		if strings.Contains(p, " | ") {
			ps, cs = strings.Split(p, " | "), strings.Split(cmd, " | ")
		}
		if len(ps) != len(cs) {
			continue
		}
		all := true
		for i := range ps {
			if !cmdRegexp(ps[i]).MatchString(cs[i]) {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}

func cmdRegexp(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		switch {
		case p[i] == '\\' && i+1 < len(p) && p[i+1] == '*':
			b.WriteString(`\*`)
			i++
		case p[i] == '*':
			b.WriteString(".*")
		default:
			b.WriteString(regexp.QuoteMeta(p[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func TestMarshalRoundTrip(t *testing.T) {
	cases := map[string]*Policy{
		"default": Default(),
		"minimal": {Version: CurrentVersion},
		"tricky strings": {
			Version: CurrentVersion,
			Secrets: Secrets{Files: []string{"*.pem", "~/.ssh/**", "&y"}, Env: []string{"*_KEY"}},
			Commands: Commands{
				Deny: []string{":(){ :|:& };:", "a: b", "# not a comment", "'quoted'", `"dq"`, "!x", `rm -rf /\*`},
				Ask:  []string{"curl * | sh", "yes", "null", "1"},
			},
		},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := Marshal(p)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got, err := Parse(out)
			if err != nil {
				t.Fatalf("Parse(Marshal(p)): %v\n%s", err, out)
			}
			if !reflect.DeepEqual(normalize(got), normalize(p)) {
				t.Fatalf("round trip mismatch\n got: %#v\nwant: %#v\nyaml:\n%s", got, p, out)
			}
		})
	}
}

func TestMarshalIsCommented(t *testing.T) {
	out, err := Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"# agentleash policy",
		"version: 1",
		"# Secret files",
		"# Exceptions",
		"# Environment variable",
		"# Commands that are always blocked",
		"# Commands that need confirmation",
		"- .env\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Marshal output missing %q:\n%s", want, s)
		}
	}
}

func TestMarshalNil(t *testing.T) {
	if _, err := Marshal(nil); err == nil {
		t.Fatal("Marshal(nil) should fail")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	writeFile(t, good, "version: 1\nsecrets:\n  files: [\".env\"]\n")
	writeFile(t, bad, "version: 1\nbogus: true\n")

	tests := []struct {
		name    string
		path    string
		wantErr []string
	}{
		{name: "valid file", path: good},
		{name: "invalid file names path and line", path: bad, wantErr: []string{"bad.yaml", "line 2", "bogus"}},
		{name: "missing file", path: filepath.Join(dir, "nope.yaml"), wantErr: []string{"read policy"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Load(tt.path)
			if tt.wantErr == nil {
				if err != nil || p == nil {
					t.Fatalf("Load() = %v, %v", p, err)
				}
				return
			}
			if p != nil {
				t.Errorf("Load() returned a policy alongside an error")
			}
			assertErrContains(t, err, tt.wantErr...)
		})
	}
}

func TestFind(t *testing.T) {
	base := t.TempDir()
	proj := filepath.Join(base, "proj")
	deep := filepath.Join(proj, "a", "b", "c")
	nested := filepath.Join(proj, "a", "sub")
	decoy := filepath.Join(base, "decoy", "x")
	for _, d := range []string{deep, nested, filepath.Join(decoy, FileName)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(proj, FileName), "version: 1\n")
	writeFile(t, filepath.Join(nested, FileName), "version: 1\n")

	tests := []struct {
		name     string
		dir      string
		wantRoot string
		wantOK   bool
	}{
		{name: "in dir itself", dir: proj, wantRoot: proj, wantOK: true},
		{name: "in ancestor", dir: deep, wantRoot: proj, wantOK: true},
		{name: "nearest wins", dir: nested, wantRoot: nested, wantOK: true},
		{name: "non-clean path", dir: deep + string(filepath.Separator) + ".." + string(filepath.Separator), wantRoot: proj, wantOK: true},
		{name: "directory named like the policy is ignored", dir: decoy, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, ok, err := find(tt.dir, boundedStat(base))
			if err != nil {
				t.Fatalf("find() error: %v", err)
			}
			if ok != tt.wantOK || root != tt.wantRoot {
				t.Fatalf("find() = %q, %v; want %q, %v", root, ok, tt.wantRoot, tt.wantOK)
			}
		})
	}
}

func TestFindRelative(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, FileName), "version: 1\n")
	t.Chdir(sub)

	root, ok, err := Find(".")
	if err != nil || !ok {
		t.Fatalf("Find(.) = %q, %v, %v", root, ok, err)
	}
	if !sameDir(t, root, base) {
		t.Fatalf("Find(.) root = %q, want %q", root, base)
	}
}

func TestFindStopsAtFilesystemRoot(t *testing.T) {
	start := filepath.Join(t.TempDir(), "x", "y")
	var visited []string
	notFound := func(name string) (fs.FileInfo, error) {
		visited = append(visited, filepath.Dir(name))
		return nil, fs.ErrNotExist
	}
	root, ok, err := find(start, notFound)
	if err != nil || ok || root != "" {
		t.Fatalf("find() = %q, %v, %v; want \"\", false, nil", root, ok, err)
	}
	if visited[0] != start {
		t.Errorf("first visited %q, want %q", visited[0], start)
	}
	last := visited[len(visited)-1]
	if filepath.Dir(last) != last {
		t.Errorf("walk stopped at %q, which is not the filesystem root", last)
	}
}

func TestFindStatError(t *testing.T) {
	denied := func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	_, ok, err := find(t.TempDir(), denied)
	if ok || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("find() ok=%v err=%v; want permission error", ok, err)
	}
}

// boundedStat behaves like os.Stat inside base and reports "not found" above
// it, so tests never depend on a stray .agentleash.yaml on the host.
func boundedStat(base string) func(string) (fs.FileInfo, error) {
	return func(name string) (fs.FileInfo, error) {
		if rel, err := filepath.Rel(base, name); err != nil || strings.HasPrefix(rel, "..") {
			return nil, fs.ErrNotExist
		}
		return os.Stat(name)
	}
}

func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	ia, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(ia, ib)
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// normalize treats nil and empty slices as equal for comparisons.
func normalize(p *Policy) *Policy {
	c := *p
	for _, s := range []*[]string{&c.Secrets.Files, &c.Secrets.AllowFiles, &c.Secrets.Env, &c.Commands.Deny, &c.Commands.Ask} {
		if len(*s) == 0 {
			*s = nil
		}
	}
	return &c
}

func assertErrContains(t *testing.T, err error, subs ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", subs)
	}
	for _, s := range subs {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q does not contain %q", err.Error(), s)
		}
	}
}

func TestProtectFiles(t *testing.T) {
	p, err := Parse([]byte("version: 1\nprotect:\n  files: [Makefile, \".github/workflows/**\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := p.ProtectedFiles()
	if len(got) != len(BuiltinProtected)+2 || got[len(got)-1] != ".github/workflows/**" || got[0] != "./"+FileName {
		t.Errorf("ProtectedFiles() = %q", got)
	}
	for _, bad := range []string{
		"version: 1\nprotect:\n  files: [\"!x\"]\n",
		"version: 1\nprotect:\n  files: ['a\\b']\n",
		"version: 1\nprotect:\n  files: [x, x]\n",
		"version: 1\nprotect:\n  other: [x]\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) accepted an invalid protect section", bad)
		}
	}
	// Round trip, and an empty section is omitted from init output.
	out, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if q, err := Parse(out); err != nil || len(q.Protect.Files) != 2 {
		t.Fatalf("round trip: %v %+v", err, q)
	}
	def, err := Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(def), "protect:") {
		t.Errorf("default policy should not list protect: it is built in")
	}
	for _, b := range BuiltinProtected {
		if err := validateEntry(b, kindFile); err != nil {
			t.Errorf("builtin %q invalid: %v", b, err)
		}
	}
}
