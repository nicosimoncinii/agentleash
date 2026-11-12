package engine_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// corpusDefaultPolicy is the policy every case is evaluated with unless the file or the
// case sets `policy:`. It is pinned in testdata instead of using policy.Default() so the
// corpus cannot silently weaken when the built-in default changes.
const corpusDefaultPolicy = "policies/default-like.yaml"

// corpusFile is one testdata/{attacks,benign}/*.yaml file.
type corpusFile struct {
	Description string       `yaml:"description"`
	Policy      string       `yaml:"policy"`
	Cases       []corpusCase `yaml:"cases"`
}

// corpusCase is one entry of a corpus file. See testdata/README.md.
type corpusCase struct {
	Name    string   `yaml:"name"`
	Tool    string   `yaml:"tool"`
	Shell   string   `yaml:"shell"`
	Command string   `yaml:"command"`
	Paths   []string `yaml:"paths"`
	Cwd     string   `yaml:"cwd"`
	Home    string   `yaml:"home"`
	Policy  string   `yaml:"policy"`
	Expect  string   `yaml:"expect"`
	Note    string   `yaml:"note"`
}

// corpusEnv holds the absolute fixture locations used to build requests.
type corpusEnv struct {
	testdata string
	project  string
	home     string
}

func newCorpusEnv(t *testing.T) corpusEnv {
	t.Helper()
	td, err := filepath.Abs(filepath.Join("..", "..", "testdata"))
	if err != nil {
		t.Fatalf("resolve testdata: %v", err)
	}
	return corpusEnv{
		testdata: td,
		project:  filepath.Join(td, "project"),
		home:     filepath.Join(td, "home"),
	}
}

// expand replaces the {{project}} and {{home}} placeholders with forward-slash absolute
// paths, so the same case works on every OS and inside bash words.
func (env corpusEnv) expand(s, home string) string {
	s = strings.ReplaceAll(s, "{{project}}", filepath.ToSlash(env.project))
	return strings.ReplaceAll(s, "{{home}}", filepath.ToSlash(home))
}

// request builds the engine request for a case.
func (env corpusEnv) request(c corpusCase) engine.Request {
	home := env.home
	if c.Home != "" {
		home = env.expand(c.Home, env.home)
	}
	cwd := env.project
	if c.Cwd != "" {
		cwd = filepath.Join(env.project, filepath.FromSlash(c.Cwd))
	}
	var shell engine.Shell
	if c.Tool == string(engine.ToolShell) {
		shell = engine.ShellBash
		if c.Shell != "" {
			shell = engine.Shell(c.Shell)
		}
	}
	var paths []string
	for _, p := range c.Paths {
		paths = append(paths, env.expand(p, home))
	}
	return engine.Request{
		Tool:        engine.ToolKind(c.Tool),
		Command:     env.expand(c.Command, home),
		Shell:       shell,
		Paths:       paths,
		Cwd:         cwd,
		ProjectRoot: env.project,
		Home:        home,
	}
}

var (
	validTools   = map[string]bool{"shell": true, "read": true, "search": true, "write": true, "other": true}
	validShells  = map[string]bool{"": true, "bash": true, "powershell": true}
	validExpects = map[string]map[string]bool{
		"attacks": {"deny": true, "ask": true},
		"benign":  {"allow": true},
	}
)

// strictness orders decisions: allow < ask < deny. Unknown decisions rank lowest so they
// can never satisfy an attack case.
func strictness(d engine.Decision) int {
	switch d {
	case engine.Deny:
		return 2
	case engine.Ask:
		return 1
	case engine.Allow:
		return 0
	default:
		return -1
	}
}

// parseCorpusFile strictly decodes and validates one corpus file. kind is "attacks" or
// "benign" and restricts the allowed `expect` values.
func parseCorpusFile(kind string, data []byte) (*corpusFile, error) {
	allowed, ok := validExpects[kind]
	if !ok {
		return nil, fmt.Errorf("unknown corpus kind %q", kind)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f corpusFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode: exactly one YAML document per file")
	}

	var errs []error
	if strings.TrimSpace(f.Description) == "" {
		errs = append(errs, errors.New("missing description"))
	}
	if len(f.Cases) == 0 {
		errs = append(errs, errors.New("no cases"))
	}
	seen := map[string]bool{}
	for i := range f.Cases {
		c := &f.Cases[i]
		where := fmt.Sprintf("case %d (%q)", i+1, c.Name)
		switch {
		case strings.TrimSpace(c.Name) == "":
			errs = append(errs, fmt.Errorf("case %d: missing name", i+1))
		case seen[c.Name]:
			errs = append(errs, fmt.Errorf("%s: duplicate name", where))
		}
		seen[c.Name] = true
		if !validTools[c.Tool] {
			errs = append(errs, fmt.Errorf("%s: tool must be shell|read|search|write|other, got %q", where, c.Tool))
		}
		if !validShells[c.Shell] {
			errs = append(errs, fmt.Errorf("%s: shell must be bash|powershell, got %q", where, c.Shell))
		}
		if c.Shell != "" && c.Tool != "shell" {
			errs = append(errs, fmt.Errorf("%s: shell is only valid with tool: shell", where))
		}
		switch c.Tool {
		case "shell":
			if strings.TrimSpace(c.Command) == "" {
				errs = append(errs, fmt.Errorf("%s: tool shell needs a command", where))
			}
			if len(c.Paths) > 0 {
				errs = append(errs, fmt.Errorf("%s: tool shell takes a command, not paths", where))
			}
		case "read", "search", "write":
			if len(c.Paths) == 0 {
				errs = append(errs, fmt.Errorf("%s: tool %s needs paths", where, c.Tool))
			}
			if c.Command != "" {
				errs = append(errs, fmt.Errorf("%s: tool %s takes paths, not a command", where, c.Tool))
			}
		}
		switch {
		case c.Expect == "":
			errs = append(errs, fmt.Errorf("%s: missing expect", where))
		case !allowed[c.Expect]:
			errs = append(errs, fmt.Errorf("%s: expect %q not allowed in %s/", where, c.Expect, kind))
		}
		if kind == "attacks" && strings.TrimSpace(c.Note) == "" {
			errs = append(errs, fmt.Errorf("%s: attack cases need a note explaining the trick", where))
		}
		if c.Cwd != "" && (filepath.IsAbs(c.Cwd) || strings.HasPrefix(filepath.ToSlash(filepath.Clean(c.Cwd)), "..")) {
			errs = append(errs, fmt.Errorf("%s: cwd must be relative to testdata/project and stay inside it", where))
		}
	}
	return &f, errors.Join(errs...)
}

type loadedFile struct {
	kind string // attacks | benign
	name string // file base name
	file *corpusFile
}

func loadCorpus(t *testing.T, env corpusEnv) []loadedFile {
	t.Helper()
	var out []loadedFile
	for _, kind := range []string{"attacks", "benign"} {
		matches, err := filepath.Glob(filepath.Join(env.testdata, kind, "*.yaml"))
		if err != nil {
			t.Fatalf("glob %s: %v", kind, err)
		}
		if len(matches) == 0 {
			t.Fatalf("no corpus files in testdata/%s", kind)
		}
		sort.Strings(matches)
		for _, m := range matches {
			data, err := os.ReadFile(m)
			if err != nil {
				t.Fatalf("read %s: %v", m, err)
			}
			rel := kind + "/" + filepath.Base(m)
			f, err := parseCorpusFile(kind, data)
			if err != nil {
				t.Errorf("invalid corpus file %s:\n%v", rel, err)
				continue
			}
			out = append(out, loadedFile{kind: kind, name: rel, file: f})
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	return out
}

// policyCache loads each referenced policy file once.
type policyCache struct {
	mu      sync.Mutex
	dir     string
	loaded  map[string]*policy.Policy
	loadErr map[string]error
}

func (pc *policyCache) get(rel string) (*policy.Policy, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if p, ok := pc.loaded[rel]; ok {
		return p, nil
	}
	if err, ok := pc.loadErr[rel]; ok {
		return nil, err
	}
	p, err := policy.Load(filepath.Join(pc.dir, filepath.FromSlash(rel)))
	if err != nil {
		pc.loadErr[rel] = err
		return nil, err
	}
	pc.loaded[rel] = p
	return p, nil
}

// TestCorpus evaluates every attack and benign case. Attack cases must be blocked with
// the expected decision; benign cases must be allowed.
func TestCorpus(t *testing.T) {
	env := newCorpusEnv(t)
	files := loadCorpus(t, env)
	policies := &policyCache{dir: env.testdata, loaded: map[string]*policy.Policy{}, loadErr: map[string]error{}}

	type tally struct{ total, ok int }
	tallies := map[string]*tally{"attacks": {}, "benign": {}}

	for _, lf := range files {
		for _, c := range lf.file.Cases {
			polRel := corpusDefaultPolicy
			if lf.file.Policy != "" {
				polRel = lf.file.Policy
			}
			if c.Policy != "" {
				polRel = c.Policy
			}
			tl := tallies[lf.kind]
			tl.total++
			passed := t.Run(lf.name+"/"+c.Name, func(t *testing.T) {
				p, err := policies.get(polRel)
				if err != nil {
					t.Fatalf("%s: case %q: load policy %s: %v", lf.name, c.Name, polRel, err)
				}
				req := env.request(c)
				got := engine.New(p).Evaluate(req)
				switch {
				case string(got.Decision) == c.Expect:
				case lf.kind == "attacks" && strictness(got.Decision) > strictness(engine.Decision(c.Expect)):
					// Stricter than expected still blocks the attack: note it, do not fail.
					t.Logf("%s: case %q: expected %s, got stricter %s (rule %q, reason %q)",
						lf.name, c.Name, c.Expect, got.Decision, got.Rule, got.Reason)
				default:
					t.Errorf("%s: case %q: expected %s, got %s (rule %q, reason %q)\n  tool=%s shell=%s command=%q paths=%q\n  note: %s",
						lf.name, c.Name, c.Expect, got.Decision, got.Rule, got.Reason,
						req.Tool, req.Shell, req.Command, req.Paths, c.Note)
				}
			})
			if passed {
				tl.ok++
			}
		}
	}
	t.Logf("corpus summary: attacks %d/%d blocked as expected, benign %d/%d allowed",
		tallies["attacks"].ok, tallies["attacks"].total, tallies["benign"].ok, tallies["benign"].total)
}

// TestCorpusFormatStrict checks that the loader rejects malformed corpus files, so a typo
// in a case can never silently turn into a passing (or skipped) test.
func TestCorpusFormatStrict(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		yaml    string
		wantErr string
	}{
		{
			name:    "valid attack",
			kind:    "attacks",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: cat .env, expect: deny, note: n}\n",
			wantErr: "",
		},
		{
			name:    "unknown case field",
			kind:    "attacks",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: cat .env, expect: deny, note: n, exepct: deny}\n",
			wantErr: "exepct",
		},
		{
			name:    "unknown top-level field",
			kind:    "benign",
			yaml:    "description: d\ncase: []\n",
			wantErr: "case",
		},
		{
			name:    "missing expect",
			kind:    "benign",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: ls}\n",
			wantErr: "missing expect",
		},
		{
			name:    "duplicate name",
			kind:    "benign",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: ls, expect: allow}\n  - {name: a, tool: shell, command: pwd, expect: allow}\n",
			wantErr: "duplicate name",
		},
		{
			name:    "allow in attacks",
			kind:    "attacks",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: cat .env, expect: allow, note: n}\n",
			wantErr: "not allowed in attacks/",
		},
		{
			name:    "deny in benign",
			kind:    "benign",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: ls, expect: deny}\n",
			wantErr: "not allowed in benign/",
		},
		{
			name:    "attack without note",
			kind:    "attacks",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: cat .env, expect: deny}\n",
			wantErr: "need a note",
		},
		{
			name:    "bad tool",
			kind:    "benign",
			yaml:    "description: d\ncases:\n  - {name: a, tool: bash, command: ls, expect: allow}\n",
			wantErr: "tool must be",
		},
		{
			name:    "read without paths",
			kind:    "benign",
			yaml:    "description: d\ncases:\n  - {name: a, tool: read, expect: allow}\n",
			wantErr: "needs paths",
		},
		{
			name:    "shell without command",
			kind:    "benign",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, expect: allow}\n",
			wantErr: "needs a command",
		},
		{
			name:    "cwd escaping project",
			kind:    "benign",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: ls, cwd: ../.., expect: allow}\n",
			wantErr: "cwd must be relative",
		},
		{
			name:    "two documents",
			kind:    "benign",
			yaml:    "description: d\ncases:\n  - {name: a, tool: shell, command: ls, expect: allow}\n---\ndescription: e\n",
			wantErr: "one YAML document",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCorpusFile(tt.kind, []byte(tt.yaml))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

// TestCorpusStrictnessOrder guards the "stricter verdict passes" rule for attack cases.
func TestCorpusStrictnessOrder(t *testing.T) {
	if strictness(engine.Deny) <= strictness(engine.Ask) ||
		strictness(engine.Ask) <= strictness(engine.Allow) ||
		strictness(engine.Allow) <= strictness("bogus") {
		t.Fatal("strictness must order unknown < allow < ask < deny")
	}
}

// TestCorpusPolicyLoads guards the pinned baseline policy itself.
func TestCorpusPolicyLoads(t *testing.T) {
	env := newCorpusEnv(t)
	p, err := policy.Load(filepath.Join(env.testdata, filepath.FromSlash(corpusDefaultPolicy)))
	if err != nil {
		t.Fatalf("load %s: %v", corpusDefaultPolicy, err)
	}
	if len(p.Secrets.Files) == 0 || len(p.Secrets.Env) == 0 || len(p.Commands.Deny) == 0 || len(p.Commands.Ask) == 0 {
		t.Fatalf("%s must define secret files, secret env globs, deny and ask patterns", corpusDefaultPolicy)
	}
}
