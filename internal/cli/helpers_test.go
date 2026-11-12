package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// validPolicyYAML is accepted by the policy package on main and after it is implemented.
const validPolicyYAML = "version: 1\n"

// fakeAdapter is a scriptable agents.Adapter.
type fakeAdapter struct {
	name   string
	decode func(payload []byte, root, home string) (engine.Request, error)
	encode func(v engine.Verdict) ([]byte, int)

	applyChanged  []string
	applyErr      error
	removeChanged []string
	removeErr     error

	decodeCalls int
	applied     bool
	removed     bool
	gotRoot     string
	gotBinary   string
	gotPolicy   *policy.Policy
}

var _ agents.Adapter = (*fakeAdapter)(nil)

func newFake(name string) *fakeAdapter { return &fakeAdapter{name: name} }

func (f *fakeAdapter) Name() string { return f.name }

// fakePayload is the JSON shape understood by the default fake decoder.
type fakePayload struct {
	Cwd     string `json:"cwd"`
	Command string `json:"command"`
}

func (f *fakeAdapter) DecodeHook(payload []byte, root, home string) (engine.Request, error) {
	f.decodeCalls++
	if f.decode != nil {
		return f.decode(payload, root, home)
	}
	var p fakePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return engine.Request{}, err
	}
	return engine.Request{Tool: engine.ToolShell, Command: p.Command, Cwd: p.Cwd, ProjectRoot: root, Home: home}, nil
}

// fakeOutput is what the default fake encoder writes.
type fakeOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Rule     string `json:"rule"`
}

func (f *fakeAdapter) EncodeVerdict(v engine.Verdict) ([]byte, int) {
	if f.encode != nil {
		return f.encode(v)
	}
	b, err := json.Marshal(fakeOutput{Decision: string(v.Decision), Reason: v.Reason, Rule: v.Rule})
	if err != nil {
		panic(err)
	}
	return b, 0
}

func (f *fakeAdapter) Apply(root string, p *policy.Policy, binary string) ([]string, error) {
	f.applied, f.gotRoot, f.gotPolicy, f.gotBinary = true, root, p, binary
	return f.applyChanged, f.applyErr
}

func (f *fakeAdapter) Remove(root string) ([]string, error) {
	f.removed, f.gotRoot = true, root
	return f.removeChanged, f.removeErr
}

// notingAdapter adds the optional PostApplyNotes interface.
type notingAdapter struct {
	*fakeAdapter
	notes []string
}

func (n notingAdapter) PostApplyNotes() []string { return n.notes }

// evalFunc adapts a function to Evaluator.
type evalFunc func(engine.Request) engine.Verdict

func (f evalFunc) Evaluate(r engine.Request) engine.Verdict { return f(r) }

// findUp mirrors policy.Find from feat/policy (main still has a stub): directories named
// like the policy are skipped and stat errors other than "not exist" are returned.
func findUp(dir string) (string, bool, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", false, err
	}
	for {
		fi, err := os.Stat(filepath.Join(dir, policy.FileName))
		switch {
		case err == nil && !fi.IsDir():
			return dir, true, nil
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return "", false, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false, nil
		}
		dir = parent
	}
}

// testEnv is a sandboxed CLI environment rooted in temp dirs.
type testEnv struct {
	t        *testing.T
	cwd      string
	home     string
	exe      string
	adapters []agents.Adapter
	eval     evalFunc
	evalReqs []engine.Request
	env      map[string]string
	deps     Deps
}

func newEnv(t *testing.T, adapters ...agents.Adapter) *testEnv {
	t.Helper()
	cwd := t.TempDir()
	home := t.TempDir()
	exeDir := t.TempDir()
	exe := filepath.Join(exeDir, "agentleash.exe")
	writeFile(t, exe, "binary")
	if len(adapters) == 0 {
		adapters = []agents.Adapter{newFake("claude"), newFake("codex")}
	}
	e := &testEnv{t: t, cwd: cwd, home: home, exe: exe, adapters: adapters, env: map[string]string{}}
	e.eval = func(engine.Request) engine.Verdict { return engine.Verdict{Decision: engine.Allow} }
	e.deps = Deps{
		Getwd:       func() (string, error) { return e.cwd, nil },
		UserHomeDir: func() (string, error) { return e.home, nil },
		Executable:  func() (string, error) { return e.exe, nil },
		LookPath:    func(string) (string, error) { return "", errors.New("not on PATH") },
		Getenv:      func(k string) string { return e.env[k] },
		RunBinary: func(string, ...string) ([]byte, error) {
			return []byte("agentleash 1.2.3 (commit abc1234, go)\n"), nil
		},
		Adapters:   e.adapters,
		FindPolicy: findUp,
		LoadPolicy: policy.Load,
		NewEvaluator: func(*policy.Policy) Evaluator {
			return evalFunc(func(r engine.Request) engine.Verdict {
				e.evalReqs = append(e.evalReqs, r)
				return e.eval(r)
			})
		},
		Version: "1.2.3",
		Commit:  "abc1234",
	}
	return e
}

func (e *testEnv) writePolicy(dir, content string) string {
	e.t.Helper()
	p := filepath.Join(dir, policy.FileName)
	writeFile(e.t, p, content)
	return p
}

type result struct {
	stdout, stderr string
	code           int
}

func (e *testEnv) run(stdin io.Reader, args ...string) result {
	e.t.Helper()
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	var out, errb bytes.Buffer
	cmd := NewRootCmd(e.deps)
	cmd.SetIn(stdin)
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	code := Execute(cmd)
	return result{stdout: out.String(), stderr: errb.String(), code: code}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// blockingReader blocks until the test ends (simulates an agent that never closes stdin).
type blockingReader struct{ done chan struct{} }

func newBlockingReader(t *testing.T) blockingReader {
	b := blockingReader{done: make(chan struct{})}
	t.Cleanup(func() { close(b.done) })
	return b
}

func (b blockingReader) Read([]byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

// errReader always fails.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
