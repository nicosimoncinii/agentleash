package cli

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

const secretValue = "SUPERSECRET-dummy-value-123"

func payload(t *testing.T, cwd, command string) string {
	t.Helper()
	b, err := json.Marshal(fakePayload{Cwd: cwd, Command: command})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestHookFailClosedMatrix covers every branch of `agentleash hook`.
func TestHookFailClosedMatrix(t *testing.T) {
	type outcome struct {
		code     int
		decision engine.Decision // decoded from fake stdout when code == 0
		stderr   string          // substring expected on stderr
		evalRuns bool
	}
	cases := []struct {
		name  string
		setup func(e *testEnv, fake *fakeAdapter) (stdin io.Reader, args []string)
		want  outcome
	}{
		{
			name: "no policy found -> allow (project not protected)",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				return strings.NewReader(payload(t, e.cwd, "cat .env")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Allow},
		},
		{
			name: "valid policy, engine allows -> allow",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Allow, evalRuns: true},
		},
		{
			name: "valid policy, engine denies -> deny",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Deny, Reason: "secret file", Rule: ".env"}
				}
				return strings.NewReader(payload(t, e.cwd, "cat .env")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny, evalRuns: true},
		},
		{
			name: "valid policy, engine asks -> ask",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Ask, Reason: "confirm", Rule: "curl * | sh"}
				}
				return strings.NewReader(payload(t, e.cwd, "curl x | sh")), []string{"hook", "codex"}
			},
			want: outcome{code: 0, decision: engine.Ask, evalRuns: true},
		},
		{
			name: "engine returns unknown decision -> deny",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict { return engine.Verdict{Decision: "maybe"} }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny, evalRuns: true},
		},
		{
			name: "policy invalid -> deny with fix hint",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, "version: 99\n")
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny},
		},
		{
			name: "policy unreadable -> deny",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.deps.LoadPolicy = func(string) (*policy.Policy, error) { return nil, fs.ErrPermission }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny},
		},
		{
			name: "directory named .agentleash.yaml is not a policy -> allow",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				if err := os.Mkdir(filepath.Join(e.cwd, policy.FileName), 0o750); err != nil {
					t.Fatal(err)
				}
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Allow},
		},
		{
			// Review repro 1: the payload cwd points outside the protected project.
			name: "payload cwd outside the project, process cwd protected -> evaluated (deny)",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = denyIfRoot(e.cwd)
				return strings.NewReader(payload(t, t.TempDir(), "cat "+filepath.Join(e.cwd, ".env"))), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny, evalRuns: true},
		},
		{
			name: "only $CLAUDE_PROJECT_DIR leads to a policy -> evaluated (deny)",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				project := t.TempDir()
				e.writePolicy(project, validPolicyYAML)
				e.env["CLAUDE_PROJECT_DIR"] = project
				e.eval = denyIfRoot(project)
				return strings.NewReader(payload(t, t.TempDir(), "cat .env")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny, evalRuns: true},
		},
		{
			// Review repro 2: an empty nested policy must not shadow the project policy.
			name: "nested empty policy cannot weaken the root policy -> deny",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				nested := filepath.Join(e.cwd, "vendor", "x")
				e.writePolicy(e.cwd, validPolicyYAML)
				e.writePolicy(nested, validPolicyYAML)
				e.cwd = nested // even the process cwd is inside the nested project
				e.eval = denyIfRoot(filepath.Dir(filepath.Dir(nested)))
				return strings.NewReader(payload(t, nested, "cat ../../.env")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny, evalRuns: true},
		},
		{
			name: "working directory unknown -> deny",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.deps.Getwd = func() (string, error) { return "", errors.New("removed") }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny},
		},
		{
			name: "watchdog fires (stdin never closes) -> exit 2",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.deps.HookTimeout = 50 * time.Millisecond
				return newBlockingReader(t), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "took longer"},
		},
		{
			name: "encoder returns exit 1 on allow -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				fake.encode = func(engine.Verdict) ([]byte, int) { return []byte(`{}`), 1 }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "exit code 1", evalRuns: true},
		},
		{
			name: "encoder returns exit 7 on deny -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Deny, Reason: "nope", Rule: "x"}
				}
				fake.encode = func(engine.Verdict) ([]byte, int) { return nil, 7 }
				return strings.NewReader(payload(t, e.cwd, "x")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "nope", evalRuns: true},
		},
		{
			name: "deny encoded as non-JSON stdout with exit 0 -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Deny, Reason: "nope", Rule: "x"}
				}
				fake.encode = func(engine.Verdict) ([]byte, int) { return []byte("deny"), 0 }
				return strings.NewReader(payload(t, e.cwd, "x")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "blocked", evalRuns: true},
		},
		{
			name: "deny encoded as two JSON objects with exit 0 -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Deny, Reason: "nope", Rule: "x"}
				}
				fake.encode = func(engine.Verdict) ([]byte, int) { return []byte(`{"a":1}{"b":2}`), 0 }
				return strings.NewReader(payload(t, e.cwd, "x")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "blocked", evalRuns: true},
		},
		{
			name: "deny encoded as a JSON array with exit 0 -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Deny, Reason: "nope", Rule: "x"}
				}
				fake.encode = func(engine.Verdict) ([]byte, int) { return []byte(`[{"decision":"deny"}]`), 0 }
				return strings.NewReader(payload(t, e.cwd, "x")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "blocked", evalRuns: true},
		},
		{
			name: "unknown flag -> exit 2",
			setup: func(_ *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				return strings.NewReader("{}"), []string{"hook", "--bogus", "claude"}
			},
			want: outcome{code: 2, stderr: "unknown flag"},
		},
		{
			name: "extra argument -> exit 2",
			setup: func(_ *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				return strings.NewReader("{}"), []string{"hook", "claude", "codex"}
			},
			want: outcome{code: 2, stderr: "accepts 1 arg"},
		},
		{
			name: "encoder returns exit 1 with empty stdout on deny -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Deny, Reason: "secret file", Rule: ".env"}
				}
				fake.encode = func(engine.Verdict) ([]byte, int) { return nil, 1 }
				return strings.NewReader(payload(t, e.cwd, "cat .env")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "secret file", evalRuns: true},
		},
		{
			name: "encoder returns exit 1 with stdout on ask -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Ask, Reason: "confirm", Rule: "curl * | sh"}
				}
				fake.encode = func(engine.Verdict) ([]byte, int) { return []byte(`{"decision":"ask"}`), 1 }
				return strings.NewReader(payload(t, e.cwd, "curl x | sh")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "confirm", evalRuns: true},
		},
		{
			name: "policy lookup error -> deny",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.deps.FindPolicy = func(string) (string, bool, error) { return "", false, errors.New("permission denied") }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny},
		},
		{
			name: "decode error -> exit 2, reason on stderr",
			setup: func(_ *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				return strings.NewReader("{not json"), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "could not decode"},
		},
		{
			name: "decode error with policy present -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				fake.decode = func([]byte, string, string) (engine.Request, error) {
					return engine.Request{}, errors.New("bad tool_input " + secretValue)
				}
				return strings.NewReader(payload(t, e.cwd, "echo "+secretValue)), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "could not decode"},
		},
		{
			name: "decode panics -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				fake.decode = func([]byte, string, string) (engine.Request, error) { panic("decoder bug " + secretValue) }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "internal error"},
		},
		{
			name: "engine panics -> exit 2",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict { panic("engine bug") }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "internal error", evalRuns: true},
		},
		{
			name: "encoder panics -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				fake.encode = func(engine.Verdict) ([]byte, int) { panic("encoder bug") }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "internal error", evalRuns: true},
		},
		{
			name: "encoder fails open on deny (empty stdout, exit 0) -> exit 2",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Deny, Reason: "secret file", Rule: ".env"}
				}
				fake.encode = func(engine.Verdict) ([]byte, int) { return nil, 0 }
				return strings.NewReader(payload(t, e.cwd, "cat .env")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "secret file", evalRuns: true},
		},
		{
			name: "adapter exit code 2 is passed through with reason on stderr",
			setup: func(e *testEnv, fake *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.eval = func(engine.Request) engine.Verdict {
					return engine.Verdict{Decision: engine.Deny, Reason: "dangerous", Rule: "rm -rf /"}
				}
				fake.encode = func(engine.Verdict) ([]byte, int) { return nil, 2 }
				return strings.NewReader(payload(t, e.cwd, "rm -rf /")), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "dangerous", evalRuns: true},
		},
		{
			name: "stdin over size limit -> exit 2",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.deps.MaxHookInput = 16
				return strings.NewReader(payload(t, e.cwd, strings.Repeat("a", 64))), []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "too large"},
		},
		{
			name: "stdin read error -> exit 2",
			setup: func(_ *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				return errReader{}, []string{"hook", "claude"}
			},
			want: outcome{code: 2, stderr: "could not read"},
		},
		{
			name: "home dir unknown with policy -> deny",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				e.writePolicy(e.cwd, validPolicyYAML)
				e.deps.UserHomeDir = func() (string, error) { return "", errors.New("no home") }
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "claude"}
			},
			want: outcome{code: 0, decision: engine.Deny},
		},
		{
			name: "unknown agent -> exit 2",
			setup: func(e *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				return strings.NewReader(payload(t, e.cwd, "ls")), []string{"hook", "gemini"}
			},
			want: outcome{code: 2, stderr: "unknown agent"},
		},
		{
			name: "missing agent argument -> exit 2",
			setup: func(_ *testEnv, _ *fakeAdapter) (io.Reader, []string) {
				return strings.NewReader("{}"), []string{"hook"}
			},
			want: outcome{code: 2},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claude, codex := newFake("claude"), newFake("codex")
			e := newEnv(t, claude, codex)
			stdin, args := tc.setup(e, claude)
			r := e.run(stdin, args...)

			assertHookContract(t, r)
			if r.code != tc.want.code {
				t.Fatalf("exit code = %d, want %d\nstdout=%q\nstderr=%q", r.code, tc.want.code, r.stdout, r.stderr)
			}
			if tc.want.code == 0 {
				var out fakeOutput
				if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
					t.Fatalf("stdout is not the adapter's encoding: %q (%v)", r.stdout, err)
				}
				if engine.Decision(out.Decision) != tc.want.decision {
					t.Fatalf("decision = %q, want %q (reason %q)", out.Decision, tc.want.decision, out.Reason)
				}
				if out.Decision != string(engine.Allow) && out.Reason == "" {
					t.Fatalf("blocking verdict without reason")
				}
			} else if r.stdout != "" {
				t.Fatalf("exit %d must not write stdout, got %q", r.code, r.stdout)
			}
			if tc.want.code == 2 && strings.TrimSpace(r.stderr) == "" {
				t.Fatalf("exit 2 without a reason on stderr")
			}
			if !strings.Contains(r.stderr, tc.want.stderr) {
				t.Fatalf("stderr %q does not contain %q", r.stderr, tc.want.stderr)
			}
			if got := len(e.evalReqs) > 0; got != tc.want.evalRuns {
				t.Fatalf("engine called = %v, want %v", got, tc.want.evalRuns)
			}
			if strings.Contains(r.stdout+r.stderr, secretValue) {
				t.Fatalf("hook output leaked payload content: %q %q", r.stdout, r.stderr)
			}
		})
	}
}

// assertHookContract checks what Claude Code and Codex rely on: exit 0 or 2 only,
// exit 2 with a non-empty stderr, exit 0 with empty stdout or exactly one JSON object.
func assertHookContract(t *testing.T, r result) {
	t.Helper()
	switch r.code {
	case 0:
		if r.stdout != "" && !isSingleJSONObject([]byte(r.stdout)) {
			t.Fatalf("exit 0 with stdout that is not exactly one JSON object: %q", r.stdout)
		}
	case 2:
		if strings.TrimSpace(r.stderr) == "" {
			t.Fatalf("exit 2 with empty stderr (Codex would let the call run)")
		}
	default:
		t.Fatalf("hook exited %d; only 0 and 2 are allowed (stderr %q)", r.code, r.stderr)
	}
}

func TestHookAllowWithInvalidStdoutProceedsWithEmptyStdout(t *testing.T) {
	for _, out := range []string{"not json", `{"a":1} trailing`, "null", `["x"]`} {
		fake := newFake("claude")
		fake.encode = func(engine.Verdict) ([]byte, int) { return []byte(out), 0 }
		e := newEnv(t, fake)
		r := e.run(strings.NewReader(payload(t, e.cwd, "ls")), "hook", "claude")
		assertHookContract(t, r)
		if r.code != 0 || r.stdout != "" {
			t.Errorf("%q: code %d stdout %q", out, r.code, r.stdout)
		}
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct {
		name     string
		in       hookOutput
		wantCode int
		wantOut  string
	}{
		{"allow empty", hookOutput{}, 0, ""},
		{"allow json", hookOutput{stdout: []byte(" {\"x\":1}\n")}, 0, " {\"x\":1}\n"},
		{"allow garbage dropped", hookOutput{stdout: []byte("ok")}, 0, ""},
		{"blocking garbage", hookOutput{stdout: []byte("{"), blocking: true}, 2, ""},
		{"exit 2 empty stderr", hookOutput{code: 2}, 2, ""},
		{"exit 2 whitespace stderr", hookOutput{code: 2, stderr: " \n"}, 2, ""},
		{"exit 2 drops stdout", hookOutput{code: 2, stderr: "r\n", stdout: []byte("{}")}, 2, ""},
		{"exit 1", hookOutput{code: 1, stderr: "x"}, 2, ""},
		{"exit -1", hookOutput{code: -1}, 2, ""},
	}
	for _, tc := range cases {
		got := sanitize(tc.in)
		if got.code != tc.wantCode || string(got.stdout) != tc.wantOut {
			t.Errorf("%s: got code %d stdout %q", tc.name, got.code, got.stdout)
		}
		if got.code == 2 && strings.TrimSpace(got.stderr) == "" {
			t.Errorf("%s: exit 2 with empty stderr", tc.name)
		}
	}
	if b := blocked(""); strings.TrimSpace(b.stderr) == "" || b.code != 2 {
		t.Errorf("blocked(\"\") = %+v", b)
	}
}

// denyIfRoot denies only when evaluated under the policy rooted at root.
func denyIfRoot(root string) evalFunc {
	return func(r engine.Request) engine.Verdict {
		if r.ProjectRoot == root {
			return engine.Verdict{Decision: engine.Deny, Reason: "secret file", Rule: ".env"}
		}
		return engine.Verdict{Decision: engine.Allow}
	}
}

func TestHookEvaluatesEveryPolicyAndKeepsTheStrictest(t *testing.T) {
	cases := []struct {
		name          string
		outer, nested engine.Decision
		want          engine.Decision
	}{
		{"allow+allow", engine.Allow, engine.Allow, engine.Allow},
		{"outer ask", engine.Ask, engine.Allow, engine.Ask},
		{"nested ask, outer deny", engine.Deny, engine.Ask, engine.Deny},
		{"nested deny, outer ask", engine.Ask, engine.Deny, engine.Deny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			outer := e.cwd
			nested := filepath.Join(outer, "sub", "inner")
			e.writePolicy(outer, validPolicyYAML)
			e.writePolicy(nested, validPolicyYAML)
			e.eval = func(r engine.Request) engine.Verdict {
				d := tc.nested
				if r.ProjectRoot == outer {
					d = tc.outer
				}
				return engine.Verdict{Decision: d, Reason: "r-" + string(d), Rule: string(d)}
			}
			r := e.run(strings.NewReader(payload(t, nested, "x")), "hook", "claude")
			var out fakeOutput
			if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
				t.Fatalf("stdout %q: %v", r.stdout, err)
			}
			if engine.Decision(out.Decision) != tc.want {
				t.Fatalf("decision %q, want %q", out.Decision, tc.want)
			}
			roots := map[string]bool{}
			for _, req := range e.evalReqs {
				roots[req.ProjectRoot] = true
			}
			if !roots[outer] || !roots[nested] || len(e.evalReqs) != 2 {
				t.Fatalf("evaluated roots %v, want exactly %q and %q", roots, outer, nested)
			}
		})
	}
}

func TestHookNestedInvalidPolicyDenies(t *testing.T) {
	e := newEnv(t)
	nested := filepath.Join(e.cwd, "vendor", "x")
	e.writePolicy(e.cwd, "version: 99\n")
	e.writePolicy(nested, validPolicyYAML)
	r := e.run(strings.NewReader(payload(t, nested, "ls")), "hook", "claude")
	if !strings.Contains(r.stdout, `"deny"`) || !strings.Contains(r.stdout, "policy-invalid") {
		t.Fatalf("want policy-invalid deny, got code %d stdout %q", r.code, r.stdout)
	}
}

func TestHookMakesRelativeRequestCwdAbsolute(t *testing.T) {
	fake := newFake("claude")
	fake.decode = func(_ []byte, root, home string) (engine.Request, error) {
		return engine.Request{Tool: engine.ToolShell, Command: "ls", Cwd: "sub", ProjectRoot: root, Home: home}, nil
	}
	e := newEnv(t, fake)
	e.writePolicy(e.cwd, validPolicyYAML)
	e.run(strings.NewReader(payload(t, "", "ls")), "hook", "claude")
	if len(e.evalReqs) != 1 || e.evalReqs[0].Cwd != filepath.Join(e.cwd, "sub") {
		t.Fatalf("requests %+v", e.evalReqs)
	}
}

func TestHookInvalidPolicyReasonExplainsFix(t *testing.T) {
	e := newEnv(t)
	e.writePolicy(e.cwd, "version: 99\n")
	r := e.run(strings.NewReader(payload(t, e.cwd, "ls")), "hook", "claude")
	var out fakeOutput
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{policy.FileName, "agentleash doctor"} {
		if !strings.Contains(out.Reason, want) {
			t.Errorf("reason %q should mention %q", out.Reason, want)
		}
	}
	if out.Rule != "policy-invalid" {
		t.Errorf("rule = %q, want policy-invalid", out.Rule)
	}
}

func TestHookUsesPayloadCwdToFindPolicy(t *testing.T) {
	e := newEnv(t)
	project := t.TempDir()
	sub := filepath.Join(project, "pkg", "sub")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	e.writePolicy(project, validPolicyYAML)
	// The process cwd (e.cwd) has no policy; only the payload cwd leads to one.
	r := e.run(strings.NewReader(payload(t, sub, "ls")), "hook", "claude")
	if r.code != 0 {
		t.Fatalf("code %d stderr %q", r.code, r.stderr)
	}
	if len(e.evalReqs) != 1 {
		t.Fatalf("engine not called; policy was not found from payload cwd")
	}
	req := e.evalReqs[0]
	if req.ProjectRoot != project {
		t.Errorf("ProjectRoot = %q, want %q", req.ProjectRoot, project)
	}
	if req.Home != e.home {
		t.Errorf("Home = %q, want %q", req.Home, e.home)
	}
	if req.Cwd != sub {
		t.Errorf("Cwd = %q, want %q", req.Cwd, sub)
	}
}

func TestHookFallsBackToProcessCwd(t *testing.T) {
	e := newEnv(t)
	e.writePolicy(e.cwd, validPolicyYAML)
	r := e.run(strings.NewReader(payload(t, "", "ls")), "hook", "claude")
	if r.code != 0 || len(e.evalReqs) != 1 {
		t.Fatalf("code %d, evals %d, stderr %q", r.code, len(e.evalReqs), r.stderr)
	}
	if got := e.evalReqs[0]; got.ProjectRoot != e.cwd || got.Cwd != e.cwd {
		t.Errorf("request = %+v, want root and cwd %q", got, e.cwd)
	}
}

func TestHookCwdFromOptionalInterface(t *testing.T) {
	project := t.TempDir()
	fake := newFake("claude")
	e := newEnv(t, cwdAdapter{fakeAdapter: fake, cwd: project})
	e.writePolicy(project, validPolicyYAML)
	r := e.run(strings.NewReader(payload(t, "", "ls")), "hook", "claude")
	if r.code != 0 || len(e.evalReqs) != 1 {
		t.Fatalf("code %d, evals %d, stderr %q", r.code, len(e.evalReqs), r.stderr)
	}
	if e.evalReqs[0].ProjectRoot != project {
		t.Errorf("ProjectRoot = %q, want %q", e.evalReqs[0].ProjectRoot, project)
	}
}

type cwdAdapter struct {
	*fakeAdapter
	cwd string
}

func (c cwdAdapter) HookCwd([]byte) (string, error) { return c.cwd, nil }

// The real adapters on main are stubs whose DecodeHook errors: the hook must block.
func TestHookWithDefaultAdaptersFailsClosed(t *testing.T) {
	e := newEnv(t, DefaultAdapters()...)
	e.writePolicy(e.cwd, validPolicyYAML)
	for _, name := range []string{"claude", "codex"} {
		r := e.run(strings.NewReader(`{"cwd":"x"}`), "hook", name)
		if r.code == 0 && !strings.Contains(r.stdout, "deny") {
			t.Errorf("%s: expected block, got code %d stdout %q", name, r.code, r.stdout)
		}
	}
}

func TestDefaultAdaptersNames(t *testing.T) {
	var names []string
	for _, a := range DefaultAdapters() {
		names = append(names, a.Name())
	}
	if strings.Join(names, ",") != "claude,codex" {
		t.Fatalf("adapters = %v", names)
	}
}
