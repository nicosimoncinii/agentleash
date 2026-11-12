package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
	"github.com/spf13/cobra"
)

// projectDirEnvVars name environment variables an agent may set to the session's
// project directory. CLAUDE_PROJECT_DIR is documented by Claude Code for hooks.
// CODEX_PROJECT_DIR is not documented by Codex today (Codex runs hooks with the
// session cwd as working directory); it is harmless when absent.
var projectDirEnvVars = []string{"CLAUDE_PROJECT_DIR", "CODEX_PROJECT_DIR"}

// hookCwdReader is an optional adapter interface: it extracts the working directory
// from a raw hook payload so policies can be located before DecodeHook runs
// (DecodeHook needs the project root). Without it, a top-level "cwd" JSON field is
// read, which both Claude Code and Codex send.
type hookCwdReader interface {
	HookCwd(payload []byte) (string, error)
}

func newHookCmd(d *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "hook <agent>",
		Short: "Evaluate one tool call (invoked by the agent; reads the hook payload on stdin)",
		Long: `Invoked by Claude Code or Codex before every tool call. Reads the agent's
PreToolUse JSON payload on stdin and answers allow, ask or deny.

The hook fails closed: an unreadable payload, an invalid policy, a timeout or any
internal error blocks the tool call. A call is unprotected only when no
.agentleash.yaml is found from the payload cwd, the process cwd or the agent's
project directory.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitCode(runHook(d, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0]))
		},
	}
}

// hookOutput is the buffered result of one hook run. Only the calling goroutine
// writes it to the real streams, so nothing reaches stdout after the watchdog fires.
type hookOutput struct {
	stdout   []byte
	stderr   string
	code     int
	blocking bool // a deny/ask carried in stdout
}

// fallbackBlockReason is used whenever a block would otherwise have an empty reason:
// Codex treats exit 2 as a block only when stderr is non-empty.
const fallbackBlockReason = "agentleash: tool call blocked to be safe. Run `agentleash doctor` for details."

// blocked is the agent-agnostic block: exit 2 with a non-empty reason on stderr.
func blocked(reason string) hookOutput {
	if strings.TrimSpace(reason) == "" {
		reason = fallbackBlockReason
	}
	return hookOutput{stderr: reason + "\n", code: 2}
}

// sanitize enforces the hook's output contract, which both agents rely on:
//   - the exit code is 0 or 2 (agents treat any other code as a non-blocking error);
//   - exit 2 always has a non-empty reason on stderr;
//   - on exit 0, stdout is empty or exactly one JSON object.
//
// A blocking response that violates it becomes exit 2; an allow with invalid stdout
// keeps exit 0 with an empty stdout (proceed), and an allow with another code blocks.
func sanitize(h hookOutput) hookOutput {
	switch h.code {
	case 0:
		if len(h.stdout) == 0 || isSingleJSONObject(h.stdout) {
			return h
		}
		if h.blocking {
			return blocked(fallbackBlockReason)
		}
		h.stdout = nil
		return h
	case 2:
		if strings.TrimSpace(h.stderr) == "" {
			return blocked("")
		}
		h.stdout = nil
		return h
	default:
		return blocked(fmt.Sprintf("agentleash: unexpected hook exit code %d; blocked to be safe. Run `agentleash doctor`.", h.code))
	}
}

// isSingleJSONObject reports whether b holds exactly one JSON object (surrounding whitespace allowed).
func isSingleJSONObject(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	var m map[string]json.RawMessage
	if err := dec.Decode(&m); err != nil || m == nil {
		return false
	}
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

const internalErrorReason = "agentleash: internal error while evaluating the tool call; blocked to be safe. " +
	"Run `agentleash doctor` or report a bug."

// runHook returns the process exit code. It never returns 0 for a blocked call.
func runHook(d *Deps, stdin io.Reader, stdout, stderr io.Writer, agentName string) int {
	adapter := d.adapter(agentName)
	if adapter == nil {
		fprintf(stderr, "agentleash: unknown agent %q (known: %s); blocked to be safe\n", agentName, d.adapterNames())
		return 2
	}

	done := make(chan hookOutput, 1)
	go func() {
		// Any panic (adapter, policy, engine, encoder) blocks the call. The panic value
		// is not printed: it may contain payload data.
		defer func() {
			if r := recover(); r != nil {
				done <- blocked(internalErrorReason)
			}
		}()
		done <- evaluateHook(d, adapter, stdin)
	}()

	timer := time.NewTimer(d.HookTimeout)
	defer timer.Stop()
	var out hookOutput
	select {
	case out = <-done:
	case <-timer.C:
		out = blocked(fmt.Sprintf("agentleash: evaluating the tool call took longer than %s; blocked to be safe. "+
			"Run `agentleash doctor` or report a bug.", d.HookTimeout))
	}

	out = sanitize(out)
	fprintf(stderr, "%s", out.stderr)
	if len(out.stdout) > 0 {
		if _, err := stdout.Write(out.stdout); err != nil && out.blocking {
			// Cannot tell the agent about a block through stdout: fall back to exit 2.
			fprintf(stderr, "agentleash: could not write the hook response; blocked to be safe\n")
			return 2
		}
	}
	return out.code
}

func evaluateHook(d *Deps, adapter agents.Adapter, stdin io.Reader) hookOutput {
	payload, err := readLimited(stdin, d.MaxHookInput)
	if err != nil {
		return blocked("agentleash: " + err.Error() + "; blocked to be safe")
	}
	v, failReason := decide(d, adapter, payload)
	if failReason != "" {
		return blocked(failReason)
	}
	return encode(adapter, v)
}

// decide evaluates the payload. A non-empty failReason means the adapter could not
// understand the payload, so the verdict cannot be encoded in the agent's format.
func decide(d *Deps, adapter agents.Adapter, payload []byte) (v engine.Verdict, failReason string) {
	cwd, anchors, anchorErr := hookAnchors(d, adapter, payload)
	home, homeErr := d.UserHomeDir()
	if homeErr != nil {
		home = ""
	}

	var roots []string
	findErr := anchorErr
	if findErr == nil {
		roots, findErr = discoverPolicies(d, anchors)
	}
	decodeRoot := ""
	if len(roots) > 0 {
		decodeRoot = roots[0]
	}

	req, err := adapter.DecodeHook(payload, decodeRoot, home)
	if err != nil {
		// The error text is not printed: adapters may quote the payload.
		return engine.Verdict{}, fmt.Sprintf("agentleash: could not decode the %s hook payload; blocked to be safe. "+
			"Check that agentleash is up to date (`agentleash version`) and re-run `agentleash apply`.", adapter.Name())
	}

	switch {
	case findErr != nil:
		return denyVerdict("policy-lookup", fmt.Sprintf("agentleash: could not look for %s (%v); blocked to be safe. "+
			"Run `agentleash doctor` to diagnose.", policy.FileName, findErr)), ""
	case len(roots) == 0:
		// No policy from any anchor: this project is not protected by agentleash (by design).
		return engine.Verdict{Decision: engine.Allow}, ""
	case homeErr != nil:
		return denyVerdict("internal-error", "agentleash: could not determine the home directory, so \"~/\" secret paths "+
			"cannot be checked; blocked to be safe. Make sure HOME (USERPROFILE on Windows) is set."), ""
	}

	switch {
	case req.Cwd == "":
		req.Cwd = cwd
	case !filepath.IsAbs(req.Cwd):
		req.Cwd = filepath.Join(cwd, req.Cwd)
	}
	req.Home = home
	v, _ = evaluateAll(d, roots, req)
	return v, ""
}

// evaluateAll evaluates req under every policy (ProjectRoot = its root) and returns the
// strictest verdict (deny > ask > allow) with the policy file that produced it.
// A policy that cannot be loaded is a deny.
func evaluateAll(d *Deps, roots []string, req engine.Request) (engine.Verdict, string) {
	best := engine.Verdict{Decision: engine.Allow}
	bestPath := filepath.Join(roots[0], policy.FileName)
	for _, root := range roots {
		path := filepath.Join(root, policy.FileName)
		p, err := d.LoadPolicy(path)
		if err != nil {
			return denyVerdict("policy-invalid", fmt.Sprintf("agentleash: the policy file %s is invalid or unreadable (%v); "+
				"every tool call is blocked until it is fixed. Fix the file (run `agentleash doctor` for details) "+
				"or regenerate it with `agentleash init --force`.", path, err)), path
		}
		r := req
		r.ProjectRoot = root
		v := normalize(d.NewEvaluator(p).Evaluate(r))
		if strictness(v.Decision) > strictness(best.Decision) {
			best, bestPath = v, path
		}
	}
	return best, bestPath
}

func strictness(dec engine.Decision) int {
	switch dec {
	case engine.Allow:
		return 0
	case engine.Ask:
		return 1
	default:
		return 2
	}
}

// hookAnchors returns the call's working directory and every directory policies are
// searched from: the payload cwd, the process cwd and the agent's project directory.
// The payload cwd alone is not trusted: it can point outside the protected project.
func hookAnchors(d *Deps, adapter agents.Adapter, payload []byte) (cwd string, anchors []string, err error) {
	wd, err := d.Getwd()
	if err != nil {
		// The process cwd is where the agent runs the hook (normally the protected
		// project); without it we cannot rule protection out.
		return "", nil, fmt.Errorf("cannot determine the working directory: %w", err)
	}
	wd = absFrom("", wd)
	cwd = wd
	if pc := payloadCwd(adapter, payload); pc != "" {
		cwd = absFrom(wd, pc)
	}
	anchors = []string{cwd, wd}
	for _, name := range projectDirEnvVars {
		if v := d.Getenv(name); v != "" {
			anchors = append(anchors, absFrom(wd, v))
		}
	}
	return cwd, anchors, nil
}

func payloadCwd(adapter agents.Adapter, payload []byte) string {
	if r, ok := adapter.(hookCwdReader); ok {
		if c, err := r.HookCwd(payload); err == nil {
			return c
		}
		return ""
	}
	var peek struct {
		Cwd string `json:"cwd"`
	}
	if json.Unmarshal(payload, &peek) != nil {
		return ""
	}
	return peek.Cwd
}

// absFrom makes p absolute, relative to base when it is not.
func absFrom(base, p string) string {
	if filepath.IsAbs(p) || base == "" {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return filepath.Clean(p)
	}
	return filepath.Join(base, p)
}

// discoverPolicies returns every project root (directory holding a policy) found by
// walking up from each anchor, including ancestors of nested policies, so that a nested
// policy can only add restrictions. Roots are deduplicated, innermost first per anchor.
func discoverPolicies(d *Deps, anchors []string) ([]string, error) {
	var roots []string
	seen := map[string]bool{}
	for _, dir := range anchors {
		for {
			root, ok, err := d.FindPolicy(dir)
			if err != nil {
				return nil, err
			}
			if !ok {
				break
			}
			key := filepath.Clean(root)
			if runtime.GOOS == "windows" {
				key = strings.ToLower(key)
			}
			if !seen[key] {
				seen[key] = true
				roots = append(roots, root)
			}
			parent := filepath.Dir(root)
			if parent == root {
				break
			}
			dir = parent
		}
	}
	return roots, nil
}

func denyVerdict(rule, reason string) engine.Verdict {
	return engine.Verdict{Decision: engine.Deny, Rule: rule, Reason: reason}
}

// normalize turns any unexpected decision into a deny.
func normalize(v engine.Verdict) engine.Verdict {
	switch v.Decision {
	case engine.Allow:
		return v
	case engine.Ask, engine.Deny:
		if v.Reason == "" {
			v.Reason = fmt.Sprintf("agentleash: blocked by policy rule %q", v.Rule)
		}
		return v
	default:
		return denyVerdict("internal-error", "agentleash: the engine returned an unknown decision; blocked to be safe. Please report a bug.")
	}
}

// encode turns the verdict into the adapter's output. A blocking verdict is accepted
// only as exit 2 or as exit 0 with a non-empty stdout; anything else (e.g. exit 1,
// which agents treat as a non-blocking error) becomes exit 2 with the reason.
func encode(adapter agents.Adapter, v engine.Verdict) hookOutput {
	out, code := adapter.EncodeVerdict(v)
	if v.Decision == engine.Allow {
		if code != 0 {
			// Not a valid allow: fail closed (sanitize would also catch codes other than 2).
			return blocked(fmt.Sprintf("agentleash: the %s adapter returned exit code %d for an allowed call; "+
				"blocked to be safe. Run `agentleash doctor`.", adapter.Name(), code))
		}
		return hookOutput{stdout: out}
	}
	if code == 0 && len(out) > 0 {
		return hookOutput{stdout: out, blocking: true}
	}
	// code 2 from the adapter, or an invalid encoding: block the agent-agnostic way.
	return blocked(v.Reason)
}

var errTooLarge = errors.New("hook payload too large")

// readLimited reads all of r, failing if it exceeds limit bytes.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("could not read the hook payload from stdin: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w (over %d bytes)", errTooLarge, limit)
	}
	return data, nil
}
