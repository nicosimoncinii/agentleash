package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
	"github.com/spf13/cobra"
)

// postApplyNoter is an optional adapter interface for instructions the user must follow
// after `apply` (e.g. Codex requires trusting each hook once via /hooks).
type postApplyNoter interface {
	PostApplyNotes() []string
}

func newVersionCmd(d *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fprintf(cmd.OutOrStdout(), "agentleash %s (commit %s, %s)\n", d.Version, d.Commit, runtime.Version())
		},
	}
}

func newInitCmd(d *Deps) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write .agentleash.yaml with sensible defaults in the current directory",
		Args:  cobra.NoArgs,
		RunE: runtimeErrors(func(cmd *cobra.Command, _ []string) error {
			cwd, err := d.Getwd()
			if err != nil {
				return err
			}
			data, err := policy.Marshal(policy.Default())
			if err != nil {
				return fmt.Errorf("render default policy: %w", err)
			}
			path := filepath.Join(cwd, policy.FileName)
			backup, err := writePolicyFile(path, data, force)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if backup != "" {
				fprintf(out, "Backed up the previous policy to %s\n", backup)
			}
			if root, ok, err := d.FindPolicy(filepath.Dir(cwd)); err == nil && ok {
				fprintf(cmd.ErrOrStderr(), "agentleash: note: %s is nested inside the project at %s; "+
					"both policies apply and the strictest verdict wins\n", path, root)
			}
			fprintf(out, "Wrote %s\n\nNext steps:\n"+
				"  1. Review %s and adjust secrets and commands to your project.\n"+
				"  2. agentleash apply     # install hooks for Claude Code and Codex\n"+
				"  3. agentleash doctor    # verify the installation\n"+
				"  4. Commit %s so the whole team is protected.\n", path, policy.FileName, policy.FileName)
			return nil
		}),
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing .agentleash.yaml (a .bak copy is kept)")
	return cmd
}

// writePolicyFile creates path with data. With force, an existing regular file is
// backed up to path+".bak" and atomically replaced; anything else (symlink, directory)
// is refused. It returns the backup path, if any.
func writePolicyFile(path string, data []byte, force bool) (backup string, err error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Fresh file: O_EXCL so a concurrently created file is never clobbered.
		// The policy is meant to be committed and shared: 0644 is intended.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // shared, non-secret config file
		if errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("%s already exists; use --force to overwrite it", path)
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			return "", fmt.Errorf("write %s: %w", path, err)
		}
		return "", f.Close()
	case err != nil:
		return "", err
	case !force:
		return "", fmt.Errorf("%s already exists; use --force to overwrite it", path)
	case !info.Mode().IsRegular():
		return "", fmt.Errorf("%s is not a regular file (%s); refusing to overwrite it, remove it first", path, info.Mode().Type())
	}

	old, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup = path + ".bak"
	if err := atomicWrite(backup, old); err != nil {
		return "", fmt.Errorf("back up %s: %w", path, err)
	}
	if err := atomicWrite(path, data); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return backup, nil
}

// atomicWrite writes data to a temp file in path's directory and renames it over path.
func atomicWrite(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil { //nolint:gosec // shared, non-secret config file
		return err
	}
	return os.Rename(name, path)
}

func newApplyCmd(d *Deps) *cobra.Command {
	var (
		agentNames []string
		remove     bool
	)
	cmd := &cobra.Command{
		Use:   "apply [--agent claude,codex] [--remove]",
		Short: "Install (or remove) native rules and hooks for the selected agents",
		Args:  cobra.NoArgs,
		RunE: runtimeErrors(func(cmd *cobra.Command, _ []string) error {
			return agrRunApply(cmd, d, agentNames, remove)
		}),
	}
	cmd.Flags().StringSliceVar(&agentNames, "agent", nil, "agents to configure (comma separated; default: all)")
	cmd.Flags().BoolVar(&remove, "remove", false, "remove everything agentleash installed")
	return cmd
}

// agrRunApply implements `agentleash apply`: it installs (or, with remove, removes)
// agentleash for every selected adapter and reports the outcome of each one.
func agrRunApply(cmd *cobra.Command, d *Deps, agentNames []string, remove bool) error {
	selected, err := selectAdapters(d, agentNames, cmd.Flags().Changed("agent"))
	if err != nil {
		return err
	}
	root, err := agrFindPolicyRoot(d)
	if err != nil {
		return err
	}

	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
	var (
		p      *policy.Policy
		binary string
	)
	if !remove {
		if p, binary, err = agrLoadApplyInputs(d, root, errOut); err != nil {
			return err
		}
	}

	failed := false
	var notes []string
	for _, a := range selected {
		adapterNotes, ok := agrApplyAdapter(a, root, p, binary, remove, out, errOut)
		if !ok {
			failed = true
			continue
		}
		notes = append(notes, adapterNotes...)
	}
	agrPrintNextSteps(out, notes)
	if failed {
		return exitCode(1)
	}
	return nil
}

// agrFindPolicyRoot returns the directory holding the policy file that applies to the
// current working directory.
func agrFindPolicyRoot(d *Deps) (string, error) {
	cwd, err := d.Getwd()
	if err != nil {
		return "", err
	}
	root, found, err := d.FindPolicy(cwd)
	if err != nil {
		return "", fmt.Errorf("look for %s: %w", policy.FileName, err)
	}
	if !found {
		return "", fmt.Errorf("no %s found in %s or any parent directory; run `agentleash init` first", policy.FileName, cwd)
	}
	return root, nil
}

// agrLoadApplyInputs loads the policy under root and resolves the agentleash binary the
// hooks will call, warning on errOut when that binary looks like a temporary build.
func agrLoadApplyInputs(d *Deps, root string, errOut io.Writer) (*policy.Policy, string, error) {
	path := filepath.Join(root, policy.FileName)
	p, err := d.LoadPolicy(path)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w (fix it, or run `agentleash doctor`)", path, err)
	}
	binary, err := selfPath(d)
	if err != nil {
		return nil, "", fmt.Errorf("resolve agentleash binary path: %w", err)
	}
	if isTransientBinary(binary) {
		fprintf(errOut, "agentleash: warning: %s looks like a temporary build (go run?); "+
			"the hooks will break when it is deleted. Install agentleash and re-run apply.\n", binary)
	}
	return p, binary, nil
}

// agrApplyAdapter applies (or, with remove, removes) agentleash for one adapter and
// prints the result. It reports false when the adapter failed; otherwise it returns the
// adapter's post-apply notes, each prefixed with the adapter name.
func agrApplyAdapter(a agents.Adapter, root string, p *policy.Policy, binary string, remove bool, out, errOut io.Writer) ([]string, bool) {
	var (
		changed []string
		err     error
	)
	if remove {
		changed, err = a.Remove(root)
	} else {
		changed, err = a.Apply(root, p, binary)
	}
	if err != nil {
		fprintf(errOut, "✗ %s: %v\n", a.Name(), err)
		return nil, false
	}
	switch {
	case len(changed) == 0:
		fprintf(out, "✓ %s: already up to date\n", a.Name())
	case remove:
		fprintf(out, "✓ %s: removed agentleash from %d file(s)\n", a.Name(), len(changed))
	default:
		fprintf(out, "✓ %s: updated %d file(s)\n", a.Name(), len(changed))
	}
	for _, c := range changed {
		fprintf(out, "    %s\n", c)
	}
	n, ok := a.(postApplyNoter)
	if !ok || remove {
		return nil, true
	}
	var notes []string
	for _, note := range n.PostApplyNotes() {
		notes = append(notes, a.Name()+": "+note)
	}
	return notes, true
}

// agrPrintNextSteps prints the collected post-apply notes, if there are any.
func agrPrintNextSteps(out io.Writer, notes []string) {
	if len(notes) == 0 {
		return
	}
	fprintf(out, "\nNext steps:\n")
	for _, n := range notes {
		fprintf(out, "  - %s\n", n)
	}
}

func selectAdapters(d *Deps, names []string, given bool) ([]agents.Adapter, error) {
	if !given {
		return d.Adapters, nil
	}
	var out []agents.Adapter
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		a := d.adapter(n)
		if a == nil {
			return nil, usageError("unknown agent %q (known: %s)", n, d.adapterNames())
		}
		seen[n] = true
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, usageError("--agent selects no agent (known: %s)", d.adapterNames())
	}
	return out, nil
}

// selfPath returns the absolute path of the running binary for hook commands. Symlinks
// are deliberately not resolved: package managers (Homebrew, Scoop, asdf) point a stable
// path at a versioned one that disappears on upgrade. When `agentleash` on PATH is the
// same file, that path is preferred.
func selfPath(d *Deps) (string, error) {
	exe, err := d.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return "", err
	}
	if lp, err := d.LookPath("agentleash"); err == nil {
		if lp, err = filepath.Abs(lp); err == nil && sameFile(lp, exe) {
			return lp, nil
		}
	}
	return exe, nil
}

func sameFile(a, b string) bool {
	ia, err := os.Stat(a)
	if err != nil {
		return false
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ia, ib)
}

// isTransientBinary reports binaries built by `go run`/`go test` that will vanish.
func isTransientBinary(bin string) bool {
	return strings.Contains(filepath.ToSlash(bin), "/go-build")
}

type checkResult struct {
	Decision      engine.Decision `json:"decision"`
	Rule          string          `json:"rule"`
	Reason        string          `json:"reason"`
	Policy        string          `json:"policy,omitempty"`
	Protected     bool            `json:"protected"`
	DefaultPolicy bool            `json:"default_policy"`
	Warning       string          `json:"warning,omitempty"`
}

const unprotectedWarning = "no .agentleash.yaml found: hooks will NOT block anything in this project; " +
	"showing what the default policy would do"

func newCheckCmd(d *Deps) *cobra.Command {
	var (
		shell  string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   `check [--shell bash|powershell] [--json] "<command>"`,
		Short: "Dry run: would this shell command be blocked, and why?",
		Long: `Evaluates a shell command against every policy found from the current
directory upwards (the strictest verdict wins), like the hook does. Without a
policy the project is NOT protected; check then shows what the built-in default
policy would do.

Exit codes: 0 allow, 1 deny or ask, 2 usage or configuration error.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return checkError(cmd, asJSON, usageError("%v", err))
			}
			return nil
		},
		RunE: runtimeErrors(func(cmd *cobra.Command, args []string) error {
			res, err := runCheck(d, args[0], shell)
			if err != nil {
				return checkError(cmd, asJSON, err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				b, err := json.MarshalIndent(res, "", "  ")
				if err != nil {
					return err
				}
				fprintf(out, "%s\n", b)
			} else {
				if !res.Protected {
					fprintf(cmd.ErrOrStderr(), "agentleash: warning: %s\n", res.Warning)
				}
				printCheck(out, res)
			}
			if res.Decision != engine.Allow {
				return exitCode(1)
			}
			return nil
		}),
	}
	cmd.Flags().StringVar(&shell, "shell", "bash", "shell dialect of the command: bash or powershell")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON")
	return cmd
}

func printCheck(out io.Writer, res checkResult) {
	fprintf(out, "decision: %s\n", res.Decision)
	if res.Rule != "" {
		fprintf(out, "rule:     %s\n", res.Rule)
	}
	if res.Reason != "" {
		fprintf(out, "reason:   %s\n", res.Reason)
	}
	if res.Protected {
		fprintf(out, "policy:   %s\n", res.Policy)
	} else {
		fprintf(out, "policy:   built-in default policy (project NOT protected; run `agentleash init`)\n")
	}
}

// checkError also reports err as JSON on stdout when --json is set.
func checkError(cmd *cobra.Command, asJSON bool, err error) error {
	if asJSON {
		b, mErr := json.Marshal(map[string]string{"error": err.Error()})
		if mErr == nil {
			fprintf(cmd.OutOrStdout(), "%s\n", b)
		}
	}
	return err
}

func runCheck(d *Deps, command, shell string) (checkResult, error) {
	var sh engine.Shell
	switch strings.ToLower(shell) {
	case "bash", "":
		sh = engine.ShellBash
	case "powershell", "pwsh":
		sh = engine.ShellPowerShell
	default:
		return checkResult{}, usageError("unsupported --shell %q (use bash or powershell)", shell)
	}
	cwd, err := d.Getwd()
	if err != nil {
		return checkResult{}, usageError("%v", err)
	}
	cwd = absFrom("", cwd)
	home, err := d.UserHomeDir()
	if err != nil {
		return checkResult{}, usageError("could not determine the home directory: %v", err)
	}
	roots, err := discoverPolicies(d, []string{cwd})
	if err != nil {
		return checkResult{}, usageError("look for %s: %v", policy.FileName, err)
	}
	req := engine.Request{Tool: engine.ToolShell, Command: command, Shell: sh, Cwd: cwd, Home: home}

	if len(roots) == 0 {
		req.ProjectRoot = cwd
		v := normalize(d.NewEvaluator(policy.Default()).Evaluate(req))
		return checkResult{Decision: v.Decision, Rule: v.Rule, Reason: v.Reason, DefaultPolicy: true, Warning: unprotectedWarning}, nil
	}
	// Load every policy first so a broken one is reported as a configuration error.
	for _, root := range roots {
		path := filepath.Join(root, policy.FileName)
		if _, err := d.LoadPolicy(path); err != nil {
			return checkResult{}, usageError("%s: %v (the hook blocks every tool call until this is fixed)", path, err)
		}
	}
	v, path := evaluateAll(d, roots, req)
	return checkResult{Decision: v.Decision, Rule: v.Rule, Reason: v.Reason, Policy: path, Protected: true}, nil
}
