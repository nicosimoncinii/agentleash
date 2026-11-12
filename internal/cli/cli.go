// Package cli implements the agentleash command line: init, apply, check, hook,
// doctor and version. Every external dependency (streams, working directory, home
// directory, executable path, adapters, policy loading, engine) is injectable so
// the commands can be tested in memory.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/agents/claude"
	"github.com/nicosimoncinii/agentleash/internal/agents/codex"
	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
	"github.com/spf13/cobra"
)

// DefaultMaxHookInput bounds the hook payload read from stdin. Larger payloads are denied.
const DefaultMaxHookInput int64 = 10 << 20 // 10 MiB

// DefaultHookTimeout is the hook's internal watchdog. When it fires the call is blocked.
const DefaultHookTimeout = 5 * time.Second

// Evaluator is the subset of *engine.Engine the CLI needs.
type Evaluator interface {
	Evaluate(engine.Request) engine.Verdict
}

// Deps are the CLI's external dependencies. Zero fields fall back to the real ones.
type Deps struct {
	// Stdin, Stdout and Stderr default to cobra's (process) streams. Tests may also
	// use cobra's SetIn/SetOut/SetErr on the returned root command.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Getwd returns the working directory (default os.Getwd).
	Getwd func() (string, error)
	// UserHomeDir returns the home directory (default os.UserHomeDir).
	UserHomeDir func() (string, error)
	// Executable returns the path of the running binary (default os.Executable).
	Executable func() (string, error)
	// LookPath resolves a command on PATH (default exec.LookPath).
	LookPath func(file string) (string, error)
	// Getenv reads an environment variable (default os.Getenv).
	Getenv func(key string) string
	// RunBinary runs an installed agentleash binary for `doctor` (default: os/exec with a timeout).
	RunBinary func(bin string, args ...string) (stdout []byte, err error)

	// Adapters is the agent registry (default DefaultAdapters()).
	Adapters []agents.Adapter

	// FindPolicy, LoadPolicy and NewEvaluator default to policy.Find, policy.Load and engine.New.
	FindPolicy   func(dir string) (root string, ok bool, err error)
	LoadPolicy   func(path string) (*policy.Policy, error)
	NewEvaluator func(*policy.Policy) Evaluator

	// MaxHookInput is the stdin limit for `hook` in bytes (default DefaultMaxHookInput).
	MaxHookInput int64
	// HookTimeout bounds a whole `hook` run (default DefaultHookTimeout).
	HookTimeout time.Duration

	// Version and Commit are injected from package main's ldflags.
	Version string
	Commit  string
}

// DefaultAdapters returns the built-in agent adapters.
func DefaultAdapters() []agents.Adapter {
	return []agents.Adapter{claude.Adapter{}, codex.Adapter{}}
}

func (d *Deps) withDefaults() {
	if d.Getwd == nil {
		d.Getwd = os.Getwd
	}
	if d.UserHomeDir == nil {
		d.UserHomeDir = os.UserHomeDir
	}
	if d.Executable == nil {
		d.Executable = os.Executable
	}
	if d.LookPath == nil {
		d.LookPath = exec.LookPath
	}
	if d.Getenv == nil {
		d.Getenv = os.Getenv
	}
	if d.RunBinary == nil {
		d.RunBinary = runBinary
	}
	if d.Adapters == nil {
		d.Adapters = DefaultAdapters()
	}
	if d.FindPolicy == nil {
		d.FindPolicy = policy.Find
	}
	if d.LoadPolicy == nil {
		d.LoadPolicy = policy.Load
	}
	if d.NewEvaluator == nil {
		// Resolve symlinks so a link created by an earlier tool call to a secret is caught.
		d.NewEvaluator = func(p *policy.Policy) Evaluator {
			return engine.New(p, engine.WithSymlinkResolver(filepath.EvalSymlinks))
		}
	}
	if d.MaxHookInput <= 0 {
		d.MaxHookInput = DefaultMaxHookInput
	}
	if d.HookTimeout <= 0 {
		d.HookTimeout = DefaultHookTimeout
	}
	if d.Version == "" {
		d.Version = "dev"
	}
	if d.Commit == "" {
		d.Commit = "none"
	}
}

func (d *Deps) adapter(name string) agents.Adapter {
	for _, a := range d.Adapters {
		if a.Name() == name {
			return a
		}
	}
	return nil
}

func (d *Deps) adapterNames() string {
	names := make([]string, 0, len(d.Adapters))
	for _, a := range d.Adapters {
		names = append(names, a.Name())
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// NewRootCmd builds the agentleash command tree. Run it with Execute to get an exit code.
func NewRootCmd(deps Deps) *cobra.Command {
	deps.withDefaults()
	d := &deps
	root := &cobra.Command{
		Use:           "agentleash",
		Short:         "One policy file. Every coding agent. Secrets stay secret.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	if d.Stdin != nil {
		root.SetIn(d.Stdin)
	}
	if d.Stdout != nil {
		root.SetOut(d.Stdout)
	}
	if d.Stderr != nil {
		root.SetErr(d.Stderr)
	}
	root.AddCommand(
		newInitCmd(d),
		newApplyCmd(d),
		newCheckCmd(d),
		newHookCmd(d),
		newDoctorCmd(d),
		newVersionCmd(d),
	)
	return root
}

// exitError carries a process exit code. silent errors have already been reported.
type exitError struct {
	code   int
	err    error
	silent bool
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// usageError is a usage error (exit 2).
func usageError(format string, a ...any) error {
	return &exitError{code: 2, err: fmt.Errorf(format, a...)}
}

// exitCode reports an already printed outcome.
func exitCode(code int) error {
	if code == 0 {
		return nil
	}
	return &exitError{code: code, silent: true}
}

// runtimeErrors marks every error returned by fn as a runtime failure (exit 1), so that
// Execute can treat errors raised by cobra itself (flags, args, unknown commands) as usage errors.
func runtimeErrors(fn func(cmd *cobra.Command, args []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		err := fn(cmd, args)
		var ee *exitError
		if err == nil || errors.As(err, &ee) {
			return err
		}
		return &exitError{code: 1, err: err}
	}
}

// Execute runs the command and maps the outcome to a process exit code:
// 0 success, 1 failure (or a blocked command for `check`), 2 usage error.
// `hook` returns the exit code chosen by the agent adapter.
func Execute(cmd *cobra.Command) int {
	err := cmd.Execute()
	if err == nil {
		return 0
	}
	stderr := cmd.ErrOrStderr()
	var ee *exitError
	if errors.As(err, &ee) {
		if !ee.silent && ee.err != nil {
			fprintf(stderr, "agentleash: %v\n", ee.err)
		}
		return ee.code
	}
	fprintf(stderr, "agentleash: %v\nRun 'agentleash --help' for usage.\n", err)
	return 2
}

// runBinary runs bin with args and a short timeout, returning its stdout.
func runBinary(bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, args...).Output() //nolint:gosec // bin is the agentleash binary being diagnosed
}

// fprintf writes best-effort output; a broken stdout/stderr is not actionable here.
func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}
