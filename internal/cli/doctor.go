package cli

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/policy"
	"github.com/spf13/cobra"
)

// hookConfigFiler is an optional adapter interface naming the file (relative to the
// project root) that holds its hook, for `doctor`.
type hookConfigFiler interface {
	HookConfigFile() string
}

// knownHookConfigs is used for adapters that do not implement hookConfigFiler.
var knownHookConfigs = map[string][]string{
	"claude": {filepath.Join(".claude", "settings.json"), filepath.Join(".claude", "settings.local.json")},
	"codex":  {filepath.Join(".codex", "hooks.json")},
}

// hookArgRe finds the " hook " argument that follows the binary in a legacy shell-form command.
var hookArgRe = regexp.MustCompile(`\s+hook(\s|$)`)

func newDoctorCmd(d *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Verify the policy and the installed hooks",
		Args:  cobra.NoArgs,
		RunE: runtimeErrors(func(cmd *cobra.Command, _ []string) error {
			r := &report{w: cmd.OutOrStdout()}
			runDoctor(d, r)
			if r.failed {
				return exitCode(1)
			}
			return nil
		}),
	}
}

type report struct {
	w      io.Writer
	failed bool
}

func (r *report) ok(format string, a ...any)   { fprintf(r.w, "✓ "+format+"\n", a...) }
func (r *report) info(format string, a ...any) { fprintf(r.w, "- "+format+"\n", a...) }
func (r *report) bad(format string, a ...any) {
	r.failed = true
	fprintf(r.w, "✗ "+format+"\n", a...)
}

func runDoctor(d *Deps, r *report) {
	cwd, err := d.Getwd()
	if err != nil {
		r.bad("cannot determine the working directory: %v", err)
		return
	}
	root, found, err := d.FindPolicy(cwd)
	switch {
	case err != nil:
		r.bad("could not look for %s: %v", policy.FileName, err)
		return
	case !found:
		r.bad("no %s found in %s or any parent directory (run `agentleash init`)", policy.FileName, cwd)
		return
	}
	path := filepath.Join(root, policy.FileName)
	r.ok("policy found: %s", path)
	if _, err := d.LoadPolicy(path); err != nil {
		r.bad("policy is invalid: %v (every tool call is blocked until it is fixed)", err)
	} else {
		r.ok("policy is valid")
	}

	configured := 0
	probed := map[string]bool{}
	for _, a := range d.Adapters {
		files := hookConfigFiles(a)
		if len(files) == 0 {
			r.info("%s: don't know where its hook lives; skipped", a.Name())
			continue
		}
		if checkAgent(d, r, a.Name(), root, files, probed) {
			configured++
		}
	}
	if configured == 0 {
		r.bad("no agent is configured; run `agentleash apply`")
	}
}

func hookConfigFiles(a agents.Adapter) []string {
	if f, ok := a.(hookConfigFiler); ok {
		return []string{f.HookConfigFile()}
	}
	return knownHookConfigs[a.Name()]
}

// checkAgent reports on one agent's hook; it returns false when the agent is not configured at all.
func checkAgent(d *Deps, r *report, name, root string, files []string, probed map[string]bool) bool {
	existing, hooks := 0, 0
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		existing++
		if err != nil {
			r.bad("%s: cannot read %s: %v", name, rel, err)
			continue
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			r.bad("%s: %s is not valid JSON: %v", name, rel, err)
			continue
		}
		for _, bin := range hookBinaries(doc, name) {
			hooks++
			if !binaryExists(bin) {
				r.bad("%s: hook binary not found: %s (re-run `agentleash apply --agent %s`)", name, bin, name)
				continue
			}
			r.ok("%s: hook installed in %s (%s)", name, rel, bin)
			if !probed[bin] {
				probed[bin] = true
				probeBinary(d, r, bin)
			}
		}
	}
	switch {
	case existing == 0:
		r.info("%s: not configured (%s not found; run `agentleash apply --agent %s` to protect it)",
			name, strings.Join(files, ", "), name)
		return false
	case hooks == 0:
		r.bad("%s: agentleash hook not installed in %s (run `agentleash apply --agent %s`)", name, strings.Join(files, ", "), name)
	}
	return true
}

// probeBinary runs `<bin> version` to make sure the hook binary actually starts.
func probeBinary(d *Deps, r *report, bin string) {
	out, err := d.RunBinary(bin, "version")
	if err != nil {
		r.bad("hook binary %s does not run: %v", bin, err)
		return
	}
	v := strings.TrimSpace(string(out))
	if !strings.Contains(v, " "+d.Version+" ") {
		r.info("hook binary reports %q; this agentleash is %s", v, d.Version)
		return
	}
	r.ok("hook binary runs: %s", v)
}

// hookBinaries returns the binary of every agentleash hook handler for agent found
// anywhere in a JSON document. A handler is an object with "command" (and, for Codex,
// an optional "commandWindows" override, preferred on Windows) plus optional "args".
// Detection uses agents.IsAgentleashCommand: exec form (command = binary path, args =
// ["hook", agent]) or legacy shell form (`<binary> hook <agent>`).
func hookBinaries(doc any, agent string) []string {
	var bins []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if bin, ok := handlerBinary(t, agent); ok {
				bins = append(bins, bin)
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(doc)
	return bins
}

func handlerBinary(h map[string]any, agent string) (string, bool) {
	args := stringSlice(h["args"])
	cmd, _ := h["command"].(string)
	win, _ := h["commandWindows"].(string)
	candidates := []string{cmd, win}
	if runtime.GOOS == "windows" {
		candidates = []string{win, cmd}
	}
	for _, c := range candidates {
		if c == "" || !agents.IsAgentleashCommand(c, args, agent) {
			continue
		}
		if len(args) > 0 {
			return c, true // exec form: command is the binary itself (may contain spaces)
		}
		return hookBinary(c), true
	}
	return "", false
}

func stringSlice(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}

// hookBinary extracts the executable from a hook command such as
// `"C:\Program Files\agentleash.exe" hook claude` or `/usr/bin/agentleash hook codex`.
func hookBinary(cmd string) string {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return ""
	}
	if q := s[0]; q == '"' || q == '\'' {
		if j := strings.IndexByte(s[1:], q); j >= 0 {
			return s[1 : 1+j]
		}
	}
	if loc := hookArgRe.FindStringIndex(s); loc != nil {
		return strings.TrimSpace(s[:loc[0]])
	}
	return strings.Fields(s)[0]
}

func binaryExists(bin string) bool {
	if bin == "" {
		return false
	}
	if filepath.IsAbs(bin) {
		info, err := os.Stat(bin)
		return err == nil && !info.IsDir()
	}
	_, err := exec.LookPath(bin)
	return err == nil
}
