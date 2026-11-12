package codex

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

const (
	codexDir   = ".codex"
	hooksFile  = "hooks.json"
	configFile = "config.toml"
)

// fileEdit is a planned change to one file. next == nil means the file must not exist.
type fileEdit struct {
	path   string
	old    []byte
	exists bool
	mode   fs.FileMode
	next   []byte
}

func apply(projectRoot string, p *policy.Policy, binary string) ([]string, error) {
	if p == nil {
		return nil, errors.New("codex apply: nil policy")
	}
	if strings.TrimSpace(binary) == "" {
		return nil, errors.New("codex apply: empty agentleash binary path")
	}
	// cmd.exe expands %VAR% (and !VAR! with delayed expansion) even inside double quotes, so
	// commandWindows would run a different program and the hook would fail open.
	if strings.ContainsAny(binary, "%!") {
		return nil, fmt.Errorf("codex apply: binary path %q contains %% or !, which cmd.exe expands even "+
			"inside quotes; install agentleash to a path without them", binary)
	}
	setApplyWarnings(nil)
	changed, warnings, err := plan(projectRoot, ourGroup(binary), p.Secrets.Env)
	setApplyWarnings(warnings)
	return changed, err
}

func remove(projectRoot string) ([]string, error) {
	changed, _, err := plan(projectRoot, nil, nil)
	return changed, err
}

// plan computes both edits before writing anything, so an unsafe config.toml never leaves a
// half-applied hooks.json behind.
func plan(projectRoot string, group *object, env []string) (changed, warnings []string, err error) {
	dir := filepath.Join(projectRoot, codexDir)
	hooks, err := load(filepath.Join(dir, hooksFile))
	if err != nil {
		return nil, nil, err
	}
	if hooks.next, err = mergeHooks(hooks.old, group); err != nil {
		return nil, nil, fmt.Errorf("codex: %s: %w", hooks.path, err)
	}
	cfg, err := load(filepath.Join(dir, configFile))
	if err != nil {
		return nil, nil, err
	}
	if cfg.next, warnings, err = editConfig(cfg.old, env); err != nil {
		return nil, nil, fmt.Errorf("codex: %s: %w", cfg.path, err)
	}

	for _, e := range []*fileEdit{hooks, cfg} {
		ok, err := e.commit(dir)
		if err != nil {
			return changed, warnings, err
		}
		if ok {
			changed = append(changed, e.path)
		}
	}
	return changed, warnings, nil
}

func load(path string) (*fileEdit, error) {
	e := &fileEdit{path: path, mode: 0o600}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return e, nil
	case err != nil:
		return nil, fmt.Errorf("codex: %w", err)
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("codex: %s is not a regular file", path)
	}
	if e.old, err = os.ReadFile(path); err != nil {
		return nil, fmt.Errorf("codex: %w", err)
	}
	if e.old == nil {
		e.old = []byte{}
	}
	e.exists, e.mode = true, info.Mode().Perm()
	return e, nil
}

// commit applies the edit, keeping a .bak copy of any existing file it modifies or deletes.
func (e *fileEdit) commit(dir string) (bool, error) {
	switch {
	case e.next == nil && !e.exists:
		return false, nil
	case e.next != nil && e.exists && bytes.Equal(e.next, e.old):
		return false, nil
	}
	if e.exists {
		if err := writeAtomic(e.path+".bak", e.old, e.mode); err != nil {
			return false, fmt.Errorf("codex: backup %s: %w", e.path, err)
		}
	}
	if e.next == nil {
		if err := os.Remove(e.path); err != nil {
			return false, fmt.Errorf("codex: %w", err)
		}
		return true, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("codex: %w", err)
	}
	if err := writeAtomic(e.path, e.next, e.mode); err != nil {
		return false, fmt.Errorf("codex: write %s: %w", e.path, err)
	}
	return true, nil
}

func writeAtomic(path string, data []byte, mode fs.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
