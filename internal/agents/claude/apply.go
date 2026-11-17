package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

const (
	// hookMatcher lists the tools whose calls agentleash inspects. It contains only
	// letters and "|", so Claude Code treats it as a list of exact tool names.
	hookMatcher = "Bash|PowerShell|Read|Grep|Glob|Edit|MultiEdit|Write|NotebookEdit"
	// hookTimeout is the handler timeout in seconds.
	hookTimeout = 30
	// stateFileName records which permissions.deny rules agentleash added, so Remove
	// never deletes a rule the user wrote. It lives next to settings.json instead of
	// inside it because Claude Code may reject unknown settings keys.
	stateFileName = "agentleash-state.json"
	stateVersion  = 1
)

func settingsPath(root string) string { return filepath.Join(root, ".claude", "settings.json") }
func statePath(root string) string    { return filepath.Join(root, ".claude", stateFileName) }

// state is the content of stateFileName.
type state struct {
	Version         int      `json:"version"`
	PermissionsDeny []string `json:"permissionsDeny"`
}

// hookGroup and hookHandler render the PreToolUse entry with a stable key order.
type hookGroup struct {
	Matcher string        `json:"matcher"`
	Hooks   []hookHandler `json:"hooks"`
}

// hookHandler is an exec-form command hook: Claude Code spawns Command with Args
// directly, with no shell, so paths with spaces need no quoting and Windows does not
// depend on Git Bash.
type hookHandler struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
	// OnFailure "block" makes Claude Code (v2.1.295+) block the tool call when the
	// hook cannot start, times out, exits with an unexpected code or prints invalid
	// output.
	OnFailure string `json:"onFailure"`
}

// Static notes shown after every apply.
var staticNotes = []string{
	`Claude Code v2.1.295 or later is required for the hook's onFailure: "block"; on older versions a failing or timed-out hook does not block tool calls (check with: claude --version).`,
	"Start claude from the project root: .claude/settings.json is only read from the session's primary working directory.",
	"Commit .claude/" + stateFileName + " together with .claude/settings.json: it records which permission rules agentleash manages, so later apply/remove runs do not touch yours.",
}

// userHomeDir is replaced in tests.
var userHomeDir = os.UserHomeDir

// lastNotes holds the warnings of the most recent Apply in this process. The CLI
// calls PostApplyNotes on the same (stateless) Adapter value right after Apply.
var lastNotes struct {
	sync.Mutex
	notes []string
}

func setNotes(notes []string) {
	lastNotes.Lock()
	defer lastNotes.Unlock()
	lastNotes.notes = notes
}

// PostApplyNotes returns instructions and warnings for the user after Apply: the
// warnings of the most recent Apply followed by the standing requirements.
func (Adapter) PostApplyNotes() []string {
	lastNotes.Lock()
	defer lastNotes.Unlock()
	return append(slices.Clone(lastNotes.notes), staticNotes...)
}

// Apply merges agentleash's Read/Edit deny rules and PreToolUse hook into
// <projectRoot>/.claude/settings.json, preserving everything else. It is idempotent:
// a run that changes nothing in meaning writes nothing. Before the first change to an
// existing file it saves the original as settings.json.bak.
func (Adapter) Apply(projectRoot string, p *policy.Policy, binary string) ([]string, error) {
	setNotes(nil)
	if p == nil {
		return nil, errors.New("claude: apply: nil policy")
	}
	command, err := resolveBinary(binary)
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("claude: apply: %w", err)
	}
	home, _ := userHomeDir() // unknown home: "~/" globs overlap no project glob
	block, notes, err := denyBlock(p, root, home)
	if err != nil {
		return nil, fmt.Errorf("claude: apply: %w", err)
	}
	cfg, err := load(projectRoot)
	if err != nil {
		return nil, err
	}
	hadHook, err := hasHook(cfg.doc)
	if err != nil {
		return nil, cfg.wrap(err)
	}
	if hadHook && cfg.state == nil {
		notes = append(notes, missingStateNote(cfg.doc, block))
	}
	if err := mergeDeny(cfg.doc, block, cfg.owned); err != nil {
		return nil, cfg.wrap(err)
	}
	if err := updateHook(cfg.doc, command, true); err != nil {
		return nil, cfg.wrap(err)
	}
	changed, err := cfg.save(block, true)
	setNotes(notes)
	return changed, err
}

// Remove deletes the hook and deny rules Apply installed and leaves the rest of
// settings.json unchanged in meaning.
func (Adapter) Remove(projectRoot string) ([]string, error) {
	cfg, err := load(projectRoot)
	if err != nil {
		return nil, err
	}
	if err := mergeDeny(cfg.doc, nil, cfg.owned); err != nil {
		return nil, cfg.wrap(err)
	}
	if err := updateHook(cfg.doc, "", false); err != nil {
		return nil, cfg.wrap(err)
	}
	return cfg.save(nil, false)
}

// resolveBinary returns the hook executable. A relative path is made absolute so the
// hook works from any working directory; a bare name is left for PATH lookup.
func resolveBinary(binary string) (string, error) {
	b := strings.TrimSpace(binary)
	if b == "" {
		return "", errors.New("claude: apply: empty binary path")
	}
	slashed := strings.ReplaceAll(b, `\`, "/")
	if !strings.Contains(slashed, "/") || filepath.IsAbs(b) ||
		strings.HasPrefix(slashed, "/") || windowsDrive.MatchString(slashed) {
		return b, nil
	}
	abs, err := filepath.Abs(b)
	if err != nil {
		return "", fmt.Errorf("claude: apply: %w", err)
	}
	return abs, nil
}

func missingStateNote(doc *object, block []string) string {
	var existing []string
	if perms, ok, err := doc.childObject("permissions"); err == nil && ok {
		if items, _, err := perms.childArray("deny"); err == nil {
			want := toSet(block)
			for _, it := range items {
				var s string
				if json.Unmarshal(it, &s) == nil && want[s] {
					existing = append(existing, s)
				}
			}
		}
	}
	note := ".claude/" + stateFileName + " was missing although the agentleash hook is installed, so earlier agentleash rules can no longer be told apart from yours"
	if len(existing) > 0 {
		note += "; these entries are now kept as yours (remove duplicates by hand if agentleash added them): " + strings.Join(existing, ", ")
	}
	return note
}

// config is a loaded settings.json plus agentleash's state file.
type config struct {
	root    string
	doc     *object
	orig    []byte
	canon   []byte // canonical render of the original document
	existed bool
	mode    fs.FileMode
	owned   []string
	state   []byte // current state file bytes, nil when absent
}

func (c *config) wrap(err error) error {
	return fmt.Errorf("claude: %s: %w", settingsPath(c.root), err)
}

func load(root string) (*config, error) {
	c := &config{root: root, doc: newObject(), mode: 0o644}

	sp := statePath(root)
	data, err := os.ReadFile(sp)
	switch {
	case err == nil:
		var st state
		if err := json.Unmarshal(data, &st); err != nil || st.Version != stateVersion {
			reason := fmt.Sprintf("unsupported version %d", st.Version)
			if err != nil {
				reason = err.Error()
			}
			return nil, fmt.Errorf("claude: %s is corrupt (%s); to recover, delete it and re-run `agentleash apply` "+
				"(the permission rules it tracked stay in .claude/settings.json and become yours to remove by hand)", sp, reason)
		}
		c.state, c.owned = data, st.PermissionsDeny
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("claude: %w", err)
	}

	path := settingsPath(root)
	data, err = os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return c, nil
	case err != nil:
		return nil, fmt.Errorf("claude: %w", err)
	}
	c.orig, c.existed = data, true
	if fi, err := os.Stat(path); err == nil {
		c.mode = fi.Mode().Perm()
	}
	if len(bytes.TrimSpace(data)) > 0 {
		if c.doc, err = parseObject(data); err != nil {
			return nil, c.wrap(err)
		}
	}
	if c.canon, err = c.doc.render(); err != nil {
		return nil, c.wrap(err)
	}
	return c, nil
}

// save writes settings.json and the state file when their meaning changed. An
// existing settings.json that is semantically unchanged is never rewritten, whatever
// its formatting. The first time agentleash modifies an existing settings.json the
// original is kept as settings.json.bak; later runs never overwrite that backup.
// create allows creating a missing settings.json.
func (c *config) save(owned []string, create bool) ([]string, error) {
	settings, err := c.doc.render()
	if err != nil {
		return nil, c.wrap(err)
	}
	var newState []byte
	if len(owned) > 0 {
		if newState, err = json.MarshalIndent(state{Version: stateVersion, PermissionsDeny: owned}, "", "  "); err != nil {
			return nil, err
		}
		newState = append(newState, '\n')
	}

	var changed []string
	path := settingsPath(c.root)
	if (c.existed && !bytes.Equal(settings, c.canon)) || (!c.existed && create) {
		if err := c.agrWriteSettings(path, settings); err != nil {
			return nil, err
		}
		changed = append(changed, path)
	}
	return c.agrSaveState(changed, newState)
}

// agrWriteSettings writes settings to the settings.json at path (following a symlink so
// it stays a symlink), first backing up the original to settings.json.bak when the file
// existed and no backup exists yet.
func (c *config) agrWriteSettings(path string, settings []byte) error {
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved // keep a symlinked settings.json a symlink
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return fmt.Errorf("claude: %w", err)
	}
	if c.existed {
		if _, err := os.Lstat(path + ".bak"); errors.Is(err, fs.ErrNotExist) {
			if err := writeFileAtomic(path+".bak", c.orig, c.mode); err != nil {
				return err
			}
		}
	}
	return writeFileAtomic(target, settings, c.mode)
}

// agrSaveState writes newState to the state file, or removes the file when newState is
// nil, if that changes it. It returns changed plus the state path when it was touched.
func (c *config) agrSaveState(changed []string, newState []byte) ([]string, error) {
	switch sp := statePath(c.root); {
	case newState == nil && c.state != nil:
		if err := os.Remove(sp); err != nil {
			return changed, fmt.Errorf("claude: %w", err)
		}
		changed = append(changed, sp)
	case newState != nil && !bytes.Equal(newState, c.state):
		if err := os.MkdirAll(filepath.Dir(sp), 0o750); err != nil {
			return changed, fmt.Errorf("claude: %w", err)
		}
		if err := writeFileAtomic(sp, newState, 0o644); err != nil {
			return changed, err
		}
		changed = append(changed, sp)
	}
	return changed, nil
}

// writeFileAtomic writes data to a temporary file in the same directory and renames
// it over path, so an interrupted write never leaves a truncated settings file.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("claude: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("claude: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("claude: %w", err)
	}
	// Project settings are shared, non-secret configuration: keep them readable.
	if err = os.Chmod(tmp.Name(), mode); err != nil { //nolint:gosec // see comment above
		return fmt.Errorf("claude: %w", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("claude: %w", err)
	}
	return nil
}

// mergeDeny rebuilds permissions.deny as agentleash's block followed by the user's
// entries in their original order. prevOwned lists the rules agentleash added
// earlier: one occurrence of each is removed (the block comes first, so that is
// agentleash's copy; a later identical rule the user added survives). The block goes
// first so its "!" carve-outs only reach agentleash's rules. Containers left empty
// are deleted.
func mergeDeny(doc *object, block, prevOwned []string) error {
	perms, hadPerms, err := doc.childObject("permissions")
	if err != nil {
		return fmt.Errorf("permissions %w", err)
	}
	if !hadPerms {
		if len(block) == 0 {
			return nil
		}
		perms = newObject()
	}
	items, hadDeny, err := perms.childArray("deny")
	if err != nil {
		return fmt.Errorf("permissions.deny %w", err)
	}

	pending := map[string]int{}
	for _, r := range prevOwned {
		pending[r]++
	}
	var user []json.RawMessage
	removed := false
	for _, it := range items {
		var s string
		if json.Unmarshal(it, &s) == nil && pending[s] > 0 {
			pending[s]--
			removed = true
			continue
		}
		user = append(user, it)
	}

	out := make([]json.RawMessage, 0, len(block)+len(user))
	for _, r := range block {
		raw, err := marshalJSON(r)
		if err != nil {
			return err
		}
		out = append(out, bytes.TrimSpace(raw))
	}
	out = append(out, user...)

	switch {
	case len(out) > 0:
		if err := perms.setArray("deny", out); err != nil {
			return err
		}
	case !hadDeny || !removed:
		return nil // nothing added and nothing of ours removed: leave it as it was
	default:
		perms.del("deny")
	}
	if perms.len() == 0 {
		doc.del("permissions")
		return nil
	}
	return doc.setObject("permissions", perms)
}

// hasHook reports whether hooks.PreToolUse already holds an agentleash handler.
func hasHook(doc *object) (bool, error) {
	hooks, ok, err := doc.childObject("hooks")
	if err != nil || !ok {
		return false, err
	}
	groups, _, err := hooks.childArray("PreToolUse")
	if err != nil {
		return false, err
	}
	for _, g := range groups {
		if _, removed, _ := stripAgentleash(g); removed {
			return true, nil
		}
	}
	return false, nil
}

// updateHook removes every agentleash handler from hooks.PreToolUse and, when install
// is true, adds one matcher group running command. The group takes the place of the
// first group that held only agentleash handlers, so re-applying keeps its position.
// Groups and containers emptied by the removal are deleted.
func updateHook(doc *object, command string, install bool) error {
	hooks, hadHooks, err := doc.childObject("hooks")
	if err != nil {
		return fmt.Errorf("hooks %w", err)
	}
	if !hadHooks {
		if !install {
			return nil
		}
		hooks = newObject()
	}
	groups, _, err := hooks.childArray("PreToolUse")
	if err != nil {
		return fmt.Errorf("hooks.PreToolUse %w", err)
	}

	insertAt := -1
	modified := false
	var out []json.RawMessage
	for _, g := range groups {
		kept, removed, grp := stripAgentleash(g)
		if !removed {
			out = append(out, g)
			continue
		}
		modified = true
		if len(kept) == 0 {
			if insertAt < 0 {
				insertAt = len(out)
			}
			continue
		}
		if err := grp.setArray("hooks", kept); err != nil {
			return err
		}
		raw, err := grp.raw()
		if err != nil {
			return err
		}
		out = append(out, raw)
	}

	if install {
		raw, err := marshalJSON(hookGroup{
			Matcher: hookMatcher,
			Hooks: []hookHandler{{
				Type: "command", Command: command, Args: []string{"hook", "claude"},
				Timeout: hookTimeout, OnFailure: "block",
			}},
		})
		if err != nil {
			return err
		}
		if insertAt < 0 {
			insertAt = len(out)
		}
		out = slices.Insert(out, insertAt, json.RawMessage(bytes.TrimSpace(raw)))
		modified = true
	}
	if !modified {
		return nil
	}

	if len(out) == 0 {
		hooks.del("PreToolUse")
	} else if err := hooks.setArray("PreToolUse", out); err != nil {
		return err
	}
	if hooks.len() == 0 {
		doc.del("hooks")
		return nil
	}
	return doc.setObject("hooks", hooks)
}

// stripAgentleash returns the handlers of matcher group g that are not agentleash's,
// recognising both exec-form handlers and legacy shell-form commands.
// removed is false when g is left untouched (including groups it cannot parse).
func stripAgentleash(g json.RawMessage) (kept []json.RawMessage, removed bool, grp *object) {
	grp, err := parseObject(g)
	if err != nil {
		return nil, false, nil
	}
	handlers, ok, err := grp.childArray("hooks")
	if err != nil || !ok {
		return nil, false, nil
	}
	for _, h := range handlers {
		var handler struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}
		if json.Unmarshal(h, &handler) == nil && agents.IsAgentleashCommand(handler.Command, handler.Args, "claude") {
			removed = true
			continue
		}
		kept = append(kept, h)
	}
	return kept, removed, grp
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
