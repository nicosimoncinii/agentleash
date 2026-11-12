// Package codex adapts agentleash to OpenAI Codex CLI.
//
// Formats verified against the official docs (2026-11):
//   - Hooks: https://learn.chatgpt.com/docs/hooks (formerly developers.openai.com/codex/hooks)
//   - Config: https://learn.chatgpt.com/docs/config-file/config-reference and
//     https://learn.chatgpt.com/docs/config-file/config-advanced#shell-environment-policy
//   - Wire schemas: github.com/openai/codex codex-rs/hooks/schema/generated/pre-tool-use.command.*.schema.json
//
// Hooks: <root>/.codex/hooks.json -> hooks.PreToolUse[] matcher groups with "command" handlers.
// Project hooks load only in trusted projects, and each hook must be trusted once via /hooks.
//
// PreToolUse stdin carries tool_name, tool_input and cwd. Shell calls (including unified
// exec_command) arrive as tool_name "Bash" with tool_input.command; apply_patch arrives as
// tool_name "apply_patch" with the patch text in tool_input.command. The payload does not say
// which shell runs the command (the model may pick zsh, bash, sh, pwsh, powershell or cmd per
// call), so shell requests use the "auto" dialect: the engine evaluates every dialect and keeps
// the strictest verdict.
//
// Blocking (pre_tool_use.rs): exit 0 with {"hookSpecificOutput":{"hookEventName":"PreToolUse",
// "permissionDecision":"deny","permissionDecisionReason":"..."}}, or exit 2 with a non-empty
// reason on stderr. Codex FAILS OPEN (runs the tool) on any other exit code, exit 2 with empty
// stderr, a timeout, JSON-looking but invalid stdout, an empty deny reason, or
// permissionDecision "ask". So engine.Ask is mapped to deny and every deny carries a reason.
package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// Adapter implements agents.Adapter for Codex.
type Adapter struct{}

var _ agents.Adapter = Adapter{}

// Name returns the CLI identifier of this adapter.
func (Adapter) Name() string { return "codex" }

// lastApply holds the warnings of the most recent Apply in this process (Adapter is a
// stateless value type, and the CLI asks for notes right after calling Apply).
var lastApply struct {
	sync.Mutex
	warnings []string
}

func setApplyWarnings(w []string) {
	lastApply.Lock()
	defer lastApply.Unlock()
	lastApply.warnings = append([]string(nil), w...)
}

// PostApplyNotes returns the reminders the CLI prints after a successful Apply, followed by
// warnings ("Warning: ...") about user settings that conflict with the policy.
func (Adapter) PostApplyNotes() []string {
	notes := []string{
		"Codex loads project hooks only for trusted projects, and every new or changed hook must be " +
			"reviewed and trusted once: start Codex in this project and open /hooks to trust the agentleash hook.",
		"Hooks are a guardrail, not a sandbox: they raise the bar for agents but are not a complete enforcement boundary.",
	}
	lastApply.Lock()
	defer lastApply.Unlock()
	return append(notes, lastApply.warnings...)
}

// hookInput is the subset of the Codex PreToolUse stdin object agentleash needs.
type hookInput struct {
	HookEventName string          `json:"hook_event_name"`
	Cwd           string          `json:"cwd"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

// DecodeHook converts a Codex PreToolUse payload into an engine.Request.
// Any malformed or incomplete payload is an error so the CLI fails closed.
func (Adapter) DecodeHook(payload []byte, projectRoot, home string) (engine.Request, error) {
	var in hookInput
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&in); err != nil {
		return engine.Request{}, fmt.Errorf("codex hook: invalid JSON payload: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return engine.Request{}, errors.New("codex hook: unexpected data after JSON payload")
	}
	if in.HookEventName != "" && in.HookEventName != "PreToolUse" {
		return engine.Request{}, fmt.Errorf("codex hook: unsupported hook_event_name %q (want PreToolUse)", in.HookEventName)
	}
	if in.ToolName == "" {
		return engine.Request{}, errors.New("codex hook: missing tool_name")
	}
	if in.Cwd == "" {
		return engine.Request{}, errors.New("codex hook: missing cwd")
	}

	req := engine.Request{Cwd: in.Cwd, ProjectRoot: projectRoot, Home: home}
	switch {
	case isShellTool(in.ToolName):
		cmd, shell, argv, err := decodeShell(in.ToolInput)
		if err != nil {
			return engine.Request{}, fmt.Errorf("codex hook: %s: %w", in.ToolName, err)
		}
		req.Tool, req.Command, req.Shell = engine.ToolShell, cmd, shell
		// exec_command intercepts `apply_patch` invocations (heredoc or argv) and applies them
		// with no second PreToolUse, so the patch targets are checked here as well.
		req.Paths = embeddedPatchPaths(in.Cwd, home, cmd, argv)
	case isPatchTool(in.ToolName):
		patch, err := stringField(in.ToolInput, "command")
		if err != nil {
			return engine.Request{}, fmt.Errorf("codex hook: %s: %w", in.ToolName, err)
		}
		paths := patchPaths(patch)
		if len(paths) == 0 {
			return engine.Request{}, fmt.Errorf("codex hook: %s: no file paths found in patch", in.ToolName)
		}
		req.Tool = engine.ToolWrite
		req.Paths = resolvePatchPaths(in.Cwd, home, paths, nil)
	default:
		// MCP tools (mcp__server__tool) and other local function tools.
		req.Tool = engine.ToolOther
	}
	return req, nil
}

func isShellTool(name string) bool {
	switch name {
	case "Bash", "exec_command", "shell", "shell_command", "local_shell":
		return true
	}
	return false
}

func isPatchTool(name string) bool {
	switch name {
	case "apply_patch", "Edit", "Write":
		return true
	}
	return false
}

func isAbsAnyOS(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) ||
		(len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}

func tildeRest(p string) (string, bool) {
	if p == "~" {
		return "", true
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return p[2:], true
	}
	return "", false
}

// resolvePatchPaths turns patch paths into the paths the engine must check. Relative paths are
// anchored at cwd and at every extra base directory (the target of a leading `cd <dir> &&`).
// apply_patch itself does not expand "~", so "~/x" is the literal cwd/~/x; the home-expanded
// path is checked too, erring on the strict side.
func resolvePatchPaths(cwd, home string, paths, bases []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range paths {
		if isAbsAnyOS(p) {
			add(p)
			continue
		}
		if rest, ok := tildeRest(p); ok && home != "" {
			add(filepath.Join(home, filepath.FromSlash(rest)))
		}
		add(filepath.Join(cwd, filepath.FromSlash(p)))
		for _, b := range bases {
			add(filepath.Join(b, filepath.FromSlash(p)))
		}
	}
	return out
}

// cdPrefixRe matches the `cd <dir> &&` prefix Codex accepts before an apply_patch invocation.
var cdPrefixRe = regexp.MustCompile(`(?m)^\s*cd\s+(?:'([^']*)'|"([^"]*)"|([^\s&;|'"]+))\s*&&`)

// embeddedPatchPaths returns the write targets of an apply_patch body embedded in a shell
// command (heredoc form) or passed as an argv element. It over-approximates: any command that
// contains a "*** Begin Patch" line contributes its header paths.
func embeddedPatchPaths(cwd, home, cmd string, argv []string) []string {
	texts := append([]string{cmd}, argv...)
	var paths []string
	seen := map[string]bool{}
	found := false
	for _, t := range texts {
		if !strings.Contains(t, patchBegin) {
			continue
		}
		found = true
		for _, p := range patchPaths(t) {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	if !found {
		return nil
	}
	var bases []string
	for _, m := range cdPrefixRe.FindAllStringSubmatch(cmd, -1) {
		dir := m[1] + m[2] + m[3]
		switch rest, ok := tildeRest(dir); {
		case ok && home != "":
			bases = append(bases, filepath.Join(home, filepath.FromSlash(rest)))
		case isAbsAnyOS(dir):
			bases = append(bases, dir)
		default:
			bases = append(bases, filepath.Join(cwd, filepath.FromSlash(dir)))
		}
	}
	return resolvePatchPaths(cwd, home, paths, bases)
}

func toolInputObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("missing tool_input")
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("tool_input is not an object: %w", err)
	}
	return obj, nil
}

func stringField(raw json.RawMessage, key string) (string, error) {
	obj, err := toolInputObject(raw)
	if err != nil {
		return "", err
	}
	v, ok := obj[key]
	if !ok {
		return "", fmt.Errorf("missing tool_input.%s", key)
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("tool_input.%s is not a string: %w", key, err)
	}
	if strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("empty tool_input.%s", key)
	}
	return s, nil
}

// decodeShell extracts the command text and dialect from a shell tool_input, plus the raw argv
// when the command was an array. The command is a string (documented form) or an argv array
// (older shell tool), which is joined with POSIX quoting so the engine parses exactly the
// words Codex would execute.
func decodeShell(raw json.RawMessage) (cmd string, shell engine.Shell, argv []string, err error) {
	obj, err := toolInputObject(raw)
	if err != nil {
		return "", "", nil, err
	}
	v, ok := obj["command"]
	if !ok {
		v, ok = obj["cmd"] // raw exec_command arguments
	}
	if !ok {
		return "", "", nil, errors.New("missing tool_input.command")
	}
	// Codex does not send the model-selected shell today (exec_command forwards only
	// {"command": cmd}); honour an explicit field if a future payload carries one.
	shell = engine.ShellAuto
	if s, ok := obj["shell"]; ok {
		var name string
		if json.Unmarshal(s, &name) == nil {
			shell = shellFromName(name)
		}
	}

	switch {
	case json.Unmarshal(v, &cmd) == nil:
	case json.Unmarshal(v, &argv) == nil:
		if len(argv) == 0 {
			return "", "", nil, errors.New("empty tool_input.command")
		}
		if script, ok := powerShellScript(argv); ok {
			cmd, shell = script, engine.ShellPowerShell
		} else {
			cmd = joinArgv(argv)
		}
	default:
		return "", "", nil, errors.New("tool_input.command is neither a string nor an array of strings")
	}
	if strings.TrimSpace(cmd) == "" {
		return "", "", nil, errors.New("empty tool_input.command")
	}
	return cmd, shell, argv, nil
}

// shellFromName maps an explicit shell name or path to a dialect; unknown names stay "auto".
func shellFromName(name string) engine.Shell {
	switch baseName(strings.TrimSpace(name)) {
	case "powershell", "pwsh":
		return engine.ShellPowerShell
	case "bash", "sh", "zsh", "dash":
		return engine.ShellBash
	}
	return engine.ShellAuto
}

// baseName returns the lower-cased executable name without directory or .exe, for both
// POSIX and Windows paths regardless of the host OS.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(p), ".exe")
}

func isPowerShell(name string) bool {
	b := baseName(strings.TrimSpace(name))
	return b == "powershell" || b == "pwsh"
}

// powerShellScript unwraps `powershell[.exe] ... -Command <script...>`.
func powerShellScript(argv []string) (string, bool) {
	if !isPowerShell(argv[0]) {
		return "", false
	}
	for i, a := range argv[1:] {
		switch strings.ToLower(a) {
		case "-command", "-c", "/command", "/c":
			return strings.Join(argv[i+2:], " "), true
		}
	}
	return "", false
}

// joinArgv renders argv as a POSIX shell command line.
func joinArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = posixQuote(a)
	}
	return strings.Join(parts, " ")
}

// posixQuote single-quotes s unless it consists only of characters that are never special
// to a POSIX shell.
func posixQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=+@%,") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

type preToolUseOutput struct {
	HookSpecificOutput preToolUseDecision `json:"hookSpecificOutput"`
}

type preToolUseDecision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// askReason is appended when engine.Ask is downgraded to deny.
const askReason = "agentleash: this action needs human confirmation, but Codex PreToolUse hooks cannot ask, " +
	"so it was blocked. A human must run the command manually, or adjust .agentleash.yaml (commands.ask) " +
	"if it should be allowed."

const fallbackReason = "agentleash: blocked by .agentleash.yaml policy."

// EncodeVerdict renders a verdict for Codex as exit 0 plus deny JSON (the documented
// structured form). Codex also blocks on exit 2 with a non-empty stderr reason, which the CLI
// may use for its own error paths; every other exit code, exit 2 with empty stderr, or a
// timeout fails open. Allow emits nothing so Codex's normal approval flow still applies.
func (Adapter) EncodeVerdict(v engine.Verdict) ([]byte, int) {
	var reason string
	switch v.Decision {
	case engine.Allow:
		return nil, 0
	case engine.Deny:
		reason = strings.TrimSpace(v.Reason)
		if reason == "" {
			reason = fallbackReason
		}
	case engine.Ask:
		reason = askReason
		if r := strings.TrimSpace(v.Reason); r != "" {
			reason = r + "\n" + askReason
		}
	default:
		reason = fmt.Sprintf("agentleash: unknown decision %q; blocked to be safe.", v.Decision)
	}
	out, err := json.Marshal(preToolUseOutput{HookSpecificOutput: preToolUseDecision{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}})
	if err != nil { // unreachable: only strings are marshalled
		out = []byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"agentleash: internal error; blocked to be safe."}}`)
	}
	return append(out, '\n'), 0
}

// Apply installs the agentleash PreToolUse hook into <root>/.codex/hooks.json and the secret
// env globs into <root>/.codex/config.toml, merging with existing user configuration.
func (Adapter) Apply(projectRoot string, p *policy.Policy, binary string) ([]string, error) {
	return apply(projectRoot, p, binary)
}

// Remove deletes everything Apply installed, leaving user configuration intact.
func (Adapter) Remove(projectRoot string) ([]string, error) {
	return remove(projectRoot)
}
