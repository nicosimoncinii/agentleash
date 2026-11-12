package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nicosimoncinii/agentleash/internal/engine"
)

// hookPayload is the subset of the PreToolUse stdin JSON agentleash needs.
// See https://code.claude.com/docs/en/hooks (PreToolUse input).
type hookPayload struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	Cwd       string          `json:"cwd"`
}

// DecodeHook converts a Claude Code PreToolUse payload into an engine.Request.
// Any missing or malformed field the decision depends on is an error, so the
// caller can fail closed.
func (Adapter) DecodeHook(payload []byte, projectRoot, home string) (engine.Request, error) {
	var p hookPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return engine.Request{}, fmt.Errorf("claude: decode hook payload: %w", err)
	}
	if p.ToolName == "" {
		return engine.Request{}, errors.New("claude: hook payload has no tool_name")
	}
	if p.Cwd == "" {
		return engine.Request{}, errors.New("claude: hook payload has no cwd")
	}
	req := engine.Request{Cwd: p.Cwd, ProjectRoot: projectRoot, Home: home}

	kind, ok := toolKinds[p.ToolName]
	if !ok {
		req.Tool = engine.ToolOther
		return req, nil
	}
	req.Tool = kind

	in, err := decodeToolInput(p.ToolName, p.ToolInput)
	if err != nil {
		return engine.Request{}, err
	}

	switch p.ToolName {
	case "Bash", "PowerShell":
		req.Shell = engine.ShellBash
		if p.ToolName == "PowerShell" {
			req.Shell = engine.ShellPowerShell
		}
		req.Command, err = in.required("command")
	case "Read", "Edit", "MultiEdit", "Write":
		req.Paths, err = in.requiredPath("file_path")
	case "NotebookEdit":
		req.Paths, err = in.requiredPath("notebook_path")
	case "Grep":
		req.Paths, err = in.searchPaths(p.Cwd, "glob", false)
	case "Glob":
		// Glob returns file NAMES only, never contents: listing names leaks no
		// secret, so only the search root is checked (denied when it is a
		// secret or inside a secret directory). The pattern is still required
		// for a well-formed payload. Grep, which reads contents, keeps its
		// glob filter.
		req.Paths, err = in.searchPaths(p.Cwd, "pattern", true)
		if err == nil {
			req.Paths = req.Paths[:1]
		}
	}
	if err != nil {
		return engine.Request{}, err
	}
	return req, nil
}

// toolKinds maps the Claude Code tools agentleash inspects to engine kinds.
var toolKinds = map[string]engine.ToolKind{
	"Bash":         engine.ToolShell,
	"PowerShell":   engine.ToolShell,
	"Read":         engine.ToolRead,
	"Grep":         engine.ToolSearch,
	"Glob":         engine.ToolSearch,
	"Edit":         engine.ToolWrite,
	"MultiEdit":    engine.ToolWrite,
	"Write":        engine.ToolWrite,
	"NotebookEdit": engine.ToolWrite,
}

// toolInput is a decoded tool_input object of a known tool.
type toolInput struct {
	tool   string
	fields map[string]json.RawMessage
}

func decodeToolInput(tool string, raw json.RawMessage) (toolInput, error) {
	in := toolInput{tool: tool}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return in, fmt.Errorf("claude: %s payload has no tool_input", tool)
	}
	if err := json.Unmarshal(raw, &in.fields); err != nil || in.fields == nil {
		return in, fmt.Errorf("claude: %s tool_input is not a JSON object", tool)
	}
	return in, nil
}

// optional returns a string field; ok is false when the field is absent or null.
func (in toolInput) optional(name string) (s string, ok bool, err error) {
	raw, present := in.fields[name]
	if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, fmt.Errorf("claude: %s tool_input.%s is not a string", in.tool, name)
	}
	return s, s != "", nil
}

func (in toolInput) required(name string) (string, error) {
	s, ok, err := in.optional(name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("claude: %s tool_input.%s is missing or empty", in.tool, name)
	}
	return s, nil
}

func (in toolInput) requiredPath(name string) ([]string, error) {
	s, err := in.required(name)
	if err != nil {
		return nil, err
	}
	return []string{s}, nil
}

// searchPaths returns the searched directory (tool_input.path, defaulting to cwd)
// followed by the file-name glob in field globField when present.
func (in toolInput) searchPaths(cwd, globField string, globRequired bool) ([]string, error) {
	dir, ok, err := in.optional("path")
	if err != nil {
		return nil, err
	}
	if !ok {
		dir = cwd
	}
	paths := []string{dir}
	var glob string
	if globRequired {
		glob, err = in.required(globField)
		ok = err == nil
	} else {
		glob, ok, err = in.optional(globField)
	}
	if err != nil {
		return nil, err
	}
	if ok {
		paths = append(paths, glob)
	}
	return paths, nil
}

// hookOutput is the PreToolUse decision JSON written to stdout.
// See https://code.claude.com/docs/en/hooks (PreToolUse decision control).
type hookOutput struct {
	HookSpecificOutput hookDecision `json:"hookSpecificOutput"`
}

type hookDecision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// EncodeVerdict converts a verdict into Claude Code hook output. The exit code
// is always 0: Claude Code reads the decision from the JSON on stdout.
//
// Allow produces no output at all. An explicit "allow" would skip Claude Code's
// own permission prompt, so agentleash only ever narrows what Claude Code permits.
// Unknown decisions fail closed as deny.
func (Adapter) EncodeVerdict(v engine.Verdict) ([]byte, int) {
	decision, reason := string(v.Decision), v.Reason
	switch v.Decision {
	case engine.Allow:
		return nil, 0
	case engine.Ask, engine.Deny:
		if reason == "" {
			reason = "blocked by agentleash policy"
		}
	default:
		decision = string(engine.Deny)
		reason = fmt.Sprintf("agentleash: unknown decision %q; blocking (fail closed)", v.Decision)
	}
	out, err := marshalJSON(hookOutput{HookSpecificOutput: hookDecision{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}})
	if err != nil {
		// Unreachable for this fixed struct; exit 2 blocks the call regardless.
		return nil, 2
	}
	return out, 0
}

// marshalJSON encodes v compactly without HTML escaping, followed by a newline.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
