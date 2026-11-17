package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/agents"
)

// hookMatcher selects the tools agentleash inspects. Codex compiles a matcher made only of
// [A-Za-z0-9_|] as an exact, '|'-separated list of tool names (codex-rs/hooks/src/engine/matcher.rs).
// Shell and unified exec calls are reported as "Bash"; "exec_command" is listed for robustness.
// apply_patch also matches its "Edit"/"Write" aliases, so naming it once is enough.
const hookMatcher = "Bash|exec_command|apply_patch"

// hookStatusMessage is shown by Codex while the hook runs. It contains agents.HookMarker, a
// Codex-specific extra marker that still identifies our handler if the binary was renamed.
const hookStatusMessage = agents.HookMarker + ": checking tool call against .agentleash.yaml"

// cmdSpecial are characters that need double quotes in a cmd.exe command line.
const cmdSpecial = " \t&|<>^()%!,;=\""

// hookCommand is the POSIX command line (run by Codex via `$SHELL -lc`).
func hookCommand(binary string) string {
	return posixQuote(binary) + " hook codex"
}

// hookCommandWindows is the cmd.exe command line (run by Codex via `%COMSPEC% /C`).
func hookCommandWindows(binary string) string {
	if strings.ContainsAny(binary, cmdSpecial) {
		return `"` + binary + `" hook codex`
	}
	return binary + " hook codex"
}

// ourGroup is the PreToolUse matcher group agentleash installs.
func ourGroup(binary string) *object {
	h := newObject()
	h.set("type", "command")
	h.set("command", hookCommand(binary))
	if w := hookCommandWindows(binary); w != hookCommand(binary) {
		h.set("commandWindows", w)
	}
	h.set("statusMessage", hookStatusMessage)
	g := newObject()
	g.set("matcher", hookMatcher)
	g.set("hooks", []any{h})
	return g
}

func isOurHandler(v any) bool {
	h, ok := v.(*object)
	if !ok {
		return false
	}
	// Codex handlers are shell-form strings (no args array); commandWindows is the Windows variant.
	for _, k := range []string{"command", "commandWindows", "command_windows"} {
		if s, _ := h.vals[k].(string); agents.IsAgentleashCommand(s, nil, "codex") {
			return true
		}
	}
	s, _ := h.vals["statusMessage"].(string)
	return strings.Contains(s, agents.HookMarker)
}

// mergeHooks removes every agentleash handler from a hooks.json document and, when group is
// non-nil, installs group where the first removed agentleash group was (or at the end).
// data == nil means the file does not exist. A nil result means the file should be deleted.
func mergeHooks(data []byte, group *object) ([]byte, error) {
	root, hooks, pre, err := agrLoadHooksDoc(data)
	if err != nil {
		return nil, err
	}
	kept, removed, insertAt := agrStripOurGroups(pre)

	switch {
	case group != nil && insertAt >= 0:
		kept = append(kept[:insertAt], append([]any{group}, kept[insertAt:]...)...)
	case group != nil:
		kept = append(kept, group)
	case !removed:
		return data, nil // nothing of ours: leave the file byte-for-byte alone
	}

	if len(kept) > 0 {
		hooks.set("PreToolUse", kept)
	} else {
		hooks.del("PreToolUse")
	}
	if len(hooks.keys) > 0 {
		root.set("hooks", hooks)
	} else {
		root.del("hooks")
	}
	if len(root.keys) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	if err := encodeOrderedJSON(&buf, root, ""); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// agrLoadHooksDoc decodes a hooks.json document (nil data means an empty one) and returns
// its root object, its "hooks" object and its "hooks.PreToolUse" array, each created empty
// when absent. It fails when any of them has the wrong JSON type.
func agrLoadHooksDoc(data []byte) (root, hooks *object, pre []any, err error) {
	root = newObject()
	if data != nil {
		v, err := decodeOrderedJSON(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse hooks.json: %w", err)
		}
		var ok bool
		if root, ok = v.(*object); !ok {
			return nil, nil, nil, errors.New("hooks.json: top level is not a JSON object")
		}
	}
	hooks = newObject()
	if v, ok := root.vals["hooks"]; ok {
		if hooks, ok = v.(*object); !ok {
			return nil, nil, nil, errors.New(`hooks.json: "hooks" is not an object`)
		}
	}
	if v, ok := hooks.vals["PreToolUse"]; ok {
		if pre, ok = v.([]any); !ok {
			return nil, nil, nil, errors.New(`hooks.json: "hooks.PreToolUse" is not an array`)
		}
	}
	return root, hooks, pre, nil
}

// agrStripOurGroups removes every agentleash handler from the PreToolUse groups in pre.
// It returns the groups to keep, whether anything was removed, and the index in kept
// of the first group that held only agentleash handlers (-1 if none).
func agrStripOurGroups(pre []any) (kept []any, removed bool, insertAt int) {
	insertAt = -1
	kept = make([]any, 0, len(pre)+1)
	for _, g := range pre {
		gobj, ok := g.(*object)
		if !ok {
			kept = append(kept, g)
			continue
		}
		handlers, ok := gobj.vals["hooks"].([]any)
		if !ok {
			kept = append(kept, g)
			continue
		}
		rest := agrForeignHandlers(handlers)
		if len(rest) == len(handlers) {
			kept = append(kept, g)
			continue
		}
		removed = true
		if len(rest) == 0 {
			if insertAt < 0 {
				insertAt = len(kept)
			}
			continue
		}
		gobj.set("hooks", rest)
		kept = append(kept, gobj)
	}
	return kept, removed, insertAt
}

// agrForeignHandlers returns the handlers that are not agentleash's, in order (nil if none).
func agrForeignHandlers(handlers []any) []any {
	var rest []any
	for _, h := range handlers {
		if !isOurHandler(h) {
			rest = append(rest, h)
		}
	}
	return rest
}

// object is a JSON object that remembers key order, so rewriting hooks.json keeps the
// user's layout of keys (whitespace is normalised to two-space indentation).
type object struct {
	keys []string
	vals map[string]any
}

func newObject() *object { return &object{vals: map[string]any{}} }

func (o *object) set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *object) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func decodeOrderedJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := readJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after JSON value")
	}
	return v, nil
}

func readJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool or nil
	}
	switch d {
	case '{':
		o := newObject()
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok {
				return nil, fmt.Errorf("invalid object key %v", kt)
			}
			v, err := readJSONValue(dec)
			if err != nil {
				return nil, err
			}
			o.set(k, v)
		}
		_, err := dec.Token() // '}'
		return o, err
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := readJSONValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.Token() // ']'
		return arr, err
	}
	return nil, fmt.Errorf("unexpected delimiter %v", d)
}

func encodeOrderedJSON(buf *bytes.Buffer, v any, indent string) error {
	inner := indent + "  "
	switch v := v.(type) {
	case *object:
		if len(v.keys) == 0 {
			buf.WriteString("{}")
			return nil
		}
		buf.WriteString("{\n")
		for i, k := range v.keys {
			buf.WriteString(inner)
			if err := encodeJSONScalar(buf, k); err != nil {
				return err
			}
			buf.WriteString(": ")
			if err := encodeOrderedJSON(buf, v.vals[k], inner); err != nil {
				return err
			}
			if i < len(v.keys)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(indent + "}")
	case []any:
		if len(v) == 0 {
			buf.WriteString("[]")
			return nil
		}
		buf.WriteString("[\n")
		for i, e := range v {
			buf.WriteString(inner)
			if err := encodeOrderedJSON(buf, e, inner); err != nil {
				return err
			}
			if i < len(v)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(indent + "]")
	default:
		return encodeJSONScalar(buf, v)
	}
	return nil
}

func encodeJSONScalar(buf *bytes.Buffer, v any) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	buf.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return nil
}
