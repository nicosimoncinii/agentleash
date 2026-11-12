package codex

// config.toml editing.
//
// No maintained Go TOML library round-trips comments and formatting, so config.toml is edited
// as text: agentleash only inserts or deletes one marked block (tomlBegin ... end marker) and
// never rewrites user lines. The end marker carries a checksum of the block body, so a block
// the user edited by hand is detected instead of being silently dropped. go-toml/v2 is used
// read-only to prove, on every path (insert, re-apply, remove), that the edit changes nothing
// but agentleash's own entries; otherwise nothing is written and the user is told why.
//
// Key choice (https://learn.chatgpt.com/docs/config-file/config-advanced#shell-environment-policy):
// `[shell_environment_policy.filters]` ("PATTERN" = "exclude") is the canonical form; the
// `exclude` / `include_only` arrays are legacy, and Codex rejects a layer that mixes the two.
// So agentleash writes filters, unless this file already uses a legacy array, in which case it
// adds its patterns to `exclude` instead.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/nicosimoncinii/agentleash/internal/agents"
)

const (
	tomlBegin     = "# >>> " + agents.HookMarker + ": managed block (agentleash apply), do not edit >>>"
	tomlEndPrefix = "# <<< " + agents.HookMarker
)

// tomlEndRe matches a complete end-marker line and captures the body checksum.
var tomlEndRe = regexp.MustCompile(`^# <<< ` + regexp.QuoteMeta(agents.HookMarker) + ` sha256:([0-9a-f]{16}) <<<$`)

const (
	sepKey      = "shell_environment_policy"
	filtersHdr  = sepKey + ".filters"
	manualHint  = "add the patterns to shell_environment_policy in .codex/config.toml by hand"
	blockHint   = "move your own settings out of the agentleash block (or delete the whole block), then re-run"
	excludeWord = "exclude"
)

var (
	excludeInTableRe = regexp.MustCompile(`^[ \t]*(?:exclude|"exclude"|'exclude')[ \t]*=[ \t]*\[`)
	excludeDottedRe  = regexp.MustCompile(`^[ \t]*shell_environment_policy[ \t]*\.[ \t]*(?:exclude|"exclude"|'exclude')[ \t]*=[ \t]*\[`)
)

// editConfig returns the new config.toml content with env as agentleash's excluded env globs
// (nil/empty env removes them), plus warnings about user filters that conflict with them.
// data == nil means the file does not exist; a nil result means the file should not exist.
func editConfig(data []byte, env []string) ([]byte, []string, error) {
	text := string(data)
	nl := "\n"
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
	}
	user, bodies, err := stripManaged(text, nl)
	if err != nil {
		return nil, nil, err
	}
	userMap, err := parseTOML(user)
	if err != nil {
		return nil, nil, fmt.Errorf("parse .codex/config.toml: %w", err)
	}
	if len(bodies) > 0 {
		if err := verifyStrip(text, userMap, bodies); err != nil {
			return nil, nil, err
		}
	}

	var sep map[string]any
	if v, ok := userMap[sepKey]; ok {
		if sep, ok = v.(map[string]any); !ok {
			return nil, nil, fmt.Errorf("config.toml: %s is not a table; %s", sepKey, manualHint)
		}
	}
	_, hasExclude := sep[excludeWord]
	includeOnly, hasIncludeOnly := sep["include_only"]

	var out string
	var warnings []string
	var verify func(got map[string]any) error
	switch {
	case hasExclude || hasIncludeOnly:
		if inc, ok := includeOnly.([]any); ok {
			for _, e := range inc {
				if s, ok := e.(string); ok {
					warnings = append(warnings, includeConflicts(env, "include_only entry "+tomlString(s), s)...)
				}
			}
		}
		if !hasExclude {
			want := missing(env, nil)
			if len(want) == 0 {
				out = user
				break
			}
			pos, ok := findHeader(user, sepKey)
			if !ok {
				return nil, nil, fmt.Errorf("config.toml: no [%s] header found; %s", sepKey, manualHint)
			}
			lines := []string{excludeWord + " = ["}
			for _, p := range want {
				lines = append(lines, "  "+tomlString(p)+",")
			}
			lines = append(lines, "]")
			out = insertBlock(user, pos, lines, nl)
			verify = func(got map[string]any) error {
				gsep, _ := got[sepKey].(map[string]any)
				if !reflect.DeepEqual(gsep[excludeWord], toAny(want)) {
					return errors.New("exclude array mismatch")
				}
				delete(gsep, excludeWord)
				return nil
			}
			break
		}
		existing, ok := sep[excludeWord].([]any)
		if !ok {
			return nil, nil, fmt.Errorf("config.toml: %s.exclude is not an array; %s", sepKey, manualHint)
		}
		var handled []string
		for _, e := range existing {
			if s, ok := e.(string); ok {
				handled = append(handled, s)
			}
		}
		want := missing(env, handled)
		if len(want) == 0 {
			out = user
			break
		}
		pos, err := findExcludeArray(user)
		if err != nil {
			return nil, nil, err
		}
		var lines []string
		for _, p := range want {
			lines = append(lines, tomlString(p)+",")
		}
		out = insertBlock(user, pos, lines, nl)
		verify = func(got map[string]any) error {
			gsep, _ := got[sepKey].(map[string]any)
			arr, _ := gsep[excludeWord].([]any)
			if !reflect.DeepEqual(arr, append(toAny(want), existing...)) {
				return errors.New("exclude array mismatch")
			}
			gsep[excludeWord] = existing
			return nil
		}
	default:
		filters, hasFilters := sep["filters"].(map[string]any)
		if _, ok := sep["filters"]; ok && !hasFilters {
			return nil, nil, fmt.Errorf("config.toml: %s is not a table; %s", filtersHdr, manualHint)
		}
		// Only keys whose value is "exclude" already do our job. A same-named key with another
		// value cannot be overridden (keys merge case-insensitively; a duplicate is invalid), so
		// it is reported instead of silently skipped.
		handled := sortedKeys(filters) // existing keys can never be added again
		for _, k := range handled {
			v, _ := filters[k].(string)
			if strings.EqualFold(v, excludeWord) {
				continue
			}
			overridden := false
			for _, g := range env {
				if strings.EqualFold(g, k) {
					overridden = true
					warnings = append(warnings, fmt.Sprintf(
						"Warning: .codex/config.toml filter %s = %s overrides agentleash's exclude for %s "+
							"(filter keys are case-insensitive), so matching variables are NOT removed from "+
							"commands Codex runs. Change it to \"exclude\" or delete it, then re-run apply.",
						tomlString(k), tomlString(v), tomlString(g)))
				}
			}
			if !overridden && strings.EqualFold(v, "include") {
				warnings = append(warnings, includeConflicts(env, "filter "+tomlString(k)+" = \"include\"", k)...)
			}
		}
		want := missing(env, handled)
		if len(want) == 0 {
			out = user
			break
		}
		var lines []string
		if hasFilters {
			pos, ok := findHeader(user, filtersHdr)
			if !ok {
				return nil, nil, fmt.Errorf("config.toml: %s is not written as a [%s] table; %s", filtersHdr, filtersHdr, manualHint)
			}
			for _, p := range want {
				lines = append(lines, tomlString(p)+" = "+tomlString(excludeWord))
			}
			out = insertBlock(user, pos, lines, nl)
		} else {
			lines = append(lines, "["+filtersHdr+"]")
			for _, p := range want {
				lines = append(lines, tomlString(p)+" = "+tomlString(excludeWord))
			}
			out = appendBlock(user, lines, nl)
		}
		verify = func(got map[string]any) error {
			gsep, _ := got[sepKey].(map[string]any)
			gf, _ := gsep["filters"].(map[string]any)
			for _, p := range want {
				if gf[p] != excludeWord {
					return fmt.Errorf("filter %q missing", p)
				}
				delete(gf, p)
			}
			if !hasFilters {
				delete(gsep, "filters")
				if sep == nil {
					delete(got, sepKey)
				}
			}
			return nil
		}
	}

	if verify != nil {
		got, err := parseTOML(out)
		if err != nil {
			return nil, nil, fmt.Errorf("config.toml: cannot insert agentleash settings safely (%w); %s", err, manualHint)
		}
		if err := verify(got); err != nil || !reflect.DeepEqual(got, userMap) {
			return nil, nil, fmt.Errorf("config.toml: cannot insert agentleash settings safely; %s", manualHint)
		}
	}
	switch {
	case out == text:
		return data, warnings, nil // unchanged (including "file does not exist")
	case strings.TrimSpace(out) == "":
		return nil, warnings, nil // the file held only agentleash settings
	}
	return []byte(out), warnings, nil
}

// includeConflicts warns when a user include names variables an agentleash exclude glob
// matches: Codex applies exclusions first, so those variables are removed anyway.
func includeConflicts(env []string, what, name string) []string {
	var out []string
	for _, g := range env {
		if ok, _ := path.Match(strings.ToUpper(g), strings.ToUpper(name)); ok || strings.EqualFold(g, name) {
			out = append(out, fmt.Sprintf(
				"Warning: .codex/config.toml %s matches agentleash's secret exclude %s. Codex applies "+
					"exclusions first, so those variables will not reach commands. If %s is not a secret, "+
					"narrow secrets.env in .agentleash.yaml.",
				what, tomlString(g), name))
		}
	}
	return out
}

func parseTOML(s string) (map[string]any, error) {
	var m map[string]any
	if err := toml.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func bodySum(body string) string {
	sum := sha256.Sum256([]byte(strings.ReplaceAll(body, "\r\n", "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// stripManaged removes every agentleash block, together with the line break that precedes it,
// and returns the block bodies. A block whose checksum does not match was edited by hand and
// is refused rather than dropped.
func stripManaged(text, nl string) (string, []string, error) {
	var bodies []string
	for {
		i := strings.Index(text, tomlBegin)
		if i < 0 {
			return text, bodies, nil
		}
		if i > 0 && text[i-1] != '\n' {
			return "", nil, fmt.Errorf("config.toml: agentleash marker found in the middle of a line; %s", blockHint)
		}
		bodyStart := i + len(tomlBegin) + len(leadingNewline(text[i+len(tomlBegin):]))
		j := strings.Index(text[bodyStart:], tomlEndPrefix)
		if j < 0 {
			return "", nil, fmt.Errorf("config.toml: agentleash block has no end marker; %s", blockHint)
		}
		endStart := bodyStart + j
		endLen := strings.IndexAny(text[endStart:], "\r\n")
		if endLen < 0 {
			endLen = len(text) - endStart
		}
		m := tomlEndRe.FindStringSubmatch(text[endStart : endStart+endLen])
		body := strings.TrimRight(text[bodyStart:endStart], "\r\n")
		if m == nil || m[1] != bodySum(body) {
			return "", nil, fmt.Errorf("config.toml: the agentleash block was edited by hand or sits inside another value; %s", blockHint)
		}
		bodies = append(bodies, strings.ReplaceAll(body, "\r\n", "\n"))

		start, end := i, endStart+endLen
		switch {
		case strings.HasSuffix(text[:start], "\r\n"):
			start -= 2
		case strings.HasSuffix(text[:start], "\n"):
			start--
		default: // block at the very start of the file: drop the line break after it
			end += len(leadingNewline(text[end:]))
		}
		rest := text[end:]
		if strings.TrimSpace(rest) == "" {
			// Block was appended at the end of the file: restore a single trailing newline.
			head := strings.TrimRight(text[:start], "\r\n")
			if head != "" {
				head += nl
			}
			text = head
			continue
		}
		text = text[:start] + rest
	}
}

// verifyStrip proves that stripping our blocks removed exactly the entries they declare: the
// original document minus those entries must equal the stripped document. This catches marker
// text inside multi-line strings and any other case where the strip would lose user content.
func verifyStrip(original string, stripped map[string]any, bodies []string) error {
	fail := fmt.Errorf("config.toml: removing the agentleash block would change other settings; %s", blockHint)
	want, err := parseTOML(original)
	if err != nil {
		return fmt.Errorf("parse .codex/config.toml: %w", err)
	}
	for _, body := range bodies {
		if err := subtractBlock(want, stripped, body); err != nil {
			return fail
		}
	}
	if !reflect.DeepEqual(want, stripped) {
		return fail
	}
	return nil
}

// subtractBlock removes the entries a block body declares from doc.
func subtractBlock(doc, stripped map[string]any, body string) error {
	lines := strings.Split(body, "\n")
	sep, _ := doc[sepKey].(map[string]any)
	if sep == nil {
		return errors.New("no shell_environment_policy")
	}
	removeFilters := func(entries map[string]any) error {
		filters, _ := sep["filters"].(map[string]any)
		if filters == nil || len(entries) == 0 {
			return errors.New("no filters")
		}
		for k, v := range entries {
			if !reflect.DeepEqual(filters[k], v) {
				return fmt.Errorf("filter %q differs", k)
			}
			delete(filters, k)
		}
		return nil
	}
	switch {
	case lines[0] == "["+filtersHdr+"]": // appended table
		parsed, err := parseTOML(body)
		if err != nil {
			return err
		}
		psep, _ := parsed[sepKey].(map[string]any)
		entries, _ := psep["filters"].(map[string]any)
		if err := removeFilters(entries); err != nil {
			return err
		}
		ssep, _ := stripped[sepKey].(map[string]any)
		if f, _ := sep["filters"].(map[string]any); len(f) == 0 && ssep["filters"] == nil {
			delete(sep, "filters")
		}
		if len(sep) == 0 && stripped[sepKey] == nil {
			delete(doc, sepKey)
		}
	case strings.HasPrefix(lines[0], excludeWord+" = ["): // exclude array next to include_only
		parsed, err := parseTOML(body)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(sep[excludeWord], parsed[excludeWord]) {
			return errors.New("exclude differs")
		}
		delete(sep, excludeWord)
	case strings.HasSuffix(lines[0], ","): // elements prepended to a legacy exclude array
		parsed, err := parseTOML("x = [\n" + body + "\n]")
		if err != nil {
			return err
		}
		ours, _ := parsed["x"].([]any)
		arr, _ := sep[excludeWord].([]any)
		if len(arr) < len(ours) || !reflect.DeepEqual(arr[:len(ours)], ours) {
			return errors.New("exclude prefix differs")
		}
		sep[excludeWord] = arr[len(ours):]
	default: // keys inserted into an existing filters table
		entries, err := parseTOML(body)
		if err != nil {
			return err
		}
		return removeFilters(entries)
	}
	return nil
}

func leadingNewline(s string) string {
	switch {
	case strings.HasPrefix(s, "\r\n"):
		return "\r\n"
	case strings.HasPrefix(s, "\n"):
		return "\n"
	}
	return ""
}

// block renders a managed block; the end marker carries a checksum of the body.
func block(lines []string, nl string) string {
	body := strings.Join(lines, "\n")
	return tomlBegin + nl + strings.Join(lines, nl) + nl +
		tomlEndPrefix + " sha256:" + bodySum(body) + " <<<"
}

// insertBlock inserts a managed block at pos (the end of a header line, or just after an
// array's '['), so that stripManaged restores the text exactly.
func insertBlock(text string, pos int, lines []string, nl string) string {
	ins := nl + block(lines, nl)
	if leadingNewline(text[pos:]) == "" {
		ins += nl
	}
	return text[:pos] + ins + text[pos:]
}

// appendBlock adds a managed block at the end of the file, separated by a blank line.
func appendBlock(text string, lines []string, nl string) string {
	head := strings.TrimRight(text, "\r\n")
	if head == "" {
		return block(lines, nl) + nl
	}
	return head + nl + nl + block(lines, nl) + nl
}

// tomlLines splits text into lines, returning each line's start offset and content (without
// its line break).
func tomlLines(text string) (starts []int, lines []string) {
	off := 0
	for off <= len(text) {
		k := strings.IndexByte(text[off:], '\n')
		var line string
		if k < 0 {
			line = text[off:]
		} else {
			line = text[off : off+k]
		}
		starts = append(starts, off)
		lines = append(lines, strings.TrimSuffix(line, "\r"))
		if k < 0 {
			break
		}
		off += k + 1
	}
	return starts, lines
}

// headerName returns the normalised table name of a `[table]` header line ("" for other lines,
// "[[array]]" for array-of-tables headers).
func headerName(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "[[") {
		return "[[array]]", true
	}
	if !strings.HasPrefix(t, "[") {
		return "", false
	}
	end := strings.IndexByte(t, ']')
	if end < 0 {
		return "", false
	}
	name := strings.NewReplacer(" ", "", "\t", "", `"`, "", "'", "").Replace(t[1:end])
	return name, true
}

// findHeader returns the offset of the end of the `[name]` header line.
func findHeader(text, name string) (int, bool) {
	starts, lines := tomlLines(text)
	for i, line := range lines {
		if n, ok := headerName(line); ok && n == name {
			return starts[i] + len(line), true
		}
	}
	return 0, false
}

// findExcludeArray returns the offset just after the '[' that opens shell_environment_policy.exclude.
func findExcludeArray(text string) (int, error) {
	starts, lines := tomlLines(text)
	table := ""
	for i, line := range lines {
		if n, ok := headerName(line); ok {
			table = n
			continue
		}
		var loc []int
		switch table {
		case sepKey:
			loc = excludeInTableRe.FindStringIndex(line)
		case "":
			loc = excludeDottedRe.FindStringIndex(line)
		}
		if loc != nil {
			return starts[i] + loc[1], nil
		}
	}
	return 0, fmt.Errorf("config.toml: cannot locate %s.exclude; %s", sepKey, manualHint)
}

// missing returns the env globs not already present in handled (compared case-insensitively,
// like Codex does), without duplicates.
func missing(env, handled []string) []string {
	seen := map[string]bool{}
	for _, s := range handled {
		seen[strings.ToLower(s)] = true
	}
	var out []string
	for _, p := range env {
		if p == "" || seen[strings.ToLower(p)] {
			continue
		}
		seen[strings.ToLower(p)] = true
		out = append(out, p)
	}
	return out
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// tomlString renders s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
