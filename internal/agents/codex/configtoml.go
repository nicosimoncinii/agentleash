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
	user, userMap, err := agrStripAndParse(text, nl)
	if err != nil {
		return nil, nil, err
	}
	sep, err := agrPolicyTable(userMap)
	if err != nil {
		return nil, nil, err
	}

	e := &agrConfigEdit{user: user, nl: nl, env: env, sep: sep}
	out, warnings, verify, err := e.agrPlan()
	if err != nil {
		return nil, nil, err
	}
	if err := agrVerifyEdit(out, userMap, verify); err != nil {
		return nil, nil, err
	}
	switch {
	case out == text:
		return data, warnings, nil // unchanged (including "file does not exist")
	case strings.TrimSpace(out) == "":
		return nil, warnings, nil // the file held only agentleash settings
	}
	return []byte(out), warnings, nil
}

// agrVerifier checks a re-parsed edited document: it confirms agentleash's entries are as
// intended and removes them from got, so that got can then be compared with the user's
// own document.
type agrVerifier func(got map[string]any) error

// agrConfigEdit holds the inputs shared by the config.toml edit strategies: the user's
// text without agentleash blocks, its line break, the wanted env globs and the user's
// shell_environment_policy table (nil when absent).
type agrConfigEdit struct {
	user string
	nl   string
	env  []string
	sep  map[string]any
}

// agrStripAndParse removes agentleash's blocks from text, parses what remains, and proves
// that the removal changed nothing else. It returns the stripped text and its parse.
func agrStripAndParse(text, nl string) (string, map[string]any, error) {
	user, bodies, err := stripManaged(text, nl)
	if err != nil {
		return "", nil, err
	}
	userMap, err := parseTOML(user)
	if err != nil {
		return "", nil, fmt.Errorf("parse .codex/config.toml: %w", err)
	}
	if len(bodies) > 0 {
		if err := verifyStrip(text, userMap, bodies); err != nil {
			return "", nil, err
		}
	}
	return user, userMap, nil
}

// agrPolicyTable returns the user's shell_environment_policy table (nil when absent), or
// an error when that key is not a table.
func agrPolicyTable(userMap map[string]any) (map[string]any, error) {
	v, ok := userMap[sepKey]
	if !ok {
		return nil, nil
	}
	sep, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config.toml: %s is not a table; %s", sepKey, manualHint)
	}
	return sep, nil
}

// agrPlan picks the edit strategy: legacy exclude/include_only arrays when the user's
// table already uses them, filters otherwise. It returns the new text, the warnings and
// the verifier for the edit (nil when the text is unchanged).
func (e *agrConfigEdit) agrPlan() (string, []string, agrVerifier, error) {
	_, hasExclude := e.sep[excludeWord]
	includeOnly, hasIncludeOnly := e.sep["include_only"]
	if !hasExclude && !hasIncludeOnly {
		return e.agrAddFilters()
	}
	warnings := agrIncludeOnlyWarnings(e.env, includeOnly)
	var (
		out    string
		verify agrVerifier
		err    error
	)
	if hasExclude {
		out, verify, err = e.agrExtendExclude()
	} else {
		out, verify, err = e.agrAddExclude()
	}
	if err != nil {
		return "", nil, nil, err
	}
	return out, warnings, verify, nil
}

// agrIncludeOnlyWarnings warns about every include_only string entry that an agentleash
// exclude glob matches.
func agrIncludeOnlyWarnings(env []string, includeOnly any) []string {
	inc, ok := includeOnly.([]any)
	if !ok {
		return nil
	}
	var warnings []string
	for _, e := range inc {
		if s, ok := e.(string); ok {
			warnings = append(warnings, includeConflicts(env, "include_only entry "+tomlString(s), s)...)
		}
	}
	return warnings
}

// agrAddExclude adds a managed `exclude = [...]` array under the [shell_environment_policy]
// header of a table that uses include_only but has no exclude array yet.
func (e *agrConfigEdit) agrAddExclude() (string, agrVerifier, error) {
	want := missing(e.env, nil)
	if len(want) == 0 {
		return e.user, nil, nil
	}
	pos, ok := findHeader(e.user, sepKey)
	if !ok {
		return "", nil, fmt.Errorf("config.toml: no [%s] header found; %s", sepKey, manualHint)
	}
	lines := []string{excludeWord + " = ["}
	for _, p := range want {
		lines = append(lines, "  "+tomlString(p)+",")
	}
	lines = append(lines, "]")
	out := insertBlock(e.user, pos, lines, e.nl)
	verify := func(got map[string]any) error {
		gsep, _ := got[sepKey].(map[string]any)
		if !reflect.DeepEqual(gsep[excludeWord], toAny(want)) {
			return errors.New("exclude array mismatch")
		}
		delete(gsep, excludeWord)
		return nil
	}
	return out, verify, nil
}

// agrExtendExclude prepends the missing env globs, as a managed block, to the user's
// existing legacy exclude array.
func (e *agrConfigEdit) agrExtendExclude() (string, agrVerifier, error) {
	existing, ok := e.sep[excludeWord].([]any)
	if !ok {
		return "", nil, fmt.Errorf("config.toml: %s.exclude is not an array; %s", sepKey, manualHint)
	}
	var handled []string
	for _, v := range existing {
		if s, ok := v.(string); ok {
			handled = append(handled, s)
		}
	}
	want := missing(e.env, handled)
	if len(want) == 0 {
		return e.user, nil, nil
	}
	pos, err := findExcludeArray(e.user)
	if err != nil {
		return "", nil, err
	}
	var lines []string
	for _, p := range want {
		lines = append(lines, tomlString(p)+",")
	}
	out := insertBlock(e.user, pos, lines, e.nl)
	verify := func(got map[string]any) error {
		gsep, _ := got[sepKey].(map[string]any)
		arr, _ := gsep[excludeWord].([]any)
		if !reflect.DeepEqual(arr, append(toAny(want), existing...)) {
			return errors.New("exclude array mismatch")
		}
		gsep[excludeWord] = existing
		return nil
	}
	return out, verify, nil
}

// agrAddFilters adds the missing env globs as `"GLOB" = "exclude"` filters, inside the
// user's [shell_environment_policy.filters] table when there is one, or in a new table
// appended at the end of the file.
func (e *agrConfigEdit) agrAddFilters() (string, []string, agrVerifier, error) {
	filters, hasFilters := e.sep["filters"].(map[string]any)
	if _, ok := e.sep["filters"]; ok && !hasFilters {
		return "", nil, nil, fmt.Errorf("config.toml: %s is not a table; %s", filtersHdr, manualHint)
	}
	handled := sortedKeys(filters) // existing keys can never be added again
	warnings := agrFilterWarnings(e.env, filters, handled)
	want := missing(e.env, handled)
	if len(want) == 0 {
		return e.user, warnings, nil, nil
	}
	var out string
	if hasFilters {
		pos, ok := findHeader(e.user, filtersHdr)
		if !ok {
			return "", nil, nil, fmt.Errorf("config.toml: %s is not written as a [%s] table; %s", filtersHdr, filtersHdr, manualHint)
		}
		out = insertBlock(e.user, pos, agrFilterLines(nil, want), e.nl)
	} else {
		out = appendBlock(e.user, agrFilterLines([]string{"[" + filtersHdr + "]"}, want), e.nl)
	}
	return out, warnings, agrFiltersVerifier(want, hasFilters, e.sep == nil), nil
}

// agrFilterLines appends a `"GLOB" = "exclude"` line for each glob in want to lines.
func agrFilterLines(lines, want []string) []string {
	for _, p := range want {
		lines = append(lines, tomlString(p)+" = "+tomlString(excludeWord))
	}
	return lines
}

// agrFiltersVerifier checks that every glob in want became an "exclude" filter and removes
// those filters, plus the tables agentleash created: the filters table when the user had
// none, and shell_environment_policy too when the user had no such table (noSep).
func agrFiltersVerifier(want []string, hasFilters, noSep bool) agrVerifier {
	return func(got map[string]any) error {
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
			if noSep {
				delete(got, sepKey)
			}
		}
		return nil
	}
}

// agrFilterWarnings reports the user filters (the sorted keys in handled) that conflict
// with agentleash's exclude globs. Only keys whose value is "exclude" already do our job.
// A same-named key with another value cannot be overridden (keys merge case-insensitively;
// a duplicate is invalid), so it is reported instead of silently skipped; an "include"
// filter that an exclude glob matches is reported as well.
func agrFilterWarnings(env []string, filters map[string]any, handled []string) []string {
	var warnings []string
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
	return warnings
}

// agrVerifyEdit re-parses the edited text and proves, with verify, that it differs from
// the user's document only by agentleash's entries. A nil verify means nothing was edited.
func agrVerifyEdit(out string, userMap map[string]any, verify agrVerifier) error {
	if verify == nil {
		return nil
	}
	got, err := parseTOML(out)
	if err != nil {
		return fmt.Errorf("config.toml: cannot insert agentleash settings safely (%w); %s", err, manualHint)
	}
	if err := verify(got); err != nil || !reflect.DeepEqual(got, userMap) {
		return fmt.Errorf("config.toml: cannot insert agentleash settings safely; %s", manualHint)
	}
	return nil
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
	switch {
	case lines[0] == "["+filtersHdr+"]": // appended table
		return agrSubtractFiltersTable(doc, stripped, sep, body)
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
		return agrRemoveFilters(sep, entries)
	}
	return nil
}

// agrRemoveFilters removes entries from sep's filters table; every entry must be
// present there with the same value.
func agrRemoveFilters(sep, entries map[string]any) error {
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

// agrSubtractFiltersTable removes an appended [shell_environment_policy.filters] block
// body from doc (whose shell_environment_policy table is sep), dropping the tables it
// leaves empty unless the stripped document still has them.
func agrSubtractFiltersTable(doc, stripped, sep map[string]any, body string) error {
	parsed, err := parseTOML(body)
	if err != nil {
		return err
	}
	psep, _ := parsed[sepKey].(map[string]any)
	entries, _ := psep["filters"].(map[string]any)
	if err := agrRemoveFilters(sep, entries); err != nil {
		return err
	}
	ssep, _ := stripped[sepKey].(map[string]any)
	if f, _ := sep["filters"].(map[string]any); len(f) == 0 && ssep["filters"] == nil {
		delete(sep, "filters")
	}
	if len(sep) == 0 && stripped[sepKey] == nil {
		delete(doc, sepKey)
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
