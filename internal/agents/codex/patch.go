package codex

import "strings"

// Codex apply_patch file-operation headers.
var patchHeaders = []string{
	"*** Add File:",
	"*** Update File:",
	"*** Delete File:",
	"*** Move to:",
}

// patchBegin marks an apply_patch body, also when it is embedded in a shell command
// (`apply_patch <<'EOF' ...`), which Codex intercepts and applies without a second PreToolUse.
const patchBegin = "*** Begin Patch"

// patchPaths returns every path an apply_patch body creates, modifies, deletes or moves to,
// in order of appearance and without duplicates.
//
// Codex's streaming parser matches headers on line.trim() everywhere except inside Update
// hunks (where a leading space makes the line context). Headers are therefore matched on the
// trimmed line in every state: an Update-hunk context line that looks like a header at worst
// adds an extra path, which errs on the safe side. Likewise the path is TrimSpace'd although
// Codex keeps leading spaces after the marker ("*** Add File:  a" is the path " a"), so the
// engine sees the canonical name of a path that could only be a near-duplicate of it.
func patchPaths(patch string) []string {
	var paths []string
	seen := map[string]bool{}
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, h := range patchHeaders {
			rest, ok := strings.CutPrefix(line, h)
			if !ok {
				continue
			}
			p := strings.TrimSpace(rest)
			if p != "" && !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
			break
		}
	}
	return paths
}
