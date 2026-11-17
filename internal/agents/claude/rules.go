package claude

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// Claude Code Read/Edit rules use gitignore syntax with four anchors
// (https://code.claude.com/docs/en/permissions, "How path patterns match"):
//
//	//path  absolute from the filesystem root (Windows: C:\x is matched as /c/x)
//	~/path  from the home directory
//	/path   from the settings source: the primary working directory for project settings
//	path    from the current directory; a bare name matches at any depth
//
// A deny rule "!path" carves its paths out of the "path"/"./path" rules listed before
// it in the same settings file only; it cannot carve out of "/", "~/" or "//" rules,
// nor reopen a path inside an excluded directory.

type anchor int

const (
	anchorBare anchor = iota // relative, no slash: matches at any depth
	anchorRoot               // relative with a slash: anchored at the project root
	anchorHome
	anchorAbs
	anchorUNC // network path: no documented rule form
)

// glob is a normalised policy glob.
type glob struct {
	raw    string
	anchor anchor
	body   string // slash-separated path below the anchor
	dir    bool   // written as "dir/": the rule covers everything below it
}

var windowsDrive = regexp.MustCompile(`^[A-Za-z]:/`)

// parseGlob normalises a policy glob: backslashes become "/", "./" is dropped and a
// trailing "dir/" becomes "dir/**" (the documented directory form). Policy globs are
// paths, so "\" is never a gitignore escape here. Drive letters are lower-cased as
// Claude Code does; the rest of a Windows path keeps its case although Windows is
// case-insensitive, so write globs with the on-disk case.
func parseGlob(raw string) (glob, error) {
	g := glob{raw: raw}
	s := strings.TrimSpace(raw)
	if s == "" {
		return g, fmt.Errorf("empty glob")
	}
	if strings.HasPrefix(s, `\\`) || strings.HasPrefix(s, "//") {
		g.anchor, g.body = anchorUNC, s
		return g, nil
	}
	s = strings.ReplaceAll(s, `\`, "/")
	switch {
	case strings.HasPrefix(s, "~/"):
		g.anchor, s = anchorHome, s[2:]
	case strings.HasPrefix(s, "~"):
		return g, fmt.Errorf("glob %q: only \"~/...\" is supported for home-relative paths", raw)
	case windowsDrive.MatchString(s):
		g.anchor, s = anchorAbs, strings.ToLower(s[:1])+"/"+s[3:]
	case strings.HasPrefix(s, "/"):
		g.anchor, s = anchorAbs, strings.TrimLeft(s, "/")
	default:
		for strings.HasPrefix(s, "./") {
			s = s[2:]
		}
		// gitignore: a pattern without an inner slash, or one starting with "**/",
		// matches at any depth. Keep those relative (unanchored), the only form a "!"
		// carve-out can reach, and drop a redundant "**/" before a single name: the
		// docs state that Read(.env) and Read(**/.env) are equivalent.
		anyDepth := false
		for strings.HasPrefix(s, "**/") {
			s, anyDepth = s[3:], true
		}
		inner := strings.Contains(strings.TrimSuffix(s, "/"), "/")
		switch {
		case inner && anyDepth:
			g.anchor, s = anchorBare, "**/"+s
		case inner:
			g.anchor = anchorRoot
		default:
			g.anchor = anchorBare
		}
	}
	if strings.HasSuffix(s, "/") {
		g.dir = true
		s = strings.TrimRight(s, "/") + "/**"
	}
	if s == "" || s == "/**" {
		return g, fmt.Errorf("glob %q names no file", raw)
	}
	g.body = s
	return g, nil
}

// rulePath renders the glob with Claude Code's anchor prefix.
func (g glob) rulePath() string {
	switch g.anchor {
	case anchorRoot:
		return "/" + g.body
	case anchorHome:
		return "~/" + g.body
	case anchorAbs:
		return "//" + g.body
	default:
		return g.body
	}
}

func (g glob) relative() bool { return g.anchor == anchorBare || g.anchor == anchorRoot }

// overlap reports whether some concrete path is matched by both secret and allow,
// and whether a "!" carve-out can reopen it natively.
//
// Both globs are mapped to absolute segment lists using the project root and home
// directory, so a project glob and a "~/" glob only overlap when the project really
// contains (or is) that home location. Carving needs an unanchored relative secret
// rule, a relative allow entry, and a secret that is not a whole-directory rule
// ("x/**"): the docs say a carve-out reaches only "path"/"./path" rules and cannot
// reopen a file inside a blocked directory.
func overlap(secret, allow glob, root, home string) (overlaps, carvable bool) {
	if secret.anchor == anchorUNC || allow.anchor == anchorUNC {
		return false, false
	}
	if !pathsIntersect(secret.segments(root, home), allow.segments(root, home)) {
		return false, false
	}
	return true, secret.anchor == anchorBare && allow.relative() && !strings.HasSuffix(secret.body, "**")
}

// segments maps the glob to lower-cased absolute path segments ("**" spans any
// number of segments). Comparison is case-insensitive, like the engine's.
func (g glob) segments(root, home string) []string {
	body := strings.Split(strings.ToLower(g.body), "/")
	switch g.anchor {
	case anchorBare:
		return append(append(dirSegments(root, "<unknown project root>"), "**"), body...)
	case anchorRoot:
		return append(dirSegments(root, "<unknown project root>"), body...)
	case anchorHome:
		return append(dirSegments(home, "<unknown home>"), body...)
	default:
		return body
	}
}

// dirSegments splits a native directory path into lower-cased segments, mapping
// `C:\x` to ["c", "x"] like Claude Code's POSIX form. An empty directory becomes a
// placeholder segment that matches no real path.
func dirSegments(dir, unknown string) []string {
	s := strings.ToLower(strings.ReplaceAll(dir, `\`, "/"))
	if windowsDrive.MatchString(s) {
		s = s[:1] + "/" + s[3:]
	}
	var out []string
	for _, seg := range strings.Split(s, "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return []string{unknown}
	}
	return out
}

// pathsIntersect reports whether some path is matched by both segment patterns.
func pathsIntersect(a, b []string) bool {
	memo := map[[2]int]bool{}
	var f func(i, j int) bool
	f = func(i, j int) bool {
		if i == len(a) && j == len(b) {
			return true
		}
		key := [2]int{i, j}
		if v, ok := memo[key]; ok {
			return v
		}
		memo[key] = false
		res := false
		switch {
		case i < len(a) && a[i] == "**":
			res = f(i+1, j) || (j < len(b) && f(i, j+1))
		case j < len(b) && b[j] == "**":
			res = f(i, j+1) || (i < len(a) && f(i+1, j))
		case i < len(a) && j < len(b):
			res = segmentsIntersect(a[i], b[j]) && f(i+1, j+1)
		}
		memo[key] = res
		return res
	}
	return f(0, 0)
}

// segToken is one element of a single-segment glob.
type segToken struct {
	star bool // "*": any run of characters
	any  bool // "?" or a [class]: any single character (classes are not modelled)
	ch   rune
}

func tokenize(seg string) []segToken {
	var out []segToken
	rs := []rune(seg)
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '*':
			if len(out) == 0 || !out[len(out)-1].star {
				out = append(out, segToken{star: true})
			}
		case '?':
			out = append(out, segToken{any: true})
		case '[':
			end := slices.Index(rs[i+1:], ']')
			if end < 0 {
				out = append(out, segToken{ch: '['}) // unterminated: a literal
				continue
			}
			out = append(out, segToken{any: true})
			i += end + 1
		default:
			out = append(out, segToken{ch: rs[i]})
		}
	}
	return out
}

// segmentsIntersect reports whether some file name is matched by both segment globs.
// Character classes count as any character, so the answer errs towards "overlaps".
func segmentsIntersect(x, y string) bool {
	a, b := tokenize(x), tokenize(y)
	memo := map[[2]int]bool{}
	var f func(i, j int) bool
	f = func(i, j int) bool {
		if i == len(a) && j == len(b) {
			return true
		}
		key := [2]int{i, j}
		if v, ok := memo[key]; ok {
			return v
		}
		memo[key] = false
		res := false
		switch {
		case i < len(a) && a[i].star:
			res = f(i+1, j) || (j < len(b) && f(i, j+1))
		case j < len(b) && b[j].star:
			res = f(i, j+1) || (i < len(a) && f(i+1, j))
		case i < len(a) && j < len(b):
			res = (a[i].any || b[j].any || a[i].ch == b[j].ch) && f(i+1, j+1)
		}
		memo[key] = res
		return res
	}
	return f(0, 0)
}

// uncarvableReason explains why a "!" carve-out cannot reopen an allow entry
// overlapping secret. The bare-secret case means the allow entry is not relative.
func uncarvableReason(secret glob) string {
	switch {
	case secret.anchor != anchorBare:
		return `a "!" exception only reaches unanchored relative rules, and this rule is anchored with "/", "~/" or "//"`
	case strings.HasSuffix(secret.body, "**"):
		return `the rule blocks a whole directory, and a "!" exception cannot reopen files inside a blocked directory`
	default:
		return `a "!" exception is read relative to the current directory, so a "~/" or absolute allow entry cannot be carved out`
	}
}

// denyBlock builds agentleash's permissions.deny block for a policy:
//
//	Read(<secret>)... Read(!<allow>)... Edit(<secret>)... Edit(!<allow>)... Edit(<protected>)...
//
// Edit rules cover Write, Edit, MultiEdit and NotebookEdit, which Read rules do not.
// The block goes first in permissions.deny so its "!" carve-outs only reach
// agentleash's own rules. When an allow_files entry overlaps a secret rule that a
// carve-out cannot reach (anchored or directory rules, non-relative allow entries),
// the native rule is kept anyway (fail closed) and a note explains that the allowed
// file stays blocked by Claude Code's native layer.
//
// root and home locate project-relative and "~/" globs for the overlap test.
func denyBlock(p *policy.Policy, root, home string) (block, notes []string, err error) {
	var allows []glob
	for _, a := range p.Secrets.AllowFiles {
		g, err := parseGlob(a)
		if err != nil {
			return nil, nil, fmt.Errorf("allow_files: %w", err)
		}
		allows = append(allows, g)
	}

	var secrets, negations []string
	seen := map[string]bool{}
	for _, f := range p.Secrets.Files {
		if strings.HasPrefix(strings.TrimSpace(f), "!") {
			continue // exceptions belong in allow_files
		}
		s, err := parseGlob(f)
		if err != nil {
			return nil, nil, fmt.Errorf("secrets.files: %w", err)
		}
		if s.anchor == anchorUNC {
			notes = append(notes, fmt.Sprintf("secret %q is a network (UNC) path; Claude Code has no documented rule form for it, so only the agentleash hook protects it", f))
			continue
		}
		var carve []string
		for _, a := range allows {
			ov, canCarve := overlap(s, a, root, home)
			switch {
			case !ov:
			case canCarve:
				carve = append(carve, "!"+a.body)
			default:
				// Fail closed: keep the native rule and say what it over-blocks.
				notes = append(notes, fmt.Sprintf(
					"allow_files %q stays blocked by Claude Code's native rules Read(%s)/Edit(%s) for secret %q, although the policy allows it: %s. "+
						"agentleash keeps the native rule so the secret stays protected even if the hook does not run; read the file outside Claude Code, or narrow the secret glob",
					a.raw, s.rulePath(), s.rulePath(), f, uncarvableReason(s)))
			}
		}
		if r := s.rulePath(); !seen[r] {
			seen[r] = true
			secrets = append(secrets, r)
		}
		for _, n := range carve {
			if !seen[n] {
				seen[n] = true
				negations = append(negations, n)
			}
		}
	}

	for _, tool := range []string{"Read", "Edit"} {
		for _, r := range secrets {
			block = append(block, tool+"("+r+")")
		}
		for _, n := range negations {
			block = append(block, tool+"("+n+")")
		}
	}
	prot, err := protectRules(p)
	if err != nil {
		return nil, nil, err
	}
	return append(block, prot...), notes, nil
}

// protectRules returns Edit(...) rules for the write-protected files
// (agentleash's own configuration and protect.files). They stay readable, so
// there is no Read rule. A "./" entry is anchored at the project root, which
// Claude Code spells with a leading "/".
func protectRules(p *policy.Policy) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range p.ProtectedFiles() {
		g, err := parseGlob(f)
		if err != nil {
			return nil, fmt.Errorf("protect.files: %w", err)
		}
		if g.anchor == anchorUNC {
			continue
		}
		r := g.rulePath()
		if rel, ok := strings.CutPrefix(f, "./"); ok && !strings.HasPrefix(r, "/") {
			r = "/" + rel
		}
		if r = "Edit(" + r + ")"; !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}
