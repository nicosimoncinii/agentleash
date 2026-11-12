package claude

import (
	"fmt"
	"path"
	"regexp"
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
		g.anchor = anchorBare
		if strings.Contains(strings.TrimSuffix(s, "/"), "/") {
			g.anchor = anchorRoot
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

// overlap reports whether some path matched by allow may also be matched by secret.
// dirOnly is true when the bare secret only matches a parent directory of allow
// (a "!" rule cannot reopen a path inside an excluded directory). The comparison is
// conservative: when unsure it reports an overlap.
func overlap(secret, allow glob) (overlaps, dirOnly bool) {
	if allow.anchor == anchorUNC {
		return false, false
	}
	allowSegs := strings.Split(allow.body, "/")
	if secret.anchor == anchorBare {
		if !allow.relative() {
			return true, false // cannot tell whether it lies under the project
		}
		pat := strings.Split(secret.body, "/") // "name" or "name/**"
		fileMatch, dirMatch := false, false
		for i, seg := range allowSegs {
			switch {
			case !segMatch(pat[0], seg):
			case i < len(allowSegs)-1:
				dirMatch = true
			case len(pat) == 1:
				fileMatch = true
			}
		}
		return fileMatch || dirMatch, dirMatch
	}
	secretSegs := strings.Split(secret.body, "/")
	switch {
	case secret.anchor == anchorRoot && allow.anchor == anchorBare:
		// A bare allow name matches at any depth: compare file names.
		last := secretSegs[len(secretSegs)-1]
		return last == "**" || segMatch(last, allowSegs[len(allowSegs)-1]), false
	case secret.anchor == allow.anchor:
		return matchSegs(secretSegs, allowSegs), false
	default:
		// Home or absolute secrets vs project-relative allows (and vice versa):
		// assumes the project does not live inside a secret location.
		return false, false
	}
}

// matchSegs matches gitignore-style path segments, where "**" spans any number of them.
func matchSegs(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		return matchSegs(pat[1:], segs) || (len(segs) > 0 && matchSegs(pat, segs[1:]))
	}
	return len(segs) > 0 && segMatch(pat[0], segs[0]) && matchSegs(pat[1:], segs[1:])
}

func segMatch(pat, seg string) bool {
	ok, err := path.Match(pat, seg)
	return ok || err != nil // a malformed pattern counts as a match: be conservative
}

// denyBlock builds agentleash's permissions.deny block for a policy:
//
//	Read(<secret>)... Read(!<allow>)... Edit(<secret>)... Edit(!<allow>)...
//
// Edit rules cover Write, Edit, MultiEdit and NotebookEdit, which Read rules do not.
// The block goes first in permissions.deny so its "!" carve-outs only reach
// agentleash's own rules. A secret glob that overlaps an allow_files entry but cannot
// be carved (anchored or directory rules, non-relative allow entries) gets no native
// rule at all, and a note explains that only the hook enforces it.
func denyBlock(p *policy.Policy) (block, notes []string, err error) {
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
		carvable := true
		for _, a := range allows {
			ov, dirOnly := overlap(s, a)
			if !ov {
				continue
			}
			if s.anchor != anchorBare || dirOnly || !a.relative() {
				carvable = false
				notes = append(notes, fmt.Sprintf("secret %q overlaps allow_files %q, which Claude Code cannot carve out of an anchored or directory rule; no native Read/Edit rule is written for it and only the agentleash hook enforces it", f, a.raw))
				break
			}
			carve = append(carve, "!"+a.body)
		}
		if !carvable {
			continue
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
	return block, notes, nil
}
