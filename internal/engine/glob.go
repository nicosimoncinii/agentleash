package engine

// This file implements glob-vs-glob intersection. The engine never touches the
// filesystem to expand a glob; instead it asks "is there any string that both
// the argument glob and the secret glob accept?". If yes, the argument could
// reach a secret and is denied.
//
// Internal pattern syntax (shared by secret patterns and shell arguments):
//
//	\c      literal c (only used to escape * ? [ ] \)
//	*       shell wildcard: any run of characters within one path segment
//	?       shell wildcard: any single character
//	[...]   character class ([!..] / [^..] negation, ranges, [:posix:] classes)
//	dynStar any run of characters within one segment (from extglobs, 8.3 names,
//	        dynamic shell words); unlike *, it is not subject to the dotfile rule
//	dynAny  any run of characters including '/' (only appears before path
//	        resolution; resolution rewrites it to a leading "**")
//	**      (a whole segment) zero or more path segments
//
// All comparisons are done on lower-cased text: agentleash treats paths as
// case-insensitive on every platform (NTFS and APFS are case-insensitive by
// default; on Linux this only produces harmless false positives).

const (
	dynAny  = '\x00'
	dynStar = '\x01'
)

type tokKind uint8

const (
	tLit tokKind = iota
	tAny
	tClass
	tStar
)

type gtok struct {
	kind  tokKind
	ch    rune
	class *charClass
	// shell marks * and ? that came from an unquoted shell glob: these obey
	// the dotfile rule (a leading '.' must be matched explicitly).
	shell bool
}

type charClass struct {
	negated bool
	fuzzy   bool // contains constructs we do not model ([:alpha:], [=a=]); accept anything
	ranges  [][2]rune
}

func (c *charClass) matches(r rune) bool {
	if c.fuzzy {
		return true
	}
	in := false
	for _, rg := range c.ranges {
		if r >= rg[0] && r <= rg[1] {
			in = true
			break
		}
	}
	return in != c.negated
}

// onlyDot reports whether the class can only match '.'.
func (c *charClass) onlyDot() bool {
	if c.fuzzy || c.negated {
		return false
	}
	for _, rg := range c.ranges {
		if rg[0] != '.' || rg[1] != '.' {
			return false
		}
	}
	return len(c.ranges) > 0
}

// parseSegment turns one path segment in internal syntax into tokens.
func parseSegment(s string) []gtok {
	rs := []rune(s)
	var out []gtok
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch r {
		case '\\':
			if i+1 < len(rs) {
				i++
				out = append(out, gtok{kind: tLit, ch: rs[i]})
			} else {
				out = append(out, gtok{kind: tLit, ch: '\\'})
			}
		case '*':
			// Collapse runs of stars.
			if len(out) > 0 && out[len(out)-1].kind == tStar {
				continue
			}
			out = append(out, gtok{kind: tStar, shell: true})
		case dynStar, dynAny:
			if len(out) > 0 && out[len(out)-1].kind == tStar {
				out[len(out)-1].shell = false
				continue
			}
			out = append(out, gtok{kind: tStar})
		case '?':
			out = append(out, gtok{kind: tAny, shell: true})
		case '[':
			cls, n, ok := parseClass(rs[i:])
			if !ok {
				out = append(out, gtok{kind: tLit, ch: '['})
				continue
			}
			out = append(out, gtok{kind: tClass, class: cls})
			i += n - 1
		default:
			out = append(out, gtok{kind: tLit, ch: r})
		}
	}
	return out
}

// parseClass parses a bracket expression starting at rs[0]=='['. It returns the
// class, the number of runes consumed and whether the expression was closed.
func parseClass(rs []rune) (*charClass, int, bool) {
	c := &charClass{}
	i := 1
	if i < len(rs) && (rs[i] == '!' || rs[i] == '^') {
		c.negated = true
		i++
	}
	first := true
	for i < len(rs) {
		r := rs[i]
		if r == ']' && !first {
			return c, i + 1, true
		}
		first = false
		if r == '[' && i+1 < len(rs) && (rs[i+1] == ':' || rs[i+1] == '=' || rs[i+1] == '.') {
			c.fuzzy = true
			end := -1
			for j := i + 2; j+1 < len(rs); j++ {
				if rs[j] == rs[i+1] && rs[j+1] == ']' {
					end = j + 2
					break
				}
			}
			if end < 0 {
				return nil, 0, false
			}
			i = end
			continue
		}
		if r == '\\' && i+1 < len(rs) {
			i++
			r = rs[i]
		}
		lo, hi := r, r
		if i+2 < len(rs) && rs[i+1] == '-' && rs[i+2] != ']' {
			hi = rs[i+2]
			if hi == '\\' && i+3 < len(rs) {
				hi = rs[i+3]
				i++
			}
			i += 2
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		c.ranges = append(c.ranges, [2]rune{lo, hi})
		i++
	}
	return nil, 0, false
}

// admits reports whether the single-character token t can match some rune
// that is also accepted by u (u may be nil meaning "any rune"), honouring the
// "not a dot" constraint when noDot is set.
func admitsPair(t, u *gtok, noDot bool) bool {
	// Reduce to: is there a rune r accepted by both?
	switch {
	case t.kind == tLit && (u == nil || u.kind == tAny):
		return !noDot || t.ch != '.'
	case u != nil && u.kind == tLit && t.kind == tAny:
		return !noDot || u.ch != '.'
	case t.kind == tLit && u.kind == tLit:
		return t.ch == u.ch && (!noDot || t.ch != '.')
	case t.kind == tLit && u.kind == tClass:
		return u.class.matches(t.ch) && (!noDot || t.ch != '.')
	case t.kind == tClass && u != nil && u.kind == tLit:
		return t.class.matches(u.ch) && (!noDot || u.ch != '.')
	case t.kind == tClass && (u == nil || u.kind == tAny):
		return !noDot || !t.class.onlyDot()
	case u != nil && u.kind == tClass && t.kind == tAny:
		return !noDot || !u.class.onlyDot()
	default:
		// Any/Any, Class/Class: conservatively assume they overlap.
		return true
	}
}

// segmentsIntersect reports whether some single path-segment name is accepted
// by both token lists. a is the argument side: if its first token is a shell
// wildcard (* or ?), the dotfile rule applies unless dotglob is set.
func segmentsIntersect(a, b []gtok, dotglob bool) bool {
	dotRule := !dotglob && len(a) > 0 && a[0].shell && (a[0].kind == tStar || a[0].kind == tAny)
	n, m := len(a), len(b)
	memo := make(map[[3]int]bool)
	var f func(i, j int, started bool) bool
	f = func(i, j int, started bool) bool {
		if i == n && j == m {
			return true
		}
		st := 0
		if started {
			st = 1
		}
		key := [3]int{i, j, st}
		if v, ok := memo[key]; ok {
			return v
		}
		memo[key] = false
		noDot := dotRule && !started
		res := i < n && a[i].kind == tStar && f(i+1, j, started)
		if !res && j < m && b[j].kind == tStar && f(i, j+1, started) {
			res = true
		}
		if !res && i < n && j < m {
			ai, bj := &a[i], &b[j]
			switch {
			case ai.kind == tStar && bj.kind == tStar:
				// Both stars consume one shared ordinary character; only
				// relevant for the "first character" state of the dot rule.
				if !started {
					res = f(i, j, true)
				}
			case ai.kind == tStar:
				res = admitsPair(bj, nil, noDot) && f(i, j+1, true)
			case bj.kind == tStar:
				res = admitsPair(ai, nil, noDot) && f(i+1, j, true)
			default:
				res = admitsPair(ai, bj, noDot) && f(i+1, j+1, true)
			}
		}
		memo[key] = res
		return res
	}
	return f(0, 0, false)
}

// segmentsMatch is segmentsIntersect with one refinement for the case where
// BOTH sides contain a '*': the overlap must not come only from each star
// swallowing the other side's literal text ("crossing"). Otherwise
// "*.md" would collide with "id_rsa*" through the name "id_rsa.md". We
// require that a minimal instance of one side (stars replaced by "" or by
// a single ordinary character) is accepted by the other side. This keeps
// "cat *" vs "*.pem", ".e*" vs ".env.*" and "*rsa*" vs "id_rsa*" as
// matches.
func segmentsMatch(a, b []gtok, dotglob bool) bool {
	if !segmentsIntersect(a, b, dotglob) {
		return false
	}
	if !hasStar(a) || !hasStar(b) {
		return true
	}
	for _, fill := range []rune{0, 'x'} {
		if segmentsIntersect(a, instantiate(b, fill), dotglob) || segmentsIntersect(instantiate(a, fill), b, true) {
			return true
		}
	}
	return false
}

func hasStar(ts []gtok) bool {
	for _, t := range ts {
		if t.kind == tStar {
			return true
		}
	}
	return false
}

// instantiate replaces stars with fill (0 = empty) and single-char
// wildcards with 'x', producing a literal token list.
func instantiate(ts []gtok, fill rune) []gtok {
	out := make([]gtok, 0, len(ts))
	for _, t := range ts {
		switch t.kind {
		case tStar:
			if fill != 0 {
				out = append(out, gtok{kind: tLit, ch: fill})
			}
		case tAny:
			out = append(out, gtok{kind: tLit, ch: 'x'})
		default:
			out = append(out, t)
		}
	}
	return out
}

// gseg is a parsed path segment.
type gseg struct {
	globstar bool // "**": zero or more segments
	toks     []gtok
}

func (s gseg) isLiteral() bool {
	if s.globstar {
		return false
	}
	for _, t := range s.toks {
		if t.kind != tLit {
			return false
		}
	}
	return true
}

// gpath is a parsed, cleaned, absolute (or "**"-prefixed) path pattern.
type gpath struct {
	raw  string
	segs []gseg
}

func (p gpath) isLiteral() bool {
	for _, s := range p.segs {
		if !s.isLiteral() {
			return false
		}
	}
	return true
}

func parsePath(clean string) gpath {
	parts := splitSegments(clean)
	segs := make([]gseg, 0, len(parts))
	for _, part := range parts {
		if part == "**" {
			if len(segs) > 0 && segs[len(segs)-1].globstar {
				continue
			}
			segs = append(segs, gseg{globstar: true})
			continue
		}
		segs = append(segs, gseg{toks: parseSegment(part)})
	}
	return gpath{raw: clean, segs: segs}
}

// splitSegments splits on '/' (escapes never precede '/'). A leading '/'
// yields an empty first segment that stands for the filesystem root.
func splitSegments(s string) []string {
	if s == "" {
		return nil
	}
	return splitOn(s, '/')
}

func splitOn(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// pathsIntersect reports whether some concrete path is accepted by both a
// (argument side) and b (secret side).
func pathsIntersect(a, b gpath, dotglob bool) bool {
	n, m := len(a.segs), len(b.segs)
	memo := make(map[[2]int]int8)
	var g func(i, j int) bool
	g = func(i, j int) bool {
		if i == n && j == m {
			return true
		}
		key := [2]int{i, j}
		if v, ok := memo[key]; ok {
			return v == 1
		}
		memo[key] = 0
		res := false
		if i < n && a.segs[i].globstar {
			res = g(i+1, j) || (j < m && g(i, j+1))
		}
		if !res && j < m && b.segs[j].globstar {
			res = g(i, j+1) || (i < n && g(i+1, j))
		}
		if !res && i < n && j < m && !a.segs[i].globstar && !b.segs[j].globstar {
			res = segmentsMatch(a.segs[i].toks, b.segs[j].toks, dotglob) && g(i+1, j+1)
		}
		if res {
			memo[key] = 1
		}
		return res
	}
	return g(0, 0)
}

// globMatchString matches a literal subject against a glob pattern where '*'
// matches any run of characters including '/' and spaces (command patterns,
// env names). The subject may contain dynAny/dynStar runs, which match
// anything; in that case the result means "could match".
func globMatchString(pattern, subject string) bool {
	p := parseFlat(pattern, true)
	s := parseFlat(subject, false)
	return segmentsIntersect(s, p, true)
}

// parseFlat tokenises a flat (non-path) glob. When glob is false only the
// dynamic markers are special.
func parseFlat(s string, glob bool) []gtok {
	var out []gtok
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == dynAny || r == dynStar:
			if len(out) == 0 || out[len(out)-1].kind != tStar {
				out = append(out, gtok{kind: tStar})
			}
		case glob && r == '*':
			if len(out) == 0 || out[len(out)-1].kind != tStar {
				out = append(out, gtok{kind: tStar})
			}
		case glob && r == '?':
			out = append(out, gtok{kind: tAny})
		case glob && r == '[':
			cls, n, ok := parseClass(rs[i:])
			if !ok {
				out = append(out, gtok{kind: tLit, ch: r})
				continue
			}
			out = append(out, gtok{kind: tClass, class: cls})
			i += n - 1
		case glob && r == '\\' && i+1 < len(rs):
			i++
			out = append(out, gtok{kind: tLit, ch: rs[i]})
		default:
			out = append(out, gtok{kind: tLit, ch: r})
		}
	}
	return out
}

// hasGlobMeta reports whether an internal-syntax string has an unescaped
// wildcard or dynamic marker.
func hasGlobMeta(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '*', '?', '[', dynAny, dynStar:
			return true
		}
	}
	return false
}

// escapeGlob escapes wildcard characters so that s is matched literally.
func escapeGlob(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '*', '?', '[', ']', '\\':
			b = append(b, '\\')
		}
		b = append(b, s[i])
	}
	return string(b)
}

// unescapeGlob removes escapes (for display).
func unescapeGlob(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
			}
		case dynAny, dynStar:
			b = append(b, '*')
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}
