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

import (
	"strings"
	"unicode/utf8"
)

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
	if !hasStar(a) && !hasStar(b) {
		// Without stars every token produces exactly one character:
		// compare the two sides pairwise.
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if !admitsPair(&a[i], &b[i], dotRule && i == 0) {
				return false
			}
		}
		return true
	}
	if allLiteral(a) {
		// A literal argument (the usual case) is matched against b by the
		// linear chunk algorithm; the dot rule cannot apply to it.
		return literalGlobMatch(len(a), func(i int) rune { return a[i].ch }, b)
	}
	var buf [isectBuf]bool
	x := newIsect(b, dotRule, buf[:])
	for i := range a {
		switch x.step(&a[i]) {
		case isectDead:
			return false
		case isectAccept:
			return true
		}
	}
	return x.done()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func allLiteral(ts []gtok) bool {
	for i := range ts {
		if ts[i].kind != tLit {
			return false
		}
	}
	return true
}

// literalGlobMatch reports whether the literal text of n runes (at returns
// the i-th) is accepted by the glob b, in time linear in n for a fixed b.
// b is split at its stars into star-free chunks, each of which matches a
// fixed number of runes: the first chunk must match at the start, the last
// at the end, and the others are placed leftmost-first in between (the
// leftmost occurrence leaves the most room for the rest, so this is exact).
func literalGlobMatch(n int, at func(int) rune, b []gtok) bool {
	chunkAt := func(p int, c []gtok) bool {
		for k := range c {
			lit := gtok{kind: tLit, ch: at(p + k)}
			if !admitsPair(&lit, &c[k], false) {
				return false
			}
		}
		return true
	}
	firstStar, lastStar := -1, -1
	for k := range b {
		if b[k].kind == tStar {
			if firstStar < 0 {
				firstStar = k
			}
			lastStar = k
		}
	}
	if firstStar < 0 {
		return len(b) == n && chunkAt(0, b)
	}
	first, last := b[:firstStar], b[lastStar+1:]
	lo, hi := len(first), n-len(last)
	if lo > hi || !chunkAt(0, first) || !chunkAt(hi, last) {
		return false
	}
	start := firstStar + 1
	for k := start; k <= lastStar; k++ {
		if b[k].kind != tStar {
			continue
		}
		c := b[start:k]
		start = k + 1
		found := false
		for ; lo+len(c) <= hi; lo++ {
			if chunkAt(lo, c) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		lo += len(c)
	}
	return true
}

// flatGlob is a compiled flat pattern (globMatchString).
type flatGlob struct {
	toks []gtok
	// chunks are the UTF-8 texts between the stars when the pattern holds
	// only literals and stars (nil otherwise); see byteGlobMatch.
	chunks []string
}

var flatGlobCache pureCache[string, *flatGlob]

func compileFlatGlob(pattern string) *flatGlob {
	g := &flatGlob{toks: parseFlat(pattern, true)}
	g.chunks = starChunks(g.toks)
	return g
}

// starChunks returns the UTF-8 texts between the stars of a glob made only
// of literals and stars, for byteGlobMatch; nil for any other glob. '?' and
// classes need rune-wise matching, and so does U+FFFD: an invalid byte of
// the subject decodes to U+FFFD.
func starChunks(toks []gtok) []string {
	var chunks []string
	var cur []byte
	for _, t := range toks {
		switch {
		case t.kind == tStar:
			chunks = append(chunks, string(cur))
			cur = cur[:0]
		case t.kind != tLit || t.ch == utf8.RuneError:
			return nil
		default:
			cur = utf8.AppendRune(cur, t.ch)
		}
	}
	return append(chunks, string(cur))
}

// byteGlobMatch is literalGlobMatch on the bytes of s, for a glob made only
// of literals and stars, split into chunks at its stars. It is exact on
// runes: the UTF-8 encoding of a literal chunk can only occur in s at a
// rune boundary, because it starts with a byte that never continues a rune.
func byteGlobMatch(s string, chunks []string) bool {
	if len(chunks) == 1 {
		return s == chunks[0]
	}
	first, last := chunks[0], chunks[len(chunks)-1]
	if len(first)+len(last) > len(s) || !strings.HasPrefix(s, first) || !strings.HasSuffix(s, last) {
		return false
	}
	lo, hi := len(first), len(s)-len(last)
	for _, c := range chunks[1 : len(chunks)-1] {
		i := strings.Index(s[lo:hi], c)
		if i < 0 {
			return false
		}
		lo += i + len(c)
	}
	return true
}

// isect intersects an argument token stream a (fed one token at a time)
// with a fixed token list b. It is a forward simulation of the automaton
// whose states are (j, started): j tokens of b consumed, started once some
// character has been produced (the dotfile rule only constrains the first
// one). Each argument token costs O(len(b)), so long arguments are linear
// (the former recursive version memoised O(len(a)*len(b)) states in a map
// and recursed len(a) deep).
//
// Transitions, for the argument token ai and b[j]:
//   - ai is *: skip it (next token, same state); or let it produce b[j]
//     when b[j] is a single-character token (same token, j+1, started).
//   - b[j] is *: skip it (j+1, same token); or let it produce ai when ai is
//     a single-character token (next token, j, started).
//   - both *: they may produce one shared character (started).
//   - neither: they must produce the same character (next token, j+1).
//
// The input is accepted when the end of a is reached in state (len(b), *).
type isect struct {
	b        []gtok
	dotRule  bool
	cur, nxt []bool // index 2*j + started
	// starTail[j] reports that b[j:] is non-empty and holds only stars, so
	// any rest of the argument is accepted from (j, started) unless the dot
	// rule applies.
	starTail []bool
}

type isectResult uint8

const (
	isectAlive isectResult = iota
	isectDead
	isectAccept
)

// isectBuf is the scratch size that keeps the matcher off the heap for
// patterns of up to 20 tokens.
const isectBuf = 5 * 21

// newIsect prepares a matcher for b. buf is zeroed scratch space (usually
// a stack array of the caller); a larger one is allocated when it is too
// small.
func newIsect(b []gtok, dotRule bool, buf []bool) isect {
	m := len(b)
	if len(buf) < 5*(m+1) {
		buf = make([]bool, 5*(m+1))
	}
	x := isect{b: b, dotRule: dotRule, cur: buf[:2*(m+1)], nxt: buf[2*(m+1) : 4*(m+1)], starTail: buf[4*(m+1) : 5*(m+1)]}
	for j := m - 1; j >= 0 && b[j].kind == tStar; j-- {
		x.starTail[j] = true
	}
	x.cur[0] = true
	return x
}

// closeRow adds the states reachable without consuming the argument token
// ai (nil at the end of the argument). Transitions only go from j to j or
// j+1 and from not started to started, so one ascending pass suffices.
func (x *isect) closeRow(ai *gtok) {
	b, cur, m := x.b, x.cur, len(x.b)
	aStar := ai != nil && ai.kind == tStar
	for j := 0; j <= m; j++ {
		for st := 0; st < 2; st++ {
			if !cur[2*j+st] || j == m {
				continue
			}
			if b[j].kind == tStar {
				cur[2*(j+1)+st] = true
				if aStar && st == 0 {
					cur[2*j+1] = true
				}
			} else if aStar && admitsPair(&b[j], nil, x.dotRule && st == 0) {
				cur[2*(j+1)+1] = true
			}
		}
	}
}

// step consumes the argument token ai.
func (x *isect) step(ai *gtok) isectResult {
	x.closeRow(ai)
	b, cur, nxt, m := x.b, x.cur, x.nxt, len(x.b)
	clear(nxt)
	alive := false
	for j := 0; j <= m; j++ {
		for st := 0; st < 2; st++ {
			if !cur[2*j+st] {
				continue
			}
			noDot := x.dotRule && st == 0
			if x.starTail[j] && !noDot {
				// The rest of b is stars: they absorb the rest of a.
				return isectAccept
			}
			switch {
			case ai.kind == tStar:
				nxt[2*j+st] = true
				alive = true
			case j == m:
			case b[j].kind == tStar:
				if admitsPair(ai, nil, noDot) {
					nxt[2*j+1] = true
					alive = true
				}
			default:
				if admitsPair(ai, &b[j], noDot) {
					nxt[2*(j+1)+1] = true
					alive = true
				}
			}
		}
	}
	x.cur, x.nxt = nxt, cur
	if !alive {
		return isectDead
	}
	return isectAlive
}

// done reports whether the argument, now fully consumed, is accepted.
func (x *isect) done() bool {
	x.closeRow(nil)
	m := len(x.b)
	return x.cur[2*m] || x.cur[2*m+1]
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
	// Precomputed for pathsIntersect, which compares every segment of a
	// (possibly very long) argument with every secret pattern.
	literal bool     // only literal tokens (lit is their text)
	lit     string   // UTF-8 text of a literal segment
	chunks  []string // texts between the stars of a literals-and-stars segment
}

func newSeg(part string) gseg {
	s := gseg{toks: parseSegment(part)}
	if allLiteral(s.toks) {
		s.literal = true
		if strings.IndexByte(part, '\\') < 0 && utf8.ValidString(part) {
			s.lit = part
		} else {
			b := make([]byte, 0, len(s.toks))
			for _, t := range s.toks {
				b = utf8.AppendRune(b, t.ch)
			}
			s.lit = string(b)
		}
	} else {
		s.chunks = starChunks(s.toks)
	}
	return s
}

func (s gseg) isLiteral() bool { return !s.globstar && s.literal }

// segMatch is segmentsMatch on parsed segments, with fast paths for a
// literal argument segment (the dot rule and the "crossing" refinement only
// concern an argument with wildcards).
func segMatch(a, b *gseg, dotglob bool) bool {
	switch {
	case a.literal && b.literal:
		return a.lit == b.lit
	case a.literal && b.chunks != nil:
		return byteGlobMatch(a.lit, b.chunks)
	}
	return segmentsMatch(a.toks, b.toks, dotglob)
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
		segs = append(segs, newSeg(part))
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
//
// It is the same forward simulation as isect, one level up: "**" plays the
// role of '*' and two ordinary segments advance together when segmentsMatch
// accepts them. States are j (segments of b consumed); each segment of a
// costs O(len(b)) segment comparisons, so long paths stay linear.
//
//   - a[i] is "**": skip it (i+1, j); or let it absorb b[j] (i, j+1).
//   - b[j] is "**": skip it (i, j+1); or let it absorb a[i] (i+1, j).
//   - neither: (i+1, j+1) when the two segments match.
func pathsIntersect(a, b gpath, dotglob bool) bool {
	n, m := len(a.segs), len(b.segs)
	cur, nxt := make([]bool, m+1), make([]bool, m+1)
	cur[0] = true
	for i := 0; ; i++ {
		// Moves within row i (j -> j+1).
		aStar := i < n && a.segs[i].globstar
		for j := 0; j < m; j++ {
			if cur[j] && (aStar || b.segs[j].globstar) {
				cur[j+1] = true
			}
		}
		if i == n {
			return cur[m]
		}
		clear(nxt)
		alive := false
		for j := 0; j <= m; j++ {
			if !cur[j] {
				continue
			}
			switch {
			case aStar, j < m && b.segs[j].globstar:
				nxt[j] = true
				alive = true
			case j < m && segMatch(&a.segs[i], &b.segs[j], dotglob):
				nxt[j+1] = true
				alive = true
			}
		}
		if !alive {
			return false
		}
		cur, nxt = nxt, cur
	}
}

// globMatchString matches a literal subject against a glob pattern where '*'
// matches any run of characters including '/' and spaces (command patterns,
// env names). The subject may contain dynAny/dynStar runs, which match
// anything; in that case the result means "could match".
//
// The subject is streamed (not tokenised into a slice): it can be as long as
// the whole command, and is matched against every pattern form.
func globMatchString(pattern, subject string) bool {
	g := flatGlobCache.get(pattern, compileFlatGlob)
	p := g.toks
	if strings.IndexByte(subject, dynAny) < 0 && strings.IndexByte(subject, dynStar) < 0 {
		if g.chunks != nil {
			return byteGlobMatch(subject, g.chunks)
		}
		if isASCII(subject) {
			return literalGlobMatch(len(subject), func(i int) rune { return rune(subject[i]) }, p)
		}
		rs := []rune(subject)
		return literalGlobMatch(len(rs), func(i int) rune { return rs[i] }, p)
	}
	var buf [isectBuf]bool
	x := newIsect(p, false, buf[:])
	star := gtok{kind: tStar}
	lit := gtok{kind: tLit}
	prevStar := false
	for _, r := range subject {
		t := &lit
		if r == dynAny || r == dynStar {
			if prevStar {
				continue // a run of dynamic markers is one star
			}
			t, prevStar = &star, true
		} else {
			lit.ch, prevStar = r, false
		}
		switch x.step(t) {
		case isectDead:
			return false
		case isectAccept:
			return true
		}
	}
	return x.done()
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
