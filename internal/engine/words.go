package engine

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Word evaluation.
//
// A shell word is evaluated statically into a small set of alternatives. Each
// alternative is a string in the internal glob syntax (see glob.go):
// quoted metacharacters are escaped, unquoted ones stay active, and anything
// that is only known at runtime (unknown variables, command substitutions)
// becomes the dynAny marker. Variables assigned anywhere in the script are
// tracked flow-insensitively: every value ever assigned is an alternative.

const maxAlts = 64

// varValue is one value a variable may hold.
type varValue struct {
	word *syntax.Word // nil: unknown at analysis time
	// pattern marks for-loop items: the variable holds the *expansion* of a
	// glob, so it stays a glob even when the variable is used inside quotes.
	pattern bool
}

type wordMode uint8

const (
	modePattern wordMode = iota // internal glob syntax
	modeRaw                     // plain text (assignment values)
)

type wordKey struct {
	w    *syntax.Word
	mode wordMode
}

// wordAlts evaluates a word (memoised: nested substitutions would otherwise
// be re-evaluated exponentially often).
func (s *shellEval) wordAlts(w *syntax.Word, mode wordMode) []string {
	if w == nil {
		return []string{""}
	}
	key := wordKey{w, mode}
	if v, ok := s.memo[key]; ok {
		return v
	}
	if !s.sec.work.spend(1) {
		return []string{string(dynAny)}
	}
	v := s.wordAltsUncached(w, mode)
	s.memo[key] = v
	return v
}

func (s *shellEval) wordAltsUncached(w *syntax.Word, mode wordMode) []string {
	words := []*syntax.Word{w}
	clone := &syntax.Word{Parts: append([]syntax.WordPart(nil), w.Parts...)}
	if syntax.SplitBraces(clone) {
		words = nil
		for bw, err := range expand.BracesSeq(nil, clone) {
			if err != nil || len(words) >= maxAlts {
				return []string{string(dynAny)}
			}
			words = append(words, bw)
		}
	}
	var out []string
	for _, wd := range words {
		out = append(out, s.partsAlts(wd.Parts, false, mode)...)
		if len(out) > maxAlts {
			return []string{string(dynAny)}
		}
	}
	return dedupe(out)
}

func (s *shellEval) partsAlts(parts []syntax.WordPart, quoted bool, mode wordMode) []string {
	alts := []string{""}
	for _, p := range parts {
		pa := s.partAlts(p, quoted, mode)
		if _, ok := p.(*syntax.ParamExp); ok && !s.sec.work.expand(totalLen(pa)*len(alts)) {
			return []string{string(dynAny)} // too-complex (limits.go)
		}
		alts = product(alts, pa)
		if len(alts) > maxAlts {
			return []string{string(dynAny)}
		}
	}
	return alts
}

func totalLen(xs []string) int {
	n := 0
	for _, x := range xs {
		n += len(x)
	}
	return n
}

func product(a, b []string) []string {
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	return out
}

func (s *shellEval) partAlts(p syntax.WordPart, quoted bool, mode wordMode) []string {
	dyn := []string{string(dynAny)}
	switch x := p.(type) {
	case *syntax.Lit:
		if quoted {
			return []string{litText(unescapeDQ(x.Value), mode)}
		}
		v := unquotedLit(x.Value, mode)
		if mode == modePattern && !s.globstar {
			// Without `shopt -s globstar`, ** is just *.
			for strings.Contains(v, "**") {
				v = strings.ReplaceAll(v, "**", "*")
			}
		}
		return []string{v}
	case *syntax.SglQuoted:
		v := x.Value
		if x.Dollar {
			v = ansiC(v)
		}
		return []string{litText(v, mode)}
	case *syntax.DblQuoted:
		return s.partsAlts(x.Parts, true, mode)
	case *syntax.ParamExp:
		return s.paramAlts(x, quoted, mode)
	case *syntax.CmdSubst:
		if len(x.Stmts) == 1 {
			info := s.producer(x.Stmts[0])
			if info != nil && info.kind == stdinStatic {
				var out []string
				for _, t := range info.texts {
					out = append(out, litText(strings.TrimRight(t, "\n"), mode))
				}
				return out
			}
			if info != nil && info.kind == stdinGlob && mode == modePattern && !info.decode {
				return info.texts // e.g. $(find . -name '*.go'), $(git ls-files '*.md')
			}
		}
		return dyn
	case *syntax.ArithmExp:
		return []string{string(dynStar)}
	case *syntax.ProcSubst:
		return []string{"/dev/fd/63"}
	case *syntax.ExtGlob:
		if mode == modeRaw {
			return dyn
		}
		return []string{string(dynStar)}
	default:
		return dyn
	}
}

// litText renders literal (quoted) text.
func litText(v string, mode wordMode) string {
	if mode == modeRaw {
		return v
	}
	return escapeLit(v)
}

// escapeLit escapes glob metacharacters. In bash text a backslash is an
// ordinary character, never a path separator (grep '\.env' is a regex).
func escapeLit(v string) string {
	return escapeGlob(v)
}

// escapeLitWin is escapeLit for PowerShell/cmd text, where a backslash is a
// path separator.
func escapeLitWin(v string) string {
	return escapeGlob(strings.ReplaceAll(v, `\`, "/"))
}

// activeLit renders the value of an unquoted bash expansion: wildcards stay
// active, backslashes are literal characters.
func activeLit(v string) string {
	return strings.ReplaceAll(v, `\`, `\\`)
}

// activeLitWin renders PowerShell/cmd text: wildcards stay active and
// backslashes are path separators.
func activeLitWin(v string) string {
	return strings.ReplaceAll(v, `\`, "/")
}

// unquotedLit processes backslash escapes of an unquoted literal.
func unquotedLit(v string, mode wordMode) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(v) {
			break
		}
		i++
		n := v[i]
		if n == '\n' {
			continue
		}
		if mode == modeRaw {
			b.WriteByte(n)
			continue
		}
		b.WriteString(escapeLit(string(n)))
	}
	return b.String()
}

// unescapeDQ processes the escapes valid inside double quotes.
func unescapeDQ(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\\' && i+1 < len(v) && strings.IndexByte("$`\"\\\n", v[i+1]) >= 0 {
			i++
			if v[i] == '\n' {
				continue
			}
			b.WriteByte(v[i])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ansiC decodes $'...' escapes.
func ansiC(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\\' || i+1 >= len(v) {
			b.WriteByte(c)
			continue
		}
		i++
		switch v[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'e', 'E':
			b.WriteByte(27)
		case 'f':
			b.WriteByte(12)
		case 'v':
			b.WriteByte(11)
		case 'x':
			j := i + 1
			for j < len(v) && j < i+3 && isHex(v[j]) {
				j++
			}
			if n, err := strconv.ParseUint(v[i+1:j], 16, 8); err == nil {
				b.WriteByte(byte(n))
			}
			i = j - 1
		case 'u', 'U':
			maxLen := 4
			if v[i] == 'U' {
				maxLen = 8
			}
			j := i + 1
			var r rune
			for j < len(v) && j <= i+maxLen && isHex(v[j]) && r <= utf8.MaxRune {
				r = r*16 + hexVal(v[j])
				j++
			}
			if j > i+1 && r <= utf8.MaxRune {
				b.WriteRune(r)
			}
			i = j - 1
		case 'c':
			if i+1 < len(v) {
				i++
				b.WriteByte(v[i] & 0x1f)
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i
			for j < len(v) && j < i+3 && v[j] >= '0' && v[j] <= '7' {
				j++
			}
			if n, err := strconv.ParseUint(v[i:j], 8, 8); err == nil {
				b.WriteByte(byte(n))
			}
			i = j - 1
		default:
			b.WriteByte(v[i])
		}
	}
	return b.String()
}

func hexVal(c byte) rune {
	switch {
	case c >= 'a':
		return rune(c-'a') + 10
	case c >= 'A':
		return rune(c-'A') + 10
	default:
		return rune(c - '0')
	}
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// paramAlts evaluates a parameter expansion.
func (s *shellEval) paramAlts(pe *syntax.ParamExp, quoted bool, mode wordMode) []string {
	dyn := []string{string(dynAny)}
	if pe.Param == nil || pe.Excl || pe.Length || pe.Width || pe.IsSet || pe.Slice != nil ||
		pe.Repl != nil || pe.Names != 0 || pe.Index != nil || pe.NestedParam != nil || len(pe.Modifiers) > 0 {
		return dyn
	}
	vals := s.varAlts(pe.Param.Value)
	if pe.Exp != nil {
		switch pe.Exp.Op {
		case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AssignUnset, syntax.AssignUnsetOrNull:
			vals = append(vals, s.expWordAlts(pe.Exp.Word)...)
		case syntax.AlternateUnset, syntax.AlternateUnsetOrNull:
			vals = append(s.expWordAlts(pe.Exp.Word), typedAlt{text: ""})
		case syntax.ErrorUnset, syntax.ErrorUnsetOrNull, syntax.UpperFirst, syntax.UpperAll, syntax.LowerFirst, syntax.LowerAll:
			// value unchanged for our case-insensitive purposes
		default:
			return dyn
		}
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		switch {
		case mode == modeRaw && v.pattern:
			out = append(out, unescapeKeepDyn(v.text))
		case mode == modeRaw:
			out = append(out, v.text)
		case v.pattern:
			out = append(out, v.text)
		case quoted:
			out = append(out, escapeKeepDyn(v.text))
		default:
			out = append(out, activeLit(v.text))
		}
	}
	return dedupe(out)
}

// typedAlt is a raw variable value; pattern means already in internal syntax.
type typedAlt struct {
	text    string
	pattern bool
}

func (s *shellEval) expWordAlts(w *syntax.Word) []typedAlt {
	var out []typedAlt
	for _, a := range s.wordAlts(w, modeRaw) {
		out = append(out, typedAlt{text: a})
	}
	return out
}

// varAlts returns every value a variable may hold.
func (s *shellEval) varAlts(name string) []typedAlt {
	unknown := []typedAlt{{text: string(dynAny)}}
	if s.resolving[name] || len(s.resolving) > 8 {
		return unknown
	}
	vals, assigned := s.vars[name]
	var out []typedAlt
	switch name {
	case "HOME":
		if s.req.Home != "" {
			out = append(out, typedAlt{text: osPath(s.req.Home)})
		} else {
			out = append(out, unknown...)
		}
	case "IFS":
		if !assigned {
			return []typedAlt{{text: " \t\n"}} // default IFS: word splitting on whitespace
		}
	case "PWD":
		if s.req.Cwd != "" && !s.sec.basesUnknown {
			out = append(out, typedAlt{text: osPath(s.req.Cwd)})
		} else {
			out = append(out, unknown...)
		}
	default:
		if !assigned {
			return unknown
		}
	}
	s.resolving[name] = true
	defer delete(s.resolving, name)
	for _, v := range vals {
		if v.word == nil {
			out = append(out, unknown...)
			continue
		}
		if v.pattern {
			for _, a := range s.wordAlts(v.word, modePattern) {
				out = append(out, typedAlt{text: a, pattern: true})
			}
			continue
		}
		for _, a := range s.wordAlts(v.word, modeRaw) {
			out = append(out, typedAlt{text: a})
		}
	}
	if len(out) > maxAlts {
		return unknown
	}
	return out
}

// osPath converts a path from the Request (an OS path, possibly with
// Windows separators) to the forward-slash form used for bash values.
func osPath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

func escapeKeepDyn(v string) string {
	return escapeLit(v)
}

func unescapeKeepDyn(v string) string {
	var b []byte
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
		}
		b = append(b, v[i])
	}
	return string(b)
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// isDynamic reports whether an alternative contains runtime-only parts.
func isDynamic(alt string) bool {
	return strings.IndexByte(alt, dynAny) >= 0
}

// plain returns the display/text form of an alternative.
func plain(alt string) string {
	return unescapeGlob(alt)
}

// staticText returns the single static plain text of a word's alternatives,
// or ok=false when the word is dynamic or ambiguous.
func staticText(alts []string) (string, bool) {
	if len(alts) != 1 || isDynamic(alts[0]) || strings.IndexByte(alts[0], dynStar) >= 0 {
		return "", false
	}
	return plain(alts[0]), true
}
