package engine

import "strings"

// psrLexer holds the state of psTokenize: the runes being scanned, the word
// under construction (text and $(...) sub-expressions) and the tokens so far.
type psrLexer struct {
	rs     []rune
	cur    strings.Builder
	subs   []string
	inWord bool
	toks   []psTok
}

// flush ends the current word, if any, and appends it as a token.
func (lx *psrLexer) flush() {
	if lx.inWord {
		lx.toks = append(lx.toks, psTok{text: lx.cur.String(), subs: lx.subs})
	}
	lx.cur.Reset()
	lx.subs = nil
	lx.inWord = false
}

// emit ends the current word and appends the operator op.
func (lx *psrLexer) emit(op string) {
	lx.flush()
	lx.toks = append(lx.toks, psTok{op: op})
}

// at reports whether rs[i] exists and equals r.
func (lx *psrLexer) at(i int, r rune) bool {
	return i < len(lx.rs) && lx.rs[i] == r
}

// readVar reads a variable reference starting at rs[i]=='$' and returns
// the placeholder text and the index after it.
func (lx *psrLexer) readVar(i int) (string, int) {
	rs := lx.rs
	if lx.at(i+1, '{') {
		j := i + 2
		for j < len(rs) && rs[j] != '}' {
			j++
		}
		name := string(rs[i+2 : min(j, len(rs))])
		return string(phStart) + strings.ToLower(name) + string(phEnd), min(j+1, len(rs))
	}
	j := i + 1
	for j < len(rs) && psrVarRune(rs[j]) {
		if rs[j] == ':' && (j+1 >= len(rs) || !isWordRune(rs[j+1])) {
			break
		}
		j++
		if j == i+2 && (rs[i+1] == '$' || rs[i+1] == '?' || rs[i+1] == '^') {
			break
		}
	}
	if j == i+1 {
		return "$", j
	}
	return string(phStart) + strings.ToLower(string(rs[i+1:j])) + string(phEnd), j
}

// psrVarRune reports whether r may continue a $name variable reference.
func psrVarRune(r rune) bool {
	return isWordRune(r) || r == ':' || r == '?' || r == '$' || r == '^'
}

// readParen reads a parenthesised body starting at rs[i]=='(' and returns
// the inner text, the index after the closing ')' and whether it was closed.
func (lx *psrLexer) readParen(i int) (string, int, bool) {
	rs := lx.rs
	depth := 0
	for j := i; j < len(rs); j++ {
		switch rs[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return string(rs[i+1 : j]), j + 1, true
			}
		case '\'':
			j = lx.skipSingle(j)
		case '"':
			j = lx.skipDouble(j)
		}
	}
	return "", len(rs), false
}

// skipSingle skips a single-quoted string inside a parenthesised body
// (rs[j] is the opening quote).
// It returns the index of the closing quote (or len(rs)).
func (lx *psrLexer) skipSingle(j int) int {
	j++
	for j < len(lx.rs) && lx.rs[j] != '\'' {
		j++
	}
	return j
}

// skipDouble skips a "..." string (with backtick escapes) inside a
// parenthesised body; rs[j]=='"'. It returns the index of the closing quote
// (or len(rs) or beyond).
func (lx *psrLexer) skipDouble(j int) int {
	for j++; j < len(lx.rs) && lx.rs[j] != '"'; j++ {
		if lx.rs[j] == '`' {
			j++
		}
	}
	return j
}

// readDQ reads a double-quoted body (after the opening quote) until the
// closing quote (or "@ for here-strings).
func (lx *psrLexer) readDQ(i int, here bool) (int, bool) {
	rs := lx.rs
	for i < len(rs) {
		c := rs[i]
		switch {
		case here && c == '\n' && lx.at(i+1, '"') && lx.at(i+2, '@'):
			return i + 3, true
		case !here && c == '"':
			if lx.at(i+1, '"') {
				lx.cur.WriteRune('"')
				i += 2
				continue
			}
			return i + 1, true
		case c == '`' && i+1 < len(rs):
			lx.cur.WriteRune(rs[i+1])
			i += 2
		case c == '$' && lx.at(i+1, '('):
			next, ok := lx.addSubExpr(i)
			if !ok {
				return len(rs), false
			}
			i = next
		case c == '$':
			ph, next := lx.readVar(i)
			lx.cur.WriteString(ph)
			i = next
		default:
			lx.cur.WriteRune(c)
			i++
		}
	}
	return i, false
}

// addSubExpr records the $(...) sub-expression starting at rs[i]=='$' in the
// current word and returns the index after it; ok is false when unclosed.
func (lx *psrLexer) addSubExpr(i int) (int, bool) {
	inner, next, ok := lx.readParen(i + 1)
	if !ok {
		return next, false
	}
	lx.subs = append(lx.subs, inner)
	lx.cur.WriteRune(dynAny)
	return next, true
}

// step scans the token piece starting at rs[i] and returns the index after
// it; ok is false when a quote, comment or here-string is not terminated.
func (lx *psrLexer) step(i int) (int, bool) {
	c := lx.rs[i]
	switch {
	case c == ' ' || c == '\t' || c == '\r':
		lx.flush()
		return i + 1, true
	case c == '\n':
		lx.emit(";")
		return i + 1, true
	case c == '#' && !lx.inWord:
		return lx.skipLineComment(i), true
	case c == '<' && lx.at(i+1, '#'):
		return lx.skipBlockComment(i)
	case c == '`':
		return lx.backtick(i), true
	case c == '@' && lx.hereStart(i):
		lx.inWord = true
		return lx.hereString(i)
	case c == '\'':
		lx.inWord = true
		return lx.singleQuoted(i)
	case c == '"':
		lx.inWord = true
		return lx.readDQ(i+1, false)
	case c == '$' && lx.at(i+1, '('):
		next, ok := lx.addSubExpr(i)
		if ok {
			lx.inWord = true
		}
		return next, ok
	case c == '@' && (lx.at(i+1, '(') || lx.at(i+1, '{')):
		lx.emit(string(lx.rs[i+1]))
		return i + 2, true
	case c == '$':
		ph, next := lx.readVar(i)
		lx.inWord = true
		lx.cur.WriteString(ph)
		return next, true
	case c == '[' && !lx.inWord:
		return lx.typeLiteral(i), true
	}
	return lx.operator(i), true
}

// skipLineComment skips a # comment up to (not including) the newline.
func (lx *psrLexer) skipLineComment(i int) int {
	for i < len(lx.rs) && lx.rs[i] != '\n' {
		i++
	}
	return i
}

// skipBlockComment skips a <# ... #> comment starting at rs[i].
func (lx *psrLexer) skipBlockComment(i int) (int, bool) {
	end := strings.Index(string(lx.rs[i:]), "#>")
	if end < 0 {
		return i, false
	}
	return i + len([]rune(string(lx.rs[i:])[:end+2])), true
}

// backtick handles a backtick escape outside quotes; a backtick before a
// newline is a line continuation.
func (lx *psrLexer) backtick(i int) int {
	if i+1 >= len(lx.rs) {
		return i + 1
	}
	if lx.rs[i+1] != '\n' {
		lx.cur.WriteRune(lx.rs[i+1])
		lx.inWord = true
	}
	return i + 2
}

// hereStart reports whether rs[i]=='@' opens a here-string (@' or @"
// followed by a line break).
func (lx *psrLexer) hereStart(i int) bool {
	return (lx.at(i+1, '\'') || lx.at(i+1, '"')) && (lx.at(i+2, '\n') || lx.at(i+2, '\r'))
}

// hereString reads a here-string starting at rs[i]=='@'.
func (lx *psrLexer) hereString(i int) (int, bool) {
	if lx.rs[i+1] != '\'' {
		return lx.readDQ(i+3, true)
	}
	rest := string(lx.rs[i+2:])
	end := strings.Index(rest, "\n'@")
	if end < 0 {
		return i, false
	}
	lx.cur.WriteString(strings.TrimLeft(rest[:end], "\r\n"))
	return i + 2 + len([]rune(rest[:end+3])), true
}

// singleQuoted reads a single-quoted string starting at rs[i]; a doubled quote is a literal quote.
func (lx *psrLexer) singleQuoted(i int) (int, bool) {
	rs := lx.rs
	for j := i + 1; j < len(rs); {
		if rs[j] != '\'' {
			lx.cur.WriteRune(rs[j])
			j++
			continue
		}
		if lx.at(j+1, '\'') {
			lx.cur.WriteRune('\'')
			j += 2
			continue
		}
		return j + 1, true
	}
	return i, false
}

// typeLiteral reads a [Type] literal starting at rs[i]=='['; an unclosed
// bracket is a literal character.
func (lx *psrLexer) typeLiteral(i int) int {
	rs := lx.rs
	depth := 0
	j := i
	for ; j < len(rs); j++ {
		if rs[j] == '[' {
			depth++
		} else if rs[j] == ']' {
			depth--
			if depth == 0 {
				break
			}
		}
	}
	lx.inWord = true
	if j >= len(rs) {
		lx.cur.WriteRune(rs[i])
		return i + 1
	}
	lx.cur.WriteString(string(rs[i : j+1]))
	return j + 1
}

// operator handles operators (&&, ||, punctuation, redirections, =) and
// plain word characters at rs[i].
func (lx *psrLexer) operator(i int) int {
	c := lx.rs[i]
	switch {
	case c == '&' && lx.at(i+1, '&'):
		lx.emit("&&")
		return i + 2
	case c == '|' && lx.at(i+1, '|'):
		lx.emit("||")
		return i + 2
	case strings.ContainsRune("|;(){},&+", c):
		lx.emit(string(c))
		return i + 1
	case c == '>' || c == '<':
		lx.emit(string(c))
		if lx.at(i+1, '>') {
			return i + 2
		}
		return i + 1
	case c == '=' && !lx.inWord:
		lx.emit("=")
		return i + 1
	}
	lx.inWord = true
	lx.cur.WriteRune(c)
	return i + 1
}
