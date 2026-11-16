package engine

import (
	"regexp"
	"strings"
)

// elispDirRe finds Emacs Lisp directory listings, whose directory is the
// first argument after the function name: (directory-files "." t).
var elispDirRe = regexp.MustCompile(`\(\s*(?:directory-files(?:-recursively|-and-attributes)?|file-expand-wildcards)\s+("(?:[^"\\]|\\.)*"|[^\s()]+|\()`)

// scanElispDirReads is scanDirReads for Lisp call syntax: listing the
// current, home, root or a runtime-chosen directory and reading what it
// finds reads every file there (.env included). A named subdirectory
// literal is allowed.
func (s *shellEval) scanElispDirReads(lang, code string) {
	for _, m := range elispDirRe.FindAllStringSubmatch(code, -1) {
		arg := m[1]
		if strings.HasPrefix(arg, `"`) {
			dir := strings.Trim(arg, `"`)
			if !cwdArgs[dir] && !strings.HasPrefix(dir, "~") && !strings.ContainsAny(dir, "*?[") {
				continue // a named subdirectory
			}
			arg = dir
		} else {
			arg = "(runtime value)"
		}
		if mt, ok := s.sec.checkPath(activeLit(".*")); ok {
			mt.glob = true
			mt.path = "every file in " + displayDir(arg)
			s.c.deny(RuleSecretFile+":"+mt.pattern, secretFileReason(mt, "reading (from "+lang+" code)", s.sec))
			return
		}
	}
}
