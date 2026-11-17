package engine

import (
	"fmt"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Write-then-run in the same command (§7.2): a script written by a `>`/`>>`
// redirect of echo, printf or a heredoc (or by tee, and carried by cp/mv) and
// then executed or sourced in the same command is analysed as what it is:
// a shell script through a child evaluator, or interpreter code through the
// one-liner scanner. Content only known at runtime (command output, an
// expansion) that is later executed is denied as dynamic-shell. Scripts
// written in an earlier call are only checked by their path (§7.7).

// maxWritesPerFile bounds the writes tracked for one file; beyond it the
// content counts as unknown (fail closed).
const maxWritesPerFile = 16

// writeRec is one write to a file: its possible texts, or dynamic.
type writeRec struct {
	texts   []string
	dynamic bool
	// download holds the pipeline-stage forms of a downloader (curl,
	// wget, ...) whose output is the content. Running it is matched as
	// `curl … | sh` by the command patterns (§7.5), like `curl -o f; sh f`,
	// instead of being denied as dynamic-shell.
	download []string
}

// downloaders fetch remote content to stdout or a file.
var downloaders = set("curl", "wget", "iwr", "invoke-webrequest", "irm", "invoke-restmethod")

// downloadForms returns the stage forms of st when it is a simple command
// that runs a downloader (at any wrapper level), or nil.
func (s *shellEval) downloadForms(st *syntax.Stmt) []string {
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil
	}
	for _, argv := range s.callArgv(call) {
		for _, level := range unwrapLevels(argv) {
			if len(level) > 0 && downloaders[cmdBase(level[0])] {
				return s.stageForms(st)
			}
		}
	}
	return nil
}

// writtenFiles are the files a script writes, shared by every evaluator of
// one bash analysis (sh -c children included).
type writtenFiles struct {
	byKey    map[string][]writeRec
	analysed map[string]bool
}

func newWrittenFiles() *writtenFiles {
	return &writtenFiles{byKey: map[string][]writeRec{}, analysed: map[string]bool{}}
}

// writeKey normalises a static file name.
func writeKey(t string) string {
	if t == "" || strings.ContainsAny(t, string([]rune{dynAny, dynStar})) {
		return ""
	}
	return path.Clean(strings.ReplaceAll(t, `\`, "/"))
}

func (w *writtenFiles) add(key string, rec writeRec) {
	if key == "" {
		return
	}
	recs := w.byKey[key]
	if len(recs) >= maxWritesPerFile {
		recs[len(recs)-1] = writeRec{dynamic: true}
		return
	}
	w.byKey[key] = append(recs, rec)
}

// lookup returns the writes of every tracked file that `op` may name: the
// same cleaned path, or the same base name (a `cd` in between, or an
// absolute spelling, is not modelled: matching the base name is the
// conservative choice).
func (w *writtenFiles) lookup(op string) (keys []string) {
	k := writeKey(op)
	if k == "" || len(w.byKey) == 0 {
		return nil
	}
	if _, ok := w.byKey[k]; ok {
		keys = append(keys, k)
	}
	base := path.Base(k)
	for key := range w.byKey {
		if key != k && path.Base(key) == base {
			keys = append(keys, key)
		}
	}
	return keys
}

var writeOps = map[syntax.RedirOperator]bool{
	syntax.RdrOut: true, syntax.AppOut: true, syntax.RdrClob: true,
	syntax.RdrAll: true, syntax.AppAll: true, syntax.RdrAllClob: true,
}

// staticArg returns the static text of a word, or "".
func (s *shellEval) staticArg(w *syntax.Word) string {
	t, ok := staticText(s.wordAlts(w, modePattern))
	if !ok {
		return ""
	}
	return plain(t)
}

// collectWrites records the files written by the script and their content.
func (s *shellEval) collectWrites(root syntax.Node) {
	teeIn := map[*syntax.Stmt]*stdinInfo{}
	teeDl := map[*syntax.Stmt][]string{}
	s.walk(root, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				if call, ok := x.Y.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 && cmdBase(s.staticArg(call.Args[0])) == "tee" {
					teeIn[x.Y] = s.producer(x.X)
					teeDl[x.Y] = s.downloadForms(x.X)
				}
			}
		case *syntax.Stmt:
			s.stmtWrites(x, teeIn, teeDl)
		}
		return true
	})
}

func (s *shellEval) stmtWrites(st *syntax.Stmt, teeIn map[*syntax.Stmt]*stdinInfo, teeDl map[*syntax.Stmt][]string) {
	call, _ := st.Cmd.(*syntax.CallExpr)
	name := ""
	if call != nil && len(call.Args) > 0 {
		name = cmdBase(s.staticArg(call.Args[0]))
	}
	s.inrRedirWrites(st, call, name)
	if call == nil {
		return
	}
	switch name {
	case "tee":
		s.inrTeeWrites(st, call, teeIn, teeDl)
	case "cp", "mv", "install":
		s.inrCopyWrites(call)
	}
}

// echoNewline reports whether the producer is an echo that ends its output
// with a newline (no -n).
func echoNewline(name string, call *syntax.CallExpr) bool {
	if name != "echo" {
		return false
	}
	if len(call.Args) > 1 {
		if lit := call.Args[1].Lit(); strings.HasPrefix(lit, "-") && len(lit) > 1 && strings.Trim(lit[1:], "neE") == "" && strings.Contains(lit, "n") {
			return false
		}
	}
	return true
}

func (s *shellEval) contentRec(info *stdinInfo, newline bool) writeRec {
	if info == nil || info.kind != stdinStatic || info.decode {
		return writeRec{dynamic: true}
	}
	texts := make([]string, 0, len(info.texts))
	for _, t := range info.texts {
		if newline {
			t += "\n"
		}
		texts = append(texts, t)
	}
	return writeRec{texts: texts}
}

// checkWrittenRuns analyses the written files that the script executes,
// sources or feeds to a shell or interpreter.
func (s *shellEval) checkWrittenRuns(root syntax.Node) {
	if len(s.written.byKey) == 0 {
		return
	}
	s.walk(root, func(n syntax.Node) bool {
		if st, ok := n.(*syntax.Stmt); ok {
			s.inrStmtWrittenRuns(st)
		}
		return true
	})
}

// runWritten analyses the content written to op, run by cmd as lang ("sh",
// an interpreter name, or "" for direct execution: the shebang decides).
func (s *shellEval) runWritten(cmd, op, lang string) {
	for _, key := range s.written.lookup(op) {
		recs := s.written.byKey[key]
		for _, r := range recs {
			if r.download != nil {
				// Download-then-run: decided by the command patterns as
				// `curl … | sh` (ask under the default policy), exactly like
				// `curl -o f URL && sh f` (§7.5).
				run := []string{cmdBase(cmd), "sh", "bash"}
				applyPatterns(s.e.policy, s.c, s.sec.work, s.req.Home, nil, [][]string{r.download, run})
				continue
			}
			if r.dynamic {
				s.c.deny(RuleDynamicShell, fmt.Sprintf("`%s` runs %q, which this command writes with content only known at runtime (command output or an expansion); it cannot be checked, so it was blocked. Write the script with literal text (echo, printf or a quoted heredoc).", display(cmd), display(op)))
				return
			}
		}
		for _, content := range writtenContents(recs) {
			s.analyseWritten(cmd, op, lang, content)
		}
	}
}

// writtenContents returns the possible contents of a file: every suffix of
// its writes concatenated in order (a `>` restarts the file, `>>` appends;
// flow-insensitive), with a bounded product of alternatives.
func writtenContents(recs []writeRec) []string {
	var out []string
	for i := range recs {
		acc := []string{""}
		for _, r := range recs[i:] {
			var next []string
			for _, a := range acc {
				for _, t := range r.texts {
					if len(next) < maxAlts {
						next = append(next, a+t)
					}
				}
			}
			acc = next
		}
		out = append(out, acc...)
	}
	return dedupe(out)
}

func (s *shellEval) analyseWritten(cmd, op, lang, content string) {
	if lang == "" {
		lang = shebangLang(content)
	}
	guard := lang + "\x00" + content
	if s.written.analysed[guard] || !s.sec.work.spend(len(content)/64+1) {
		return
	}
	s.written.analysed[guard] = true
	switch {
	case lang == "sh":
		ch := s.child()
		ch.run(content)
	case interpreters[lang]:
		s.scanCode(lang, content)
	default:
		s.c.deny(RuleDynamicShell, fmt.Sprintf("`%s` runs %q, written in this command for %q, which cannot be analysed; blocked to be safe.", display(cmd), display(op), display(lang)))
	}
}

// shebangLang picks the language of a directly executed script: the
// shebang's program (through env), or the shell without a shebang.
func shebangLang(content string) string {
	if !strings.HasPrefix(content, "#!") {
		return "sh"
	}
	line, _, _ := strings.Cut(content[2:], "\n")
	f := strings.Fields(line)
	if len(f) == 0 {
		return "sh"
	}
	prog := cmdBase(f[0])
	if prog == "env" {
		prog = ""
		for _, w := range f[1:] {
			if strings.HasPrefix(w, "-") || strings.Contains(w, "=") {
				continue
			}
			prog = cmdBase(w)
			break
		}
	}
	if shells[prog] {
		return "sh"
	}
	if prog == "" {
		return "?"
	}
	return prog
}
