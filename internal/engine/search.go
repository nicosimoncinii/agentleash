package engine

import (
	"fmt"
	"strings"
)

// rgValueOpts are ripgrep options that take a separate value.
var rgValueOpts = set("-e", "--regexp", "-f", "--file", "-A", "--after-context", "-B", "--before-context",
	"-C", "--context", "-m", "--max-count", "-M", "--max-columns", "-j", "--threads", "-d", "--max-depth",
	"-E", "--encoding", "-r", "--replace", "-T", "--type-not", "--type-add", "--type-clear", "--pre",
	"--pre-glob", "--ignore-file", "--max-filesize", "--sort", "--sortr", "--color", "--colors",
	"--path-separator", "--context-separator", "--field-context-separator", "--field-match-separator",
	"--engine", "--dfa-size-limit", "--regex-size-limit", "--hostname-bin", "--hyperlink-format")

// rgRestricting options limit the search to chosen files or print no
// content: an unrestricted search with them is fine.
var rgRestricting = set("-g", "--glob", "--iglob", "-t", "--type", "--files", "-l", "--files-with-matches",
	"--files-without-match", "-c", "--count", "--count-matches", "-q", "--quiet", "--type-list")

// checkUnrestrictedSearch asks before `rg -uu` (or --hidden with
// --no-ignore) over a directory containing the project root or home: with
// every ignore rule off, ripgrep also searches .env and other secret files
// that are normally gitignored, and prints their matching lines. A plain
// `rg foo` respects .gitignore and hidden-file rules and stays allowed.
func (s *shellEval) checkUnrestrictedSearch(args []cmdArg) {
	var sc exrRgScan
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		if !ok {
			if strings.HasPrefix(args[i].textOr(), "-") {
				return // a runtime option could be anything; other rules apply
			}
			sc.operands = append(sc.operands, args[i])
			continue
		}
		next, stop := sc.exrArg(args, i, t)
		if stop {
			return
		}
		i = next
	}
	noIgnore := sc.noIgnore || sc.unrestricted >= 1
	hidden := sc.hidden || sc.unrestricted >= 2
	if !noIgnore || !hidden {
		return
	}
	operands := sc.operands
	if !sc.explicitPattern && len(operands) > 0 {
		operands = operands[1:] // the pattern
	}
	if len(operands) == 0 {
		operands = []cmdArg{litArg(".")}
	}
	s.exrAskUnrestricted(operands)
}

// exrRgScan is the parsed command line of a ripgrep invocation.
type exrRgScan struct {
	unrestricted    int
	hidden          bool
	noIgnore        bool
	explicitPattern bool
	operands        []cmdArg
}

// exrArg interprets the static argument t at index i. It returns the index
// of the last argument consumed, and stop when the search is restricted to
// chosen files or prints no content.
func (sc *exrRgScan) exrArg(args []cmdArg, i int, t string) (next int, stop bool) {
	key := t
	if eq := strings.IndexByte(t, '='); eq > 0 && strings.HasPrefix(t, "--") {
		key = t[:eq]
	}
	switch {
	case t == "--":
		sc.operands = append(sc.operands, args[i+1:]...)
		i = len(args)
	case rgRestricting[key] || strings.HasPrefix(t, "--glob=") || strings.HasPrefix(t, "--iglob=") || strings.HasPrefix(t, "--type="):
		return i, true
	case key == "--unrestricted":
		sc.unrestricted++
	case key == "--hidden":
		sc.hidden = true
	case key == "--no-ignore" || key == "--no-ignore-vcs" || key == "--no-ignore-dot" || key == "--no-ignore-files":
		sc.noIgnore = true
	case key == "-e" || key == "--regexp" || key == "-f" || key == "--file":
		sc.explicitPattern = true
		if key == t {
			i++
		}
	case rgValueOpts[key]:
		if key == t {
			i++
		}
	case strings.HasPrefix(t, "--"):
	case strings.HasPrefix(t, "-") && len(t) > 1:
		skipNext, restricted := sc.exrShortCluster(t)
		if restricted {
			return i, true
		}
		if skipNext {
			i++
		}
	default:
		sc.operands = append(sc.operands, args[i])
	}
	return i, false
}

// exrShortCluster interprets a short option cluster: it counts u, notes
// '.', and stops at a letter taking a value. skipNext is true when that
// value is the next argument; restricted is true for -g/-t (restricting the
// search) and -l/-c/-q (no content printed).
func (sc *exrRgScan) exrShortCluster(t string) (skipNext, restricted bool) {
	for j := 1; j < len(t); j++ {
		c := t[j]
		switch {
		case c == 'u':
			sc.unrestricted++
		case c == '.':
			sc.hidden = true
		case strings.IndexByte("gt", c) >= 0:
			return false, true // -g GLOB / -t TYPE restrict the search
		case strings.IndexByte("lcq", c) >= 0:
			return false, true // names, counts or nothing: no content printed
		case rgValueOpts["-"+string(c)]:
			if c == 'e' || c == 'f' {
				sc.explicitPattern = true
			}
			return j == len(t)-1, false
		}
	}
	return false, false
}

// exrAskUnrestricted asks when a search directory contains the project
// root, home or another secret location.
func (s *shellEval) exrAskUnrestricted(operands []cmdArg) {
	for _, d := range operands {
		for _, alt := range d.alts {
			if isDynamic(alt) {
				continue
			}
			if m, ok := s.sec.containsSecretRoot(alt); ok {
				s.c.ask(RuleSecretDir, fmt.Sprintf("`rg` with every ignore rule disabled (-uu, or --hidden with --no-ignore) over %q also searches secret files that are normally gitignored (secrets.files: %q) and prints their matching lines. Search without -uu, exclude them (-g '!.env*'), or search only source directories.", display(plain(alt)), m.pattern))
				return
			}
		}
	}
}
