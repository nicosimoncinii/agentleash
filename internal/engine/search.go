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
	unrestricted, hidden, noIgnore := 0, false, false
	explicitPattern := false
	var operands []cmdArg
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		if !ok {
			if strings.HasPrefix(args[i].textOr(), "-") {
				return // a runtime option could be anything; other rules apply
			}
			operands = append(operands, args[i])
			continue
		}
		key := t
		if eq := strings.IndexByte(t, '='); eq > 0 && strings.HasPrefix(t, "--") {
			key = t[:eq]
		}
		switch {
		case t == "--":
			operands = append(operands, args[i+1:]...)
			i = len(args)
		case rgRestricting[key] || strings.HasPrefix(t, "--glob=") || strings.HasPrefix(t, "--iglob=") || strings.HasPrefix(t, "--type="):
			return
		case key == "--unrestricted":
			unrestricted++
		case key == "--hidden":
			hidden = true
		case key == "--no-ignore" || key == "--no-ignore-vcs" || key == "--no-ignore-dot" || key == "--no-ignore-files":
			noIgnore = true
		case key == "-e" || key == "--regexp" || key == "-f" || key == "--file":
			explicitPattern = true
			if key == t {
				i++
			}
		case rgValueOpts[key]:
			if key == t {
				i++
			}
		case strings.HasPrefix(t, "--"):
		case strings.HasPrefix(t, "-") && len(t) > 1:
			// A short cluster: count u, note '.', stop at a letter taking a value.
			for j := 1; j < len(t); j++ {
				c := t[j]
				if c == 'u' {
					unrestricted++
					continue
				}
				if c == '.' {
					hidden = true
					continue
				}
				if strings.IndexByte("gt", c) >= 0 {
					return // -g GLOB / -t TYPE restrict the search
				}
				if strings.IndexByte("lcq", c) >= 0 {
					return // names, counts or nothing: no content printed
				}
				if rgValueOpts["-"+string(c)] {
					if c == 'e' || c == 'f' {
						explicitPattern = true
					}
					if j == len(t)-1 {
						i++
					}
					break
				}
			}
		default:
			operands = append(operands, args[i])
		}
	}
	noIgnore = noIgnore || unrestricted >= 1
	hidden = hidden || unrestricted >= 2
	if !noIgnore || !hidden {
		return
	}
	if !explicitPattern && len(operands) > 0 {
		operands = operands[1:] // the pattern
	}
	if len(operands) == 0 {
		operands = []cmdArg{litArg(".")}
	}
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
