package engine

import (
	"fmt"
	"strings"
)

// Argument roles: some arguments are data (a grep pattern, a sed script,
// a jq filter), some are write-only destinations, and some git subcommands
// only touch metadata. These refine the conservative "any argument" rule.

// gitMetadata reports git subcommands that never print file content:
// check-ignore, ls-files, rm --cached, update-index --assume-unchanged.
func gitMetadata(args []cmdArg) bool {
	texts := []string{"git"}
	for _, a := range args {
		texts = append(texts, a.textOr())
	}
	sub := gitVariants(texts)[0][1:]
	if len(sub) == 0 {
		return false
	}
	switch sub[0] {
	case "check-ignore", "ls-files":
		return true
	case "rm":
		return containsStr(sub, "--cached")
	case "update-index":
		return containsStr(sub, "--assume-unchanged") || containsStr(sub, "--skip-worktree") ||
			containsStr(sub, "--no-assume-unchanged") || containsStr(sub, "--no-skip-worktree")
	}
	return false
}

var (
	patternFirst = set("grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "mawk", "nawk", "jq", "yq")
	// options whose separate value is data (pattern/script)
	dataValueOpts = set("-e", "--regexp", "--expression")
	// options whose separate value is a file holding the pattern/script
	fileValueOpts = set("-f", "--file", "--from-file")
	// options taking a separate (non-path) value; skipped when looking for
	// the positional pattern
	valueOpts = set("-A", "-B", "-C", "-m", "-d", "-D", "-t", "-T", "-j", "-M", "-F", "-v", "--type",
		"--type-not", "--max-count", "--context", "--after-context", "--before-context", "--max-depth",
		"--color", "--colors", "--sort", "--threads", "--indent", "-l", "--line-length")
	// jq options taking two values (name and value/file)
	jqPairOpts = set("--arg", "--argjson", "--slurpfile", "--rawfile")
)

// dataFiltered drops the pattern/script/filter argument of grep-like tools,
// sed, awk and jq: it is data, not a path ("grep -n '.env' src/x.ts").
// Files given with -f are kept.
func dataFiltered(name string, args []cmdArg) []cmdArg {
	if !patternFirst[name] {
		return args
	}
	explicit := false
	for _, a := range args {
		if t, ok := a.text(); ok && (dataValueOpts[t] || fileValueOpts[t] || strings.HasPrefix(t, "--regexp=") || strings.HasPrefix(t, "--expression=")) {
			explicit = true
		}
	}
	out := make([]cmdArg, 0, len(args))
	patternSeen := explicit
	for i := 0; i < len(args); i++ {
		a := args[i]
		t, ok := a.text()
		switch {
		case ok && dataValueOpts[t]:
			out = append(out, a)
			i++ // the value is a pattern/script: data
		case ok && jqPairOpts[t] && (name == "jq" || name == "yq"):
			out = append(out, a)
			if t == "--slurpfile" || t == "--rawfile" {
				if i+2 < len(args) {
					out = append(out, args[i+2]) // the file
				}
			}
			i += 2
		case ok && (fileValueOpts[t] || valueOpts[t]):
			out = append(out, a)
			if i+1 < len(args) {
				out = append(out, args[i+1])
				i++
			}
		case ok && strings.HasPrefix(t, "-") && t != "-":
			out = append(out, a)
		case !patternSeen:
			patternSeen = true // the pattern / script / filter
		default:
			out = append(out, a)
		}
	}
	return out
}

var copyCmds = set("cp", "mv", "install")

// checkCopyDest handles the destination of cp/mv/install. Copying a
// non-secret file ONTO a secret path (cp .env.example .env) reads nothing
// secret: it is asked, not denied. Returns the remaining arguments.
func (s *shellEval) checkCopyDest(name string, args []cmdArg) []cmdArg {
	destIdx := -1
	var positional []int
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		switch {
		case ok && (t == "-t" || t == "--target-directory") && i+1 < len(args):
			destIdx = i + 1
			i++
		case ok && strings.HasPrefix(t, "--target-directory="):
			return args // rare; keep the conservative rule
		case ok && strings.HasPrefix(t, "-") && t != "-":
		default:
			positional = append(positional, i)
		}
	}
	if destIdx < 0 {
		if len(positional) < 2 {
			return args
		}
		destIdx = positional[len(positional)-1]
	}
	dest := args[destIdx]
	if t, ok := dest.text(); ok {
		lit := escapeLit(t)
		if m, ok := s.sec.checkPath(lit); ok && !m.glob {
			s.c.ask(RuleSecretFile+":"+m.pattern, fmt.Sprintf("`%s` would overwrite the secret file %q (secrets.files: %q in .agentleash.yaml); the user must confirm. Nothing secret is read.", name, display(t), m.pattern))
			return append(append([]cmdArg(nil), args[:destIdx]...), args[destIdx+1:]...)
		}
		if m, ok := s.sec.dirHoldsSecret(lit); ok {
			s.c.ask(RuleSecretFile+":"+m.pattern, fmt.Sprintf("`%s` would write into %q, a directory holding secret files (secrets.files: %q); the user must confirm.", name, display(t), m.pattern))
			return append(append([]cmdArg(nil), args[:destIdx]...), args[destIdx+1:]...)
		}
	}
	return args
}
