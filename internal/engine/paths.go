package engine

import (
	"regexp"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// Secret pattern semantics (see also docs/design.md §7.1):
//
//   - Patterns are gitignore-style globs: '*' and '?' never cross '/', "**"
//     spans any number of directories, [...] is a character class.
//   - A pattern without a '/' (".env", "*.pem", "id_rsa*") matches the
//     basename at ANY depth, anywhere on the filesystem — not only under the
//     project root. This is stricter than gitignore on purpose: a copy of .env
//     in /tmp is still a secret.
//   - A leading "**/" also matches anywhere.
//   - A pattern containing a '/' elsewhere ("config/secrets.yml") is anchored
//     at Request.ProjectRoot (falling back to Cwd).
//   - "~/..." is anchored at Request.Home; absolute paths and drive letters
//     are used as-is.
//   - A trailing '/' is ignored. Every pattern also matches everything below
//     it: "~/.aws" protects "~/.aws/credentials".
//   - Matching is case-insensitive on every platform.
//   - allow_files use the same syntax. A concrete path matching an allow
//     pattern is never secret. Globs and dynamic arguments are not exempted
//     by allow_files (we cannot prove the glob only hits allowed files).

// compiledPattern is one policy glob resolved against a request.
type compiledPattern struct {
	orig string
	path gpath // matches the path itself
	tree gpath // matches the path and everything below it
}

// anywhere reports whether the pattern is unanchored ("**/..." or basename).
func (c compiledPattern) anywhere() bool {
	return len(c.path.segs) > 0 && c.path.segs[0].globstar
}

type secretSet struct {
	files   []compiledPattern
	allow   []compiledPattern
	env     []string // lower-cased env name globs
	envOrig []string // as written in the policy (for rules)
	// builtin are engine-provided secret paths (env exposure via procfs).
	builtin []compiledPattern
	home    string
	root    string
	windows bool // request paths look like Windows: enable ADS / 8.3 spellings
	work    *budget
	aliases []pathAlias
	bases   []string
	// basesUnknown means the working directory may be anything (e.g. after
	// "cd $X"); relative paths are then matched anywhere.
	basesUnknown bool
	dotglob      bool
	resolve      func(string) (string, error)
}

func newSecretSet(p *policy.Policy, req Request, resolve func(string) (string, error)) *secretSet {
	s := &secretSet{home: normalizeAbs(canonicalDir(req.Home, resolve)), resolve: resolve, work: newBudget()}
	root := normalizeAbs(canonicalDir(req.ProjectRoot, resolve))
	cwd := normalizeAbs(canonicalDir(req.Cwd, resolve))
	if cwd != "" {
		s.bases = append(s.bases, cwd)
	}
	if root != "" && root != cwd {
		s.bases = append(s.bases, root)
	}
	s.root = root
	for _, p := range []string{root, cwd, s.home} {
		if driveRe.MatchString(p) {
			s.windows = true
		}
	}
	anchor := root
	if anchor == "" {
		anchor = cwd
	}
	for _, f := range p.Secrets.Files {
		if c, ok := compilePattern(f, anchor, s.home); ok {
			s.files = append(s.files, c)
		}
	}
	for _, f := range p.Secrets.AllowFiles {
		if c, ok := compilePattern(f, anchor, s.home); ok {
			s.allow = append(s.allow, c)
		}
	}
	for _, e := range p.Secrets.Env {
		e = strings.TrimSpace(e)
		if e != "" {
			s.env = append(s.env, strings.ToLower(e))
			s.envOrig = append(s.envOrig, e)
		}
	}
	for _, b := range []string{"/proc/*/environ", "/proc/*/task/*/environ"} {
		c, _ := compilePattern(b, "", "")
		c.orig = "/proc/*/environ"
		s.builtin = append(s.builtin, c)
	}
	return s
}

// compilePattern turns a policy glob into absolute internal syntax.
func compilePattern(raw, anchor, home string) (compiledPattern, bool) {
	p := strings.TrimSpace(raw)
	p = strings.TrimPrefix(p, "!") // no negation: use allow_files
	if p == "" {
		return compiledPattern{}, false
	}
	p = policyToInternal(p)
	p = strings.ToLower(p)
	dirOnly := strings.HasSuffix(p, "/")
	for strings.HasSuffix(p, "/") && len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	var abs string
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			abs = "**" + strings.TrimPrefix(p, "~")
		} else {
			abs = home + strings.TrimPrefix(p, "~")
		}
	case isAbsInternal(p):
		abs = p
	case strings.HasPrefix(p, "**/") || p == "**":
		abs = p
	case !strings.Contains(p, "/"):
		abs = "**/" + p
	default:
		p = strings.TrimPrefix(p, "./")
		if anchor == "" {
			abs = "**/" + p
		} else {
			abs = anchor + "/" + p
		}
	}
	clean := cleanInternal(mapDrivePrefixes(abs))
	cp := compiledPattern{orig: strings.TrimSpace(raw), path: parsePath(clean)}
	// "Covers everything below it" applies to directories: anchored paths
	// (~/.ssh, config/secrets) and patterns ending in "/". A basename glob
	// such as "*.pem" or ".env" only constrains the last path segment, so
	// "cat */package.json" is not a match through a directory "x.pem/".
	cp.tree = cp.path
	if dirOnly || !cp.anywhere() {
		cp.tree = parsePath(clean + "/**")
	}
	return cp, true
}

// policyToInternal converts a policy glob: a backslash escapes a glob
// metacharacter, any other backslash is a Windows path separator.
func policyToInternal(p string) string {
	if winPatternRe.MatchString(p) {
		// Clearly a Windows path (C:\..., or \name segments): every
		// backslash is a separator.
		return strings.ReplaceAll(p, `\`, "/")
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' {
			if i+1 < len(p) && strings.IndexByte("*?[]\\ !#", p[i+1]) >= 0 {
				if p[i+1] == ' ' || p[i+1] == '!' || p[i+1] == '#' {
					b.WriteByte(p[i+1])
				} else {
					b.WriteByte('\\')
					b.WriteByte(p[i+1])
				}
				i++
				continue
			}
			b.WriteByte('/')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// literalToInternal converts a literal OS path (from an agent file tool) to
// internal syntax: wildcards are escaped and backslashes become '/'.
func literalToInternal(p string) string {
	return escapeGlob(strings.ReplaceAll(p, `\`, "/"))
}

// globToInternal converts an agent-supplied glob (Glob/Grep tools).
func globToInternal(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

func normalizeAbs(p string) string {
	if p == "" {
		return ""
	}
	return cleanInternal(mapDrivePrefixes(strings.ToLower(literalToInternal(p))))
}

var (
	driveRe      = regexp.MustCompile(`^[a-z]:(/|$)`)
	winPatternRe = regexp.MustCompile(`^[A-Za-z]:\\|\\[A-Za-z0-9_.~-]`)
)

func isAbsInternal(p string) bool {
	return strings.HasPrefix(p, "/") || driveRe.MatchString(p)
}

var (
	msysDrive   = regexp.MustCompile(`^/([a-z])(/|$)`)
	mntDrive    = regexp.MustCompile(`^/(?:mnt|cygdrive)/([a-z])(/|$)`)
	procCwd     = regexp.MustCompile(`^/proc/[^/]+/(?:task/[^/]+/)?cwd(/|$)`)
	procRoot    = regexp.MustCompile(`^/proc/[^/]+/(?:task/[^/]+/)?root(/|$)`)
	uncPrefix   = regexp.MustCompile(`^//[?.]/(unc/)?`)
	shortName83 = regexp.MustCompile(`^([^~/.]{1,6})~[0-9]+(\.[^/.]{1,3})?$`)
)

// mapDrivePrefixes canonicalises the many spellings of a Windows drive and
// some procfs aliases. Input must already be lower-case.
func mapDrivePrefixes(p string) string {
	p = uncPrefix.ReplaceAllString(p, "/")
	if m := mntDrive.FindStringSubmatchIndex(p); m != nil {
		p = p[m[2]:m[3]] + ":/" + strings.TrimPrefix(p[m[1]:], "/")
	} else if m := msysDrive.FindStringSubmatchIndex(p); m != nil {
		p = p[m[2]:m[3]] + ":/" + strings.TrimPrefix(p[m[1]:], "/")
	}
	if m := procCwd.FindStringIndex(p); m != nil {
		p = "**/" + p[m[1]:]
	} else if m := procRoot.FindStringIndex(p); m != nil {
		p = "/" + p[m[1]:]
	}
	return p
}

// cleanInternal is path.Clean for internal syntax: it handles a drive or
// root first segment, "**" and dynamic segments, and strips the Windows
// trailing dots/spaces that the OS ignores (".env." opens ".env").
func cleanInternal(p string) string {
	if p == "" {
		return ""
	}
	parts := splitSegments(p)
	var out []string
	rooted := false
	start := 0
	switch {
	case parts[0] == "":
		rooted = true
		out = append(out, "")
		start = 1
	case driveRe.MatchString(parts[0] + "/"):
		rooted = true
		out = append(out, parts[0])
		start = 1
	}
	for _, seg := range parts[start:] {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 && out[len(out)-1] == "**" {
				continue
			}
			if len(out) > 1 || (len(out) == 1 && !rooted) {
				out = out[:len(out)-1]
				continue
			}
			if !rooted {
				out = append(out, "..")
			}
			continue
		}
		if seg != "**" {
			seg = trimWinTrailing(seg)
			if seg == "" {
				continue
			}
		}
		out = append(out, seg)
	}
	if rooted && len(out) == 1 {
		return out[0] + "/"
	}
	return strings.Join(out, "/")
}

func trimWinTrailing(seg string) string {
	for len(seg) > 0 {
		c := seg[len(seg)-1]
		if c != '.' && c != ' ' {
			break
		}
		if len(seg) >= 2 && seg[len(seg)-2] == '\\' {
			break
		}
		seg = seg[:len(seg)-1]
	}
	return seg
}

// candidates expands one argument string (internal syntax, lower-cased) into
// absolute internal paths to test. Relative paths are joined with every
// possible working directory.
func (s *secretSet) candidates(arg string) []string {
	out := s.candidatesRaw(arg)
	if len(s.aliases) == 0 {
		return out
	}
	for _, c := range out {
		out = append(out, s.throughAliases(c)...)
		if len(out) > maxAlts {
			break
		}
	}
	return out
}

// unknownBase prefixes a relative path whose working directory is only
// known at runtime (after `cd "$(...)"`). The first segment never matches
// an anchored pattern, so only "anywhere" patterns (.env, *.pem) apply: we
// assume a runtime cd does not enter a secret directory (documented gap).
var unknownBase = string(rune(2)) + "/**/"

func (s *secretSet) candidatesRaw(arg string) []string {
	p := strings.ToLower(arg)
	if p == "" {
		return nil
	}
	if i := strings.LastIndexByte(p, dynAny); i >= 0 {
		// Anything up to the dynamic part may be any directory.
		rest := p[i+1:]
		return s.variants("**/" + string(dynStar) + rest)
	}
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if s.home == "" {
			return s.variants("**" + p[1:])
		}
		return s.variants(s.home + p[1:])
	case strings.HasPrefix(p, "~"):
		// ~user/...: another user's home, a sibling of ours.
		rest := p[1:]
		if s.home == "" {
			return s.variants("**/" + rest)
		}
		return s.variants(s.home + "/../" + rest)
	}
	p = mapDrivePrefixes(p)
	if isAbsInternal(p) || strings.HasPrefix(p, "**") {
		return s.variants(p)
	}
	if len(s.bases) == 0 {
		return s.variants("**/" + p)
	}
	if s.basesUnknown {
		return s.variants(unknownBase + p)
	}
	var out []string
	for _, b := range s.bases {
		out = append(out, s.variants(b+"/"+p)...)
	}
	return out
}

// pathAlias is a link created in the same script (ln -s, mount --bind):
// paths under link also name the corresponding path under target.
type pathAlias struct {
	link   string // absolute internal path
	target string // absolute internal path, or dynAny for a runtime target
}

// addAlias registers link -> target (internal syntax, as written).
func (s *secretSet) addAlias(target, link string) {
	if isDynamic(link) || hasGlobMeta(link) || len(s.aliases) >= maxBases {
		return
	}
	var targets []string
	if isDynamic(target) || hasGlobMeta(target) {
		targets = []string{string(dynAny)}
	} else {
		targets = s.candidates(target)
	}
	for _, l := range s.candidates(link) {
		for _, t := range targets {
			if l != t {
				s.aliases = append(s.aliases, pathAlias{link: l, target: t})
			}
		}
	}
}

// throughAliases returns the extra spellings of p reachable through links.
func (s *secretSet) throughAliases(p string) []string {
	var out []string
	for _, a := range s.aliases {
		if p != a.link && !strings.HasPrefix(p, a.link+"/") {
			continue
		}
		rest := p[len(a.link):]
		if a.target == string(dynAny) {
			out = append(out, "**/"+string(dynStar)+rest)
			continue
		}
		out = append(out, cleanInternal(a.target+rest))
	}
	return out
}

// addBase records a directory a cd/Set-Location may switch to (internal
// syntax). Runtime or unusual targets make relative paths match anywhere.
func (s *secretSet) addBase(alt string) {
	if s.basesUnknown {
		return
	}
	if isDynamic(alt) || hasGlobMeta(alt) || alt == "-" {
		s.basesUnknown = true
		return
	}
	p := strings.ToLower(alt)
	var next []string
	switch {
	case p == "" || p == "~" || strings.HasPrefix(p, "~/"):
		if s.home == "" {
			s.basesUnknown = true
			return
		}
		next = []string{cleanInternal(s.home + p[min(1, len(p)):])}
	case strings.HasPrefix(p, "~"):
		s.basesUnknown = true
		return
	default:
		p = mapDrivePrefixes(p)
		if isAbsInternal(p) {
			next = []string{cleanInternal(p)}
		} else {
			for _, b := range s.bases {
				next = append(next, cleanInternal(b+"/"+p))
			}
		}
	}
	for _, n := range next {
		if !containsStr(s.bases, n) {
			s.bases = append(s.bases, n)
		}
	}
	if len(s.bases) > maxBases {
		s.basesUnknown = true
	}
}

// variants cleans p and adds Windows alternate spellings: an alternate data
// stream suffix ("file:stream") and 8.3 short names ("SECRET~1").
func (s *secretSet) variants(p string) []string {
	c := cleanInternal(p)
	out := []string{c}
	if !s.windows && !driveRe.MatchString(c) {
		return out
	}
	segs := splitSegments(c)
	plainSegs := append([]string(nil), segs...) // ADS stripped
	dotSegs := append([]string(nil), segs...)   // 8.3 expanded, leading dot
	noDotSegs := append([]string(nil), segs...) // 8.3 expanded, no dot
	changed, short := false, false
	for i, seg := range segs {
		if i == 0 && driveRe.MatchString(seg+"/") {
			continue
		}
		if j := strings.IndexByte(seg, ':'); j > 0 {
			seg = seg[:j]
			plainSegs[i], dotSegs[i], noDotSegs[i] = seg, seg, seg
			changed = true
		}
		if m := shortName83.FindStringSubmatch(seg); m != nil {
			// SECRET~1.YML is the short name of a long name whose
			// characters (dots and spaces removed) start with "secret"
			// and whose extension starts with "yml".
			g := m[1] + string(dynStar)
			if m[2] != "" {
				g += m[2] + string(dynStar)
			}
			dotSegs[i], noDotSegs[i] = "."+g, g
			short = true
		}
	}
	if changed {
		out = append(out, cleanInternal(strings.Join(plainSegs, "/")))
	}
	if short {
		out = append(out, cleanInternal(strings.Join(dotSegs, "/")), cleanInternal(strings.Join(noDotSegs, "/")))
	}
	return out
}

// match describes why a path was considered secret.
type match struct {
	pattern string // policy pattern (or builtin) that matched
	path    string // display form of the offending argument
	glob    bool   // the argument was a glob / dynamic word
	builtin bool   // engine builtin (procfs environ)
}

// checkPath tests one argument (internal syntax). It returns the first
// matching secret pattern.
func (s *secretSet) checkPath(arg string) (match, bool) {
	if !s.work.spend(4*len(s.files) + 1) {
		return match{}, false
	}
	cands := s.candidates(arg)
	// When the injected resolver knows the real (canonical) path of a
	// concrete argument, alternate spellings such as Windows 8.3 short
	// names are moot: only the literal spellings and the canonical path
	// are checked, so allow_files keep working under C:\Users\RUNNER~1\.
	canonical := false
	if s.resolve != nil && !hasGlobMeta(arg) {
		for _, c := range cands {
			if hasGlobMeta(c) {
				continue
			}
			if r, ok := resolveLongest(s.resolve, unescapeGlob(c)); ok {
				canonical = true
				if m, ok := s.checkAbs(normalizeAbs(r)); ok {
					m.path = unescapeGlob(arg)
					return m, true
				}
			}
		}
	}
	for _, c := range cands {
		if canonical && hasGlobMeta(c) {
			continue
		}
		if m, ok := s.checkAbs(c); ok {
			m.path = unescapeGlob(arg)
			return m, true
		}
	}
	return match{}, false
}

// canonicalDir resolves a request directory through the injected resolver
// (symlinks, Windows 8.3 short names), keeping the input when it fails.
func canonicalDir(p string, resolve func(string) (string, error)) string {
	if r, ok := resolveLongest(resolve, p); ok {
		return r
	}
	return p
}

// resolveLongest canonicalises the longest existing prefix of p and
// re-appends the remainder, so a path that does not exist yet (or whose
// leaf the resolver cannot see) lands in the same canonical space as its
// parents: with /var -> /private/var, "/var/x/home/.ssh" becomes
// "/private/var/x/home/.ssh" even when .ssh does not exist. A secret path
// must never escape matching because of a symlinked parent.
func resolveLongest(resolve func(string) (string, error), p string) (string, bool) {
	if resolve == nil || p == "" {
		return "", false
	}
	rest := ""
	cur := p
	for i := 0; i < 64; i++ {
		if r, err := resolve(cur); err == nil && r != "" {
			if rest == "" {
				return r, true
			}
			sep := "/"
			if strings.Contains(r, `\`) && !strings.Contains(r, "/") {
				sep = `\`
			}
			return strings.TrimRight(r, `/\`) + sep + rest, true
		}
		j := strings.LastIndexAny(strings.TrimRight(cur, `/\`), `/\`)
		if j <= 0 {
			return "", false
		}
		leaf := strings.TrimRight(cur, `/\`)[j+1:]
		if rest == "" {
			rest = leaf
		} else {
			rest = leaf + "/" + rest
		}
		cur = cur[:j]
		if strings.HasSuffix(cur, ":") { // C: -> C:\ (a drive root)
			cur += `\`
		}
	}
	return "", false
}

func (s *secretSet) checkAbs(c string) (match, bool) {
	gp := parsePath(c)
	literal := gp.isLiteral()
	// prefix is the argument up to its first "**" (unknown directories).
	globstar := false
	var prefix gpath
	for i, sg := range gp.segs {
		if sg.globstar {
			globstar = true
			prefix = gpath{segs: gp.segs[:i]}
			break
		}
	}
	for _, b := range s.builtin {
		if pathsIntersect(gp, b.path, true) {
			return match{pattern: b.orig, glob: !literal, builtin: true}, true
		}
	}
	for _, f := range s.files {
		// A "**" in the argument (unknown directories) must not be read as
		// "somewhere inside a directory named like the secret": find . -name
		// '*.go' would otherwise collide with every secret. The argument
		// matches if it can BE a secret path, or if the part before its
		// "**" is already inside a secret directory (find ~/.ssh -name x).
		var hit bool
		if globstar {
			hit = pathsIntersect(gp, f.path, s.dotglob) ||
				(len(prefix.segs) > 0 && pathsIntersect(prefix, f.tree, s.dotglob))
		} else {
			hit = pathsIntersect(gp, f.tree, s.dotglob)
		}
		if !hit {
			continue
		}
		if literal && s.allowed(gp) {
			continue
		}
		return match{pattern: f.orig, glob: !literal}, true
	}
	return match{}, false
}

func (s *secretSet) allowed(gp gpath) bool {
	for _, a := range s.allow {
		if pathsIntersect(gp, a.tree, true) {
			return true
		}
	}
	return false
}

// dirHoldsSecret reports whether a concrete argument is a directory that
// contains a location named by an anchored secret pattern ("~/.ssh" for
// "~/.ssh/id_*", "config" for "config/secrets.yml"). Directories that
// contain the project root or the home directory are excluded: those hold
// secrets for every policy and are handled by the recursive copy/search
// rules instead.
func (s *secretSet) dirHoldsSecret(arg string) (match, bool) {
	if hasGlobMeta(arg) {
		return match{}, false
	}
	for _, c := range s.candidates(arg) {
		if hasGlobMeta(c) {
			continue
		}
		self := parsePath(strings.TrimSuffix(c, "/") + "/**")
		if (s.root != "" && pathsIntersect(self, parsePath(s.root), true)) ||
			(s.home != "" && pathsIntersect(self, parsePath(s.home), true)) {
			continue
		}
		dir := strings.TrimSuffix(c, "/")
		for _, f := range s.files {
			if f.anywhere() {
				continue
			}
			// Only real ancestors of the pattern's fixed directory count:
			// "~/.ssh" for "~/.ssh/id_*", never "~/.ssh/id_ed25519.pub".
			p := f.fixedDir()
			if p == dir || strings.HasPrefix(p, dir+"/") || (dir == "" && strings.HasPrefix(p, "/")) {
				return match{pattern: f.orig, path: unescapeGlob(arg)}, true
			}
		}
	}
	return match{}, false
}

// fixedDir is the longest wildcard-free directory prefix of the pattern:
// "/home/u/.ssh" for "~/.ssh/id_*" and "~/.ssh/**", "/p/config" for
// "config/secrets.yml".
func (c compiledPattern) fixedDir() string {
	segs := splitSegments(c.path.raw)
	n := len(segs)
	for i, sg := range segs {
		if sg == "**" || hasGlobMeta(sg) {
			n = i
			break
		}
	}
	if n == len(segs) {
		n-- // fully literal: the last segment is the secret itself
	}
	if n <= 0 {
		return ""
	}
	return strings.Join(segs[:n], "/")
}

// containsSecretRoot reports whether a directory argument contains the
// project root, the home directory, or a location named by an anchored
// secret pattern (used for recursive copy / archive commands). Basename
// patterns such as ".env" could live in any directory, so they are only
// considered through the project root and home.
func (s *secretSet) containsSecretRoot(arg string) (match, bool) {
	if len(s.files) == 0 {
		return match{}, false
	}
	for _, c := range s.candidates(arg) {
		sub := parsePath(strings.TrimSuffix(c, "/") + "/**")
		for _, r := range []string{s.root, s.home} {
			if r != "" && pathsIntersect(sub, parsePath(r), true) {
				return match{pattern: s.files[0].orig, path: unescapeGlob(arg)}, true
			}
		}
		for _, f := range s.files {
			if f.anywhere() {
				continue
			}
			if pathsIntersect(sub, f.path, true) {
				return match{pattern: f.orig, path: unescapeGlob(arg)}, true
			}
		}
	}
	return match{}, false
}

// envMatch returns the env glob matching name, if any.
func (s *secretSet) envMatch(name string) (string, bool) {
	n := strings.ToLower(name)
	for i, g := range s.env {
		if globMatchString(g, n) {
			return s.envOrig[i], true
		}
	}
	return "", false
}

// allowHint suggests safe alternatives for a blocked secret pattern.
func (s *secretSet) allowHint() string {
	if len(s.allow) == 0 {
		return "If you need to know which settings exist, ask the user."
	}
	var names []string
	for _, a := range s.allow {
		names = append(names, a.orig)
	}
	return "Use " + strings.Join(names, ", ") + " to learn the variable names, or ask the user."
}
