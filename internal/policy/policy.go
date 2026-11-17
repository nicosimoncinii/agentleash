// Package policy loads, defaults and validates the .agentleash.yaml policy file.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the conventional name of the policy file at the project root.
const FileName = ".agentleash.yaml"

// CurrentVersion is the only policy schema version understood by this build.
const CurrentVersion = 1

// Policy is the in-memory representation of .agentleash.yaml.
type Policy struct {
	Version  int      `yaml:"version"`
	Secrets  Secrets  `yaml:"secrets"`
	Commands Commands `yaml:"commands"`
	// Protect lists extra files the agent may read but never modify. The
	// built-in list (BuiltinProtected) is always enforced on top of it.
	Protect Protect `yaml:"protect,omitempty"`
}

// Protect describes files that are readable but not writable by the agent.
type Protect struct {
	// Files use the same glob syntax as Secrets.Files.
	Files []string `yaml:"files,omitempty"`
}

// BuiltinProtected are agentleash's own configuration files and the agent
// settings that load its hooks. They are always write-protected, whatever the
// policy says, so an agent cannot switch agentleash off by editing them.
var BuiltinProtected = []string{
	"./" + FileName,
	"./.claude/settings.json",
	"./.claude/settings.local.json",
	"./.claude/agentleash-state.json",
	"./.codex/hooks.json",
	"./.codex/config.toml",
	"~/.claude/settings.json",
	"~/.claude/settings.local.json",
	"~/.codex/config.toml",
	"~/.codex/hooks.json",
}

// ProtectedFiles returns the built-in protected files followed by the
// policy's own protect.files entries.
func (p *Policy) ProtectedFiles() []string {
	out := append([]string(nil), BuiltinProtected...)
	if p != nil {
		out = append(out, p.Protect.Files...)
	}
	return out
}

// Secrets describes what must never reach the agent.
type Secrets struct {
	// Files are path globs (path.Match syntax per "/"-separated segment, plus
	// "**" as a whole segment for zero or more directories). They are NOT
	// gitignore patterns: relative globs are anchored at the project root and
	// do not float to any depth, a leading "/" is an absolute filesystem path,
	// "~/..." is the user's home directory, and "!" negation is rejected (use
	// AllowFiles). See docs/design.md §5.
	Files []string `yaml:"files"`
	// AllowFiles are explicit exceptions to Files (e.g. ".env.example"), same syntax.
	AllowFiles []string `yaml:"allow_files"`
	// Env are glob patterns over environment variable names (e.g. "*_TOKEN").
	Env []string `yaml:"env"`
}

// Commands lists shell command patterns. These are NOT path.Match globs:
// "*" matches any run of characters (including "/" and spaces), `\*` is a
// literal star, and everything else is literal. Patterns are matched against
// each normalised simple command, or stage by stage against a pipeline when
// they contain " | ". See docs/design.md §5 for the full contract.
type Commands struct {
	Deny []string `yaml:"deny"`
	Ask  []string `yaml:"ask"`
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Parse decodes and validates policy YAML. Decoding is strict: unknown fields,
// an empty document and multiple documents are errors. The returned policy is
// nil whenever err is non-nil.
func Parse(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var p Policy
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("parse policy: file is empty (expected at least \"version: 1\")")
		}
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse policy: expected a single YAML document")
	}
	// yaml.v3 silently drops null sequence items ("-", "- ~", "- null") when
	// decoding into []string, so find them on the node tree instead.
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := errors.Join(nullItems(&doc, "")...); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return &p, nil
}

// nullItems reports every null scalar inside a sequence, naming the field.
func nullItems(n *yaml.Node, field string) []error {
	var errs []error
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			errs = append(errs, nullItems(c, field)...)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			f := n.Content[i].Value
			if field != "" {
				f = field + "." + f
			}
			errs = append(errs, nullItems(n.Content[i+1], f)...)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			if c.Kind == yaml.ScalarNode && c.Tag == "!!null" {
				errs = append(errs, fmt.Errorf("line %d: %s[%d]: empty entry (null list item)", c.Line, field, i))
			}
		}
	}
	return errs
}

// Default returns the policy written by `agentleash init`. It is a superset of
// the example in docs/design.md §5, tuned to keep false positives low for
// everyday development. Each call returns a fresh copy that callers may mutate.
func Default() *Policy {
	return &Policy{
		Version: CurrentVersion,
		Secrets: Secrets{
			Files: []string{
				// dotenv files at the root and in any subdirectory
				".env",
				".env.*",
				"**/.env",
				"**/.env.*",
				// keys and certificates
				"**/*.pem",
				"**/*.key",
				"**/id_rsa*",
				"**/id_ed25519*",
				"**/*.p12",
				"**/*.pfx",
				"**/id_ecdsa*",
				"**/*.ppk",
				// project-level tool credentials and state
				".envrc",
				"**/.envrc",
				"**/.npmrc",
				"**/.pypirc",
				"**/.netrc",
				"**/.git-credentials",
				"**/credentials.json",
				"**/*.tfstate",
				"**/*.tfstate.*",
				"**/secrets.y*ml",
				// user-level credential stores
				"~/.aws/credentials",
				"~/.ssh/**",
				"~/.gnupg/**",
				"~/.docker/config.json",
				"~/.kube/config",
				"~/.config/gh/hosts.yml",
				"~/.config/gcloud/**",
				"~/.azure/**",
				"~/.npmrc",
				"~/.pypirc",
				"~/.netrc",
				"~/.git-credentials",
				"~/.pgpass",
				"~/.terraform.d/credentials.tfrc.json",
			},
			AllowFiles: []string{
				".env.example",
				".env.sample",
				".env.template",
				".env.dist",
				"**/.env.example",
				"**/.env.sample",
				"**/.env.template",
				"**/.env.dist",
				// public keys are not secret
				"**/*.pub",
				"~/.ssh/*.pub",
			},
			Env: []string{
				"*_KEY",
				"*_SECRET*",
				"*_TOKEN",
				"*PASSWORD*",
				"*_PASSWD*",
				"*_API_KEY*",
				"*_PRIVATE_KEY*",
				"*_CONNECTION_STRING*",
				"DATABASE_URL",
				"AWS_ACCESS_KEY_ID",
				"AWS_SECRET_ACCESS_KEY",
				"AWS_SESSION_TOKEN",
				"GITHUB_TOKEN",
			},
		},
		// Command patterns: "*" matches anything (including "/" and spaces) and
		// `\*` is a literal star; see docs/design.md §5.
		Commands: Commands{
			Deny: []string{
				"rm -rf /",
				`rm -rf /\*`,
				"rm -rf ~",
				"rm -rf ~/",
				`rm -rf ~/\*`,
				"rm -rf $HOME",
				"rm -rf --no-preserve-root /",
				"rm -fr /",
				`rm -fr /\*`,
				"rm -fr ~",
				"rm -fr ~/",
				`rm -fr ~/\*`,
				"git push --force*",
				"git push -f*",
				"git push * --force*",
				"git push * -f*",
				"mkfs*",
				// writes to raw disks only; "of=/dev/null" stays allowed
				"dd *of=/dev/sd*",
				"dd *of=/dev/hd*",
				"dd *of=/dev/vd*",
				"dd *of=/dev/xvd*",
				"dd *of=/dev/nvme*",
				"dd *of=/dev/mmcblk*",
				"dd *of=/dev/disk*",
				"dd *of=/dev/rdisk*",
				":(){ :|:& };:",
				"chmod -R 777 /",
			},
			Ask: []string{
				"curl * | sh",
				"curl * | bash",
				"wget * | sh",
				"wget * | bash",
				"git reset --hard*",
				"git clean -fd*",
				"git clean -df*",
				"git clean -xdf*",
				"git clean -xfd*",
				"npm publish*",
			},
		},
	}
}

// globKind selects the extra rules applied to a list of patterns.
type globKind int

const (
	kindFile    globKind = iota // path globs: "/"-separated segments, "**" allowed
	kindEnv                     // environment variable name globs
	kindCommand                 // shell command patterns
)

// Validate reports every configuration error at once (joined with errors.Join).
// Each message names the offending field, e.g. "secrets.files[2]: ...".
func (p *Policy) Validate() error {
	if p == nil {
		return errors.New("nil policy")
	}
	var errs []error
	switch {
	case p.Version == 0:
		errs = append(errs, fmt.Errorf("version: missing (set \"version: %d\")", CurrentVersion))
	case p.Version != CurrentVersion:
		errs = append(errs, fmt.Errorf("version: unsupported version %d (this build understands %d)", p.Version, CurrentVersion))
	}
	errs = append(errs, validateList("secrets.files", p.Secrets.Files, kindFile)...)
	errs = append(errs, validateList("secrets.allow_files", p.Secrets.AllowFiles, kindFile)...)
	errs = append(errs, validateList("secrets.env", p.Secrets.Env, kindEnv)...)
	errs = append(errs, validateList("commands.deny", p.Commands.Deny, kindCommand)...)
	errs = append(errs, validateList("commands.ask", p.Commands.Ask, kindCommand)...)
	errs = append(errs, validateList("protect.files", p.Protect.Files, kindFile)...)
	return errors.Join(errs...)
}

func validateList(field string, entries []string, kind globKind) []error {
	var errs []error
	seen := make(map[string]int, len(entries))
	for i, e := range entries {
		name := fmt.Sprintf("%s[%d]", field, i)
		if err := validateEntry(e, kind); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if j, dup := seen[e]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate of %s[%d] %q", name, field, j, e))
			continue
		}
		seen[e] = i
	}
	return errs
}

func validateEntry(e string, kind globKind) error {
	if strings.TrimSpace(e) == "" {
		return errors.New("empty entry")
	}
	if strings.TrimSpace(e) != e {
		return fmt.Errorf("%q has leading or trailing whitespace", e)
	}
	switch kind {
	case kindCommand:
		// Command patterns are not path.Match globs: only "*" (and `\*`) is
		// special, so any non-blank string is a valid pattern (design §5).
		return nil
	case kindFile:
		if strings.HasPrefix(e, "!") {
			return fmt.Errorf("%q: negation is not supported; list exceptions in secrets.allow_files instead", e)
		}
		if strings.Contains(e, `\`) {
			return fmt.Errorf("%q: use forward slashes in file globs (backslash is a glob escape)", e)
		}
		if strings.HasPrefix(e, "~") && !strings.HasPrefix(e, "~/") {
			return fmt.Errorf("%q: only \"~/\" (current user's home) is supported", e)
		}
		for _, seg := range strings.Split(e, "/") {
			if seg == "**" {
				continue
			}
			if err := checkGlob(seg); err != nil {
				return fmt.Errorf("invalid glob %q: %w", e, err)
			}
		}
		return nil
	case kindEnv:
		if strings.ContainsAny(e, " \t\r\n=") {
			return fmt.Errorf("%q: environment variable names cannot contain whitespace or '='", e)
		}
	}
	if err := checkGlob(e); err != nil {
		return fmt.Errorf("invalid glob %q: %w", e, err)
	}
	return nil
}

// checkGlob reports whether pattern is valid path.Match syntax.
func checkGlob(pattern string) error {
	_, err := path.Match(pattern, "")
	return err
}

// fileHeader is written at the top of every marshalled policy.
const fileHeader = `agentleash policy: one file for every coding agent (Claude Code, Codex).
Docs: https://github.com/nicosimoncinii/agentleash
After editing, run "agentleash apply" to refresh the native agent rules.`

// sectionComments maps "parent.key" paths to the comment written above them.
var sectionComments = map[string]string{ //nolint:gosec // G101 false positive: YAML comment text keyed by field name, no credentials.
	"version": "Policy schema version. Only 1 is supported.",
	"secrets": "What must never reach the agent, via its file tools or the shell.",
	"secrets.files": `Secret files. Globs: * ? [...] within a path segment, ** as a whole segment.
Relative globs are anchored at the project root (".env" is only the root
file; use "**/.env" for any depth). A leading "/" is an absolute path and
"~/" is your home directory. "!" negation is not supported: use allow_files.`,
	"secrets.allow_files": `Exceptions to secrets.files that the agent may read,
e.g. committed templates such as .env.example. Same glob syntax as files.`,
	"secrets.env": `Environment variable name globs. Matching variables are hidden from
the agent and commands that would print them are blocked.`,
	"commands": `Shell command patterns. "*" matches any run of characters, including "/"
and spaces; "\*" is a literal star; everything else is literal. Commands are
normalised first (whitespace collapsed; wrappers such as sudo, env, nohup and
timeout stripped). Patterns containing " | " match a pipeline stage by stage;
all other patterns match each simple command.`,
	"commands.deny": "Commands that are always blocked.",
	"protect": `Files the agent may read but never modify. agentleash always protects
its own files (.agentleash.yaml, .claude/settings*.json, .codex/hooks.json,
.codex/config.toml and the user-level equivalents); list extra ones here.`,
	"commands.ask": `Commands that need confirmation. Claude Code asks you; Codex has no
"ask" support, so these are denied with an explanation.`,
}

// Marshal renders a policy as a commented, human-friendly YAML file for
// `agentleash init`. Parse(Marshal(p)) round-trips.
func Marshal(p *Policy) ([]byte, error) {
	if p == nil {
		return nil, errors.New("marshal policy: nil policy")
	}
	var root yaml.Node
	if err := root.Encode(p); err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	annotate(&root, "")
	doc := &yaml.Node{Kind: yaml.DocumentNode, HeadComment: fileHeader, Content: []*yaml.Node{&root}}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	return buf.Bytes(), nil
}

// annotate attaches sectionComments to mapping keys, recursing into nested maps.
func annotate(n *yaml.Node, prefix string) {
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		p := key.Value
		if prefix != "" {
			p = prefix + "." + key.Value
		}
		if c, ok := sectionComments[p]; ok {
			key.HeadComment = c
		}
		annotate(val, p)
	}
}

// Find walks up from dir looking for FileName and returns the project root
// (the directory containing it). ok is false when no policy file exists up to
// the filesystem root. dir may be relative; root is always absolute and clean.
// A directory named FileName is ignored. Stat errors other than "not exist"
// (e.g. permission denied) are returned so callers can fail closed.
// root is not symlink-resolved (e.g. macOS /var vs /private/var); callers that
// compare it with other paths must normalise both sides (filepath.EvalSymlinks).
func Find(dir string) (root string, ok bool, err error) {
	return find(dir, os.Stat)
}

func find(dir string, stat func(string) (fs.FileInfo, error)) (string, bool, error) {
	cur, err := filepath.Abs(dir)
	if err != nil {
		return "", false, fmt.Errorf("find policy: %w", err)
	}
	for {
		fi, err := stat(filepath.Join(cur, FileName))
		switch {
		case err == nil && !fi.IsDir():
			return cur, true, nil
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return "", false, fmt.Errorf("find policy: %w", err)
		}
		parent := filepath.Dir(cur)
		if parent == cur { // filesystem root: "/", `C:\` or `\\server\share\`
			return "", false, nil
		}
		cur = parent
	}
}
