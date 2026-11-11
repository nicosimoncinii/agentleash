// Package policy loads, defaults and validates the .agentleash.yaml policy file.
package policy

import (
	"errors"
	"fmt"
	"os"

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
}

// Secrets describes what must never reach the agent.
type Secrets struct {
	// Files are gitignore-style globs. Relative globs are anchored at the project root;
	// "~/..." is the user's home directory; absolute paths are used as-is.
	Files []string `yaml:"files"`
	// AllowFiles are explicit exceptions to Files (e.g. ".env.example").
	AllowFiles []string `yaml:"allow_files"`
	// Env are glob patterns over environment variable names (e.g. "*_TOKEN").
	Env []string `yaml:"env"`
}

// Commands lists shell command patterns matched against each simple command.
type Commands struct {
	Deny []string `yaml:"deny"`
	Ask  []string `yaml:"ask"`
}

// Load reads and validates a policy file.
// TODO(policy): implement (issue: policy package).
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

// Parse decodes and validates policy YAML.
// TODO(policy): strict decoding (unknown fields are errors), Validate.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return &p, p.Validate()
}

// Default returns the policy written by `agentleash init`.
// TODO(policy): fill sensible defaults.
func Default() *Policy {
	return &Policy{Version: CurrentVersion}
}

// Validate reports configuration errors.
// TODO(policy): validate globs and patterns.
func (p *Policy) Validate() error {
	if p.Version != CurrentVersion {
		return errors.New("unsupported policy version")
	}
	return nil
}

// Marshal renders a policy as YAML for `agentleash init`.
// TODO(policy): emit a commented, human-friendly file.
func Marshal(p *Policy) ([]byte, error) {
	return yaml.Marshal(p)
}

// Find walks up from dir looking for FileName and returns the project root
// (the directory containing it). ok is false when no policy file exists.
// TODO(policy): implement and test.
func Find(dir string) (root string, ok bool, err error) {
	return "", false, errors.New("not implemented")
}
