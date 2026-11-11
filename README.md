<div align="center">

# agentleash

**One policy file. Every coding agent. Secrets stay secret.**

[![CI](https://github.com/nicosimoncinii/agentleash/actions/workflows/ci.yml/badge.svg)](https://github.com/nicosimoncinii/agentleash/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nicosimoncinii/agentleash.svg)](https://pkg.go.dev/github.com/nicosimoncinii/agentleash)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

> [!WARNING]
> **Pre-release.** agentleash is under active development and not ready for use yet.

## The problem

Claude Code, Codex and friends can read your files and run shell commands. Each agent has
its own way to keep secrets out of reach, and **none of them stops the shell**:

```text
Read(.env)            -> blocked by your deny rule
cat .env              -> 🔓 goes straight into the model context
```

Teams using more than one agent maintain several configs that drift apart.

## What agentleash does

- **One file**, `.agentleash.yaml`, committed with your project.
- **`agentleash apply`** installs it into every supported agent:
  native deny rules **and** a runtime hook (defense in depth).
- **Understands the shell**: pipes, `&&`, `$(...)`, backticks, `sh -c "..."`, globs like
  `cat .en*`, `base64 .env`, `printenv`, `echo $AWS_SECRET_ACCESS_KEY`...
- **Fails closed**: when in doubt, it blocks and tells the agent why.
- **Proven by a public attack corpus**: every bypass attempt in [`testdata/attacks`](testdata/attacks)
  must be blocked, every command in [`testdata/benign`](testdata/benign) must pass.

```yaml
# .agentleash.yaml
version: 1
secrets:
  files: [".env", ".env.*", "**/*.pem", "~/.aws/credentials"]
  allow_files: [".env.example"]
  env: ["*_KEY", "*_SECRET*", "*_TOKEN", "*PASSWORD*"]
commands:
  deny: ["rm -rf /", "git push --force*"]
  ask:  ["curl * | sh"]
```

## Supported agents

| Agent | Native rules | Runtime hook | Status |
|---|---|---|---|
| Claude Code | `permissions.deny` | `PreToolUse` | 🚧 v0.1 |
| Codex CLI | `shell_environment_policy` | `PreToolUse` | 🚧 v0.1 |
| Gemini CLI | | | 🗺️ planned |
| Cursor | | | 🗺️ planned |

## Install

```bash
go install github.com/nicosimoncinii/agentleash/cmd/agentleash@latest
```

Prebuilt binaries will be published on the Releases page.

## Usage

```bash
agentleash init             # create .agentleash.yaml
agentleash apply            # install rules + hooks for Claude Code and Codex
agentleash check "cat .env" # dry run: would this be blocked?
agentleash doctor           # verify everything is wired up
```

> Codex asks you to trust new hooks once: open Codex and run `/hooks`.

## Honest limits

Both Anthropic and OpenAI describe hooks as *a guardrail, not a complete enforcement
boundary*. agentleash raises the bar a lot, but it is **not a sandbox**: a determined
process can still find ways around it. Combine it with OS-level sandboxing for untrusted
work, and keep real secrets out of your repository. Found a bypass?
Please report it privately, see [SECURITY.md](SECURITY.md).

## Roadmap

- [ ] v0.1: Claude Code + Codex, secrets + dangerous commands, attack corpus
- [ ] Gemini CLI and Cursor adapters
- [ ] Audit log of blocked actions
- [ ] Secret placeholders (agent sees `{{STRIPE_KEY}}`, real value injected at run time)
- [ ] Network egress allowlist

## Contributing

Contributions are welcome, especially **new bypass attempts for the attack corpus**.
See [CONTRIBUTING.md](CONTRIBUTING.md) and the [design document](docs/design.md).

## License

[MIT](LICENSE)
