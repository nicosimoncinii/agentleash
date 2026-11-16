<div align="center">

# agentleash

**One policy file. Every coding agent. Secrets stay secret.**

[![CI](https://github.com/nicosimoncinii/agentleash/actions/workflows/ci.yml/badge.svg)](https://github.com/nicosimoncinii/agentleash/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nicosimoncinii/agentleash.svg)](https://pkg.go.dev/github.com/nicosimoncinii/agentleash)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

> [!NOTE]
> **Early release.** agentleash works today with Claude Code and Codex, but it is young:
> read [Honest limits](#honest-limits) before relying on it.

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
  (430+ cases, written by red-team rounds) must be blocked, every command in
  [`testdata/benign`](testdata/benign) (270+ real agent commands) must pass. CI runs it on
  Linux, macOS and Windows on every push, plus end-to-end tests against the built binary.

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
| Claude Code | `permissions.deny` | `PreToolUse` | ✅ |
| Codex CLI | `shell_environment_policy` (env filtering) | `PreToolUse` | ✅ |
| Gemini CLI | | | 🗺️ planned |
| Cursor | | | 🗺️ planned |

## Install

Download the archive for your platform from the
[latest release](https://github.com/nicosimoncinii/agentleash/releases/latest)
(Linux, macOS and Windows, amd64 and arm64), check it against `checksums.txt`, and put the
`agentleash` binary on your `PATH`.

Or build from source (Go 1.27+):

```bash
go install github.com/nicosimoncinii/agentleash/cmd/agentleash@latest
```

`agentleash apply` writes the binary's absolute path into the agent hooks, so re-run it after
moving or upgrading the binary.

## Usage

```bash
agentleash init             # create .agentleash.yaml
agentleash apply            # install rules + hooks for Claude Code and Codex
agentleash check "cat .env" # dry run: would this be blocked?
agentleash doctor           # verify everything is wired up
```

> Codex asks you to trust new hooks once: open Codex and run `/hooks`.

## Requirements

- **Claude Code v2.1.295 or later.** Older versions ignore the hook's `onFailure: "block"`,
  so a crashed or timed-out hook would let the tool call through. Start `claude` from the
  project root: project settings are only read from there.
- **Codex:** the project must be trusted, and the agentleash hook must be trusted once via
  `/hooks`. Until then Codex does not run it.

## Honest limits

Both Anthropic and OpenAI describe hooks as *a guardrail, not a complete enforcement
boundary*. agentleash raises the bar a lot, but it is **not a sandbox**: a determined
process can still find ways around it. Combine it with OS-level sandboxing for untrusted
work, and keep real secrets out of your repository.

Known gaps (details in [docs/design.md](docs/design.md) §7.7):

- **Write-then-execute across calls**: a script, Makefile or `npm run` target written earlier
  (or with the Write tool) is checked by path, not by its contents. A script written and run
  in the *same* command (`echo … > x.sh && bash x.sh`) is analysed.
- **Whole-tree reads** such as `grep -r foo .` or `docker build .` can still reach `.env`
  (use `.dockerignore`); `rg -uu` over the project asks first.
- **Interpreter one-liners** (`python -c`, `node -e`) are scanned heuristically; heavily
  obfuscated code can get through.
- **PowerShell** is tokenized, not fully parsed.
- **Codex**: commands typed into an interactive shell via `write_stdin` do not trigger
  hooks ([#18](https://github.com/nicosimoncinii/agentleash/issues/18)).
- An agent could edit `.agentleash.yaml` itself to weaken it
  ([#17](https://github.com/nicosimoncinii/agentleash/issues/17)).

Found a bypass? Please report it privately, see [SECURITY.md](SECURITY.md).

## Roadmap

- [x] v0.1: Claude Code + Codex, secrets + dangerous commands, attack corpus
- [x] v0.2: red-team hardening (interpreters, runners, write-then-run, `rm`/`git` variants)
- [ ] Self-protection of agent and agentleash config ([#17](https://github.com/nicosimoncinii/agentleash/issues/17))
- [ ] Gemini CLI and Cursor adapters
- [ ] Audit log of blocked actions
- [ ] Secret placeholders (agent sees `{{STRIPE_KEY}}`, real value injected at run time)
- [ ] Network egress allowlist

## Contributing

Contributions are welcome, especially **new bypass attempts for the attack corpus**.
See [CONTRIBUTING.md](CONTRIBUTING.md) and the [design document](docs/design.md).

## License

[MIT](LICENSE)
