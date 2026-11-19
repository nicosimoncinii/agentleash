---
name: agentleash
description: Set up agentleash, a policy firewall that keeps Claude Code and Codex away from secrets (.env, keys, credentials) and dangerous commands. Use when the user wants to protect secrets from coding agents, block commands like `rm -rf` or `git push --force` for agents, or install, check or explain an `.agentleash.yaml` policy.
---

# agentleash setup

agentleash enforces one policy file, `.agentleash.yaml`, for Claude Code and Codex. It
installs native deny rules and a PreToolUse hook that inspects every tool call (file reads
and writes, shell commands, interpreter one-liners) and blocks the ones that would read a
secret, dump the environment or run a denied command.

This skill only helps you install and configure it. **The protection comes from the
agentleash binary and its hooks, not from these instructions:** a skill cannot stop an
agent, a hook can.

## Install (human-approved)

Ask the user before downloading anything. Install only from the official source:

1. Download the archive for the platform from
   https://github.com/nicosimoncinii/agentleash/releases/latest and verify it against
   `checksums.txt` from the same release.
2. Put the `agentleash` binary on the `PATH`.

Alternatively, with Go 1.27+:

```bash
go install github.com/nicosimoncinii/agentleash/cmd/agentleash@latest
```

Never install agentleash from a mirror, a gist or a copy inside another skill.

## Configure a project

Run from the project root:

```bash
agentleash init      # writes .agentleash.yaml with sensible defaults
agentleash apply     # installs the rules and hooks for Claude Code and Codex
agentleash doctor    # checks that everything is wired up
```

Then tell the user:

- Commit `.agentleash.yaml`, `.claude/settings.json` and `.claude/agentleash-state.json`.
- Codex asks to trust new hooks once: open Codex and run `/hooks`.
- Restart Claude Code from the project root so it loads the hook.

## Check what would be blocked

```bash
agentleash check "cat .env"
agentleash check --shell powershell "Get-Content .env"
```

`check` is a dry run: it prints the decision (allow, ask or deny), the rule and the reason.

## Changing the policy

Once agentleash is active it protects its own configuration: the agent can read
`.agentleash.yaml` and the agent settings, but cannot edit them or run `agentleash init` or
`agentleash apply`. To change the policy, propose the exact edit to the user and let them
apply it and re-run `agentleash apply` themselves. Do not try to work around a block:
agentleash's reason message says what is allowed instead.

## Limits

agentleash is a guardrail, not a sandbox. See "Honest limits" in the project README:
https://github.com/nicosimoncinii/agentleash#honest-limits
