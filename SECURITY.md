# Security Policy

agentleash is a security tool, so bypasses matter.

## Reporting a vulnerability or bypass

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
*Security* tab → *Report a vulnerability*.

Please include:

- the agent (Claude Code / Codex) and its version;
- your `.agentleash.yaml`;
- the exact command or tool call that bypassed the policy;
- your OS and shell.

We aim to acknowledge reports within 72 hours. Once fixed, the bypass is added to the
public attack corpus in `testdata/attacks/` and credited to you (unless you prefer otherwise).

## Scope

agentleash is a guardrail, not a sandbox (see "Honest limits" in the README). Reports are
still welcome for anything that lets an agent read a protected secret or run a denied
command through a supported agent with a correctly applied policy.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
