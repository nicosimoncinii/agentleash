# Instructions for coding agents working on this repository

Read `docs/design.md` first. It is the source of truth for scope and contracts.

## Commands

- Test: `go test -race ./...`
- Single package: `go test ./internal/engine/...`
- Build: `go build ./cmd/agentleash`
- Vet: `go vet ./...`

## Rules

- Contracts live in `internal/engine/types.go`, `internal/policy/policy.go` and
  `internal/agents/agents.go`. Do not change them without updating `docs/design.md`.
- `internal/engine` is pure: no agent-specific code, no disk writes.
- Fail closed. Any doubt → `Deny` with a helpful reason.
- Test first (red → green → refactor). Table-driven tests.
- Never overwrite user config files: merge, mark entries with `agents.HookMarker`, back up.
- Conventional Commits; small focused PRs; one branch per issue.
- Never add real secrets anywhere. Fixtures in `testdata/project` hold dummy values only.
