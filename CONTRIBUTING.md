# Contributing to agentleash

Thanks for helping keep coding agents on a leash!

## Development setup

Requirements: Go (see `go.mod` for the version).

```bash
git clone https://github.com/nicosimoncinii/agentleash
cd agentleash
go test -race ./...
go run ./cmd/agentleash --help
```

`go test ./e2e/ -v` runs the end-to-end tests: they build the binary and pipe real Claude Code
and Codex hook payloads through `agentleash hook`.

Optional: [`golangci-lint`](https://golangci-lint.run/) for `golangci-lint run`.

## Workflow

1. Open (or pick) an issue. For anything non-trivial, agree on the approach first.
2. Branch from `main`: `feat/<topic>`, `fix/<topic>`, `test/<topic>`, `docs/<topic>`.
3. Write tests first. Keep PRs small and focused.
4. Use [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(engine): detect base64 reads of secret files`.
5. Open a PR using the template. CI must be green and one review is required.

## Adding to the attack corpus

The fastest way to contribute. Add a YAML file to `testdata/attacks/` (must be blocked) or
`testdata/benign/` (must be allowed). See `testdata/README.md` for the format. If you found
a **working** bypass, report it privately first (see [SECURITY.md](SECURITY.md)).

## Code guidelines

- `internal/engine` is pure logic: no agent-specific code, no writes to disk.
- Fail closed: if the engine cannot be sure a command is safe, it denies with a reason.
- Reasons are read by the agent: say what was blocked and what to do instead.
- Never overwrite user configuration; merge and mark agentleash's own entries.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
