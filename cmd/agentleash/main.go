// Command agentleash keeps coding agents away from your secrets.
package main

import (
	"os"

	"github.com/nicosimoncinii/agentleash/internal/cli"
)

// Set by GoReleaser via -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(cli.Execute(cli.NewRootCmd(cli.Deps{Version: version, Commit: commit})))
}
