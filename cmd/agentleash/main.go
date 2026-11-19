// Command agentleash keeps coding agents away from your secrets.
package main

import (
	"os"
	"runtime/debug"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/cli"
)

// Set by GoReleaser via -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

func main() {
	info, ok := debug.ReadBuildInfo()
	v, c := resolveVersion(version, commit, info, ok)
	os.Exit(cli.Execute(cli.NewRootCmd(cli.Deps{Version: v, Commit: c})))
}

// resolveVersion fills in the version and commit when they were not set by
// ldflags (go install, go build): the module version recorded by the Go
// toolchain (v0.3.0 for go install ...@v0.3.0) and the VCS revision when the
// binary was built from a checkout.
func resolveVersion(version, commit string, info *debug.BuildInfo, ok bool) (string, string) {
	if !ok || info == nil {
		return version, commit
	}
	if version == "dev" {
		if mv := info.Main.Version; mv != "" && mv != "(devel)" {
			version = strings.TrimPrefix(mv, "v")
		}
	}
	if commit == "none" {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				commit = s.Value[:min(7, len(s.Value))]
			}
		}
	}
	return version, commit
}
