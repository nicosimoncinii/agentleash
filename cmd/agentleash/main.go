// Command agentleash keeps coding agents away from your secrets.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Set by GoReleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "agentleash",
		Short:         "One policy file. Every coding agent. Secrets stay secret.",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "agentleash %s (%s)\n", version, commit)
		},
	})
	// TODO(cli): init, apply, check, hook, doctor (issue: CLI).
	return root
}
