// Command cert-agentd is the tokyo3-ca per-workload credential agent.
//
// Runs on every workload that needs renewable identity credentials.
// Authenticates to certd via the workload's existing mTLS cert, requests
// short-lived SPIFFE X.509 client certs (for mTLS infrastructure) and
// optional SSH user certs (for outbound automation that SSHes to hosts),
// writes credentials atomically to known filesystem paths, and renews
// them before expiry.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const appName = "cert-agentd"

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   appName,
		Short: "tokyo3-ca workload credential agent",
	}
	root.AddCommand(runCmd(), versionCmd())
	return root
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the renewal loop in the foreground",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("cert-agentd run: not yet implemented")
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Printf("%s %s\n", appName, Version)
		},
	}
}
