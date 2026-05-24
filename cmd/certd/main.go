// Command certd is the tokyo3-ca certificate authority server.
//
// Issues short-lived SSH and X.509 (SPIFFE) certificates against an internal
// role table that maps OIDC groups to allowed principals and host patterns.
// Authenticates callers via mTLS workload certs (machines) or OIDC ID tokens
// (humans). Publishes audit events to NATS JetStream and serves a web portal
// for role administration, session replay, and host registry browsing.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const appName = "certd"

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
		Short: "tokyo3-ca certificate authority server",
	}
	root.AddCommand(serveCmd(), versionCmd())
	return root
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the CA HTTPS server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("certd serve: not yet implemented")
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
