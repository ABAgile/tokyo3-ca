package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// checkCertCmd exits 0 when the leaf certificate at the given path is
// currently valid and stays valid for at least --within more. Built for
// container entrypoints deciding whether an on-disk SVID is still usable
// as the agent's bootstrap mTLS identity (the agent image ships no
// openssl, so `openssl x509 -checkend` is not available there).
func checkCertCmd() *cobra.Command {
	var within time.Duration
	cmd := &cobra.Command{
		Use:   "check-cert <cert.pem>",
		Short: "Exit 0 when the certificate remains valid for at least --within",
		Args:  cobra.ExactArgs(1),
		// A failing check is an expected scripting outcome, not a
		// usage error — keep the output to the one-line reason.
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return checkCert(args[0], within, time.Now())
		},
	}
	cmd.Flags().DurationVar(&within, "within", 30*time.Second, "required remaining validity")
	return cmd
}

// checkCert reports nil when the first PEM certificate in path is valid
// at now and does not expire within the given duration. Missing,
// empty, or unparseable files are failures — callers treat any error
// as "re-seed / regenerate".
func checkCert(path string, within time.Duration, now time.Time) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("%s: no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%s: parse certificate: %w", path, err)
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%s: not valid until %s", path, cert.NotBefore.Format(time.RFC3339))
	}
	if now.Add(within).After(cert.NotAfter) {
		return fmt.Errorf("%s: expires %s (less than %s remaining)",
			path, cert.NotAfter.Format(time.RFC3339), within)
	}
	return nil
}
