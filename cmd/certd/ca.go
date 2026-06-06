package main

// CA-material tooling, exposed as `certd ca <subcommand>`. These are
// occasional operator operations (one-shot at deploy / rotation time),
// not part of the long-running `serve` path — but they live in the same
// binary so they reuse the one signer-loading seam (loadSigner, below)
// and the same x509engine code certd issues leaves with. When KMS
// support lands in the signer seam, bootstrap + rotate inherit it for
// free. See OPERATIONS.md §2.1 for the production procedure.

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// caCmd is the `certd ca` parent command. Wired into rootCmd alongside
// serve + version.
func caCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ca",
		Short: "CA-material tooling (issuer cert bootstrap, rotation, trust bundles, workload bootstrap)",
	}
	c.AddCommand(caBootstrapCmd(), caRotateCmd(), caBundleCmd(), caIssueWorkloadCmd(), caIssueServerCmd())
	return c
}

// ── certd ca bootstrap ──────────────────────────────────────────────────────

func caBootstrapCmd() *cobra.Command {
	var keyPath, kmsKey, cn, out string
	var force bool
	c := &cobra.Command{
		Use:   "bootstrap",
		Short: "Mint the X.509 issuer cert (CERTD_CA_X509_CERT_FILE) from the CA signing key",
		Long: "Self-signs a CA issuer certificate over the signing key's public half — " +
			"the public trust anchor every workload pins to verify a certd-issued mTLS peer. " +
			"The signing key never leaves its store (file or KMS); this performs exactly one " +
			"signature. Run once per CA generation; commit the result to config management.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			sig, err := resolveCASigner(cmd.Context(), keyPath, kmsKey)
			if err != nil {
				return err
			}
			cert, err := x509engine.NewSelfSignedCA(rand.Reader, sig, cn)
			if err != nil {
				return fmt.Errorf("mint issuer cert: %w", err)
			}
			return writeCertPEM(out, cert, force)
		},
	}
	c.Flags().StringVar(&keyPath, "key", os.Getenv("CERTD_CA_KEY_FILE"), "CA signing key (PKCS#8 PEM); default $CERTD_CA_KEY_FILE")
	c.Flags().StringVar(&kmsKey, "kms-key", os.Getenv("CERTD_CA_KMS_KEY"), "KMS key reference (ARN / resource name); default $CERTD_CA_KMS_KEY. Wins over --key")
	c.Flags().StringVar(&cn, "cn", "tokyo3-ca", "Subject CommonName for the issuer cert")
	c.Flags().StringVar(&out, "out", os.Getenv("CERTD_CA_X509_CERT_FILE"), "Output path; default $CERTD_CA_X509_CERT_FILE, or stdout if empty")
	c.Flags().BoolVar(&force, "force", false, "Overwrite --out if it already exists")
	return c
}

// ── certd ca rotate ─────────────────────────────────────────────────────────

func caRotateCmd() *cobra.Command {
	var newKeyPath, newKMSKey, cn, out, bundleOut string
	var oldCerts []string
	var force bool
	c := &cobra.Command{
		Use:   "rotate",
		Short: "Mint a new issuer cert from a new signing key and emit an overlap trust bundle",
		Long: "Key rotation is the disruptive case: leaves signed by the new key only validate " +
			"against the new issuer cert. Mint the new issuer cert from --key or --kms-key, then " +
			"write a trust bundle (--bundle-out) concatenating the old issuer cert(s) (--old) with " +
			"the new one. Distribute the bundle to every consumer BEFORE cutting issuance over to " +
			"the new key; once all old-key leaves have expired, drop the old cert with " +
			"`certd ca bundle`.\n\n" +
			"Rotating the issuer cert over the SAME key needs no bundle — `certd ca bootstrap " +
			"--force` re-mints it and existing leaves still validate (chains verify against the key).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if newKeyPath == "" && newKMSKey == "" {
				return errors.New("the new signing key is required: pass --key or --kms-key")
			}
			if out == "" {
				return errors.New("--out (the new issuer cert path) is required")
			}
			sig, err := resolveCASigner(cmd.Context(), newKeyPath, newKMSKey)
			if err != nil {
				return err
			}
			newCert, err := x509engine.NewSelfSignedCA(rand.Reader, sig, cn)
			if err != nil {
				return fmt.Errorf("mint new issuer cert: %w", err)
			}
			if err := writeCertPEM(out, newCert, force); err != nil {
				return err
			}
			if bundleOut == "" {
				fmt.Fprintln(os.Stderr, "certd ca rotate: new issuer written; pass --bundle-out + --old to emit the overlap trust bundle")
				return nil
			}
			// Bundle = old issuer cert(s) ⊕ the freshly-minted new one.
			pemParts := make([][]byte, 0, len(oldCerts)+1)
			for _, p := range oldCerts {
				b, err := readCertFilePEM(p)
				if err != nil {
					return err
				}
				pemParts = append(pemParts, b)
			}
			pemParts = append(pemParts, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw}))
			return writeBundle(bundleOut, pemParts, force)
		},
	}
	c.Flags().StringVar(&newKeyPath, "key", "", "New CA signing key (PKCS#8 PEM) to rotate to (--key or --kms-key required)")
	c.Flags().StringVar(&newKMSKey, "kms-key", "", "New KMS key reference to rotate to; wins over --key")
	c.Flags().StringVar(&cn, "cn", "tokyo3-ca", "Subject CommonName for the new issuer cert")
	c.Flags().StringVar(&out, "out", "", "Output path for the new issuer cert (required)")
	c.Flags().StringArrayVar(&oldCerts, "old", nil, "Existing issuer cert(s) to keep in the overlap bundle (repeatable)")
	c.Flags().StringVar(&bundleOut, "bundle-out", "", "Output path for the old⊕new trust bundle")
	c.Flags().BoolVar(&force, "force", false, "Overwrite outputs if they already exist")
	return c
}

// ── certd ca bundle ─────────────────────────────────────────────────────────

func caBundleCmd() *cobra.Command {
	var out string
	var force bool
	c := &cobra.Command{
		Use:   "bundle <issuer.crt> [issuer.crt ...]",
		Short: "Concatenate issuer certs into a trust bundle (also used to prune an old cert: just omit it)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			pemParts := make([][]byte, 0, len(args))
			for _, p := range args {
				b, err := readCertFilePEM(p)
				if err != nil {
					return err
				}
				pemParts = append(pemParts, b)
			}
			return writeBundle(out, pemParts, force)
		},
	}
	c.Flags().StringVar(&out, "out", "", "Output path; stdout if empty")
	c.Flags().BoolVar(&force, "force", false, "Overwrite --out if it already exists")
	return c
}

// ── helpers ─────────────────────────────────────────────────────────────────

// readCertFilePEM reads path and returns its normalized CERTIFICATE PEM,
// erroring if it doesn't contain exactly one parseable certificate.
func readCertFilePEM(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no CERTIFICATE PEM block", path)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("%s: parse certificate: %w", path, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}), nil
}

// writeCertPEM emits a single cert as PEM to out (or stdout when out is
// empty). Refuses to clobber an existing file unless force is set.
func writeCertPEM(out string, cert *x509.Certificate, force bool) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return writePEMBytes(out, pemBytes, force)
}

// writeBundle concatenates the given PEM blocks (in order) and writes
// them to out (or stdout). Order matters for readers that stop at the
// first match — list leaf-most issuers first if it ever matters; for a
// flat set of root anchors it does not.
func writeBundle(out string, pemParts [][]byte, force bool) error {
	var buf []byte
	for _, p := range pemParts {
		buf = append(buf, p...)
	}
	return writePEMBytes(out, buf, force)
}

func writePEMBytes(out string, b []byte, force bool) error {
	if out == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	if !force {
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("%s already exists (pass --force to overwrite)", out)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", out, err)
		}
	}
	// 0644: the issuer cert + trust bundles are public material.
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
	return nil
}
