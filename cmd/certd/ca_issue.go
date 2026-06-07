package main

// `certd ca issue-workload` and `certd ca issue-server` — mint a workload's
// keypair + cert OFFLINE, so infrastructure (cert-agentd, a NATS/Postgres
// listener) has a credential before it can call certd's sign API. They are
// the offline twins of the sign path: both reuse the signer seam
// (resolveCASigner — so they sign through a KMS key where `openssl` cannot)
// and the x509engine leaf builders, so a bootstrap cert is byte-shaped like a
// runtime-issued one. The two differ only in SAN shape / EKU:
//
//   - issue-workload → SPIFFE X.509-SVID: one URI SAN, clientAuth+serverAuth.
//   - issue-server   → TLS server cert: DNS/IP SANs, serverAuth.
//
// Both issue OUTSIDE the role table / mTLS-principal policy (operator action,
// same trust as holding the CA key) and don't touch the active-cert store —
// the workload's first real renewal enrolls it.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// ── certd ca issue-workload ───────────────────────────────────────────────────

func caIssueWorkloadCmd() *cobra.Command {
	var spiffeURI, cn, keyType, caCertPath, keyPath, kmsKey, outCert, outKey, bundleOut string
	var ttl time.Duration
	var force bool
	c := &cobra.Command{
		Use:   "issue-workload",
		Short: "Mint a workload SPIFFE SVID (keypair + cert) offline for bootstrap",
		Long: "Generates a keypair and signs a SPIFFE X.509-SVID (URI SAN, " +
			"clientAuth+serverAuth) with the CA key — the offline equivalent of the " +
			"sign-workload endpoint, for seeding a workload (e.g. cert-agentd) before it " +
			"can authenticate to certd. Set --spiffe-uri to the identity the workload renews " +
			"under and that its certd principal maps, or its first renewal is rejected.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if spiffeURI == "" {
				return errors.New("--spiffe-uri is required")
			}
			if outCert == "" || outKey == "" {
				return errors.New("--out-cert and --out-key are required")
			}
			lc, err := prepareLeaf(cmd.Context(), keyPath, kmsKey, caCertPath, keyType)
			if err != nil {
				return err
			}
			cert, err := x509engine.SignWorkloadCert(rand.Reader, lc.sig, lc.issuer, x509engine.WorkloadCertParams{
				PublicKey:         lc.pub,
				SPIFFEURI:         spiffeURI,
				SubjectCommonName: cn,
				ValidAfter:        lc.now,
				ValidBefore:       lc.now.Add(ttl),
				Serial:            lc.serial,
			})
			if err != nil {
				return fmt.Errorf("sign workload cert: %w", err)
			}
			if err := writeLeafOutputs(lc, cert, outCert, outKey, bundleOut, force); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "issued workload SVID for %s (serial %s, expires %s)\n",
				spiffeURI, cert.SerialNumber, cert.NotAfter.UTC().Format(time.RFC3339))
			return nil
		},
	}
	c.Flags().StringVar(&spiffeURI, "spiffe-uri", "", "SPIFFE URI SAN for the workload identity (required); must match what the workload renews under")
	c.Flags().StringVar(&cn, "cn", "", "Optional Subject CommonName (e.g. a Postgres role for CN→role cert auth)")
	addLeafFlags(c, &keyType, &caCertPath, &keyPath, &kmsKey, &outCert, &outKey, &bundleOut, &ttl, &force)
	return c
}

// ── certd ca issue-server ─────────────────────────────────────────────────────

func caIssueServerCmd() *cobra.Command {
	var dnsNames, ipAddrs []string
	var spiffeURI, cn, keyType, caCertPath, keyPath, kmsKey, outCert, outKey, bundleOut string
	var ttl time.Duration
	var force bool
	c := &cobra.Command{
		Use:   "issue-server",
		Short: "Mint a TLS server cert (keypair + cert) offline, with DNS/IP SANs",
		Long: "Generates a keypair and signs a TLS server cert (DNS/IP SANs, serverAuth) " +
			"with the CA key — for a listener (NATS, Postgres, …) whose clients verify it by " +
			"hostname. The SPIFFE workload builder can't do this (it emits a URI SAN only). " +
			"Pass --spiffe-uri to additionally embed the server's SPIFFE identity.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(dnsNames) == 0 && len(ipAddrs) == 0 {
				return errors.New("at least one --dns or --ip is required for a server cert")
			}
			if outCert == "" || outKey == "" {
				return errors.New("--out-cert and --out-key are required")
			}
			ips := make([]net.IP, 0, len(ipAddrs))
			for _, s := range ipAddrs {
				ip := net.ParseIP(s)
				if ip == nil {
					return fmt.Errorf("invalid --ip %q", s)
				}
				ips = append(ips, ip)
			}
			lc, err := prepareLeaf(cmd.Context(), keyPath, kmsKey, caCertPath, keyType)
			if err != nil {
				return err
			}
			cert, err := x509engine.SignServerCert(rand.Reader, lc.sig, lc.issuer, x509engine.ServerCertParams{
				PublicKey:         lc.pub,
				DNSNames:          dnsNames,
				IPAddresses:       ips,
				SPIFFEURI:         spiffeURI,
				SubjectCommonName: cn,
				ValidAfter:        lc.now,
				ValidBefore:       lc.now.Add(ttl),
				Serial:            lc.serial,
			})
			if err != nil {
				return fmt.Errorf("sign server cert: %w", err)
			}
			if err := writeLeafOutputs(lc, cert, outCert, outKey, bundleOut, force); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "issued server cert for %v (serial %s, expires %s)\n",
				dnsNames, cert.SerialNumber, cert.NotAfter.UTC().Format(time.RFC3339))
			return nil
		},
	}
	c.Flags().StringArrayVar(&dnsNames, "dns", nil, "DNS SAN (repeatable); at least one --dns or --ip required")
	c.Flags().StringArrayVar(&ipAddrs, "ip", nil, "IP SAN (repeatable)")
	c.Flags().StringVar(&spiffeURI, "spiffe-uri", "", "Optional SPIFFE URI SAN to also embed on the server cert")
	c.Flags().StringVar(&cn, "cn", "", "Optional Subject CommonName; defaults to the first --dns")
	addLeafFlags(c, &keyType, &caCertPath, &keyPath, &kmsKey, &outCert, &outKey, &bundleOut, &ttl, &force)
	return c
}

// addLeafFlags registers the signer-source + output flags both issue-* commands share.
func addLeafFlags(c *cobra.Command, keyType, caCertPath, keyPath, kmsKey, outCert, outKey, bundleOut *string, ttl *time.Duration, force *bool) {
	c.Flags().StringVar(keyType, "key-type", "ed25519", "Leaf key algorithm: ed25519 | ecdsa-p256")
	c.Flags().DurationVar(ttl, "ttl", 720*time.Hour, "Cert validity; for a bootstrap leaf, only needs to outlast the gap until first renewal")
	c.Flags().StringVar(caCertPath, "ca-cert", os.Getenv("CERTD_CA_X509_CERT_FILE"), "Issuer cert PEM (the leaf's parent); default $CERTD_CA_X509_CERT_FILE")
	c.Flags().StringVar(keyPath, "key", os.Getenv("CERTD_CA_KEY_FILE"), "CA signing key (PKCS#8 PEM); default $CERTD_CA_KEY_FILE")
	c.Flags().StringVar(kmsKey, "kms-key", os.Getenv("CERTD_CA_KMS_KEY"), "KMS key reference; default $CERTD_CA_KMS_KEY. Wins over --key")
	c.Flags().StringVar(outCert, "out-cert", "", "Output path for the cert, 0644 (required)")
	c.Flags().StringVar(outKey, "out-key", "", "Output path for the private key, 0600 (required)")
	c.Flags().StringVar(bundleOut, "bundle-out", "", "Optional: also write the issuer cert here as the workload's trust anchor")
	c.Flags().BoolVar(force, "force", false, "Overwrite outputs if they already exist")
}

// leafContext is the signer + issuer + freshly-generated keypair both issue-*
// commands resolve before building their (workload or server) leaf.
type leafContext struct {
	sig    signer.Signer
	issuer *x509.Certificate
	pub    crypto.PublicKey
	keyPEM []byte
	serial *big.Int
	now    time.Time
}

// prepareLeaf resolves the CA signer, loads + key-checks the issuer cert, and
// generates the leaf keypair + serial — the shared front half of both commands.
func prepareLeaf(ctx context.Context, keyPath, kmsKey, caCertPath, keyType string) (*leafContext, error) {
	if caCertPath == "" {
		return nil, errors.New("--ca-cert (the issuer cert) is required; default is $CERTD_CA_X509_CERT_FILE")
	}
	sig, err := resolveCASigner(ctx, keyPath, kmsKey)
	if err != nil {
		return nil, err
	}
	issuer, err := loadIssuerCert(caCertPath)
	if err != nil {
		return nil, err
	}
	// The leaf chains to the issuer over the signing key — if --ca-cert isn't
	// that key's cert, the chain won't verify.
	if !publicKeysEqual(issuer.PublicKey, sig.Public()) {
		return nil, errors.New("--ca-cert public key does not match the signing key (--key/--kms-key); the leaf would not chain")
	}
	pub, keyPEM, err := generateLeafKey(keyType)
	if err != nil {
		return nil, err
	}
	serial, err := x509engine.RandomSerial(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return &leafContext{sig: sig, issuer: issuer, pub: pub, keyPEM: keyPEM, serial: serial, now: time.Now().UTC()}, nil
}

// writeLeafOutputs writes the key (0600), then the cert (0644), then the
// optional issuer bundle — key-first/cert-last (cert is the commit point).
//
// When the issuer is an intermediate (not a self-signed root), the cert file is
// written as leaf+intermediate so a bootstrapped workload presents the full
// chain on its very first handshake, exactly like a runtime-renewed cert. In a
// single-tier deployment the issuer is the root anchor, ChainPEMForLeaf returns
// "", and the cert file is the leaf alone (today's behaviour).
func writeLeafOutputs(lc *leafContext, cert *x509.Certificate, outCert, outKey, bundleOut string, force bool) error {
	if err := writeKeyPEM(outKey, lc.keyPEM, force); err != nil {
		return err
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	leafPEM = append(leafPEM, []byte(x509engine.ChainPEMForLeaf(lc.issuer))...)
	if err := writePEMBytes(outCert, leafPEM, force); err != nil {
		return err
	}
	if bundleOut != "" {
		if err := writeCertPEM(bundleOut, lc.issuer, force); err != nil {
			return err
		}
	}
	return nil
}

// loadIssuerCert reads + parses a single CERTIFICATE PEM file.
func loadIssuerCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no CERTIFICATE PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: parse certificate: %w", path, err)
	}
	return cert, nil
}

// generateLeafKey makes a fresh keypair of the given type and returns the
// public key (for signing) plus the private key as PKCS#8 PEM — the format
// certd's loaders and cert-agentd's renewer expect.
func generateLeafKey(keyType string) (crypto.PublicKey, []byte, error) {
	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	switch keyType {
	case "", "ed25519":
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub, priv = p, s
	case "ecdsa-p256":
		s, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub, priv = &s.PublicKey, s
	default:
		return nil, nil, fmt.Errorf("unsupported --key-type %q (want ed25519 or ecdsa-p256)", keyType)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pub, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// writeKeyPEM writes a private key PEM to out at 0600, refusing to clobber
// unless force. Unlike writePEMBytes (public material, 0644, may be stdout) a
// key must be a real file with tight perms — the Chmod guarantees 0600 even
// when overwriting an existing, looser file.
func writeKeyPEM(out string, b []byte, force bool) error {
	if out == "" {
		return errors.New("private key output path is required")
	}
	if !force {
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("%s already exists (pass --force to overwrite)", out)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", out, err)
		}
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	if err := os.Chmod(out, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
	return nil
}
