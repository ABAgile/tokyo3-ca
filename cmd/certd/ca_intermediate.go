package main

// `certd ca issue-intermediate` — the ceremony step of the two-tier hierarchy.
// It mints an intermediate CA from the OFFLINE root and seals the
// intermediate's private key under a symmetric KMS key. The root signs exactly
// one cert here (the intermediate); thereafter `certd serve` unseals the
// intermediate key into memory and signs every leaf with it, so the root key
// never touches the online issuance path. Run on a restricted/air-gapped host
// where the root's Sign is enabled. See docs/two-tier-ca.md and docs/OPERATIONS.md.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

func caIssueIntermediateCmd() *cobra.Command {
	var rootKeyRef, rootCertPath, sealKey, cn, keyType, outCert, outSealedKey string
	var ttl time.Duration
	var force bool
	c := &cobra.Command{
		Use:   "issue-intermediate",
		Short: "Mint an intermediate CA from the offline root and seal its key (KMS or local file)",
		Long: "Generates an intermediate-CA keypair, signs the intermediate cert with the root " +
			"key (--root-key) against --root-cert, and seals the intermediate " +
			"private key under the seal key (--seal-key: a KMS key ref, or file:<path> for a " +
			"local AES-256 dev key). Writes the public intermediate cert (--out-cert → " +
			"CERTD_CA_X509_CERT_FILE) and the base64 sealed-key ciphertext (--out-sealed-key → " +
			"CERTD_CA_SEALED_KEY_FILE). certd serve unseals the key into memory at boot and signs " +
			"leaves with it; the root stays offline. The intermediate's validity is clamped to " +
			"the root's NotAfter.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if rootCertPath == "" {
				return errors.New("--root-cert (the root cert) is required; default is $CERTD_CA_ROOT_CERT_FILE")
			}
			if outCert == "" || outSealedKey == "" {
				return errors.New("--out-cert and --out-sealed-key are required")
			}
			rootSig, err := resolveCASigner(cmd.Context(), rootKeyRef)
			if err != nil {
				return err
			}
			rootCert, err := loadIssuerCert(rootCertPath)
			if err != nil {
				return err
			}
			// The intermediate chains to the root over the root key — if
			// --root-cert isn't that key's cert, the chain won't verify.
			if !publicKeysEqual(rootCert.PublicKey, rootSig.Public()) {
				return errors.New("--root-cert public key does not match the root signing key (--root-key); the intermediate would not chain")
			}
			sealer, err := resolveSealer(cmd.Context(), sealKey)
			if err != nil {
				return err
			}
			pub, keyPEM, err := generateLeafKey(keyType)
			if err != nil {
				return err
			}
			serial, err := x509engine.RandomSerial(rand.Reader)
			if err != nil {
				return fmt.Errorf("serial: %w", err)
			}
			now := time.Now().UTC()
			interCert, err := x509engine.SignIntermediateCA(rand.Reader, rootSig, rootCert, x509engine.IntermediateCertParams{
				PublicKey:         pub,
				SubjectCommonName: cn,
				ValidAfter:        now,
				ValidBefore:       now.Add(ttl),
				Serial:            serial,
			})
			if err != nil {
				return fmt.Errorf("sign intermediate: %w", err)
			}
			// Seal the private key BEFORE writing anything, so a KMS failure
			// leaves no half-written outputs.
			sealed, err := sealer.Encrypt(cmd.Context(), keyPEM)
			if err != nil {
				return fmt.Errorf("seal intermediate key: %w", err)
			}
			sealedB64 := []byte(base64.StdEncoding.EncodeToString(sealed))

			// Cert (public, 0644) first, then the sealed key (0600 — ciphertext,
			// but key-derived material, so keep perms tight).
			if err := writeCertPEM(outCert, interCert, force); err != nil {
				return err
			}
			if err := writeKeyPEM(outSealedKey, sealedB64, force); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "issued intermediate CA %q (serial %s, expires %s); sealed key → %s\n",
				interCert.Subject.CommonName, interCert.SerialNumber, interCert.NotAfter.UTC().Format(time.RFC3339), outSealedKey)
			return nil
		},
	}
	c.Flags().StringVar(&rootKeyRef, "root-key", os.Getenv("CERTD_CA_ROOT_KEY"), "Root CA signing key: file:<path> for a PKCS#8 PEM, or a KMS key ref; default $CERTD_CA_ROOT_KEY")
	c.Flags().StringVar(&rootCertPath, "root-cert", os.Getenv("CERTD_CA_ROOT_CERT_FILE"), "Root cert PEM (the intermediate's parent); default $CERTD_CA_ROOT_CERT_FILE")
	c.Flags().StringVar(&sealKey, "seal-key", os.Getenv("CERTD_CA_SEAL_KEY"), "Seal key for the intermediate private key: a KMS key ref, or file:<path> for a local AES-256 dev key; default $CERTD_CA_SEAL_KEY")
	c.Flags().StringVar(&cn, "cn", "tokyo3-ca intermediate", "Subject CommonName for the intermediate cert")
	c.Flags().StringVar(&keyType, "key-type", "ed25519", "Intermediate key algorithm: ed25519 | ecdsa-p256")
	c.Flags().DurationVar(&ttl, "ttl", 90*24*time.Hour, "Intermediate validity (clamped to the root's NotAfter); rotate at ~60% of this")
	c.Flags().StringVar(&outCert, "out-cert", "", "Output path for the intermediate cert, 0644 (required)")
	c.Flags().StringVar(&outSealedKey, "out-sealed-key", "", "Output path for the base64 sealed intermediate key, 0600 (required)")
	c.Flags().BoolVar(&force, "force", false, "Overwrite outputs if they already exist")
	return c
}
