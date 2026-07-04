package main

// `certd ca init-env` is a manifest-driven bootstrap wrapper around the lower
// level CA-material primitives. It is meant for first environment bring-up: mint
// a two-tier X.509 hierarchy, seal the intermediate key, and issue the static
// server/workload certs certd, Postgres, NATS, and bootstrap agents need before
// certd's online signing API exists.

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

func caInitEnvCmd() *cobra.Command {
	var outDir string
	var force bool
	c := &cobra.Command{
		Use:   "init-env <manifest>",
		Short: "Generate a manifest-defined certd bootstrap environment",
		Long: "Reads a YAML manifest and writes the CA/bootstrap material needed " +
			"before certd can serve: optional SSH CA key, root cert/key, sealed " +
			"intermediate, and static TLS server/workload certs for certd, DB, NATS, " +
			"agents, and tooling. Existing CA material is reused rather than rotated; " +
			"delete the root/intermediate files or use the lower-level rotate commands " +
			"for intentional CA rotation.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCAInitEnv(cmd.Context(), args[0], outDir, force)
		},
	}
	c.Flags().StringVar(&outDir, "out-dir", ".", "Base directory for relative output paths")
	c.Flags().BoolVar(&force, "force", false, "Overwrite leaf/bundle outputs; existing CA key material is still reused")
	return c
}

type initEnvManifest struct {
	SSHCA        initEnvSSHCA        `yaml:"ssh_ca"`
	Root         initEnvRoot         `yaml:"root"`
	Seal         initEnvSeal         `yaml:"seal"`
	Intermediate initEnvIntermediate `yaml:"intermediate"`
	Servers      []initEnvServer     `yaml:"servers"`
	Workloads    []initEnvWorkload   `yaml:"workloads"`
	Bundles      []initEnvBundle     `yaml:"bundles"`
}

type initEnvSSHCA struct {
	Key       string `yaml:"key"`
	PublicKey string `yaml:"public_key"`
	Comment   string `yaml:"comment"`
}

type initEnvRoot struct {
	Key     string `yaml:"key"`
	KeyRef  string `yaml:"key_ref"`
	Cert    string `yaml:"cert"`
	CN      string `yaml:"cn"`
	KeyType string `yaml:"key_type"`
}

type initEnvSeal struct {
	Key    string `yaml:"key"`
	KeyRef string `yaml:"key_ref"`
}

type initEnvIntermediate struct {
	Cert      string `yaml:"cert"`
	SealedKey string `yaml:"sealed_key"`
	CN        string `yaml:"cn"`
	KeyType   string `yaml:"key_type"`
	TTL       string `yaml:"ttl"`
}

type initEnvServer struct {
	Name      string   `yaml:"name"`
	DNS       []string `yaml:"dns"`
	IPs       []string `yaml:"ips"`
	SPIFFEURI string   `yaml:"spiffe_uri"`
	CN        string   `yaml:"cn"`
	KeyType   string   `yaml:"key_type"`
	Cert      string   `yaml:"cert"`
	Key       string   `yaml:"key"`
	TTL       string   `yaml:"ttl"`
}

type initEnvWorkload struct {
	Name      string `yaml:"name"`
	SPIFFEURI string `yaml:"spiffe_uri"`
	CN        string `yaml:"cn"`
	KeyType   string `yaml:"key_type"`
	Cert      string `yaml:"cert"`
	Key       string `yaml:"key"`
	TTL       string `yaml:"ttl"`
}

type initEnvBundle struct {
	Path  string   `yaml:"path"`
	Certs []string `yaml:"certs"`
}

type initEnvIssuer struct {
	sig  signer.Signer
	cert *x509.Certificate
}

func runCAInitEnv(ctx context.Context, manifestPath, outDir string, force bool) error {
	m, err := readInitEnvManifest(manifestPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create --out-dir %s: %w", outDir, err)
	}
	if err := ensureSSHCA(m.SSHCA, outDir); err != nil {
		return err
	}
	root, err := ensureInitEnvRoot(ctx, m.Root, outDir)
	if err != nil {
		return err
	}
	sealKeyRef, err := ensureInitEnvSeal(m.Seal, outDir)
	if err != nil {
		return err
	}
	issuer, err := ensureInitEnvIntermediate(ctx, m.Intermediate, outDir, root, sealKeyRef)
	if err != nil {
		return err
	}
	for _, s := range m.Servers {
		if err := issueInitEnvServer(s, outDir, issuer, force); err != nil {
			return err
		}
	}
	for _, w := range m.Workloads {
		if err := issueInitEnvWorkload(w, outDir, issuer, force); err != nil {
			return err
		}
	}
	for _, b := range m.Bundles {
		if err := writeInitEnvBundle(b, outDir, force); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "initialized certd bootstrap environment from %s into %s\n", manifestPath, outDir)
	return nil
}

func readInitEnvManifest(path string) (initEnvManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return initEnvManifest{}, fmt.Errorf("open manifest %s: %w", path, err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var m initEnvManifest
	if err := dec.Decode(&m); err != nil {
		return initEnvManifest{}, fmt.Errorf("decode manifest %s: %w", path, err)
	}
	if m.Root.Cert == "" {
		return initEnvManifest{}, errors.New("manifest root.cert is required")
	}
	if m.Intermediate.Cert == "" || m.Intermediate.SealedKey == "" {
		return initEnvManifest{}, errors.New("manifest intermediate.cert and intermediate.sealed_key are required")
	}
	return m, nil
}

func ensureSSHCA(cfg initEnvSSHCA, outDir string) error {
	if cfg.Key == "" && cfg.PublicKey == "" {
		return nil
	}
	if cfg.Key == "" || cfg.PublicKey == "" {
		return errors.New("manifest ssh_ca.key and ssh_ca.public_key must be set together")
	}
	keyPath := initEnvPath(outDir, cfg.Key)
	pubPath := initEnvPath(outDir, cfg.PublicKey)
	var sig signer.Signer
	if _, err := os.Stat(keyPath); err == nil {
		loaded, err := signer.LoadEd25519FromPEMFile(keyPath)
		if err != nil {
			return fmt.Errorf("load ssh_ca.key %s: %w", keyPath, err)
		}
		sig = loaded
	} else if errors.Is(err, os.ErrNotExist) {
		_, keyPEM, err := generateLeafKey("ed25519")
		if err != nil {
			return fmt.Errorf("generate ssh ca key: %w", err)
		}
		if err := ensureParent(keyPath); err != nil {
			return err
		}
		if err := writeKeyPEM(keyPath, keyPEM, true); err != nil {
			return err
		}
		loaded, err := signer.LoadFromPKCS8PEM(keyPEM, "generated ssh ca")
		if err != nil {
			return err
		}
		sig = loaded
	} else {
		return fmt.Errorf("stat ssh_ca.key %s: %w", keyPath, err)
	}
	pub, err := ssh.NewPublicKey(sig.Public())
	if err != nil {
		return fmt.Errorf("ssh ca public key: %w", err)
	}
	comment := cfg.Comment
	if comment == "" {
		comment = "certd-user-ca"
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n") + " " + comment + "\n"
	if err := ensureParent(pubPath); err != nil {
		return err
	}
	return writePEMBytes(pubPath, []byte(line), true)
}

func ensureInitEnvRoot(ctx context.Context, cfg initEnvRoot, outDir string) (initEnvIssuer, error) {
	keyRef, err := initEnvRootKeyRef(cfg, outDir)
	if err != nil {
		return initEnvIssuer{}, err
	}
	if err := ensureFileSignerKey(keyRef, defaultString(cfg.KeyType, "ed25519"), "root"); err != nil {
		return initEnvIssuer{}, err
	}
	sig, err := resolveCASigner(ctx, keyRef)
	if err != nil {
		return initEnvIssuer{}, err
	}
	certPath := initEnvPath(outDir, cfg.Cert)
	if cert, err := loadIssuerCert(certPath); err == nil {
		if !publicKeysEqual(cert.PublicKey, sig.Public()) {
			return initEnvIssuer{}, fmt.Errorf("root cert %s public key does not match root key", certPath)
		}
		return initEnvIssuer{sig: sig, cert: cert}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return initEnvIssuer{}, err
	}
	cn := cfg.CN
	if cn == "" {
		cn = "tokyo3-ca root"
	}
	cert, err := x509engine.NewSelfSignedRootCA(rand.Reader, sig, cn)
	if err != nil {
		return initEnvIssuer{}, fmt.Errorf("mint root cert: %w", err)
	}
	if err := ensureParent(certPath); err != nil {
		return initEnvIssuer{}, err
	}
	if err := writeCertPEM(certPath, cert, false); err != nil {
		return initEnvIssuer{}, err
	}
	return initEnvIssuer{sig: sig, cert: cert}, nil
}

func initEnvRootKeyRef(cfg initEnvRoot, outDir string) (string, error) {
	if cfg.KeyRef != "" {
		return initEnvKeyRef(outDir, cfg.KeyRef), nil
	}
	if cfg.Key == "" {
		return "", errors.New("manifest root.key or root.key_ref is required")
	}
	return "file:" + initEnvPath(outDir, cfg.Key), nil
}

func ensureFileSignerKey(keyRef, keyType, name string) error {
	path, ok := strings.CutPrefix(keyRef, "file:")
	if !ok {
		return nil
	}
	if keyType != "ed25519" {
		return fmt.Errorf("%s file keys must be ed25519 because resolveCASigner loads file: refs as PKCS#8 Ed25519 (got %q)", name, keyType)
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s key %s: %w", name, path, err)
	}
	_, keyPEM, err := generateLeafKey(keyType)
	if err != nil {
		return fmt.Errorf("generate %s key: %w", name, err)
	}
	if err := ensureParent(path); err != nil {
		return err
	}
	return writeKeyPEM(path, keyPEM, false)
}

func ensureInitEnvSeal(cfg initEnvSeal, outDir string) (string, error) {
	keyRef := cfg.KeyRef
	if keyRef == "" && cfg.Key != "" {
		keyRef = "file:" + initEnvPath(outDir, cfg.Key)
	}
	if keyRef == "" {
		return "", errors.New("manifest seal.key or seal.key_ref is required")
	}
	keyRef = initEnvKeyRef(outDir, keyRef)
	path, ok := strings.CutPrefix(keyRef, "file:")
	if !ok {
		return keyRef, nil
	}
	if _, err := os.Stat(path); err == nil {
		return keyRef, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat seal key %s: %w", path, err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate seal key: %w", err)
	}
	if err := ensureParent(path); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return "", fmt.Errorf("write seal key %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", fmt.Errorf("chmod seal key %s: %w", path, err)
	}
	return keyRef, nil
}

func ensureInitEnvIntermediate(ctx context.Context, cfg initEnvIntermediate, outDir string, root initEnvIssuer, sealKeyRef string) (initEnvIssuer, error) {
	certPath := initEnvPath(outDir, cfg.Cert)
	sealedPath := initEnvPath(outDir, cfg.SealedKey)
	if certExists(certPath) && certExists(sealedPath) {
		cert, sig, err := loadSealedIntermediate(ctx, certPath, sealedPath, sealKeyRef)
		if err != nil {
			return initEnvIssuer{}, err
		}
		return initEnvIssuer{sig: sig, cert: cert}, nil
	}
	pub, keyPEM, err := generateLeafKey(defaultString(cfg.KeyType, "ed25519"))
	if err != nil {
		return initEnvIssuer{}, err
	}
	serial, err := x509engine.RandomSerial(rand.Reader)
	if err != nil {
		return initEnvIssuer{}, fmt.Errorf("intermediate serial: %w", err)
	}
	ttl, err := initEnvDuration(cfg.TTL, 90*24*time.Hour)
	if err != nil {
		return initEnvIssuer{}, fmt.Errorf("intermediate.ttl: %w", err)
	}
	now := time.Now().UTC()
	cn := cfg.CN
	if cn == "" {
		cn = "tokyo3-ca intermediate"
	}
	cert, err := x509engine.SignIntermediateCA(rand.Reader, root.sig, root.cert, x509engine.IntermediateCertParams{
		PublicKey:         pub,
		SubjectCommonName: cn,
		ValidAfter:        now,
		ValidBefore:       now.Add(ttl),
		Serial:            serial,
	})
	if err != nil {
		return initEnvIssuer{}, fmt.Errorf("sign intermediate: %w", err)
	}
	sealer, err := resolveSealer(ctx, sealKeyRef)
	if err != nil {
		return initEnvIssuer{}, err
	}
	sealed, err := sealer.Encrypt(ctx, keyPEM)
	if err != nil {
		return initEnvIssuer{}, fmt.Errorf("seal intermediate key: %w", err)
	}
	if err := ensureParent(certPath); err != nil {
		return initEnvIssuer{}, err
	}
	if err := ensureParent(sealedPath); err != nil {
		return initEnvIssuer{}, err
	}
	if err := writeCertPEM(certPath, cert, false); err != nil {
		return initEnvIssuer{}, err
	}
	if err := writeKeyPEM(sealedPath, []byte(base64.StdEncoding.EncodeToString(sealed)), false); err != nil {
		return initEnvIssuer{}, err
	}
	sig, err := signer.LoadFromPKCS8PEM(keyPEM, "generated bootstrap intermediate")
	if err != nil {
		return initEnvIssuer{}, err
	}
	return initEnvIssuer{sig: sig, cert: cert}, nil
}

func loadSealedIntermediate(ctx context.Context, certPath, sealedPath, sealKeyRef string) (*x509.Certificate, signer.Signer, error) {
	cert, err := loadIssuerCert(certPath)
	if err != nil {
		return nil, nil, err
	}
	sealedB64, err := os.ReadFile(sealedPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read sealed intermediate %s: %w", sealedPath, err)
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sealedB64)))
	if err != nil {
		return nil, nil, fmt.Errorf("decode sealed intermediate %s: %w", sealedPath, err)
	}
	sealer, err := resolveSealer(ctx, sealKeyRef)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := sealer.Decrypt(ctx, sealed)
	if err != nil {
		return nil, nil, fmt.Errorf("unseal intermediate key: %w", err)
	}
	sig, err := signer.LoadFromPKCS8PEM(keyPEM, "unsealed bootstrap intermediate")
	if err != nil {
		return nil, nil, err
	}
	if !publicKeysEqual(cert.PublicKey, sig.Public()) {
		return nil, nil, fmt.Errorf("intermediate cert %s public key does not match sealed key", certPath)
	}
	return cert, sig, nil
}

func issueInitEnvServer(cfg initEnvServer, outDir string, issuer initEnvIssuer, force bool) error {
	if cfg.Name == "" {
		return errors.New("server entry missing name")
	}
	if len(cfg.DNS) == 0 && len(cfg.IPs) == 0 {
		return fmt.Errorf("server %q needs at least one dns or ip", cfg.Name)
	}
	certOut, keyOut := initEnvLeafPaths(outDir, cfg.Name, cfg.Cert, cfg.Key)
	pub, keyPEM, err := generateLeafKey(defaultString(cfg.KeyType, "ed25519"))
	if err != nil {
		return fmt.Errorf("server %s key: %w", cfg.Name, err)
	}
	serial, err := x509engine.RandomSerial(rand.Reader)
	if err != nil {
		return fmt.Errorf("server %s serial: %w", cfg.Name, err)
	}
	ttl, err := initEnvDuration(cfg.TTL, 720*time.Hour)
	if err != nil {
		return fmt.Errorf("server %s ttl: %w", cfg.Name, err)
	}
	ips := make([]net.IP, 0, len(cfg.IPs))
	for _, raw := range cfg.IPs {
		ip := net.ParseIP(raw)
		if ip == nil {
			return fmt.Errorf("server %s invalid ip %q", cfg.Name, raw)
		}
		ips = append(ips, ip)
	}
	now := time.Now().UTC()
	cert, err := x509engine.SignServerCert(rand.Reader, issuer.sig, issuer.cert, x509engine.ServerCertParams{
		PublicKey:         pub,
		DNSNames:          cfg.DNS,
		IPAddresses:       ips,
		SPIFFEURI:         cfg.SPIFFEURI,
		SubjectCommonName: cfg.CN,
		ValidAfter:        now,
		ValidBefore:       now.Add(ttl),
		Serial:            serial,
	})
	if err != nil {
		return fmt.Errorf("server %s cert: %w", cfg.Name, err)
	}
	return writeInitEnvLeaf(issuer, cert, keyPEM, certOut, keyOut, force)
}

func issueInitEnvWorkload(cfg initEnvWorkload, outDir string, issuer initEnvIssuer, force bool) error {
	if cfg.Name == "" {
		return errors.New("workload entry missing name")
	}
	if cfg.SPIFFEURI == "" {
		return fmt.Errorf("workload %q needs spiffe_uri", cfg.Name)
	}
	certOut, keyOut := initEnvLeafPaths(outDir, cfg.Name, cfg.Cert, cfg.Key)
	pub, keyPEM, err := generateLeafKey(defaultString(cfg.KeyType, "ed25519"))
	if err != nil {
		return fmt.Errorf("workload %s key: %w", cfg.Name, err)
	}
	serial, err := x509engine.RandomSerial(rand.Reader)
	if err != nil {
		return fmt.Errorf("workload %s serial: %w", cfg.Name, err)
	}
	ttl, err := initEnvDuration(cfg.TTL, 720*time.Hour)
	if err != nil {
		return fmt.Errorf("workload %s ttl: %w", cfg.Name, err)
	}
	now := time.Now().UTC()
	cert, err := x509engine.SignWorkloadCert(rand.Reader, issuer.sig, issuer.cert, x509engine.WorkloadCertParams{
		PublicKey:         pub,
		SPIFFEURI:         cfg.SPIFFEURI,
		SubjectCommonName: cfg.CN,
		ValidAfter:        now,
		ValidBefore:       now.Add(ttl),
		Serial:            serial,
	})
	if err != nil {
		return fmt.Errorf("workload %s cert: %w", cfg.Name, err)
	}
	return writeInitEnvLeaf(issuer, cert, keyPEM, certOut, keyOut, force)
}

func writeInitEnvLeaf(issuer initEnvIssuer, cert *x509.Certificate, keyPEM []byte, certOut, keyOut string, force bool) error {
	if err := ensureParent(certOut); err != nil {
		return err
	}
	if err := ensureParent(keyOut); err != nil {
		return err
	}
	lc := &leafContext{sig: issuer.sig, issuer: issuer.cert, pub: cert.PublicKey, keyPEM: keyPEM, serial: cert.SerialNumber, now: cert.NotBefore}
	return writeLeafOutputs(lc, cert, certOut, keyOut, "", force)
}

func writeInitEnvBundle(cfg initEnvBundle, outDir string, force bool) error {
	if cfg.Path == "" {
		return errors.New("bundle path is required")
	}
	if len(cfg.Certs) == 0 {
		return fmt.Errorf("bundle %s needs at least one cert", cfg.Path)
	}
	parts := make([][]byte, 0, len(cfg.Certs))
	for _, p := range cfg.Certs {
		b, err := readCertFilePEM(initEnvPath(outDir, p))
		if err != nil {
			return err
		}
		parts = append(parts, b)
	}
	out := initEnvPath(outDir, cfg.Path)
	if err := ensureParent(out); err != nil {
		return err
	}
	return writeBundle(out, parts, force)
}

func initEnvLeafPaths(outDir, name, cert, key string) (string, string) {
	if cert == "" {
		cert = name + ".crt"
	}
	if key == "" {
		key = name + ".key"
	}
	return initEnvPath(outDir, cert), initEnvPath(outDir, key)
}

func initEnvPath(outDir, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(outDir, p)
}

func initEnvKeyRef(outDir, ref string) string {
	path, ok := strings.CutPrefix(ref, "file:")
	if !ok {
		return ref
	}
	return "file:" + initEnvPath(outDir, path)
}

func initEnvDuration(raw string, def time.Duration) (time.Duration, error) {
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, errors.New("must be positive")
	}
	return d, nil
}

func certExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ensureParent(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent for %s: %w", path, err)
	}
	return nil
}

func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
