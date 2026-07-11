package x509engine_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// makeCA returns a fresh in-memory CA signer + its self-signed CA cert
// suitable for use as the issuer in [SignWorkloadCert].
func makeCA(t *testing.T) (signer.Signer, *x509.Certificate) {
	t.Helper()
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	caCert, err := x509engine.NewSelfSignedCA(rand.Reader, caSig, "tokyo3-ca-test")
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}
	return caSig, caCert
}

// makeSubjectKey returns a fresh Ed25519 public key to act as the
// workload's public key (the "subject" of an X.509 issuance).
func makeSubjectKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("subject keygen: %v", err)
	}
	return pub
}

// ── SignWorkloadCert ──────────────────────────────────────────────────────────

func TestSignWorkloadCert_RoundTrip(t *testing.T) {
	caSig, caCert := makeCA(t)
	subject := makeSubjectKey(t)

	now := time.Now().UTC()
	cert, err := x509engine.SignWorkloadCert(rand.Reader, caSig, caCert, x509engine.WorkloadCertParams{
		PublicKey:         subject,
		SPIFFEURI:         "spiffe://corp/svc/billing",
		SubjectCommonName: "billing-svc",
		DNSNames:          []string{"billing", "billing.example"},
		ValidAfter:        now,
		ValidBefore:       now.Add(24 * time.Hour),
		Serial:            big.NewInt(42),
	})
	if err != nil {
		t.Fatalf("SignWorkloadCert: %v", err)
	}

	if cert.Subject.CommonName != "billing-svc" {
		t.Errorf("Subject.CN = %q, want billing-svc", cert.Subject.CommonName)
	}
	if cert.SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("SerialNumber = %s, want 42", cert.SerialNumber)
	}
	if cert.IsCA {
		t.Error("IsCA = true on workload cert; want false")
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://corp/svc/billing" {
		t.Errorf("URIs = %v, want [spiffe://corp/svc/billing]", cert.URIs)
	}
	if !slices.Equal(cert.DNSNames, []string{"billing", "billing.example"}) {
		t.Errorf("DNSNames = %v, want [billing billing.example]", cert.DNSNames)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsage missing DigitalSignature")
	}

	// Build a verifier rooted at the CA and confirm the workload
	// cert is a valid issuance.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("workload cert failed to verify against CA: %v", err)
	}
	serverOpts := opts
	serverOpts.DNSName = "billing.example"
	serverOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, err := cert.Verify(serverOpts); err != nil {
		t.Errorf("workload server identity failed DNS verification: %v", err)
	}
}

func TestSignWorkloadCert_DefaultsCNFromSPIFFEURI(t *testing.T) {
	caSig, caCert := makeCA(t)
	cert, err := x509engine.SignWorkloadCert(rand.Reader, caSig, caCert, x509engine.WorkloadCertParams{
		PublicKey:   makeSubjectKey(t),
		SPIFFEURI:   "spiffe://corp/svc/billing",
		ValidAfter:  time.Now(),
		ValidBefore: time.Now().Add(time.Hour),
		Serial:      big.NewInt(1),
		// SubjectCommonName intentionally empty
	})
	if err != nil {
		t.Fatalf("SignWorkloadCert: %v", err)
	}
	if cert.Subject.CommonName != "spiffe://corp/svc/billing" {
		t.Errorf("Subject.CN = %q, want SPIFFE URI fallback", cert.Subject.CommonName)
	}
}

func TestSignWorkloadCert_ValidationErrors(t *testing.T) {
	caSig, caCert := makeCA(t)
	subject := makeSubjectKey(t)
	now := time.Now()

	tests := []struct {
		name     string
		mutate   func(*x509engine.WorkloadCertParams)
		mutateCA func() *x509.Certificate // override the caCert; nil to use the default
		wantMsg  string
	}{
		{
			name:    "nil public key",
			mutate:  func(p *x509engine.WorkloadCertParams) { p.PublicKey = nil },
			wantMsg: "public key is required",
		},
		{
			name:    "empty spiffe uri",
			mutate:  func(p *x509engine.WorkloadCertParams) { p.SPIFFEURI = "" },
			wantMsg: "spiffe uri is required",
		},
		{
			name:    "wrong scheme",
			mutate:  func(p *x509engine.WorkloadCertParams) { p.SPIFFEURI = "https://corp/x" },
			wantMsg: `scheme "spiffe"`,
		},
		{
			name:    "missing trust domain",
			mutate:  func(p *x509engine.WorkloadCertParams) { p.SPIFFEURI = "spiffe:///path" },
			wantMsg: "trust domain",
		},
		{
			name:    "nil serial",
			mutate:  func(p *x509engine.WorkloadCertParams) { p.Serial = nil },
			wantMsg: "serial is required",
		},
		{
			name:    "zero valid-after",
			mutate:  func(p *x509engine.WorkloadCertParams) { p.ValidAfter = time.Time{} },
			wantMsg: "valid-after is required",
		},
		{
			name: "valid-before equals valid-after",
			mutate: func(p *x509engine.WorkloadCertParams) {
				p.ValidAfter = now
				p.ValidBefore = now
			},
			wantMsg: "must be after",
		},
		{
			name:     "nil ca cert",
			mutate:   func(p *x509engine.WorkloadCertParams) {},
			mutateCA: func() *x509.Certificate { return nil },
			wantMsg:  "ca cert is required",
		},
		{
			name:   "non-CA cert passed as issuer",
			mutate: func(p *x509engine.WorkloadCertParams) {},
			mutateCA: func() *x509.Certificate {
				// Sign a non-CA cert and pretend it's the issuer.
				c, err := x509engine.SignWorkloadCert(rand.Reader, caSig, caCert, x509engine.WorkloadCertParams{
					PublicKey:   subject,
					SPIFFEURI:   "spiffe://corp/svc/x",
					ValidAfter:  now,
					ValidBefore: now.Add(time.Hour),
					Serial:      big.NewInt(99),
				})
				if err != nil {
					t.Fatalf("setup non-CA cert: %v", err)
				}
				return c
			},
			wantMsg: "not marked as a CA",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := x509engine.WorkloadCertParams{
				PublicKey:   subject,
				SPIFFEURI:   "spiffe://corp/svc/billing",
				ValidAfter:  now,
				ValidBefore: now.Add(time.Hour),
				Serial:      big.NewInt(1),
			}
			tc.mutate(&p)
			ca := caCert
			if tc.mutateCA != nil {
				ca = tc.mutateCA()
			}
			_, err := x509engine.SignWorkloadCert(rand.Reader, caSig, ca, p)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q should contain %q", err, tc.wantMsg)
			}
		})
	}
}

// TestSignWorkloadCert_ClampsNotAfterToIssuer verifies a leaf is never issued
// past its issuer's own expiry: a leaf requesting validity beyond the CA's
// NotAfter is shortened to the CA's NotAfter (so the chain never outlives the
// issuer). The same clamp covers SignServerCert (both go through signTemplate).
func TestSignWorkloadCert_ClampsNotAfterToIssuer(t *testing.T) {
	caSig, caCert := makeCA(t)
	now := time.Now().UTC()
	cert, err := x509engine.SignWorkloadCert(rand.Reader, caSig, caCert, x509engine.WorkloadCertParams{
		PublicKey:   makeSubjectKey(t),
		SPIFFEURI:   "spiffe://corp/svc/billing",
		ValidAfter:  now,
		ValidBefore: caCert.NotAfter.Add(20 * 365 * 24 * time.Hour), // well past the ~10y CA
		Serial:      big.NewInt(7),
	})
	if err != nil {
		t.Fatalf("SignWorkloadCert: %v", err)
	}
	if !cert.NotAfter.Equal(caCert.NotAfter) {
		t.Errorf("leaf NotAfter = %s, want clamped to issuer NotAfter %s", cert.NotAfter, caCert.NotAfter)
	}
}

// TestSignWorkloadCert_RejectsIssuerAtOrPastExpiry verifies issuance is refused
// when the issuer expires at or before the requested valid-after — there is no
// validity window left to issue into, so the clamp would otherwise invert it.
func TestSignWorkloadCert_RejectsIssuerAtOrPastExpiry(t *testing.T) {
	caSig, caCert := makeCA(t)
	after := caCert.NotAfter.Add(time.Hour) // starts after the issuer is already dead
	_, err := x509engine.SignWorkloadCert(rand.Reader, caSig, caCert, x509engine.WorkloadCertParams{
		PublicKey:   makeSubjectKey(t),
		SPIFFEURI:   "spiffe://corp/svc/billing",
		ValidAfter:  after,
		ValidBefore: after.Add(time.Hour),
		Serial:      big.NewInt(8),
	})
	if err == nil || !strings.Contains(err.Error(), "issuer expires") {
		t.Errorf("err = %v, want 'issuer expires'", err)
	}
}

// TestChainPEMForLeaf_SelfSignedRoot verifies a self-signed root is recognised
// as such and emits no leaf chain — the single-tier no-op guarantee (the
// intermediate branch is covered end-to-end in the API layer's chain test).
func TestChainPEMForLeaf_SelfSignedRoot(t *testing.T) {
	_, root := makeCA(t)
	if !x509engine.IsSelfSigned(root) {
		t.Error("IsSelfSigned(self-signed root) = false, want true")
	}
	if got := x509engine.ChainPEMForLeaf(root); got != "" {
		t.Errorf("ChainPEMForLeaf(root) = %q, want empty", got)
	}
	if got := x509engine.ChainPEMForLeaf(nil); got != "" {
		t.Errorf("ChainPEMForLeaf(nil) = %q, want empty", got)
	}
}

// ── NewSelfSignedCA ───────────────────────────────────────────────────────────

func TestNewSelfSignedCA_HasExpectedShape(t *testing.T) {
	caSig, _ := makeCA(t) // implicitly tests NewSelfSignedCA; assert shape here
	cert, err := x509engine.NewSelfSignedCA(rand.Reader, caSig, "tokyo3-ca-explicit-cn")
	if err != nil {
		t.Fatalf("NewSelfSignedCA: %v", err)
	}
	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}
	if cert.Subject.CommonName != "tokyo3-ca-explicit-cn" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("KeyUsage missing CertSign")
	}
	if !cert.MaxPathLenZero {
		t.Error("MaxPathLenZero should be true (no sub-CAs)")
	}
	// ~10 year validity.
	if dur := cert.NotAfter.Sub(cert.NotBefore); dur < 8*365*24*time.Hour || dur > 12*365*24*time.Hour {
		t.Errorf("validity = %s, want ~10y", dur)
	}

	// Self-signature must verify against itself.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("CA cert is not validly self-signed: %v", err)
	}
}

func TestNewSelfSignedCA_DefaultsCN(t *testing.T) {
	caSig, _ := makeCA(t)
	cert, err := x509engine.NewSelfSignedCA(rand.Reader, caSig, "")
	if err != nil {
		t.Fatalf("NewSelfSignedCA(empty cn): %v", err)
	}
	if cert.Subject.CommonName != "tokyo3-ca" {
		t.Errorf("default CN = %q, want tokyo3-ca", cert.Subject.CommonName)
	}
}

func TestNewSelfSignedCA_RejectsNilSigner(t *testing.T) {
	_, err := x509engine.NewSelfSignedCA(rand.Reader, nil, "x")
	if err == nil || !strings.Contains(err.Error(), "ca signer is required") {
		t.Errorf("err = %v, want 'ca signer is required'", err)
	}
}

// ── NewSelfSignedRootCA + SignIntermediateCA ──────────────────────────────────

func TestNewSelfSignedRootCA_HasPathLenOne(t *testing.T) {
	caSig, _ := makeCA(t)
	root, err := x509engine.NewSelfSignedRootCA(rand.Reader, caSig, "two-tier-root")
	if err != nil {
		t.Fatalf("NewSelfSignedRootCA: %v", err)
	}
	if !root.IsCA {
		t.Error("IsCA = false, want true")
	}
	if root.MaxPathLenZero {
		t.Error("MaxPathLenZero = true; a root must permit a sub-CA beneath it")
	}
	if root.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", root.MaxPathLen)
	}
}

func TestSignIntermediateCA_RoundTrip(t *testing.T) {
	rootSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("root signer: %v", err)
	}
	root, err := x509engine.NewSelfSignedRootCA(rand.Reader, rootSig, "root")
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	intSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("intermediate signer: %v", err)
	}
	now := time.Now().UTC()
	inter, err := x509engine.SignIntermediateCA(rand.Reader, rootSig, root, x509engine.IntermediateCertParams{
		PublicKey:         intSig.Public(),
		SubjectCommonName: "int",
		ValidAfter:        now,
		ValidBefore:       now.Add(90 * 24 * time.Hour),
		Serial:            big.NewInt(5),
	})
	if err != nil {
		t.Fatalf("SignIntermediateCA: %v", err)
	}
	if !inter.IsCA {
		t.Error("intermediate IsCA = false, want true")
	}
	if !inter.MaxPathLenZero {
		t.Error("intermediate MaxPathLenZero = false; it must not sign further sub-CAs")
	}
	if inter.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("intermediate KeyUsage missing CertSign")
	}

	// Intermediate verifies to the root.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := inter.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("intermediate failed to verify to root: %v", err)
	}

	// A leaf signed by the intermediate builds leaf→intermediate→root.
	leaf, err := x509engine.SignWorkloadCert(rand.Reader, intSig, inter, x509engine.WorkloadCertParams{
		PublicKey:   makeSubjectKey(t),
		SPIFFEURI:   "spiffe://corp/svc/x",
		ValidAfter:  now,
		ValidBefore: now.Add(time.Hour),
		Serial:      big.NewInt(6),
	})
	if err != nil {
		t.Fatalf("SignWorkloadCert under intermediate: %v", err)
	}
	inters := x509.NewCertPool()
	inters.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("leaf→intermediate→root failed to verify: %v", err)
	}
}

func TestSignIntermediateCA_RejectsPathLenZeroRoot(t *testing.T) {
	caSig, root := makeCA(t) // NewSelfSignedCA → path length 0
	intSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("int signer: %v", err)
	}
	now := time.Now().UTC()
	_, err = x509engine.SignIntermediateCA(rand.Reader, caSig, root, x509engine.IntermediateCertParams{
		PublicKey:   intSig.Public(),
		ValidAfter:  now,
		ValidBefore: now.Add(time.Hour),
		Serial:      big.NewInt(1),
	})
	if err == nil || !strings.Contains(err.Error(), "path length 0") {
		t.Errorf("err = %v, want 'path length 0'", err)
	}
}

func TestSignIntermediateCA_ClampsToRootNotAfter(t *testing.T) {
	rootSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("root signer: %v", err)
	}
	root, err := x509engine.NewSelfSignedRootCA(rand.Reader, rootSig, "root")
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	intSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("int signer: %v", err)
	}
	now := time.Now().UTC()
	inter, err := x509engine.SignIntermediateCA(rand.Reader, rootSig, root, x509engine.IntermediateCertParams{
		PublicKey:   intSig.Public(),
		ValidAfter:  now,
		ValidBefore: root.NotAfter.Add(24 * time.Hour), // past the root's own expiry
		Serial:      big.NewInt(2),
	})
	if err != nil {
		t.Fatalf("SignIntermediateCA: %v", err)
	}
	if !inter.NotAfter.Equal(root.NotAfter) {
		t.Errorf("intermediate NotAfter = %s, want clamped to root NotAfter %s", inter.NotAfter, root.NotAfter)
	}
}

// ── RandomSerial ──────────────────────────────────────────────────────────────

func TestRandomSerial_PositiveAndWithinBounds(t *testing.T) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for i := range 20 {
		n, err := x509engine.RandomSerial(rand.Reader)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if n.Sign() <= 0 {
			t.Errorf("iter %d: serial=%s, want positive", i, n)
		}
		if n.Cmp(limit) >= 0 {
			t.Errorf("iter %d: serial=%s exceeds 128-bit limit", i, n)
		}
	}
}
