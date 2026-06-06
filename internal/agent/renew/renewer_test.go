package renew_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/agent/renew"
	"github.com/abagile/tokyo3-ca/internal/client"
)

// stubSigner is the [renew.Signer] test double.
type stubSigner struct {
	mu           sync.Mutex
	calls        atomic.Int32
	gotReq       client.SignWorkloadRequest
	respFn       func(client.SignWorkloadRequest) (*client.SignWorkloadResponse, error)
	adoptedURI   string // last AdoptCert(spiffeURI, …)
	adoptedSeria string // last AdoptCert(…, serial)
}

func (s *stubSigner) AdoptCert(_ context.Context, spiffeURI, serial string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adoptedURI, s.adoptedSeria = spiffeURI, serial
	return true, nil
}

func (s *stubSigner) SignWorkloadCert(_ context.Context, req client.SignWorkloadRequest) (*client.SignWorkloadResponse, error) {
	s.mu.Lock()
	s.calls.Add(1)
	s.gotReq = req
	fn := s.respFn
	s.mu.Unlock()
	if fn == nil {
		now := time.Now().UTC()
		return &client.SignWorkloadResponse{
			Certificate: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
			Serial:      "1",
			SPIFFEURI:   req.SPIFFEURI,
			ValidAfter:  now,
			ValidBefore: now.Add(time.Hour),
		}, nil
	}
	return fn(req)
}

func TestNew_RejectsMissingConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  renew.Config
		want string
	}{
		{"no signer", renew.Config{SPIFFEURI: "spiffe://td/x", CertOutputPath: "/c", KeyOutputPath: "/k"}, "signer is required"},
		{"no spiffe uri", renew.Config{Signer: &stubSigner{}, CertOutputPath: "/c", KeyOutputPath: "/k"}, "SPIFFEURI is required"},
		{"no cert path", renew.Config{Signer: &stubSigner{}, SPIFFEURI: "spiffe://td/x", KeyOutputPath: "/k"}, "CertOutputPath is required"},
		{"no key path", renew.Config{Signer: &stubSigner{}, SPIFFEURI: "spiffe://td/x", CertOutputPath: "/c"}, "KeyOutputPath is required"},
		{"bad renew fraction", renew.Config{Signer: &stubSigner{}, SPIFFEURI: "spiffe://td/x", CertOutputPath: "/c", KeyOutputPath: "/k", RenewFraction: 1.5}, "RenewFraction must be"},
		{"bad key type", renew.Config{Signer: &stubSigner{}, SPIFFEURI: "spiffe://td/x", CertOutputPath: "/c", KeyOutputPath: "/k", KeyType: "bogus"}, "unsupported KeyType"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := renew.New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRenewer_SignOnce_GeneratesKeyAndWritesCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "workload.crt")
	keyPath := filepath.Join(dir, "workload.key")

	signer := &stubSigner{}
	var sawValidAfter, sawValidBefore time.Time
	r, err := renew.New(renew.Config{
		Signer:            signer,
		SPIFFEURI:         "spiffe://tokyo3.example/host/db-1",
		SubjectCommonName: "db-1.prod",
		CertOutputPath:    certPath,
		KeyOutputPath:     keyPath,
		RequestedTTL:      time.Hour,
		OnRenewed: func(va, vb time.Time) {
			sawValidAfter = va
			sawValidBefore = vb
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	va, vb, err := r.SignOnce(context.Background())
	if err != nil {
		t.Fatalf("SignOnce: %v", err)
	}

	// The renewer acks adoption of the freshly-persisted cert.
	if signer.adoptedURI != "spiffe://tokyo3.example/host/db-1" || signer.adoptedSeria != "1" {
		t.Errorf("adopt not acked: uri=%q serial=%q", signer.adoptedURI, signer.adoptedSeria)
	}

	// Cert and key both landed on disk.
	got, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !strings.Contains(string(got), "BEGIN CERTIFICATE") {
		t.Errorf("cert file body = %q", string(got))
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !strings.Contains(string(keyBytes), "BEGIN PRIVATE KEY") {
		t.Errorf("key file body = %q", string(keyBytes))
	}

	// Key file is mode 0600.
	keyInfo, _ := os.Stat(keyPath)
	if mode := keyInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("key file mode = %o, want 0600", mode)
	}
	// Cert file is mode 0644.
	certInfo, _ := os.Stat(certPath)
	if mode := certInfo.Mode().Perm(); mode != 0o644 {
		t.Errorf("cert file mode = %o, want 0644", mode)
	}

	// Request body sent to certd carries the configured SPIFFE URI +
	// CN + TTL, and a parseable PEM public key.
	if signer.gotReq.SPIFFEURI != "spiffe://tokyo3.example/host/db-1" {
		t.Errorf("server saw SPIFFEURI = %q", signer.gotReq.SPIFFEURI)
	}
	if signer.gotReq.SubjectCommonName != "db-1.prod" {
		t.Errorf("server saw CN = %q", signer.gotReq.SubjectCommonName)
	}
	if signer.gotReq.TTLSeconds != 3600 {
		t.Errorf("server saw TTL = %d, want 3600", signer.gotReq.TTLSeconds)
	}
	if pub := signer.gotReq.PublicKey; !strings.Contains(pub, "BEGIN PUBLIC KEY") {
		t.Errorf("public key in request not PEM: %q", pub)
	} else {
		// Decoding the pub PEM must yield an ECDSA key (we only accept
		// ECDSA for workload keys).
		block, _ := pem.Decode([]byte(pub))
		if block == nil {
			t.Fatal("pub key PEM decode failed")
		}
		anyKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("ParsePKIXPublicKey: %v", err)
		}
		if _, ok := anyKey.(*ecdsa.PublicKey); !ok {
			t.Errorf("public key type = %T, want *ecdsa.PublicKey", anyKey)
		}
	}

	// OnRenewed fired with the validity envelope.
	if sawValidAfter.IsZero() || sawValidBefore.IsZero() {
		t.Error("OnRenewed not invoked")
	}
	if !sawValidAfter.Equal(va) || !sawValidBefore.Equal(vb) {
		t.Errorf("OnRenewed args (%v, %v) ≠ SignOnce return (%v, %v)",
			sawValidAfter, sawValidBefore, va, vb)
	}

	// No leftover .tmp files.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".write-atomic-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestRenewer_SignOnce_ReusesExistingKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.crt")
	keyPath := filepath.Join(dir, "c.key")

	signer := &stubSigner{}
	r, _ := renew.New(renew.Config{
		Signer:         signer,
		SPIFFEURI:      "spiffe://td/x",
		CertOutputPath: certPath,
		KeyOutputPath:  keyPath,
	})

	if _, _, err := r.SignOnce(context.Background()); err != nil {
		t.Fatalf("first SignOnce: %v", err)
	}
	firstKey, _ := os.ReadFile(keyPath)

	// Second SignOnce must reuse the same on-disk key — the public
	// key sent to certd in the second request matches the first.
	prevPub := signer.gotReq.PublicKey
	if _, _, err := r.SignOnce(context.Background()); err != nil {
		t.Fatalf("second SignOnce: %v", err)
	}
	if signer.gotReq.PublicKey != prevPub {
		t.Error("workload public key changed between renewals (key should be stable)")
	}

	// And the on-disk key file is unchanged.
	secondKey, _ := os.ReadFile(keyPath)
	if string(firstKey) != string(secondKey) {
		t.Error("key file rewritten on second renewal")
	}
}

func TestRenewer_SignOnce_RotateKey_FreshKeyEachRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.crt")
	keyPath := filepath.Join(dir, "c.key")

	signer := &stubSigner{}
	r, _ := renew.New(renew.Config{
		Signer:         signer,
		SPIFFEURI:      "spiffe://td/x",
		CertOutputPath: certPath,
		KeyOutputPath:  keyPath,
		RotateKey:      true,
	})

	if _, _, err := r.SignOnce(context.Background()); err != nil {
		t.Fatalf("first SignOnce: %v", err)
	}
	firstPub := signer.gotReq.PublicKey
	firstKey, _ := os.ReadFile(keyPath)

	if _, _, err := r.SignOnce(context.Background()); err != nil {
		t.Fatalf("second SignOnce: %v", err)
	}
	// With RotateKey, the second renewal sends a different public key and
	// rewrites the key file (fresh keypair each cycle).
	if signer.gotReq.PublicKey == firstPub {
		t.Error("public key unchanged with RotateKey (want a fresh key each renewal)")
	}
	secondKey, _ := os.ReadFile(keyPath)
	if string(firstKey) == string(secondKey) {
		t.Error("key file not rewritten with RotateKey")
	}
}

func TestRenewer_SignOnce_LoadsExistingKeyFromDisk(t *testing.T) {
	// Fresh Renewer pointing at an existing keyfile (written by a
	// previous run) must load + reuse it rather than generating a
	// new one.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.crt")
	keyPath := filepath.Join(dir, "c.key")

	// First run generates a key.
	r1, _ := renew.New(renew.Config{
		Signer: &stubSigner{}, SPIFFEURI: "spiffe://td/x",
		CertOutputPath: certPath, KeyOutputPath: keyPath,
	})
	if _, _, err := r1.SignOnce(context.Background()); err != nil {
		t.Fatalf("seed SignOnce: %v", err)
	}
	keyBefore, _ := os.ReadFile(keyPath)

	// Second Renewer (fresh in-memory state) — must read keyBefore
	// from disk and submit the matching public key to certd.
	signer2 := &stubSigner{}
	r2, _ := renew.New(renew.Config{
		Signer: signer2, SPIFFEURI: "spiffe://td/x",
		CertOutputPath: certPath, KeyOutputPath: keyPath,
	})
	if _, _, err := r2.SignOnce(context.Background()); err != nil {
		t.Fatalf("second-instance SignOnce: %v", err)
	}
	keyAfter, _ := os.ReadFile(keyPath)
	if string(keyBefore) != string(keyAfter) {
		t.Error("key file changed when a second Renewer instance picked it up")
	}
}

func TestRenewer_SignOnce_PropagatesSignerError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.crt")
	keyPath := filepath.Join(dir, "c.key")

	signer := &stubSigner{
		respFn: func(_ client.SignWorkloadRequest) (*client.SignWorkloadResponse, error) {
			return nil, errors.New("certd returned 403")
		},
	}
	r, _ := renew.New(renew.Config{
		Signer: signer, SPIFFEURI: "spiffe://td/x",
		CertOutputPath: certPath, KeyOutputPath: keyPath,
	})
	_, _, err := r.SignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "certd returned 403") {
		t.Errorf("err = %v", err)
	}
	// Cert file was not written.
	if _, statErr := os.Stat(certPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("cert file exists after failed sign: %v", statErr)
	}
	// Key is held in memory (so a retry reuses the same key) but NOT yet
	// on disk: it's persisted only with the first successful cert, as an
	// atomic bundle, so a sign failure leaves no orphaned key file.
	if _, statErr := os.Stat(keyPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("key file exists after failed first sign (should persist only with the cert): %v", statErr)
	}
}

func TestRenewer_SignOnce_RejectsEmptyCert(t *testing.T) {
	dir := t.TempDir()
	signer := &stubSigner{
		respFn: func(_ client.SignWorkloadRequest) (*client.SignWorkloadResponse, error) {
			return &client.SignWorkloadResponse{Certificate: ""}, nil
		},
	}
	r, _ := renew.New(renew.Config{
		Signer: signer, SPIFFEURI: "spiffe://td/x",
		CertOutputPath: filepath.Join(dir, "c"),
		KeyOutputPath:  filepath.Join(dir, "k"),
	})
	_, _, err := r.SignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty certificate") {
		t.Errorf("err = %v", err)
	}
}

func TestRenewer_Run_LoopsAndRenews(t *testing.T) {
	dir := t.TempDir()
	signer := &stubSigner{
		respFn: func(_ client.SignWorkloadRequest) (*client.SignWorkloadResponse, error) {
			now := time.Now().UTC()
			return &client.SignWorkloadResponse{
				Certificate: "-----BEGIN CERTIFICATE-----\nloop\n-----END CERTIFICATE-----\n",
				Serial:      "1",
				ValidAfter:  now,
				ValidBefore: now.Add(time.Millisecond),
			}, nil
		},
	}
	r, _ := renew.New(renew.Config{
		Signer: signer, SPIFFEURI: "spiffe://td/x",
		CertOutputPath:   filepath.Join(dir, "c"),
		KeyOutputPath:    filepath.Join(dir, "k"),
		MinRenewInterval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	if got := signer.calls.Load(); got < 2 {
		t.Errorf("calls = %d, want at least 2 (initial sign + at least one renew)", got)
	}
}

func TestRenewer_Run_AppendsSignErrorAttrs(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	signer := &stubSigner{
		respFn: func(_ client.SignWorkloadRequest) (*client.SignWorkloadResponse, error) {
			calls.Add(1)
			return nil, errors.New("certd unreachable")
		},
	}
	var hookCalls atomic.Int32
	r, _ := renew.New(renew.Config{
		Signer: signer, SPIFFEURI: "spiffe://td/x",
		CertOutputPath:   filepath.Join(dir, "c.crt"),
		KeyOutputPath:    filepath.Join(dir, "k"),
		MinRenewInterval: 10 * time.Millisecond,
		RetryBackoff:     10 * time.Millisecond,
		SignErrorAttrs: func() []any {
			hookCalls.Add(1)
			return []any{"mtls_cert_remaining", time.Hour}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	if got := calls.Load(); got < 2 {
		t.Errorf("sign calls = %d, want ≥ 2", got)
	}
	if got := hookCalls.Load(); got != calls.Load() {
		t.Errorf("SignErrorAttrs invocations = %d, want %d (once per failure)", got, calls.Load())
	}
}

func TestRenewer_Run_RetryOnFailureThenSucceed(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	signer := &stubSigner{
		respFn: func(_ client.SignWorkloadRequest) (*client.SignWorkloadResponse, error) {
			if calls.Add(1) == 1 {
				return nil, errors.New("transient certd outage")
			}
			now := time.Now().UTC()
			return &client.SignWorkloadResponse{
				Certificate: "-----BEGIN CERTIFICATE-----\nrecovered\n-----END CERTIFICATE-----\n",
				ValidAfter:  now,
				ValidBefore: now.Add(time.Hour),
			}, nil
		},
	}
	certPath := filepath.Join(dir, "c.crt")
	r, _ := renew.New(renew.Config{
		Signer: signer, SPIFFEURI: "spiffe://td/x",
		CertOutputPath:   certPath,
		KeyOutputPath:    filepath.Join(dir, "k"),
		MinRenewInterval: 10 * time.Millisecond,
		RetryBackoff:     20 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	if got := calls.Load(); got < 2 {
		t.Errorf("calls = %d, want ≥ 2 (failure + retry)", got)
	}
	body, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !strings.Contains(string(body), "recovered") {
		t.Errorf("cert file body = %q", string(body))
	}
}
