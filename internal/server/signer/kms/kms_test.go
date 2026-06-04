package kms_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/server/signer/kms"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// fakeKMS is an in-process stand-in for a real KMS: it holds the private
// key locally and signs exactly as AWS/GCP KMS would over the wire (DER
// ECDSA, PKCS#1 RSA, raw Ed25519), so a signer built on it round-trips
// through real crypto/x509 verification.
type fakeKMS struct{ priv crypto.Signer }

func (f *fakeKMS) PublicKey(_ context.Context) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(f.priv.Public())
}

func (f *fakeKMS) Sign(_ context.Context, msg []byte, alg kms.Algorithm, prehashed bool) ([]byte, error) {
	switch k := f.priv.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, msg) // DER (r,s), like KMS
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, msg)
	case ed25519.PrivateKey:
		if prehashed {
			return nil, errEd25519Prehashed
		}
		return ed25519.Sign(k, msg), nil
	default:
		return nil, errUnsupported
	}
}

var (
	errEd25519Prehashed = errTest("ed25519 must sign the raw message")
	errUnsupported      = errTest("unsupported key")
)

type errTest string

func (e errTest) Error() string { return string(e) }

// signerRoundTrips asserts the kms-backed signer produces a self-signed
// CA cert that verifies against its own public key — the real bootstrap
// path (x509engine.NewSelfSignedCA), end to end through crypto/x509.
func signerRoundTrips(t *testing.T, priv crypto.Signer) {
	t.Helper()
	sig, err := kms.New(context.Background(), &fakeKMS{priv: priv}, "test KMS", 0)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	cert, err := x509engine.NewSelfSignedCA(rand.Reader, sig, "tokyo3-ca test")
	if err != nil {
		t.Fatalf("NewSelfSignedCA: %v", err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("self-signed cert does not verify: %v", err)
	}
}

func TestNew_ECDSAP256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerRoundTrips(t, k)
}

func TestNew_ECDSAP384(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	signerRoundTrips(t, k)
}

func TestNew_RSA2048(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	signerRoundTrips(t, k)
}

func TestNew_Ed25519(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	signerRoundTrips(t, k) // exercises the raw-message (prehashed=false) path
}

func TestNew_UnsupportedCurve(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if _, err := kms.New(context.Background(), &fakeKMS{priv: k}, "test", 0); err == nil {
		t.Fatal("P-521 should be rejected")
	}
}

func TestNew_NilClient(t *testing.T) {
	if _, err := kms.New(context.Background(), nil, "test", 0); err == nil {
		t.Fatal("nil client should error")
	}
}

func TestNew_RequiresDescription(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := kms.New(context.Background(), &fakeKMS{priv: k}, "", 0); err == nil {
		t.Fatal("empty description should error")
	}
}

// Guards the "Algorithm values match AWS SigningAlgorithmSpec" claim
// that makes the binding a cast rather than a mapping table.
func TestAlgorithmValuesMatchAWSSpec(t *testing.T) {
	cases := map[kms.Algorithm]string{
		kms.ECDSAP256:      "ECDSA_SHA_256",
		kms.ECDSAP384:      "ECDSA_SHA_384",
		kms.RSAPKCS1SHA256: "RSASSA_PKCS1_V1_5_SHA_256",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("algorithm %q != AWS spec %q", got, want)
		}
	}
}

// Belt-and-braces: confirm the fake's ECDSA digest path matches what the
// signer feeds it (prehashed digest), so the round-trip test isn't
// passing by accident.
func TestFakeECDSADigestShape(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &fakeKMS{priv: k}
	sum := sha256.Sum256([]byte("hi"))
	der, err := f.Sign(context.Background(), sum[:], kms.ECDSAP256, true)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&k.PublicKey, sum[:], der) {
		t.Fatal("fake ECDSA signature failed to verify")
	}
}
