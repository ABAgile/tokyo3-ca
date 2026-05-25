package signer_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// BenchmarkInMemorySigner_Sign measures the per-Sign cost for the
// in-memory dev signer. Bounds the issuance latency floor — every
// SSH cert + X.509 cert eventually lands here.
func BenchmarkInMemorySigner_Sign(b *testing.B) {
	s, err := signer.NewEphemeralEd25519()
	if err != nil {
		b.Fatalf("NewEphemeralEd25519: %v", err)
	}
	msg := []byte("certd benchmark message — represents the wire-format cert bytes signed in production")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.Sign(rand.Reader, msg, crypto.Hash(0)); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}

// BenchmarkRemoteSigner_Sign measures the overhead of the
// RemoteSigner wrapper on top of an in-process sign function. The
// difference vs. InMemorySigner is the ctx-with-timeout + error
// wrap path — bounds how much the abstraction costs when a real
// KMS adapter is later plugged in.
func BenchmarkRemoteSigner_Sign(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := signer.NewRemoteSigner(signer.RemoteSignerConfig{
		PublicKey: priv.Public(),
		Sign: func(ctx context.Context, digest []byte) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return ed25519.Sign(priv, digest), nil
		},
		Description: "bench remote ed25519",
	})
	if err != nil {
		b.Fatalf("NewRemoteSigner: %v", err)
	}
	msg := []byte("certd benchmark message — represents the wire-format cert bytes signed in production")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.Sign(rand.Reader, msg, crypto.Hash(0)); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}
