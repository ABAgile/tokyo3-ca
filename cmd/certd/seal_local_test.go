package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeSealKey writes an n-byte local seal key and returns its "file:" ref.
func writeSealKey(t *testing.T, n int) string {
	t.Helper()
	key := make([]byte, n)
	for i := range key {
		key[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), "seal.key")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write seal key: %v", err)
	}
	return "file:" + path
}

func TestResolveSealer_FileSchemeRoundTrip(t *testing.T) {
	ref := writeSealKey(t, 32)
	s, err := resolveSealer(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolveSealer(%q): %v", ref, err)
	}
	plaintext := []byte("-----BEGIN PRIVATE KEY-----\nintermediate\n-----END PRIVATE KEY-----")
	sealed, err := s.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(sealed) == string(plaintext) {
		t.Fatal("ciphertext equals plaintext — not sealed")
	}
	got, err := s.Decrypt(context.Background(), sealed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip = %q, want %q", got, plaintext)
	}
}

func TestResolveSealer_FileSchemeRejectsWrongKeySize(t *testing.T) {
	ref := writeSealKey(t, 16) // AES-256 wants 32
	if _, err := resolveSealer(context.Background(), ref); err == nil {
		t.Fatal("expected an error for a 16-byte key, got nil")
	}
}

func TestLocalSealer_DecryptRejectsTamper(t *testing.T) {
	ref := writeSealKey(t, 32)
	s, err := resolveSealer(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolveSealer: %v", err)
	}
	sealed, err := s.Encrypt(context.Background(), []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	sealed[len(sealed)-1] ^= 0xff // flip a ciphertext byte → GCM auth must fail
	if _, err := s.Decrypt(context.Background(), sealed); err == nil {
		t.Error("Decrypt accepted a tampered blob; want auth failure")
	}
}
