package output_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/agent/output"
)

func TestWriteAtomic_CreatesFileWithMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.key")
	if err := output.WriteAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", string(body))
	}
	info, _ := os.Stat(path)
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0600", mode)
	}
}

func TestWriteAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := output.WriteAtomic(path, []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "new" {
		t.Errorf("body = %q, want new", string(body))
	}
}

func TestWriteAtomic_RejectsBadDir(t *testing.T) {
	// Parent dir doesn't exist — CreateTemp fails fast.
	bogus := filepath.Join(t.TempDir(), "missing-subdir", "f")
	err := output.WriteAtomic(bogus, []byte("x"), 0o644)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want ErrNotExist", err)
	}
}

func TestWriteAtomic_LeavesNoTempFilesOnSuccess(t *testing.T) {
	dir := t.TempDir()
	for range 8 {
		path := filepath.Join(dir, "f")
		if err := output.WriteAtomic(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteAtomic: %v", err)
		}
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".write-atomic-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestWriteBundleAtomic_WritesPairWithModes(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "w.crt")
	keyPath := filepath.Join(dir, "w.key")
	if err := output.WriteBundleAtomic(certPath, []byte("CERT"), 0o644, keyPath, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("WriteBundleAtomic: %v", err)
	}

	cert, _ := os.ReadFile(certPath)
	key, _ := os.ReadFile(keyPath)
	if string(cert) != "CERT" || string(key) != "KEY" {
		t.Errorf("contents = %q / %q, want CERT / KEY", cert, key)
	}
	certInfo, _ := os.Stat(certPath)
	if mode := certInfo.Mode().Perm(); mode != 0o644 {
		t.Errorf("cert mode = %o, want 0644", mode)
	}
	keyInfo, _ := os.Stat(keyPath)
	if mode := keyInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("key mode = %o, want 0600", mode)
	}

	// Overwrites both on a second bundle write, leaving no temp files.
	if err := output.WriteBundleAtomic(certPath, []byte("CERT2"), 0o644, keyPath, []byte("KEY2"), 0o600); err != nil {
		t.Fatalf("second WriteBundleAtomic: %v", err)
	}
	cert, _ = os.ReadFile(certPath)
	if string(cert) != "CERT2" {
		t.Errorf("cert not overwritten: %q", cert)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".write-atomic-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

// TestWriteBundleAtomic_BadCertDirLeavesKeyUnmoved: when the cert can't be
// staged (its directory is missing) nothing is renamed into place — neither
// the key nor the cert — so a failure never leaves a half-written pair.
func TestWriteBundleAtomic_BadCertDirLeavesKeyUnmoved(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "w.key")
	certPath := filepath.Join(dir, "missing-subdir", "w.crt")
	if err := output.WriteBundleAtomic(certPath, []byte("CERT"), 0o644, keyPath, []byte("KEY"), 0o600); err == nil {
		t.Fatal("expected error for missing cert dir")
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("key file written despite cert staging failure: %v", err)
	}
}
