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
