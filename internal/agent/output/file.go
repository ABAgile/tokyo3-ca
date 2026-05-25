// Package output writes renewed credentials to filesystem paths the
// workload's TLS stack / SSH client reads from. Atomic rename, correct
// mode bits, and SSH client-config snippets (ProxyJump +
// CertificateFile directives) so the consumer picks up new
// credentials without restart.
package output

import (
	"os"
	"path/filepath"
)

// WriteAtomic writes b to path via a temp file + rename so partial
// writes are never observable by readers. The temp file lives in the
// same directory as path to guarantee rename(2) atomicity
// (cross-filesystem renames degrade to copy+delete and lose the
// atomicity guarantee).
//
// mode is applied to the temp file before the rename; readers that
// stat path immediately after the rename see the requested mode.
func WriteAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".write-atomic-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
