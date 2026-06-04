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
	tmpName, err := stageTemp(path, b, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// WriteBundleAtomic writes a cert + key pair by staging both (temp file +
// fsync in their target directories) up front, then renaming them into
// place back-to-back — the KEY first, the CERT last.
//
// This is NOT atomic across the two files: two rename(2) calls can't be one
// transaction on POSIX, so during a key change there is a brief window where
// the new key is on disk but the cert is not yet (or, for a key-mtime-
// watching reader, the reverse). The consistency GUARANTEE is the reader's
// responsibility: a loader must read the pair together, verify the key
// matches the cert (tls.LoadX509KeyPair does this cryptographically), and
// keep the last-known-good pair on mismatch. tokyo3-base's tls.CertLoader
// and tls/reloader do exactly that — consumers should use a reloading loader
// (not a one-shot read) for rotated material.
//
// What the write ordering here BUYS (not a guarantee, an optimization): the
// cert is the commit point, so a loader that gates reload on the cert's
// mtime (as base's do) only reloads once the cert appears — by which point
// the key is already in place — so it typically reads a consistent pair
// without even exercising the keep-last-good fallback. Use [WriteAtomic] for
// a stable key (cert-only rotation): the key is unchanged, so there is
// nothing to keep in sync. If the cert rename fails after the key rename the
// key is left in place and the error returned; the caller retries.
func WriteBundleAtomic(certPath string, certPEM []byte, certMode os.FileMode, keyPath string, keyPEM []byte, keyMode os.FileMode) error {
	keyTmp, err := stageTemp(keyPath, keyPEM, keyMode)
	if err != nil {
		return err
	}
	certTmp, err := stageTemp(certPath, certPEM, certMode)
	if err != nil {
		_ = os.Remove(keyTmp)
		return err
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		_ = os.Remove(keyTmp)
		_ = os.Remove(certTmp)
		return err
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		_ = os.Remove(certTmp)
		return err
	}
	return nil
}

// stageTemp writes b to a temp file in path's directory with mode applied
// and fsync'd, and returns the temp file's name ready to be renamed into
// place. The temp is cleaned up on any error before return.
func stageTemp(path string, b []byte, mode os.FileMode) (string, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".write-atomic-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", err
	}
	return tmpName, nil
}
