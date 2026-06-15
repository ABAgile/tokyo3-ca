package main

// Hot-reload plumbing for the X.509 issuer cert certd signs under
// (CERTD_CA_X509_CERT_FILE). certd's other rotating TLS material goes
// through base tls/reloader — the server cert via reloader.CertLoader,
// the inbound client-CA bundle via reloader.NewClientCALoader. The issuer
// cert has no base equivalent: it's a standalone signing-chain cert
// carrying a key-match guard, so it keeps its own reloader here.
//
// Hot-reload covers the cheap same-key refresh (re-mint over the same key
// on expiry). A new-key issuer is REFUSED live (see issuerLoader): the
// signing key isn't hot-reloaded, so swapping in a new-key issuer would
// mint chains that don't verify — a key rotation still restarts.
//
// pemReloader is fail-safe: a truncated/absent/invalid drop-in keeps the
// last good value rather than breaking issuance.

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// pemReloader caches the parsed form of a PEM file, re-reading only when the
// file's mtime advances. Build with newPEMReloader; the zero value is unusable.
type pemReloader[T any] struct {
	path string
	load func([]byte) (T, error)
	log  *slog.Logger
	name string

	mu      sync.Mutex
	modTime time.Time
	val     T
}

// newPEMReloader reads path once up front so a misconfigured file fails the
// process at startup (not silently at the first handshake). load parses — and
// may validate — the PEM bytes; a load error is treated as "keep last good"
// on subsequent reloads.
func newPEMReloader[T any](path, name string, log *slog.Logger, load func([]byte) (T, error)) (*pemReloader[T], error) {
	r := &pemReloader[T]{path: path, load: load, log: log, name: name}
	if err := r.reloadLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

// get returns the freshest parsed value. It re-reads only when the file's
// mtime changed since the last successful load; a read/parse/validate error
// leaves the cached value untouched and logs a warning. Concurrency-safe —
// it is called per-handshake (client CA) and per-sign (issuer).
func (r *pemReloader[T]) get() T {
	r.mu.Lock()
	defer r.mu.Unlock()
	fi, err := os.Stat(r.path)
	if err == nil && fi.ModTime().Equal(r.modTime) {
		return r.val
	}
	if err := r.reloadLocked(); err != nil {
		r.log.Warn("hot-reload kept previous value", "what", r.name, "path", r.path, "err", err)
	}
	return r.val
}

// reloadLocked re-reads + re-parses the file. Caller must hold r.mu (or be
// the single-threaded constructor). On any error r.val/r.modTime are left as
// they were, so the previous good value survives.
func (r *pemReloader[T]) reloadLocked() error {
	fi, err := os.Stat(r.path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", r.path, err)
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", r.path, err)
	}
	v, err := r.load(data)
	if err != nil {
		return fmt.Errorf("%s %s: %w", r.name, r.path, err)
	}
	r.val, r.modTime = v, fi.ModTime()
	return nil
}

// issuerLoader returns a load func that parses the issuer cert AND refuses
// any cert whose public key does not match signerPub. That guard is what
// makes live issuer reload safe: certd's signing key is fixed at boot, so a
// new-key issuer dropped in mid-flight would produce unverifiable chains —
// we keep the old issuer and log until certd is restarted with the new key.
func issuerLoader(signerPub crypto.PublicKey) func([]byte) (*x509.Certificate, error) {
	return func(data []byte) (*x509.Certificate, error) {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("no CERTIFICATE PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if !publicKeysEqual(cert.PublicKey, signerPub) {
			return nil, errors.New("issuer public key does not match the CA signing key " +
				"(refusing live swap — restart certd after a signing-key rotation)")
		}
		return cert, nil
	}
}

// publicKeysEqual compares two crypto public keys via their standard-library
// Equal method (ed25519/ecdsa/rsa all implement it). Unknown types ⇒ false.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ae, ok := a.(equaler)
	return ok && ae.Equal(b)
}
