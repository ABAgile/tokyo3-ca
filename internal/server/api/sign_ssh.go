package api

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/server/sshengine"
)

// TTL bounds. Defaults apply when the caller omits ttl_seconds; the
// max is a hard ceiling at the API edge — no callable can exceed them
// regardless of role. Role-table policy layers tighter per-group caps
// on top of these.
const (
	defaultUserCertTTL = 1 * time.Hour
	maxUserCertTTL     = 24 * time.Hour
	defaultHostCertTTL = 7 * 24 * time.Hour
	maxHostCertTTL     = 30 * 24 * time.Hour
)

// maxSignRequestBytes caps the JSON request body for sign endpoints to
// keep a malicious or buggy caller from streaming megabytes through
// the decoder. Real requests are <2 KB; 64 KB gives generous headroom.
const maxSignRequestBytes = 64 * 1024

// ── request / response shapes ─────────────────────────────────────────────────

type signUserRequest struct {
	// PublicKey is the subject's SSH public key in authorized_keys
	// format (e.g., "ssh-ed25519 AAAA…").
	PublicKey string `json:"public_key"`
	// KeyID is the human-readable identifier embedded in the cert,
	// used for audit attribution. Required.
	KeyID string `json:"key_id"`
	// Principals are the Unix usernames the bearer may log in as.
	// Required; at least one entry.
	Principals []string `json:"principals"`
	// Extensions are SSH cert extensions (e.g., permit-pty,
	// permit-port-forwarding). Optional.
	Extensions map[string]string `json:"extensions,omitempty"`
	// CriticalOptions are strictly-enforced sshd options (e.g.,
	// force-command, source-address). Optional.
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	// TTLSeconds is the requested validity window in seconds. When
	// omitted or zero, defaultUserCertTTL is applied. Capped at
	// maxUserCertTTL.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

type signHostRequest struct {
	PublicKey  string   `json:"public_key"`
	KeyID      string   `json:"key_id"`
	Principals []string `json:"principals"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
}

// signResponse is the canonical reply body for both sign endpoints.
// Certificate is the SSH-cert-authorized-keys form, e.g.
// "ssh-ed25519-cert-v01@openssh.com AAAA…".
type signResponse struct {
	Certificate string    `json:"certificate"`
	Serial      uint64    `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// errorResponse is the canonical 4xx/5xx body shape.
type errorResponse struct {
	Error string `json:"error"`
}

// ── handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleSignUserCert(w http.ResponseWriter, r *http.Request) {
	var req signUserRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pub, err := parseSSHPublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public_key: "+err.Error())
		return
	}

	ttl, err := resolveTTL(req.TTLSeconds, defaultUserCertTTL, maxUserCertTTL, "user")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	serial, err := generateSerial()
	if err != nil {
		s.log.Error("generate cert serial", "err", err)
		writeError(w, http.StatusInternalServerError, "serial generation failed")
		return
	}

	now := time.Now().UTC()
	cert, err := sshengine.SignUserCert(rand.Reader, s.caSigner, sshengine.UserCertParams{
		PublicKey:       pub,
		KeyID:           req.KeyID,
		Principals:      req.Principals,
		Extensions:      req.Extensions,
		CriticalOptions: req.CriticalOptions,
		ValidAfter:      now,
		ValidBefore:     now.Add(ttl),
		Serial:          serial,
	})
	if err != nil {
		// Validation errors from sshengine are 400s; unexpected
		// failures (signer / key wrap) shouldn't happen but are
		// logged and surfaced as 500s if they do.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, signResponse{
		Certificate: strings.TrimRight(string(ssh.MarshalAuthorizedKey(cert)), "\n"),
		Serial:      cert.Serial,
		KeyID:       cert.KeyId,
		Principals:  cert.ValidPrincipals,
		ValidAfter:  time.Unix(int64(cert.ValidAfter), 0).UTC(),
		ValidBefore: time.Unix(int64(cert.ValidBefore), 0).UTC(),
	})
}

func (s *Server) handleSignHostCert(w http.ResponseWriter, r *http.Request) {
	var req signHostRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pub, err := parseSSHPublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public_key: "+err.Error())
		return
	}

	ttl, err := resolveTTL(req.TTLSeconds, defaultHostCertTTL, maxHostCertTTL, "host")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	serial, err := generateSerial()
	if err != nil {
		s.log.Error("generate cert serial", "err", err)
		writeError(w, http.StatusInternalServerError, "serial generation failed")
		return
	}

	now := time.Now().UTC()
	cert, err := sshengine.SignHostCert(rand.Reader, s.caSigner, sshengine.HostCertParams{
		PublicKey:   pub,
		KeyID:       req.KeyID,
		Principals:  req.Principals,
		ValidAfter:  now,
		ValidBefore: now.Add(ttl),
		Serial:      serial,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, signResponse{
		Certificate: strings.TrimRight(string(ssh.MarshalAuthorizedKey(cert)), "\n"),
		Serial:      cert.Serial,
		KeyID:       cert.KeyId,
		Principals:  cert.ValidPrincipals,
		ValidAfter:  time.Unix(int64(cert.ValidAfter), 0).UTC(),
		ValidBefore: time.Unix(int64(cert.ValidBefore), 0).UTC(),
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

// decodeRequest reads the JSON body into v with a size cap and strict
// (DisallowUnknownFields) decoding. Unknown fields surface as 400s so
// typos and version skew are caught at the edge rather than silently
// ignored.
func decodeRequest(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxSignRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		// MaxBytesReader returns a wrapped error; surface a stable message.
		if errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "http: request body too large") {
			return fmt.Errorf("request body too large (max %d bytes)", maxSignRequestBytes)
		}
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// parseSSHPublicKey accepts the raw `ssh-{algo} AAAA…[ comment]` form
// used in authorized_keys files. Empty input is rejected explicitly so
// the caller sees "public_key is required" rather than the lower-level
// "no key found" from ssh.ParseAuthorizedKey.
func parseSSHPublicKey(raw string) (ssh.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("public_key is required")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// resolveTTL applies the default when seconds<=0 and rejects values
// over the maximum. kind is "user" or "host"; surfaces in the error
// message so the caller knows which endpoint's bound they hit.
func resolveTTL(seconds int64, def, max time.Duration, kind string) (time.Duration, error) {
	if seconds <= 0 {
		return def, nil
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl > max {
		return 0, fmt.Errorf("ttl_seconds %d exceeds %s-cert maximum %d", seconds, kind, int64(max.Seconds()))
	}
	return ttl, nil
}

// generateSerial returns a 63-bit random serial (high bit cleared so
// the value fits in both uint64 and signed int64 representations
// downstream — Postgres BIGINT, JSON.org integers without precision
// loss, etc.).
func generateSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint64(b[:]) & 0x7fffffffffffffff
	// Zero is a valid uint64 but conventionally signals "unset"; bump it
	// to 1 on the negligible-probability collision.
	if n == 0 {
		n = 1
	}
	return n, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}
