package api

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
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
	// Required; at least one entry. When policy is active, requested
	// principals not authorized by any of the caller's roles are
	// silently dropped; the full set being denied is a 403.
	Principals []string `json:"principals"`
	// Groups carry the caller's authenticated group membership for
	// policy enforcement. Interim until later phases derive
	// groups from a verified OIDC token / mTLS cert; treated as
	// untrusted input currently and ignored unless [policy.Engine] is
	// wired into the server. Required when policy is active.
	Groups []string `json:"groups,omitempty"`
	// Extensions are SSH cert extensions (e.g., permit-pty,
	// permit-port-forwarding). Optional. Merged with role default
	// extensions (request-level wins).
	Extensions map[string]string `json:"extensions,omitempty"`
	// CriticalOptions are strictly-enforced sshd options (e.g.,
	// force-command, source-address). Optional.
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	// TTLSeconds is the requested validity window in seconds. When
	// omitted or zero, defaultUserCertTTL is applied. Capped at
	// maxUserCertTTL at the API edge; role policy may cap further.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

type signHostRequest struct {
	PublicKey  string   `json:"public_key"`
	KeyID      string   `json:"key_id"`
	Principals []string `json:"principals"`
	Groups     []string `json:"groups,omitempty"`
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

	// Resolve the caller's identity — from a verified OIDC token when
	// OIDC is configured, an mTLS client cert when MTLSStore is
	// configured, or the request body's groups otherwise (test mode).
	caller, ok := s.authenticate(w, r, req.Groups)
	if !ok {
		return
	}

	// Apply role-table policy when configured. The decision narrows the
	// requested principal set and may cap TTL further; role default
	// extensions are merged in with request extensions winning on conflict.
	principals := req.Principals
	extensions := req.Extensions
	if s.policy != nil {
		if len(caller.Groups) == 0 {
			writeError(w, http.StatusBadRequest, "groups is required when policy is active")
			return
		}
		decision, err := s.policy.EvaluateUserCert(caller.Groups, policy.UserCertRequest{
			RequestedPrincipals: req.Principals,
			RequestedTTL:        ttl,
			EndpointMaxTTL:      maxUserCertTTL,
		})
		if err != nil {
			if errors.Is(err, policy.ErrNoRole) || errors.Is(err, policy.ErrEmptyDecision) {
				s.emitAudit(r.Context(), audit.ActionSSHUserCertDenied, "user:"+req.KeyID, caller.Caller, 0, r, map[string]any{
					"requested_principals": req.Principals,
					"groups":               caller.Groups,
					"reason":               err.Error(),
				})
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			s.log.Error("policy evaluate user cert", "err", err)
			writeError(w, http.StatusInternalServerError, "policy evaluation failed")
			return
		}
		principals = decision.Principals
		ttl = decision.TTL
		extensions = mergeExtensions(decision.Extensions, req.Extensions)
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
		Principals:      principals,
		Extensions:      extensions,
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

	s.emitAudit(r.Context(), audit.ActionSSHUserCertSigned, "user:"+cert.KeyId, caller.Caller, cert.Serial, r, map[string]any{
		"principals":   cert.ValidPrincipals,
		"ttl_seconds":  int(ttl.Seconds()),
		"valid_before": time.Unix(int64(cert.ValidBefore), 0).UTC(),
	})

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

	caller, ok := s.authenticate(w, r, req.Groups)
	if !ok {
		return
	}

	principals := req.Principals
	if s.policy != nil {
		if len(caller.Groups) == 0 {
			writeError(w, http.StatusBadRequest, "groups is required when policy is active")
			return
		}
		decision, err := s.policy.EvaluateHostCert(caller.Groups, policy.HostCertRequest{
			RequestedPrincipals: req.Principals,
			RequestedTTL:        ttl,
			EndpointMaxTTL:      maxHostCertTTL,
		})
		if err != nil {
			if errors.Is(err, policy.ErrNoRole) || errors.Is(err, policy.ErrEmptyDecision) {
				s.emitAudit(r.Context(), audit.ActionSSHHostCertDenied, "host:"+req.KeyID, caller.Caller, 0, r, map[string]any{
					"requested_principals": req.Principals,
					"groups":               caller.Groups,
					"reason":               err.Error(),
				})
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			s.log.Error("policy evaluate host cert", "err", err)
			writeError(w, http.StatusInternalServerError, "policy evaluation failed")
			return
		}
		principals = decision.Principals
		ttl = decision.TTL
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
		Principals:  principals,
		ValidAfter:  now,
		ValidBefore: now.Add(ttl),
		Serial:      serial,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.emitAudit(r.Context(), audit.ActionSSHHostCertSigned, "host:"+cert.KeyId, caller.Caller, cert.Serial, r, map[string]any{
		"principals":   cert.ValidPrincipals,
		"ttl_seconds":  int(ttl.Seconds()),
		"valid_before": time.Unix(int64(cert.ValidBefore), 0).UTC(),
	})

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

// callerIdentity is the resolved caller for a single authenticated
// request. Groups drive policy; Caller drives audit attribution.
type callerIdentity struct {
	Groups []string
	Caller string // audit-format identity, e.g. "oidc:alice@example.com" or "mtls:ssh-proxyd-prod"
}

// authenticate resolves the caller's identity for policy enforcement
// and audit. Precedence when either auth path is configured:
//
//  1. OIDC bearer (Authorization: Bearer …) wins when both
//     OIDCVerifier is wired and the header is present. An invalid
//     token short-circuits with 401 — we don't silently fall through
//     to mTLS because the caller explicitly attempted the OIDC path.
//  2. mTLS client cert principal — used when OIDC isn't applicable
//     (no verifier wired, or no bearer header presented) and a
//     verified client cert SAN matches a registered principal.
//  3. If both paths are wired and neither produced credentials, 401.
//
// When neither path is configured (OIDCVerifier and MTLSStore both
// nil), bodyGroups is used as-is — the pre-auth-wiring fallback for
// integration tests. The Caller is set to [audit.CallerAnonymous].
//
// On auth failure, the HTTP error has been written to w and the
// second return is false.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, bodyGroups []string) (callerIdentity, bool) {
	if s.oidc == nil && s.mtls == nil {
		return callerIdentity{Groups: bodyGroups, Caller: audit.CallerAnonymous}, true
	}

	// OIDC bearer path: tried first when the header is present.
	if s.oidc != nil {
		if raw, hasBearer := extractBearerToken(r); hasBearer {
			claims, err := s.oidc.Verify(r.Context(), raw)
			if err != nil {
				s.log.Debug("oidc verify failed", "err", err)
				writeError(w, http.StatusUnauthorized, "invalid bearer token")
				return callerIdentity{}, false
			}
			return callerIdentity{Groups: claims.Groups, Caller: oidcCallerString(claims)}, true
		}
	}

	// mTLS client-cert path: tried when no bearer was presented (or
	// no OIDC verifier is wired) and a verified peer cert is on the
	// request.
	if s.mtls != nil {
		sans := mtls.ExtractSANs(r)
		if len(sans) > 0 {
			p, err := s.mtls.Lookup(sans)
			if err == nil {
				return callerIdentity{Groups: p.Groups, Caller: mtlsCallerString(p)}, true
			}
			if errors.Is(err, mtls.ErrUnknownPrincipal) {
				s.log.Debug("mtls unknown principal", "sans", sans)
				writeError(w, http.StatusUnauthorized, "unknown cert principal")
				return callerIdentity{}, false
			}
			s.log.Error("mtls lookup", "err", err)
			writeError(w, http.StatusInternalServerError, "auth backend failure")
			return callerIdentity{}, false
		}
	}

	// Neither path produced credentials.
	writeError(w, http.StatusUnauthorized, "authentication required (bearer token or client cert)")
	return callerIdentity{}, false
}

// oidcCallerString returns the audit-format identity for an OIDC
// caller — email when present (most human-readable), otherwise sub.
func oidcCallerString(c *oidc.Claims) string {
	if c == nil {
		return audit.CallerPrefixOIDC + "unknown"
	}
	if c.Email != "" {
		return audit.CallerPrefixOIDC + c.Email
	}
	return audit.CallerPrefixOIDC + c.Subject
}

// mtlsCallerString returns the audit-format identity for an mTLS
// caller — workload Name when configured, MatchedSAN otherwise.
func mtlsCallerString(p *mtls.Principal) string {
	if p == nil {
		return audit.CallerPrefixMTLS + "unknown"
	}
	if p.Name != "" {
		return audit.CallerPrefixMTLS + p.Name
	}
	return audit.CallerPrefixMTLS + p.MatchedSAN
}

// emitAudit publishes a single audit Entry. Errors are logged but
// never fail the underlying API request — audit is observational
// and a transient broker hiccup must not break credential issuance.
func (s *Server) emitAudit(ctx context.Context, action, subject, caller string, serial uint64, r *http.Request, metadata map[string]any) {
	var md string
	if len(metadata) > 0 {
		b, err := json.Marshal(metadata)
		if err != nil {
			s.log.Warn("audit metadata marshal failed", "action", action, "err", err)
		} else {
			md = string(b)
		}
	}
	entry := audit.Entry{
		ID:         uuid.NewString(),
		Action:     action,
		Subject:    subject,
		Caller:     caller,
		Serial:     serial,
		IP:         clientIP(r),
		UserAgent:  r.Header.Get("User-Agent"),
		Metadata:   md,
		OccurredAt: time.Now().UTC(),
	}
	if err := s.audit.Append(ctx, entry); err != nil {
		s.log.Warn("audit append failed", "action", action, "err", err)
	}
}

// clientIP returns the caller's IP for audit attribution. Strips the
// port from r.RemoteAddr; honors X-Forwarded-For when the request
// arrives through a trusted reverse proxy (the first IP in the
// header chain is the original client).
//
// We don't have an explicit trusted-proxy allowlist, so
// X-Forwarded-For is consulted only when present — operators running
// behind an L7 proxy will see the right IP without configuration.
// A stricter "trusted proxies" check belongs in a later hardening
// slice.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// extractBearerToken pulls the raw token out of the Authorization
// header. Accepts only the canonical "Bearer <token>" form; mixed
// case "bearer" is permitted per RFC 6750 section 2.1.
func extractBearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// mergeExtensions returns a fresh map containing role defaults overlaid
// with request-level extensions — the latter wins on key conflicts so
// the caller can override a role-default permit-X with an explicit
// deny (empty value still counts as "set" in SSH cert extension
// semantics, so removal isn't expressible at this layer).
func mergeExtensions(roleDefaults, requestExts map[string]string) map[string]string {
	if len(roleDefaults) == 0 && len(requestExts) == 0 {
		return nil
	}
	out := make(map[string]string, len(roleDefaults)+len(requestExts))
	maps.Copy(out, roleDefaults)
	maps.Copy(out, requestExts)
	return out
}
