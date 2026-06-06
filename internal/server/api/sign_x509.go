package api

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
	"github.com/abagile/tokyo3-ca/internal/store"
)

// X.509 TTL bounds. Same shape as the SSH endpoint constants — role
// policy may cap further per-group.
const (
	defaultX509CertTTL = 1 * time.Hour
	maxX509CertTTL     = 24 * time.Hour
)

// signX509Request is the JSON body for [POST /api/v1/x509/sign-workload].
type signX509Request struct {
	// PublicKey is the workload's public key, PEM-encoded as a
	// SubjectPublicKeyInfo block ("-----BEGIN PUBLIC KEY-----").
	PublicKey string `json:"public_key"`
	// SPIFFEURI is the requested URI SAN. Must use the spiffe://
	// scheme; role policy decides whether the caller may obtain it.
	SPIFFEURI string `json:"spiffe_uri"`
	// SubjectCommonName is an optional CN. Modern verifiers ignore
	// CN as identity; this is for human-friendly tooling only.
	SubjectCommonName string `json:"subject_common_name,omitempty"`
	// Groups carry the caller's authenticated group membership when
	// the API is in body-groups fallback mode. Ignored when OIDC or
	// mTLS is configured.
	Groups []string `json:"groups,omitempty"`
	// TTLSeconds is the requested validity window. Defaults to
	// [defaultX509CertTTL] when omitted; capped at [maxX509CertTTL]
	// and possibly further by role policy.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
	// CurrentSerial is the decimal serial of the cert the workload is
	// rotating from (empty on first issuance). Consulted only when the
	// renewal/anti-theft guard is active (an ActiveCertStore is wired):
	// it must equal the identity's current or one-step-previous serial.
	CurrentSerial string `json:"current_serial,omitempty"`
}

// signX509Response is the JSON reply body. Certificate is PEM-encoded.
type signX509Response struct {
	Certificate string    `json:"certificate"`
	Serial      string    `json:"serial"` // decimal big-int (X.509 serials don't fit uint64)
	SPIFFEURI   string    `json:"spiffe_uri"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

func (s *Server) handleSignX509WorkloadCert(w http.ResponseWriter, r *http.Request) {
	issuerCert := s.issuerCert()
	if issuerCert == nil {
		writeError(w, http.StatusServiceUnavailable, "x509 issuance not configured (no CA cert)")
		return
	}

	var req signX509Request
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pub, err := parseX509PublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public_key: "+err.Error())
		return
	}
	if req.SPIFFEURI == "" {
		writeError(w, http.StatusBadRequest, "spiffe_uri is required")
		return
	}

	ttl, err := resolveTTL(req.TTLSeconds, defaultX509CertTTL, maxX509CertTTL, "x509")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	caller, ok := s.authenticate(w, r, req.Groups)
	if !ok {
		return
	}

	spiffeURI := req.SPIFFEURI
	if s.policy != nil {
		if len(caller.Groups) == 0 {
			writeError(w, http.StatusBadRequest, "groups is required when policy is active")
			return
		}
		decision, err := s.policy.EvaluateX509Cert(caller.Groups, policy.X509CertRequest{
			RequestedSPIFFEURI: req.SPIFFEURI,
			RequestedTTL:       ttl,
			EndpointMaxTTL:     maxX509CertTTL,
		})
		if err != nil {
			if errors.Is(err, policy.ErrNoRole) || errors.Is(err, policy.ErrEmptyDecision) {
				s.emitAudit(r.Context(), audit.ActionX509WorkloadCertDenied, "workload:"+req.SPIFFEURI, caller.Caller, 0, r, map[string]any{
					"requested_spiffe_uri": req.SPIFFEURI,
					"groups":               caller.Groups,
					"reason":               err.Error(),
				})
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			s.log.Error("policy evaluate x509 cert", "err", err)
			writeError(w, http.StatusInternalServerError, "policy evaluation failed")
			return
		}
		spiffeURI = decision.SPIFFEURI
		ttl = decision.TTL
	}

	// Renewal/anti-theft guard: when a persistent active-cert store is
	// wired, a renewal must present its identity's current or one-step-
	// previous serial. A stale/unknown serial — a superseded or fabricated
	// cert reappearing — is rejected as a possible clone and alerted on.
	// prevSerial/prevNotAfter carry the serial being rotated *from* into
	// the post-issue record (the one-step grace).
	var prevSerial string
	var prevNotAfter time.Time
	if s.activeCerts != nil {
		existing, ok, err := s.activeCerts.Get(spiffeURI)
		if err != nil {
			s.log.Error("active-cert guard: get failed; denying", "spiffe_uri", spiffeURI, "err", err)
			writeError(w, http.StatusServiceUnavailable, "active-cert store unavailable")
			return
		}
		if ok {
			presented := req.CurrentSerial
			// A non-empty serial that is the current or previous one is a
			// normal rotation. Empty never matches (an empty PreviousSerial
			// must not let an empty presented slip through).
			if presented != "" && (presented == existing.CurrentSerial || presented == existing.PreviousSerial) {
				// Normal rotation: previous := the serial rotated from.
				prevSerial = presented
				if presented == existing.CurrentSerial {
					prevNotAfter = existing.CurrentNotAfter
				} else {
					prevNotAfter = existing.PreviousNotAfter
				}
			} else if time.Now().After(existing.CurrentNotAfter) {
				// Re-enroll: the recorded cert has expired, so no valid
				// credential is in the wild — the anti-theft layer is moot
				// (caller auth + role policy still gate this request). Reset
				// the chain (previous cleared) and issue. Auto-heals the
				// lockout where an agent lost its cert and presents empty.
				s.emitAudit(r.Context(), audit.ActionX509WorkloadCertReenroll, "workload:"+spiffeURI, caller.Caller, 0, r, map[string]any{
					"spiffe_uri":        spiffeURI,
					"presented_serial":  presented,
					"expired_serial":    existing.CurrentSerial,
					"expired_not_after": existing.CurrentNotAfter,
				})
			} else {
				// Stale/unknown serial while the recorded cert is still
				// valid — a superseded or fabricated cert reappearing, i.e.
				// a possible clone. Reject and alert.
				s.emitAudit(r.Context(), audit.ActionX509WorkloadCertRollback, "workload:"+spiffeURI, caller.Caller, 0, r, map[string]any{
					"spiffe_uri":       spiffeURI,
					"presented_serial": presented,
					"current_serial":   existing.CurrentSerial,
					"previous_serial":  existing.PreviousSerial,
				})
				writeError(w, http.StatusForbidden, "presented serial is not the current or previous serial for this identity (possible clone); wait for the active cert to expire to auto re-enroll, or clear the identity's active-cert record")
				return
			}
		}
	}

	serial, err := x509engine.RandomSerial(rand.Reader)
	if err != nil {
		s.log.Error("x509 serial", "err", err)
		writeError(w, http.StatusInternalServerError, "serial generation failed")
		return
	}

	now := time.Now().UTC()
	cert, err := x509engine.SignWorkloadCert(rand.Reader, s.caSigner, issuerCert, x509engine.WorkloadCertParams{
		PublicKey:         pub,
		SPIFFEURI:         spiffeURI,
		SubjectCommonName: req.SubjectCommonName,
		ValidAfter:        now,
		ValidBefore:       now.Add(ttl),
		Serial:            serial,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Record the rotation so the next renewal can be guarded: current =
	// the cert just minted, previous = the serial it rotated from (the
	// one-step grace). Fail the request on a write error — the cert is
	// minted but unrecorded, and serving it without recording would let a
	// later rollback slip past the guard; the agent keeps its prior cert
	// and retries, so state stays consistent.
	if s.activeCerts != nil {
		if err := s.activeCerts.Upsert(store.ActiveCert{
			Identity:         spiffeURI,
			CurrentSerial:    cert.SerialNumber.String(),
			CurrentNotAfter:  cert.NotAfter.UTC(),
			PreviousSerial:   prevSerial,
			PreviousNotAfter: prevNotAfter,
		}); err != nil {
			s.log.Error("active-cert guard: record failed", "spiffe_uri", spiffeURI, "err", err)
			writeError(w, http.StatusInternalServerError, "failed to record cert issuance")
			return
		}
	}

	s.emitAudit(r.Context(), audit.ActionX509WorkloadCertSigned, "workload:"+spiffeURI, caller.Caller, 0, r, map[string]any{
		"spiffe_uri":   spiffeURI,
		"serial":       cert.SerialNumber.String(),
		"ttl_seconds":  int(ttl.Seconds()),
		"valid_before": time.Unix(cert.NotAfter.Unix(), 0).UTC(),
	})

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	writeJSON(w, http.StatusOK, signX509Response{
		Certificate: string(pemBytes),
		Serial:      cert.SerialNumber.String(),
		SPIFFEURI:   spiffeURI,
		ValidAfter:  cert.NotBefore.UTC(),
		ValidBefore: cert.NotAfter.UTC(),
	})
}

// parseX509PublicKey decodes a PEM SubjectPublicKeyInfo block and
// returns the contained public key. Accepts RSA, ECDSA, and Ed25519.
func parseX509PublicKey(raw string) (any, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("expected PEM type 'PUBLIC KEY'")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
