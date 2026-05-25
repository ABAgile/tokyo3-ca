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
	if s.x509IssuerCert == nil {
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

	serial, err := x509engine.RandomSerial(rand.Reader)
	if err != nil {
		s.log.Error("x509 serial", "err", err)
		writeError(w, http.StatusInternalServerError, "serial generation failed")
		return
	}

	now := time.Now().UTC()
	cert, err := x509engine.SignWorkloadCert(rand.Reader, s.caSigner, s.x509IssuerCert, x509engine.WorkloadCertParams{
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
