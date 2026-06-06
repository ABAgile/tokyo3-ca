package api

import (
	"net/http"
	"os"
)

// trustBundleResponse is the body of GET /api/v1/x509/trust-bundle. Bundle is
// PEM and MAY contain multiple CERTIFICATE blocks — during a CA key-rotation
// overlap it is the old⊕new set, in steady state the single issuer.
type trustBundleResponse struct {
	Bundle string `json:"trust_bundle"`
}

// handleTrustBundle serves the configured trust bundle so workloads can pull
// the current X.509 trust anchor instead of having it pushed out-of-band
// (the SPIFFE "bundle endpoint" pattern). The file is read per request, so
// an operator's `certd ca rotate` / `ca bundle` edit is served immediately.
//
// Deliberately UNAUTHENTICATED: a CA trust bundle is public material, and a
// caller may need it before (or after) it holds a valid leaf. Integrity comes
// from the TLS channel — the client has already verified certd's server cert.
func (s *Server) handleTrustBundle(w http.ResponseWriter, _ *http.Request) {
	if s.trustBundlePath == "" {
		writeError(w, http.StatusServiceUnavailable, "trust bundle not configured")
		return
	}
	data, err := os.ReadFile(s.trustBundlePath)
	if err != nil {
		s.log.Error("read trust bundle", "path", s.trustBundlePath, "err", err)
		writeError(w, http.StatusInternalServerError, "trust bundle unavailable")
		return
	}
	writeJSON(w, http.StatusOK, trustBundleResponse{Bundle: string(data)})
}
