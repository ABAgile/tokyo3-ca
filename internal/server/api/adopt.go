package api

import "net/http"

// adoptRequest is the body of POST /api/v1/x509/adopt: a workload telling
// certd it has durably persisted the cert with Serial, so certd can drop the
// one-step rotation grace (collapse previous) for that identity.
type adoptRequest struct {
	SPIFFEURI string `json:"spiffe_uri"`
	Serial    string `json:"serial"`
}

// adoptResponse reports whether the grace was collapsed. Adopted is false
// (not an error) when Serial isn't the identity's current serial, the
// identity is unknown, or it's locked — all benign for the caller.
type adoptResponse struct {
	Adopted bool `json:"adopted"`
}

// handleAdoptX509 collapses the {current, previous} window to {current} once a
// workload confirms it adopted the current cert (serial == recorded current).
// This shrinks the window the rotated-from serial stays acceptable from "until
// the next renewal" to "until this ack". It mints nothing and cannot escalate,
// so it requires authentication but not role-table authorization; the
// serial==current check (enforced in the store) is the real gate — only a
// holder of the current cert knows its serial. A no-op (Adopted=false) when no
// guard store is wired.
func (s *Server) handleAdoptX509(w http.ResponseWriter, r *http.Request) {
	var req adoptRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.SPIFFEURI == "" || req.Serial == "" {
		writeError(w, http.StatusBadRequest, "spiffe_uri and serial are required")
		return
	}
	if _, ok := s.authenticate(w, r, nil); !ok {
		return // authenticate wrote the 401
	}
	if s.activeCerts == nil {
		writeJSON(w, http.StatusOK, adoptResponse{Adopted: false}) // no guard ⇒ nothing to collapse
		return
	}
	adopted, err := s.activeCerts.AdoptCurrent(req.SPIFFEURI, req.Serial)
	if err != nil {
		s.log.Error("active-cert guard: adopt failed", "spiffe_uri", req.SPIFFEURI, "err", err)
		writeError(w, http.StatusServiceUnavailable, "active-cert store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, adoptResponse{Adopted: adopted})
}
