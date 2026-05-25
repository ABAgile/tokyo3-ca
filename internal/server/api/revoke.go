package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/krl"
)

// revokeRequest is the JSON body for POST /api/v1/ssh/revoke.
// Callers populate either Serial or KeyID (or both). Reason is
// recorded in the audit Entry's metadata and the snapshot
// annotation surfaced to the portal.
type revokeRequest struct {
	Serial uint64 `json:"serial,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// revokeResponse confirms the entry was recorded. We could return
// the full snapshot here but the round-trip cost of a per-revoke
// snapshot is wasted for the common case (operators batch).
type revokeResponse struct {
	Revoked bool `json:"revoked"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if s.krl == nil {
		writeError(w, http.StatusServiceUnavailable, "revocation store not configured")
		return
	}

	var req revokeRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Serial == 0 && req.KeyID == "" {
		writeError(w, http.StatusBadRequest, "serial or key_id is required")
		return
	}

	caller, ok := s.authenticate(w, r, nil)
	if !ok {
		return
	}

	entry := krl.Revocation{
		Serial:  req.Serial,
		KeyID:   req.KeyID,
		Reason:  req.Reason,
		Revoker: caller.Caller,
	}
	if err := s.krl.Revoke(entry); err != nil {
		if errors.Is(err, krl.ErrEmptyRevocation) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.log.Error("krl revoke", "err", err)
		writeError(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	s.emitAudit(r.Context(), audit.ActionSSHCertRevoked,
		revocationSubject(req), caller.Caller, req.Serial, r, map[string]any{
			"serial":  req.Serial,
			"key_id":  req.KeyID,
			"reason":  req.Reason,
			"revoker": caller.Caller,
		})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(revokeResponse{Revoked: true})
}

// handleRevocations returns the current snapshot. Read-only; safe
// for unauthenticated consumers when ssh-proxy operates inside the
// same trust boundary as certd, but production deployments should
// still gate it behind mTLS — clients shouldn't reveal the full
// revocation set to attackers.
func (s *Server) handleRevocations(w http.ResponseWriter, r *http.Request) {
	if s.krl == nil {
		writeError(w, http.StatusServiceUnavailable, "revocation store not configured")
		return
	}
	if _, ok := s.authenticate(w, r, nil); !ok {
		return
	}
	snap := s.krl.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

// revocationSubject produces an audit Subject string of the form
// "serial:42" or "key_id:user:alice" or both joined. Empty inputs
// fall through to "(empty)" — should be unreachable since the
// handler rejects empty revocations earlier, but defensive against
// future drift.
func revocationSubject(req revokeRequest) string {
	switch {
	case req.Serial != 0 && req.KeyID != "":
		return fmt.Sprintf("serial:%d key_id:%s", req.Serial, req.KeyID)
	case req.Serial != 0:
		return fmt.Sprintf("serial:%d", req.Serial)
	case req.KeyID != "":
		return "key_id:" + req.KeyID
	default:
		return "(empty)"
	}
}
