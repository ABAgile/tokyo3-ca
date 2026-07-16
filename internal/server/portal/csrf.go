package portal

import (
	"net/http"

	"github.com/abagile/tokyo3-base/csrf"
)

// csrfScope partitions the session-bound CSRF tokens minted for this
// portal. One scope for all forms: pages mix multiple form actions (e.g.
// the role detail page carries the delete button), so per-action scoping
// would need per-form token plumbing for marginal gain.
const csrfScope = "certd-portal"

// csrfToken returns the anti-CSRF token handlers embed in form templates —
// session-bound in both auth modes (an HMAC over the sealed session's
// CSRF secret; see base/csrf), differing only in who establishes the
// session:
//
//   - OIDC mode: the login callback issued the session; the Gate
//     guarantees it exists by the time a form renders, so a missing
//     session here just yields "" — the eventual POST is bounced by the
//     Gate anyway, and an empty embedded token fails validation uniformly.
//   - Basic-auth mode: there is no login event (Basic auth
//     re-authenticates every request), so nothing naturally issues a
//     session. The first form render mints an ANONYMOUS one lazily —
//     identity fields empty, only the CSRF secret populated — purely as
//     the secret's transport; Basic auth remains the actual gate on every
//     request. Stable until expiry (no rotation), so long-running /
//     multi-tab submissions keep working.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if tok, err := s.sess.CSRFToken(r, csrfScope); err == nil {
		return tok
	}
	if s.auth != nil {
		return "" // OIDC mode: never mint sessions outside the login flow
	}
	anon, err := s.sess.NewSession()
	if err != nil {
		return "" // out of entropy — fails closed; validation rejects ""
	}
	if err := s.sess.IssueSession(w, r, anon); err != nil {
		return ""
	}
	// The fresh session cookie is on w, not r, so CSRFToken(r) can't see
	// it yet — mint the first token straight from the new secret.
	tok, err := csrf.Token(anon.CSRFSecret, csrfScope)
	if err != nil {
		return ""
	}
	return tok
}

// checkCSRF verifies the csrf_token form field on a POST against the
// request's session — the same scheme csrfToken used at render time,
// regardless of auth mode. The caller has already run r.ParseForm().
func (s *Server) checkCSRF(r *http.Request) bool {
	return s.sess.ValidateCSRF(r, r.PostForm.Get("csrf_token"), csrfScope)
}
