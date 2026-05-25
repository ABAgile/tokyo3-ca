package portal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// csrfCookieName is the cookie that holds the per-browser CSRF
// token. SameSite=Lax keeps third-party POSTs from carrying it; the
// double-submit pattern then confirms the page that submitted the
// form was loaded from this same origin (and is not a cross-site
// forgery from a different tab).
const csrfCookieName = "certd_csrf"

// csrfTokenLength is the entropy bound for the token. 32 random
// bytes (256 bits) → 44-char base64 string. More than enough to
// resist online-guessing against a stateless verifier.
const csrfTokenLength = 32

// ensureCSRFToken reads the CSRF cookie from r, generating + setting
// a new one when absent or malformed. Returns the canonical token
// value the caller embeds in form templates. Setting Set-Cookie on
// every GET keeps the rotation cadence operator-tunable later
// without a schema change here.
func ensureCSRFToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && validCSRFShape(c.Value) {
		return c.Value
	}
	buf := make([]byte, csrfTokenLength)
	_, _ = rand.Read(buf)
	token := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // template reads the value via the renderer; no JS access needed but no risk either
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// validateCSRF returns true when r.PostForm["csrf_token"] matches
// the cookie value. Both sides are checked under
// [subtle.ConstantTimeCompare] to avoid leaking timing info on the
// comparison itself.
//
// The caller is expected to have already called r.ParseForm() —
// every POST handler in the portal does. validateCSRF returns false
// rather than erroring on missing cookie / missing form field so
// the handler can render a uniform "session expired or forged
// request" message.
func validateCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || !validCSRFShape(c.Value) {
		return false
	}
	got := r.PostForm.Get("csrf_token")
	if !validCSRFShape(got) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) == 1
}

// validCSRFShape is a cheap structural check — the value must
// look like a base64url string of the right length. Catches
// truncated cookies and outright junk without involving the
// constant-time compare.
func validCSRFShape(v string) bool {
	if len(v) == 0 {
		return false
	}
	// RawURLEncoding length = ceil(csrfTokenLength * 4 / 3); for
	// 32 bytes that's 43 chars. Reject anything longer than ~80
	// to bound the work; shorter than 32 is also rejected.
	if len(v) < 32 || len(v) > 80 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// isHTTPS returns true when the request arrived over TLS. Drives
// the cookie's Secure flag — set on TLS, clear over plaintext so
// dev / curl-test setups keep working.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	return false
}
