package portal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/auth/oidcclient"
	"github.com/abagile/tokyo3-base/crypto"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
)

// OIDCConfig wires native browser-based OIDC login for the portal: an
// Authorization-Code + PKCE flow against the IdP, an encrypted session cookie,
// and (optionally) an admin-group gate. When enabled it supersedes the HTTP
// Basic gate; mutations are then attributed to the signed-in user's email.
//
// Reuses base/auth/oidcclient for the token exchange and the ca OIDC verifier
// for ID-token validation, so this package owns only the browser glue: the
// authorize redirect, the session/flow cookies, and the gate.
type OIDCConfig struct {
	Issuer       string             // IdP issuer URL (e.g. https://id.example.com)
	ClientID     string             // portal's registered OIDC client_id (= ID-token audience)
	ClientSecret string             // confidential-client secret (client_secret_post)
	RedirectURL  string             // absolute https://<certd>/portal/auth/callback
	AdminGroup   string             // required group claim for access; "" ⇒ any authenticated user
	Verifier     oidc.TokenVerifier // validates the returned ID token (audience = ClientID)
	SessionKey   []byte             // 32-byte KEK sealing the session + flow cookies
	SessionTTL   time.Duration      // session lifetime; 0 ⇒ defaultSessionTTL
}

const (
	sessionCookie     = "certd_portal_session"
	flowCookie        = "certd_portal_flow"
	defaultSessionTTL = 8 * time.Hour
	flowTTL           = 10 * time.Minute
	oidcScopes        = "openid email profile groups"
)

func (c OIDCConfig) enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && c.Verifier != nil && len(c.SessionKey) > 0
}

func (c OIDCConfig) sessionTTL() time.Duration {
	if c.SessionTTL > 0 {
		return c.SessionTTL
	}
	return defaultSessionTTL
}

// session is the authenticated identity sealed into the session cookie.
type session struct {
	Subject string    `json:"sub"`
	Email   string    `json:"email"`
	Name    string    `json:"name"`
	Groups  []string  `json:"groups"`
	Expiry  time.Time `json:"exp"`
}

// oidcFlow is the per-login CSRF/PKCE state sealed into the short-lived flow
// cookie between the authorize redirect and the callback.
type oidcFlow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"` // PKCE code_verifier
	ReturnTo string `json:"return_to"`
}

type ctxKey int

const sessionCtxKey ctxKey = 0

// sessionFromCtx returns the authenticated session injected by
// requirePortalAuth, if any.
func sessionFromCtx(r *http.Request) (session, bool) {
	s, ok := r.Context().Value(sessionCtxKey).(session)
	return s, ok
}

// handleAuthLogin starts the Authorization-Code flow: it mints state, nonce,
// and a PKCE verifier, seals them into the flow cookie, and redirects to the
// IdP's authorize endpoint (requesting the groups scope so the ID token
// carries the admin-group claim).
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	state, err1 := randB64(24)
	nonce, err2 := randB64(24)
	verifier, err3 := randB64(32)
	if err1 != nil || err2 != nil || err3 != nil {
		http.Error(w, "login init failed", http.StatusInternalServerError)
		return
	}
	flow := oidcFlow{State: state, Nonce: nonce, Verifier: verifier, ReturnTo: safeReturnTo(r.URL.Query().Get("return_to"))}
	sealed, err := s.sealValue(flow)
	if err != nil {
		http.Error(w, "login init failed", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, r, flowCookie, sealed, flowTTL)

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	http.Redirect(w, r, s.authorizeURL(state, nonce, challenge), http.StatusSeeOther)
}

// authorizeURL builds the IdP /authorize redirect for the code flow. Built
// here (rather than via oidcclient.BuildAuthorizeURL) because the portal needs
// the groups scope and a confidential-client redirect URI, neither of which
// that CLI-oriented helper supports.
func (s *Server) authorizeURL(state, nonce, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.cfg.OIDC.ClientID)
	q.Set("redirect_uri", s.cfg.OIDC.RedirectURL)
	q.Set("scope", oidcScopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return strings.TrimRight(s.cfg.OIDC.Issuer, "/") + "/authorize?" + q.Encode()
}

// handleAuthCallback completes the flow: it validates the state against the
// flow cookie, exchanges the code for tokens, verifies the ID token and its
// nonce, and establishes the session cookie.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	var flow oidcFlow
	c, err := r.Cookie(flowCookie)
	if err != nil || s.openValue(c.Value, &flow) != nil {
		http.Error(w, "login session expired — start again at /portal/auth/login", http.StatusBadRequest)
		return
	}
	s.clearCookie(w, r, flowCookie)

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "IdP returned an error: "+e, http.StatusUnauthorized)
		return
	}
	if q.Get("state") != flow.State || flow.State == "" {
		http.Error(w, "state mismatch — possible CSRF; start again", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		http.Error(w, "no authorization code", http.StatusBadRequest)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.OIDC.RedirectURL)
	form.Set("client_id", s.cfg.OIDC.ClientID)
	form.Set("client_secret", s.cfg.OIDC.ClientSecret)
	form.Set("code_verifier", flow.Verifier)
	tokens, err := oidcclient.PostToken(r.Context(), s.cfg.OIDC.Issuer, form)
	if err != nil {
		s.cfg.Log.Warn("portal oidc: token exchange failed", "err", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	claims, err := s.cfg.OIDC.Verifier.Verify(r.Context(), tokens.IDToken)
	if err != nil {
		s.cfg.Log.Warn("portal oidc: id_token verify failed", "err", err)
		http.Error(w, "invalid ID token", http.StatusUnauthorized)
		return
	}
	if claims.Nonce != flow.Nonce {
		http.Error(w, "nonce mismatch — possible token replay; start again", http.StatusBadRequest)
		return
	}

	sess := session{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Groups:  claims.Groups,
		Expiry:  s.cfg.Now().Add(s.cfg.OIDC.sessionTTL()),
	}
	sealed, err := s.sealValue(sess)
	if err != nil {
		http.Error(w, "session init failed", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, r, sessionCookie, sealed, s.cfg.OIDC.sessionTTL())
	s.cfg.Log.Info("portal oidc: login", "email", claims.Email, "groups", claims.Groups)
	http.Redirect(w, r, flow.ReturnTo, http.StatusSeeOther)
}

// handleAuthLogout clears the session cookie.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, r, sessionCookie)
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// requirePortalAuth gates every portal route behind a valid session and, when
// AdminGroup is set, membership in it. /healthz and the /auth/* endpoints are
// exempt. A GET without a session redirects to login (carrying return_to); a
// non-GET answers 401 (its body can't survive a redirect round-trip).
func (s *Server) requirePortalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/auth/login", "/auth/callback", "/auth/logout":
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := s.readSession(r)
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if g := s.cfg.OIDC.AdminGroup; g != "" && !slices.Contains(sess.Groups, g) {
			http.Error(w, "forbidden: requires membership in "+g, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess)))
	})
}

// readSession returns the live (unexpired) session from the request cookie.
func (s *Server) readSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	var sess session
	if err := s.openValue(c.Value, &sess); err != nil {
		return session{}, false
	}
	if s.cfg.Now().After(sess.Expiry) {
		return session{}, false
	}
	return sess, true
}

// ── cookie sealing ───────────────────────────────────────────────────────

func (s *Server) sealValue(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sealed, err := crypto.Seal(s.cfg.OIDC.SessionKey, b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Server) openValue(val string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		return err
	}
	pt, err := crypto.Open(s.cfg.OIDC.SessionKey, raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(pt, dst)
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/portal/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  s.cfg.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/portal/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// randB64 returns n random bytes as base64url (RFC 4648 §5, no padding).
func randB64(n int) (string, error) {
	b, err := crypto.RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// safeReturnTo confines the post-login redirect to a local absolute path, so a
// crafted return_to can't bounce the browser to an attacker origin.
func safeReturnTo(p string) string {
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
		return p
	}
	return "/"
}

// oidcCaller returns the audit caller for the signed-in user, or "" when no
// OIDC session is present (the basic-auth path then applies).
func (s *Server) oidcCaller(r *http.Request) string {
	if sess, ok := sessionFromCtx(r); ok && sess.Email != "" {
		return audit.CallerPrefixOIDC + sess.Email
	}
	return ""
}
