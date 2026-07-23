// Package portal serves the certd admin web UI — role-table CRUD,
// host registry browser, audit viewer, and revocations. Server-rendered
// HTML, no client-side framework; pages render fully on the server and
// submit via standard form posts.
//
// The portal is mounted by [Server.Routes] at /portal/. Each page is
// a single template inheriting from [baseTemplate] so the nav and
// chrome stay consistent. (Recorded-session list + asciinema replay
// lives in ssh-proxyd's own portal — it produces the recordings — not
// here in the CA.)
package portal

import (
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/crypto"
	"github.com/abagile/tokyo3-base/httpauth"
	"github.com/abagile/tokyo3-base/oidc"
	"github.com/abagile/tokyo3-base/session"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
)

// appCSS is the portal stylesheet implementing ca/DESIGN.md. Embedded so
// the portal stays a single self-contained binary.
//
//go:embed static/app.css
var appCSS []byte

// OIDCConfig wires native browser-based OIDC login for the portal: an
// Authorization-Code + PKCE flow against the IdP, an encrypted session cookie,
// and (optionally) an admin-group gate. When enabled it supersedes the HTTP
// Basic gate; mutations are then attributed to the signed-in user's email.
//
// The Authorization-Code + PKCE flow is implemented by base/oidc.Authenticator;
// the session cookie, gate, and CSRF tokens by the base/session.Manager it's
// constructed with. This struct is the wiring certd reads from env and passes
// through to both.
type OIDCConfig struct {
	Issuer       string             // IdP issuer URL (e.g. https://id.example.com)
	ClientID     string             // portal's registered OIDC client_id (= ID-token audience)
	ClientSecret string             // confidential-client secret (client_secret_post)
	RedirectURL  string             // absolute https://<certd>/portal/auth/callback
	AdminGroup   string             // required group claim for access; "" ⇒ any authenticated user
	Verifier     oidc.TokenVerifier // validates the returned ID token (audience = ClientID)
	// SessionKey is a 32-byte KEK sealing the session + flow cookies when
	// OIDC login is active. Independent of the rest of this struct: also
	// read by New even when OIDC isn't configured, to seal the Basic-auth
	// path's anonymous CSRF-carrier session cookie with a key stable
	// across restarts. Empty there ⇒ New generates an ephemeral
	// per-process key instead (restarting then invalidates in-flight CSRF
	// tokens — an affected tab needs a reload).
	SessionKey []byte
	SessionTTL time.Duration // session lifetime; 0 ⇒ base default
}

func (c OIDCConfig) enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && c.Verifier != nil && len(c.SessionKey) > 0
}

// RevocationStore is the subset of [krl.Store] the revocations page
// needs. Defined here (and not as an alias) so tests can stub the
// source without a full krl.InMemoryStore.
type RevocationStore interface {
	Revoke(r krl.Revocation) error
	Snapshot() krl.Snapshot
}

// HostStore is the subset of [mtls.Store] the hosts page needs.
// Defined here (and not as an alias) so tests can stub the source
// without seeding the full mTLS registry.
type HostStore interface {
	All() []mtls.Principal
}

// RoleStore is the subset of [policy.Store] the roles list/detail
// pages need. Defined here (and not as an alias) so tests can stub
// the source without spinning up the full policy.Engine.
type RoleStore interface {
	All() []policy.Role
}

// MutableRoleStore extends [RoleStore] with the write surface
// the CRUD-write routes use. Implementations include
// [policy.InMemoryStore]. When the portal's Config wires only a
// read-only RoleStore, the create/edit/delete routes return 405.
//
// SECURITY: this slice does not implement CSRF protection. Mounting
// the portal where the create/edit/delete routes are reachable by
// unauthenticated browsers exposes the role table to cross-site
// forgery. The deferred portal-auth slice will gate /portal/* behind
// OIDC and add a session-bound CSRF token before this surface is
// production-safe.
type MutableRoleStore interface {
	RoleStore
	ByName(name string) (policy.Role, bool)
	Add(role policy.Role) error
	Replace(oldName string, newRole policy.Role) error
	Delete(name string) error
}

// Server is the portal's HTTP handler. Construct via [New] and mount
// the result of [Server.Routes] under the prefix you want (typically
// "/portal/" — the routes are absolute internally so the prefix is
// caller-chosen).
type Server struct {
	cfg   Config
	pages map[string]*template.Template
	auth  *oidc.Authenticator // native-OIDC login flow; nil when OIDC is not configured (Basic-auth path)
	// sess is always non-nil: in OIDC mode it is the login session + gate;
	// in Basic-auth mode it only transports the anonymous CSRF secret (see
	// csrfToken) — Basic auth stays the actual gate, and a different cookie
	// prefix keeps the two modes' cookies mutually unreadable even across a
	// mode switch under the same key.
	sess *session.Manager
}

// Config wires a [Server]. Optional fields default sensibly.
type Config struct {
	// Version is the build-time semver / commit identifier. Not
	// currently rendered in the portal chrome; accepted so callers
	// keep wiring it.
	Version string

	// Log is the structured logger used for request-time events.
	// nil ⇒ slog.Default.
	Log *slog.Logger

	// Now is the clock used for session/CSRF lifetimes. nil ⇒
	// time.Now. Tests inject a fixed clock for stable assertions.
	Now func() time.Time

	// RoleStore is the source for the /roles list and detail pages.
	// When nil, those routes return 503 — the rest of the portal
	// still works (useful for headless / no-policy deployments).
	//
	// When the supplied store also satisfies [MutableRoleStore]
	// (which [policy.InMemoryStore] does), the CRUD-write routes
	// (/roles/new, /roles/{name}/edit, /roles/{name}/delete) are
	// activated. Read-only stores leave those routes returning 405.
	RoleStore RoleStore

	// HostStore powers the /hosts page (registered workload mTLS
	// principals). When nil, /hosts returns 503.
	HostStore HostStore

	// AuditStore powers the /audit page (live tail of every audit
	// stream the operator wires up — certd's own + ssh-proxyd's).
	// When nil, /audit returns 503.
	AuditStore AuditStore

	// RevocationStore powers the /portal/revocations page and the
	// revoke form. When nil, the page returns 503. Same store
	// instance should back the API's KRL field — the portal mutates
	// in place, and the API endpoint reads from the same data.
	RevocationStore RevocationStore

	// BasicAuth gates the portal behind HTTP Basic credentials. When
	// Username + Password are both populated, every /portal/* request
	// (except /healthz) must present matching Basic creds; otherwise
	// the portal stays open and operators front it with their own
	// identity-aware edge.
	//
	// Ignored when OIDC is enabled — native OIDC login supersedes it.
	BasicAuth httpauth.BasicAuthConfig

	// OIDC, when enabled (see OIDCConfig.enabled), gates the portal behind
	// native browser OIDC login + an optional admin-group check, and
	// attributes mutations to the signed-in user. Supersedes BasicAuth.
	OIDC OIDCConfig
}

// New parses the portal templates and returns a ready [Server].
// Returns an error rather than panicking so callers see template
// authoring bugs at startup.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pages, err := parsePages()
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	s := &Server{cfg: cfg, pages: pages}
	if cfg.OIDC.enabled() {
		sess, err := session.New(session.Config{
			RequiredGroup: cfg.OIDC.AdminGroup,
			SessionKey:    cfg.OIDC.SessionKey,
			SessionTTL:    cfg.OIDC.SessionTTL,
			CookiePrefix:  "certd_portal",
			// The api server mounts this tree under StripPrefix(basePath), so
			// the Manager matches routes in stripped space but must emit
			// browser-space redirects and cookie scopes — without this the
			// login redirect points outside the mount and 404s.
			BasePath: basePath,
			// /auth/callback must be exempt here (not just /healthz) or the
			// OIDC callback itself gets redirected to login before it can
			// complete — oidc.NewAuthenticator verifies this and refuses to
			// construct otherwise. The signed-out page is exempt because it
			// renders after the session is cleared, and the stylesheet is
			// exempt so that page isn't served unstyled.
			ExemptPaths: []string{"/healthz", "/auth/callback", "/auth/signed-out", "/static/app.css"},
			Now:         cfg.Now,
			Log:         cfg.Log,
		})
		if err != nil {
			return nil, fmt.Errorf("portal session: %w", err)
		}
		auth, err := oidc.NewAuthenticator(oidc.AuthenticatorConfig{
			Issuer:       cfg.OIDC.Issuer,
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			RedirectURL:  cfg.OIDC.RedirectURL,
			Verifier:     cfg.OIDC.Verifier,
			// The flow cookie shares sess's key, path scope, and clock under its
			// own name, so there's nothing left to keep in sync between the two
			// configs beyond this one line.
			FlowCookie: sess.SiblingCookie("flow"),
			// CookiePrefix/Now/Log are NOT repeated here — all logging derives
			// from sess (session.Manager.Log).
		}, sess)
		if err != nil {
			return nil, fmt.Errorf("portal oidc: %w", err)
		}
		s.sess = sess
		s.auth = auth
		return s, nil
	}
	// Basic-auth mode: no login flow, but CSRF tokens still need a sealed
	// session to bind to — csrfToken lazily issues an anonymous one. The
	// key is the configured SessionKey when set (stable across restarts),
	// else an ephemeral per-process one. The distinct cookie prefix keeps
	// this cookie from ever being readable as an OIDC login session.
	key := cfg.OIDC.SessionKey
	if len(key) == 0 {
		var err error
		key, err = crypto.RandomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("portal csrf session key: %w", err)
		}
	}
	sess, err := session.New(session.Config{
		SessionKey:   key,
		CookiePrefix: "certd_csrf",
		BasePath:     basePath,
		Now:          cfg.Now,
		Log:          cfg.Log,
	})
	if err != nil {
		return nil, fmt.Errorf("portal csrf session: %w", err)
	}
	s.sess = sess
	return s, nil
}

// render dispatches to the per-page template set keyed by name and
// executes its "page" entry — the in-set wrapper that pulls the
// page-specific title/body into the shared base layout.
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	// Every portal page is authenticated, dynamic HTML; form pages embed
	// anti-CSRF tokens. no-store keeps them out of browser/shared caches —
	// the cached-HTML token-leak channel — and off the back-forward cache.
	w.Header().Set("Cache-Control", "no-store")
	tmpl, ok := s.pages[page]
	if !ok {
		s.cfg.Log.Error("portal render: unknown page", "page", page)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "page", data); err != nil {
		s.cfg.Log.Error("portal render", "page", page, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// Routes returns the portal's handler tree. Mount under any prefix;
// the routes use a relative path so the prefix is caller-chosen.
// When [Config.BasicAuth] is enabled, every request except /healthz
// must present matching Basic credentials — operators get a real
// auth gate without standing up oauth2-proxy in front.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /static/app.css", s.handleStaticCSS)
	mux.HandleFunc("GET /roles", s.handleRolesIndex)
	mux.HandleFunc("GET /roles/new", s.handleRoleNewForm)
	mux.HandleFunc("POST /roles/new", s.handleRoleCreate)
	mux.HandleFunc("GET /roles/{name}", s.handleRoleDetail)
	mux.HandleFunc("GET /roles/{name}/edit", s.handleRoleEditForm)
	mux.HandleFunc("POST /roles/{name}/edit", s.handleRoleUpdate)
	mux.HandleFunc("POST /roles/{name}/delete", s.handleRoleDelete)
	mux.HandleFunc("GET /hosts", s.handleHostsIndex)
	mux.HandleFunc("GET /audit", s.handleAuditIndex)
	mux.HandleFunc("GET /revocations", s.handleRevocationsIndex)
	mux.HandleFunc("POST /revocations", s.handleRevocationsCreate)
	if s.auth != nil {
		mux.HandleFunc("GET /auth/login", s.auth.LoginHandler())
		mux.HandleFunc("GET /auth/callback", s.auth.CallbackHandler())
		mux.HandleFunc("POST /auth/logout", s.handleLogout)
		mux.HandleFunc("GET /auth/signed-out", s.handleSignedOut)
		return s.sess.Gate(mux)
	}
	return httpauth.BasicAuth(s.cfg.BasicAuth, mux, "/healthz")
}

// baseData carries the fields the shared base layout renders on every
// page: footer chrome (version/clock), the sidebar's navigation state,
// and the signed-in identity for the sidebar footer.
type baseData struct {
	ActivePage string       // sidebar active-link key: home/roles/hosts/audit/revocations
	UserEmail  string       // signed-in identity; empty when neither OIDC nor Basic supplies one
	SignOut    bool         // OIDC mode only: render the POST sign-out form
	Nav        []navSection // sidebar sections; planned entries render non-interactive
}

// navSection is one labeled group of sidebar destinations.
type navSection struct {
	Label string
	Items []pageEntry
}

// baseData assembles the per-request template chrome. The active page
// highlights the sidebar link; the identity comes from the OIDC session
// when present, else the Basic-auth username.
func (s *Server) baseData(r *http.Request, active string) baseData {
	b := baseData{
		ActivePage: active,
		SignOut:    s.auth != nil,
	}
	if sess, ok := session.SessionFromContext(r.Context()); ok && sess.Email != "" {
		b.UserEmail = sess.Email
	} else if u, _, ok := r.BasicAuth(); ok && u != "" {
		b.UserEmail = u
	}
	pages := s.landingPages()
	b.Nav = []navSection{
		{Label: "Access", Items: pages[0:2]},
		{Label: "Operations", Items: pages[2:4]},
	}
	return b
}

// indexData is the model passed to the landing page template.
type indexData struct {
	baseData
	Pages []pageEntry
}

type pageEntry struct {
	Name        string
	Path        string
	Key         string // sidebar active-link key (matches baseData.ActivePage)
	Description string
	Status      string // "ready" or "planned"
}

// landingPages returns the dashboard's nav entries. Each page flips
// to "ready" when its data source is wired; otherwise stays planned.
func (s *Server) landingPages() []pageEntry {
	status := func(wired bool) string {
		if wired {
			return "ready"
		}
		return "planned"
	}
	return []pageEntry{
		{Name: "Roles", Path: "/roles", Key: "roles", Description: "Role-table viewer: group → principals + host patterns", Status: status(s.cfg.RoleStore != nil)},
		{Name: "Hosts", Path: "/hosts", Key: "hosts", Description: "Registered workload mTLS principals (SPIFFE / email SANs → group claims)", Status: status(s.cfg.HostStore != nil)},
		{Name: "Revocations", Path: "/revocations", Key: "revocations", Description: "Revoked SSH certs (ssh-proxyd polls this set to refuse handshakes)", Status: status(s.cfg.RevocationStore != nil)},
		{Name: "Audit log", Path: "/audit", Key: "audit", Description: "Live audit-event viewer (NATS JetStream tail)", Status: status(s.cfg.AuditStore != nil)},
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, "index", indexData{
		baseData: s.baseData(r, "home"),
		Pages:    s.landingPages(),
	})
}

// rolesIndexData is the model passed to the roles list template.
type rolesIndexData struct {
	baseData
	Roles []policy.Role
}

func (s *Server) handleRolesIndex(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RoleStore == nil {
		http.Error(w, "role store not configured", http.StatusServiceUnavailable)
		return
	}
	s.render(w, "roles", rolesIndexData{
		baseData: s.baseData(r, "roles"),
		Roles:    s.cfg.RoleStore.All(),
	})
}

// roleDetailData is the model for a single-role page. Found indicates
// whether the requested role exists; templates render a 404-style
// message when false.
type roleDetailData struct {
	baseData
	Name      string
	Role      policy.Role
	Found     bool
	CSRFToken string // for the inline delete form
}

func (s *Server) handleRoleDetail(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RoleStore == nil {
		http.Error(w, "role store not configured", http.StatusServiceUnavailable)
		return
	}
	name := r.PathValue("name")
	data := roleDetailData{
		baseData:  s.baseData(r, "roles"),
		Name:      name,
		CSRFToken: s.csrfToken(w, r),
	}
	for _, role := range s.cfg.RoleStore.All() {
		if role.Name == name {
			data.Role = role
			data.Found = true
			break
		}
	}
	if !data.Found {
		w.WriteHeader(http.StatusNotFound)
	}
	s.render(w, "role_detail", data)
}

// roleFormData is the model for the create/edit role pages. Populated
// either from an existing role (edit) or from the request body
// (re-render on validation error so the user keeps their input).
type roleFormData struct {
	baseData

	Mode       string // "create" or "edit"
	FormAction string
	Submit     string // submit-button label
	Error      string // validation error to surface above the form
	CSRFToken  string // session-bound anti-CSRF token embedded as a hidden input

	// Editing an existing role: OriginalName is the lookup key; Form
	// is the values to render in inputs.
	OriginalName string
	Form         roleFormFields
}

// roleFormFields mirrors policy.Role but uses string fields so HTML
// forms can render input values verbatim (and round-trip on
// validation failure).
type roleFormFields struct {
	Name                  string
	GroupClaim            string
	AllowedPrincipals     string // newline-separated
	HostPatterns          string // newline-separated
	SPIFFEPatterns        string // newline-separated
	MaxUserCertTTLSeconds string // integer seconds, aligned with the workloads spec
	MaxHostCertTTLSeconds string
	MaxX509CertTTLSeconds string
	DefaultExtensions     string // "key=value" per line; empty value renders as bare "key"
}

func (s *Server) handleRoleNewForm(w http.ResponseWriter, r *http.Request) {
	if s.roleWriter(r) == nil {
		http.Error(w, "role store is read-only", http.StatusMethodNotAllowed)
		return
	}
	s.render(w, "role_form", roleFormData{
		baseData:   s.baseData(r, "roles"),
		Mode:       "create",
		FormAction: "/roles/new",
		Submit:     "Create role",
		CSRFToken:  s.csrfToken(w, r),
	})
}

func (s *Server) handleRoleCreate(w http.ResponseWriter, r *http.Request) {
	rw := s.roleWriter(r)
	if rw == nil {
		http.Error(w, "role store is read-only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "session expired or forged request — reload the page and try again", http.StatusForbidden)
		return
	}
	role, fields, err := parseRoleForm(r)
	if err != nil {
		s.renderFormError(w, r, "create", "/roles/new", "Create role", "", fields, err)
		return
	}
	if err := rw.Add(role); err != nil {
		s.renderFormError(w, r, "create", "/roles/new", "Create role", "", fields, err)
		return
	}
	s.cfg.Log.Info("portal: role created", "name", role.Name, "caller", rw.caller)
	http.Redirect(w, r, basePath+"/roles/"+role.Name, http.StatusSeeOther)
}

func (s *Server) handleRoleEditForm(w http.ResponseWriter, r *http.Request) {
	rw := s.roleWriter(r)
	if rw == nil {
		http.Error(w, "role store is read-only", http.StatusMethodNotAllowed)
		return
	}
	name := r.PathValue("name")
	role, ok := rw.byName(name)
	if !ok {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}
	s.render(w, "role_form", roleFormData{
		baseData:     s.baseData(r, "roles"),
		Mode:         "edit",
		FormAction:   "/roles/" + name + "/edit",
		Submit:       "Save changes",
		OriginalName: name,
		Form:         roleToForm(role),
		CSRFToken:    s.csrfToken(w, r),
	})
}

func (s *Server) handleRoleUpdate(w http.ResponseWriter, r *http.Request) {
	rw := s.roleWriter(r)
	if rw == nil {
		http.Error(w, "role store is read-only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "session expired or forged request — reload the page and try again", http.StatusForbidden)
		return
	}
	oldName := r.PathValue("name")
	role, fields, err := parseRoleForm(r)
	if err != nil {
		s.renderFormError(w, r, "edit", "/roles/"+oldName+"/edit", "Save changes", oldName, fields, err)
		return
	}
	if err := rw.Replace(oldName, role); err != nil {
		s.renderFormError(w, r, "edit", "/roles/"+oldName+"/edit", "Save changes", oldName, fields, err)
		return
	}
	s.cfg.Log.Info("portal: role updated", "old_name", oldName, "name", role.Name, "caller", rw.caller)
	http.Redirect(w, r, basePath+"/roles/"+role.Name, http.StatusSeeOther)
}

func (s *Server) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	rw := s.roleWriter(r)
	if rw == nil {
		http.Error(w, "role store is read-only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "session expired or forged request — reload the page and try again", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	if err := rw.Delete(name); err != nil {
		if errors.Is(err, policy.ErrRoleNotFound) {
			http.Error(w, "role not found", http.StatusNotFound)
			return
		}
		s.cfg.Log.Error("portal: role delete", "name", name, "err", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	s.cfg.Log.Info("portal: role deleted", "name", name, "caller", rw.caller)
	http.Redirect(w, r, basePath+"/roles", http.StatusSeeOther)
}

// hostsIndexData is the model for the hosts page.
type hostsIndexData struct {
	baseData
	Hosts []mtls.Principal
}

func (s *Server) handleHostsIndex(w http.ResponseWriter, r *http.Request) {
	if s.cfg.HostStore == nil {
		http.Error(w, "host store not configured", http.StatusServiceUnavailable)
		return
	}
	hosts := s.cfg.HostStore.All()
	// Sort by MatchedSAN for deterministic rendering — map iteration
	// order in the in-memory store would otherwise churn the page on
	// every refresh.
	for i := 1; i < len(hosts); i++ {
		for j := i; j > 0 && hosts[j-1].MatchedSAN > hosts[j].MatchedSAN; j-- {
			hosts[j-1], hosts[j] = hosts[j], hosts[j-1]
		}
	}
	s.render(w, "hosts", hostsIndexData{
		baseData: s.baseData(r, "hosts"),
		Hosts:    hosts,
	})
}

// revocationsIndexData is the model for the revocations list +
// create form. Error is non-empty when a POST validation failed.
// FormSerial / FormKeyID / FormReason preserve the user's typed
// input on validation failure (just like the role form does).
type revocationsIndexData struct {
	baseData
	Entries    []krl.Revocation
	Error      string
	CSRFToken  string
	FormSerial string
	FormKeyID  string
	FormReason string
}

func (s *Server) handleRevocationsIndex(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RevocationStore == nil {
		http.Error(w, "revocation store not configured", http.StatusServiceUnavailable)
		return
	}
	s.render(w, "revocations", revocationsIndexData{
		baseData:  s.baseData(r, "revocations"),
		Entries:   s.cfg.RevocationStore.Snapshot().Entries,
		CSRFToken: s.csrfToken(w, r),
	})
}

func (s *Server) handleRevocationsCreate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RevocationStore == nil {
		http.Error(w, "revocation store not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "session expired or forged request — reload the page and try again", http.StatusForbidden)
		return
	}
	rawSerial := strings.TrimSpace(r.PostForm.Get("serial"))
	keyID := strings.TrimSpace(r.PostForm.Get("key_id"))
	reason := strings.TrimSpace(r.PostForm.Get("reason"))

	var serial uint64
	if rawSerial != "" {
		n, err := parseUint64(rawSerial)
		if err != nil {
			s.renderRevocationError(w, r, "serial "+rawSerial+" is not a valid unsigned integer",
				rawSerial, keyID, reason)
			return
		}
		serial = n
	}
	if serial == 0 && keyID == "" {
		s.renderRevocationError(w, r, "serial or key_id is required",
			rawSerial, keyID, reason)
		return
	}
	if err := s.cfg.RevocationStore.Revoke(krl.Revocation{
		Serial:  serial,
		KeyID:   keyID,
		Reason:  reason,
		Revoker: "portal",
	}); err != nil {
		s.renderRevocationError(w, r, err.Error(), rawSerial, keyID, reason)
		return
	}
	s.cfg.Log.Info("portal: cert revoked", "serial", serial, "key_id", keyID, "reason", reason)
	http.Redirect(w, r, basePath+"/revocations", http.StatusSeeOther)
}

func (s *Server) renderRevocationError(w http.ResponseWriter, r *http.Request, msg, serial, keyID, reason string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "revocations", revocationsIndexData{
		baseData:   s.baseData(r, "revocations"),
		Entries:    s.cfg.RevocationStore.Snapshot().Entries,
		Error:      msg,
		CSRFToken:  s.csrfToken(w, r),
		FormSerial: serial,
		FormKeyID:  keyID,
		FormReason: reason,
	})
}

// parseUint64 is the local strconv.ParseUint analog used by the
// revoke form. Keeps the import surface tight (the renderer file
// avoids strconv otherwise).
func parseUint64(s string) (uint64, error) {
	var out uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q", c)
		}
		next := out*10 + uint64(c-'0')
		if next < out { // overflow
			return 0, fmt.Errorf("overflow")
		}
		out = next
	}
	return out, nil
}

// auditIndexData is the model for the audit list page.
type auditIndexData struct {
	baseData
	Events []AuditEvent
}

func (s *Server) handleAuditIndex(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuditStore == nil {
		http.Error(w, "audit store not configured", http.StatusServiceUnavailable)
		return
	}
	s.render(w, "audit", auditIndexData{
		baseData: s.baseData(r, "audit"),
		Events:   s.cfg.AuditStore.Events(),
	})
}

// renderFormError re-renders the form with the user's input intact
// plus an error banner. Centralized so create/edit share the same
// error UX. The CSRF token is sourced from the existing cookie (the
// browser carries it across the failing POST + the re-render), so
// the user can re-submit without reloading.
func (s *Server) renderFormError(w http.ResponseWriter, r *http.Request, mode, action, submit, originalName string, fields roleFormFields, err error) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "role_form", roleFormData{
		baseData:     s.baseData(r, "roles"),
		Mode:         mode,
		FormAction:   action,
		Submit:       submit,
		Error:        err.Error(),
		OriginalName: originalName,
		Form:         fields,
		CSRFToken:    s.csrfToken(w, r),
	})
}

// handleHealthz lets external watchdogs probe the portal without
// triggering a full render. Returns 200 with a tiny plaintext body.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

// handleStaticCSS serves the embedded portal stylesheet (ca/DESIGN.md).
func (s *Server) handleStaticCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(appCSS)
}

// logoutRedirect rewrites the session LogoutHandler's post-clear redirect.
// The base handler bounces to the login route, which immediately restarts
// the OIDC flow — and because the IdP typically still holds its own live
// SSO session, the user is silently signed straight back in, making logout
// look like a no-op. Landing on the neutral signed-out page instead keeps
// the local logout observable and leaves re-login an explicit action.
type logoutRedirect struct {
	http.ResponseWriter
}

func (w *logoutRedirect) WriteHeader(code int) {
	if code == http.StatusSeeOther {
		w.Header().Set("Location", basePath+"/auth/signed-out")
	}
	w.ResponseWriter.WriteHeader(code)
}

// handleLogout clears the portal session (delegating the cookie-clearing
// to the base session manager) and lands on the signed-out page. OIDC
// mode only — the Basic-auth path has no logout semantics.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sess.LogoutHandler()(&logoutRedirect{w}, r)
}

// handleSignedOut renders the post-logout confirmation page. Exempt from
// the session gate (after logout there is no session) and deliberately
// not auto-starting a new login — see logoutRedirect.
func (s *Server) handleSignedOut(w http.ResponseWriter, r *http.Request) {
	s.render(w, "signed_out", s.baseData(r, ""))
}

// parseRoleForm reads the form values from r and returns a
// [policy.Role] plus the form-field representation that should be
// re-rendered on validation failure (so the user keeps their typed
// input). The error is form-friendly: a single string describing
// what to fix.
func parseRoleForm(r *http.Request) (policy.Role, roleFormFields, error) {
	if err := r.ParseForm(); err != nil {
		return policy.Role{}, roleFormFields{}, fmt.Errorf("parse form: %w", err)
	}
	get := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }

	fields := roleFormFields{
		Name:                  get("name"),
		GroupClaim:            get("group_claim"),
		AllowedPrincipals:     r.PostForm.Get("allowed_principals"),
		HostPatterns:          r.PostForm.Get("host_patterns"),
		SPIFFEPatterns:        r.PostForm.Get("spiffe_patterns"),
		MaxUserCertTTLSeconds: get("max_user_cert_ttl_seconds"),
		MaxHostCertTTLSeconds: get("max_host_cert_ttl_seconds"),
		MaxX509CertTTLSeconds: get("max_x509_cert_ttl_seconds"),
		DefaultExtensions:     r.PostForm.Get("default_extensions"),
	}

	if fields.Name == "" {
		return policy.Role{}, fields, errors.New("name is required")
	}
	if fields.GroupClaim == "" {
		return policy.Role{}, fields, errors.New("group_claim is required")
	}

	role := policy.Role{
		Name:              fields.Name,
		GroupClaim:        fields.GroupClaim,
		AllowedPrincipals: splitLines(fields.AllowedPrincipals),
		HostPatterns:      splitLines(fields.HostPatterns),
		SPIFFEPatterns:    splitLines(fields.SPIFFEPatterns),
	}

	// All three TTL caps are plain integer seconds, aligned with the
	// workloads spec's ttl_seconds.
	for _, tc := range []struct {
		raw  string
		dest *int64
		name string
	}{
		{fields.MaxUserCertTTLSeconds, &role.MaxUserCertTTLSeconds, "max_user_cert_ttl_seconds"},
		{fields.MaxHostCertTTLSeconds, &role.MaxHostCertTTLSeconds, "max_host_cert_ttl_seconds"},
		{fields.MaxX509CertTTLSeconds, &role.MaxX509CertTTLSeconds, "max_x509_cert_ttl_seconds"},
	} {
		if tc.raw == "" {
			continue
		}
		secs, err := strconv.ParseInt(tc.raw, 10, 64)
		if err != nil {
			return policy.Role{}, fields, fmt.Errorf("%s %q: %w", tc.name, tc.raw, err)
		}
		if secs < 0 {
			return policy.Role{}, fields, fmt.Errorf("%s must be non-negative", tc.name)
		}
		*tc.dest = secs
	}

	if exts, err := parseExtensions(fields.DefaultExtensions); err != nil {
		return policy.Role{}, fields, err
	} else if len(exts) > 0 {
		role.DefaultExtensions = exts
	}

	return role, fields, nil
}

// splitLines splits raw on newlines, trims each piece, and drops
// empties. Used for the multi-line form fields (principals/patterns).
func splitLines(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for line := range strings.SplitSeq(raw, "\n") {
		if v := strings.TrimSpace(line); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseExtensions parses a multi-line "key=value" block. Bare keys
// (no "=") are accepted with an empty value — matches sshd's
// permit-pty / permit-port-forwarding extension style.
func parseExtensions(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, hasEq := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("default_extensions: line %q has empty key", line)
		}
		if hasEq {
			out[key] = strings.TrimSpace(value)
		} else {
			out[key] = ""
		}
	}
	return out, nil
}

// roleToForm pre-fills a roleFormFields from an existing policy.Role.
// The inverse of parseRoleForm — used by the edit page.
func roleToForm(r policy.Role) roleFormFields {
	return roleFormFields{
		Name:                  r.Name,
		GroupClaim:            r.GroupClaim,
		AllowedPrincipals:     strings.Join(r.AllowedPrincipals, "\n"),
		HostPatterns:          strings.Join(r.HostPatterns, "\n"),
		SPIFFEPatterns:        strings.Join(r.SPIFFEPatterns, "\n"),
		MaxUserCertTTLSeconds: secsString(r.MaxUserCertTTLSeconds),
		MaxHostCertTTLSeconds: secsString(r.MaxHostCertTTLSeconds),
		MaxX509CertTTLSeconds: secsString(r.MaxX509CertTTLSeconds),
		DefaultExtensions:     extensionsToForm(r.DefaultExtensions),
	}
}

// secsString renders an integer-seconds cap for a form field, blanking
// the zero value (no per-role cap).
func secsString(s int64) string {
	if s == 0 {
		return ""
	}
	return strconv.FormatInt(s, 10)
}

func extensionsToForm(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	// Stable order for deterministic re-render. Allocates a slice
	// for the keys; len(m) is always small (handful of extensions).
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		if v := m[k]; v != "" {
			b.WriteByte('=')
			b.WriteString(v)
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// sortStrings is a tiny in-place sort used by extensionsToForm. The
// package's templates and policy code don't pull sort, and this is
// the only place we need it — keeps the import surface tight.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// basePath is the prefix the api server mounts the portal under (it
// StripPrefixes the same value before dispatching). Handlers register
// prefix-relative routes; rendered links prepend this via the "url"
// template func so they resolve under /portal/ instead of the root.
const basePath = "/portal"

// parsePages builds one *template.Template per page. Each set
// contains the shared base layout plus that page's specific
// {{define "title"}} / {{define "body"}} blocks. Per-set isolation
// avoids the "last-parsed wins" problem that bites you when multiple
// pages share template names in a single set.
func parsePages() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		// url prefixes an internal (root-relative) path with the portal's
		// mount prefix so rendered links resolve under /portal/ rather than the
		// server root. The handlers themselves stay prefix-relative (the api
		// server StripPrefixes /portal), so only the rendered HREFs need this.
		"url": func(p string) string {
			return basePath + p
		},
		"fmtTime": func(t time.Time) string {
			return t.UTC().Format(time.RFC3339)
		},
		// fmtSeconds renders an integer-seconds cap human-friendly,
		// with zero meaning "fall back to the role default".
		"fmtSeconds": func(s int64) string {
			if s == 0 {
				return "(role default)"
			}
			return (time.Duration(s) * time.Second).String()
		},
	}
	pages := map[string]string{
		"index":       indexTemplate,
		"roles":       rolesTemplate,
		"role_detail": roleDetailTemplate,
		"role_form":   roleFormTemplate,
		"hosts":       hostsTemplate,
		"audit":       auditTemplate,
		"revocations": revocationsTemplate,
		"signed_out":  signedOutTemplate,
	}
	out := make(map[string]*template.Template, len(pages))
	for name, body := range pages {
		t := template.New(name).Funcs(funcs)
		if _, err := t.Parse(baseTemplate); err != nil {
			return nil, fmt.Errorf("%s base: %w", name, err)
		}
		if _, err := t.Parse(body); err != nil {
			return nil, fmt.Errorf("%s page: %w", name, err)
		}
		if t.Lookup("page") == nil || t.Lookup("title") == nil || t.Lookup("pagetitle") == nil || t.Lookup("body") == nil {
			return nil, fmt.Errorf("%s missing required define{}: page/title/pagetitle/body", name)
		}
		out[name] = t
	}
	return out, nil
}

const baseTemplate = `{{define "base"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{template "title" .}} · certd</title>
<script>try{const t=localStorage.getItem("tokyo3-theme");document.documentElement.dataset.theme=t==="light"||t==="dark"?t:"dark"}catch(_){document.documentElement.dataset.theme="dark"}</script>
<link rel="stylesheet" href="{{url "/static/app.css"}}">
</head>
<body>
<div class="portal-layout">
<aside class="sidebar" aria-label="Portal navigation">
  <a class="sidebar-brand" href="{{url "/"}}">
    <svg viewBox="0 0 24 24" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><path d="M12 2 4 5v6c0 5.1 3.4 9.4 8 11 4.6-1.6 8-5.9 8-11V5l-8-3zm-1.2 13.6-3-3 1.4-1.4 1.6 1.6 4-4 1.4 1.4-5.4 5.4z"/></svg>
    <span>certd admin portal</span>
  </a>
  <nav aria-label="Primary">
    <div class="nav-section">
      {{if eq .ActivePage "home"}}<a href="{{url "/"}}" class="active" aria-current="page">Overview</a>{{else}}<a href="{{url "/"}}">Overview</a>{{end}}
    </div>
    {{range .Nav}}
    <div class="nav-section">
      <div class="nav-section-label">{{.Label}}</div>
      {{range .Items}}
      {{if ne .Status "ready"}}<span class="nav-planned">{{.Name}} <span class="badge badge-neutral">planned</span></span>{{else if eq $.ActivePage .Key}}<a href="{{url .Path}}" class="active" aria-current="page">{{.Name}}</a>{{else}}<a href="{{url .Path}}">{{.Name}}</a>{{end}}
      {{end}}
    </div>
    {{end}}
  </nav>
  <div class="sidebar-footer">
    <div class="sidebar-user-row">
      {{if .UserEmail}}<div class="sidebar-user" title="{{.UserEmail}}">{{.UserEmail}}</div>{{end}}
      <button type="button" class="theme-toggle" data-theme-toggle aria-pressed="false" aria-label="Switch to light mode" title="Switch to light mode">
        <svg class="theme-icon-sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        <svg class="theme-icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 15.5A8.5 8.5 0 0 1 8.5 3.5 8.5 8.5 0 1 0 20.5 15.5Z"/></svg>
      </button>
    </div>
    {{if .SignOut}}
    <div class="sidebar-footer-actions">
      <form method="POST" action="{{url "/auth/logout"}}">
        <button type="submit" class="btn-link">Sign out</button>
      </form>
    </div>
    {{end}}
  </div>
</aside>
<div class="portal-main">
  <header class="portal-topbar">
    <div class="portal-heading">
      <h1>{{template "pagetitle" .}}</h1>
    </div>
  </header>
  <main class="portal-content">{{template "body" .}}</main>
</div>
</div>
<script>
(() => {
  const root = document.documentElement;
  const button = document.querySelector("[data-theme-toggle]");
  if (!button) return;
  const update = () => {
    const dark = (root.dataset.theme || "dark") === "dark";
    button.setAttribute("aria-pressed", String(dark));
    const label = dark ? "Switch to light mode" : "Switch to dark mode";
    button.setAttribute("aria-label", label);
    button.title = label;
  };
  button.addEventListener("click", () => {
    const next = (root.dataset.theme || "dark") === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem("tokyo3-theme", next); } catch (_) {}
    update();
  });
  update();
})();
</script>
</body>
</html>{{end}}`

// signedOutTemplate is a self-contained focused page — it deliberately
// does not pull in the base chrome: after logout there is no session, so
// sidebar links would only bounce through the login flow.
const signedOutTemplate = `{{define "page"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{template "title" .}} · certd</title>
<script>try{const t=localStorage.getItem("tokyo3-theme");document.documentElement.dataset.theme=t==="light"||t==="dark"?t:"dark"}catch(_){document.documentElement.dataset.theme="dark"}</script>
<link rel="stylesheet" href="{{url "/static/app.css"}}">
</head>
<body>
<main class="signed-out">
  <div class="card">
    <div class="card-body">
      <h1 class="signed-out-title">Signed out</h1>
      <p class="text-muted">Your certd portal session has ended. Your identity
      provider may still hold its own session, so signing in again might not
      prompt for credentials.</p>
      <a class="btn btn-primary" href="{{url "/"}}">Sign in to certd</a>
    </div>
  </div>
</main>
</body>
</html>{{end}}
{{define "title"}}signed out{{end}}
{{define "pagetitle"}}Signed out{{end}}
{{define "body"}}{{end}}`

const indexTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}home{{end}}
{{define "pagetitle"}}Overview{{end}}
{{define "body"}}
<p class="section-description">The certd admin portal exposes the platform's
identity-and-access state. Pages flip to ready as their data sources are
wired; planned pages stay non-interactive.</p>
<div class="resource-panel table-wrap">
<table>
<thead><tr><th>Page</th><th>Description</th><th>Status</th></tr></thead>
<tbody>
{{range .Pages}}
<tr>
  <td class="resource-name">{{if eq .Status "ready"}}<a href="{{url .Path}}">{{.Name}}</a>{{else}}{{.Name}}{{end}}</td>
  <td class="text-muted">{{.Description}}</td>
  <td>{{if eq .Status "ready"}}<span class="badge badge-success">ready</span>{{else}}<span class="badge badge-neutral">planned</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{end}}`

const rolesTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}roles{{end}}
{{define "pagetitle"}}Roles{{end}}
{{define "body"}}
<p class="section-description">Every configured role. Click a name for principals, host patterns,
and TTL caps. The role table is in-memory — restarting certd resets
it unless backed by a JSON file via <code>CERTD_ROLES_FILE</code>.</p>
<div class="quick-actions"><a class="btn btn-primary" href="{{url "/roles/new"}}">Create role</a></div>
{{if .Roles}}
<div class="resource-panel table-wrap">
<table>
<thead>
<tr>
  <th>Name</th>
  <th>Group claim</th>
  <th>Principals</th>
  <th>Host patterns</th>
</tr>
</thead>
<tbody>
{{range .Roles}}
<tr>
  <td class="resource-name"><a href="{{url "/roles"}}/{{.Name}}">{{.Name}}</a></td>
  <td><code>{{.GroupClaim}}</code></td>
  <td>{{if .AllowedPrincipals}}{{range $i, $p := .AllowedPrincipals}}{{if $i}}, {{end}}<code>{{$p}}</code>{{end}}{{else}}<em>none</em>{{end}}</td>
  <td>{{if .HostPatterns}}{{range $i, $p := .HostPatterns}}{{if $i}}, {{end}}<code>{{$p}}</code>{{end}}{{else}}<em>none</em>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="resource-panel empty-state"><em>No roles configured.</em></div>
{{end}}
{{end}}`

const roleDetailTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}role · {{.Name}}{{end}}
{{define "pagetitle"}}{{if .Found}}Role: {{.Role.Name}}{{else}}Not found{{end}}{{end}}
{{define "body"}}
<p class="text-muted"><a href="{{url "/roles"}}">&larr; All roles</a></p>
{{if not .Found}}
<p>No role named <code>{{.Name}}</code> is configured.</p>
{{else}}
<div class="page-stack">
<div class="quick-actions"><a class="btn btn-secondary" href="{{url "/roles"}}/{{.Role.Name}}/edit">Edit role</a></div>
<div class="card">
<div class="card-body">
<table class="summary-list">
<tbody>
<tr><th>Group claim</th><td><code>{{.Role.GroupClaim}}</code></td></tr>
<tr><th>Allowed principals</th><td>
{{if .Role.AllowedPrincipals}}{{range $i, $p := .Role.AllowedPrincipals}}{{if $i}}, {{end}}<code>{{$p}}</code>{{end}}{{else}}<em>none</em>{{end}}
</td></tr>
<tr><th>Host patterns</th><td>
{{if .Role.HostPatterns}}{{range $i, $p := .Role.HostPatterns}}{{if $i}}, {{end}}<code>{{$p}}</code>{{end}}{{else}}<em>none</em>{{end}}
</td></tr>
<tr><th>SPIFFE patterns</th><td>
{{if .Role.SPIFFEPatterns}}{{range $i, $p := .Role.SPIFFEPatterns}}{{if $i}}, {{end}}<code>{{$p}}</code>{{end}}{{else}}<em>none</em>{{end}}
</td></tr>
<tr><th>Max user-cert TTL</th><td>{{fmtSeconds .Role.MaxUserCertTTLSeconds}}</td></tr>
<tr><th>Max host-cert TTL</th><td>{{fmtSeconds .Role.MaxHostCertTTLSeconds}}</td></tr>
<tr><th>Max X.509-cert TTL</th><td>{{fmtSeconds .Role.MaxX509CertTTLSeconds}}</td></tr>
<tr><th>Default extensions</th><td>
{{if .Role.DefaultExtensions}}{{range $k, $v := .Role.DefaultExtensions}}<code>{{$k}}{{if $v}}={{$v}}{{end}}</code><br>{{end}}{{else}}<em>none</em>{{end}}
</td></tr>
</tbody>
</table>
</div>
</div>
<div class="card danger-zone">
  <div class="card-header"><h2>Danger zone</h2></div>
  <div class="card-body">
    <p class="text-muted">Deleting role <code>{{.Role.Name}}</code> immediately removes the signing
    permissions it grants. This cannot be undone.</p>
    <form class="form-actions" method="post" action="{{url "/roles"}}/{{.Role.Name}}/delete" onsubmit="return confirm('Delete role {{.Role.Name}}?');">
      <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
      <button type="submit" class="btn btn-danger">Delete role {{.Role.Name}}</button>
    </form>
  </div>
</div>
</div>
{{end}}
{{end}}`

const roleFormTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}{{if eq .Mode "create"}}new role{{else}}edit · {{.OriginalName}}{{end}}{{end}}
{{define "pagetitle"}}{{if eq .Mode "create"}}New role{{else}}Edit role: {{.OriginalName}}{{end}}{{end}}
{{define "body"}}
<p class="text-muted"><a href="{{url "/roles"}}">&larr; All roles</a></p>
{{if .Error}}<div class="alert alert-error">{{.Error}}</div>{{end}}
<form class="form-width" method="post" action="{{url .FormAction}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <div class="form-group">
    <label for="role-name">Name</label>
    <input type="text" id="role-name" name="name" value="{{.Form.Name}}" required autocomplete="off">
  </div>
  <div class="form-group">
    <label for="role-group-claim">Group claim</label>
    <input type="text" id="role-group-claim" name="group_claim" value="{{.Form.GroupClaim}}" required autocomplete="off">
  </div>
  <div class="form-group">
    <label for="role-principals">Allowed principals</label>
    <textarea id="role-principals" name="allowed_principals" rows="4">{{.Form.AllowedPrincipals}}</textarea>
    <p class="field-help">One principal per line.</p>
  </div>
  <div class="form-group">
    <label for="role-host-patterns">Host patterns</label>
    <textarea id="role-host-patterns" name="host_patterns" rows="4">{{.Form.HostPatterns}}</textarea>
    <p class="field-help">One pattern per line.</p>
  </div>
  <div class="form-group">
    <label for="role-spiffe-patterns">SPIFFE patterns</label>
    <textarea id="role-spiffe-patterns" name="spiffe_patterns" rows="4">{{.Form.SPIFFEPatterns}}</textarea>
    <p class="field-help">One pattern per line.</p>
  </div>
  <div class="form-group">
    <label for="role-user-ttl">Max user-cert TTL</label>
    <input type="text" id="role-user-ttl" name="max_user_cert_ttl_seconds" value="{{.Form.MaxUserCertTTLSeconds}}" autocomplete="off">
    <p class="field-help">Seconds, e.g. <code>14400</code>; blank = role default.</p>
  </div>
  <div class="form-group">
    <label for="role-host-ttl">Max host-cert TTL</label>
    <input type="text" id="role-host-ttl" name="max_host_cert_ttl_seconds" value="{{.Form.MaxHostCertTTLSeconds}}" autocomplete="off">
    <p class="field-help">Seconds; blank = role default.</p>
  </div>
  <div class="form-group">
    <label for="role-x509-ttl">Max X.509-cert TTL</label>
    <input type="text" id="role-x509-ttl" name="max_x509_cert_ttl_seconds" value="{{.Form.MaxX509CertTTLSeconds}}" autocomplete="off">
    <p class="field-help">Seconds, e.g. <code>86400</code>; blank = role default.</p>
  </div>
  <div class="form-group">
    <label for="role-extensions">Default extensions</label>
    <textarea id="role-extensions" name="default_extensions" rows="4">{{.Form.DefaultExtensions}}</textarea>
    <p class="field-help">One <code>key=value</code> per line; bare keys allowed.</p>
  </div>
  <div class="form-actions">
    <button type="submit" class="btn btn-primary">{{.Submit}}</button>
    <a class="btn btn-secondary" href="{{url "/roles"}}">Cancel</a>
  </div>
</form>
{{end}}`

const hostsTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}hosts{{end}}
{{define "pagetitle"}}Hosts{{end}}
{{define "body"}}
<p class="section-description">Workload mTLS principals registered with certd. Each entry maps a
TLS SAN (SPIFFE URI or email) to a workload identity + the group
claims it inherits. Authentication-time lookups consult this set on
every signing request that traverses the mTLS path.</p>
{{if .Hosts}}
<div class="resource-panel table-wrap">
<table>
<thead>
<tr>
  <th>SAN</th>
  <th>Name</th>
  <th>Groups</th>
</tr>
</thead>
<tbody>
{{range .Hosts}}
<tr>
  <td><code>{{.MatchedSAN}}</code></td>
  <td class="resource-name">{{.Name}}</td>
  <td>{{if .Groups}}{{range $i, $g := .Groups}}{{if $i}}, {{end}}<code>{{$g}}</code>{{end}}{{else}}<em>none</em>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="resource-panel empty-state"><em>No hosts registered.</em></div>
{{end}}
{{end}}`

const auditTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}audit{{end}}
{{define "pagetitle"}}Audit{{end}}
{{define "body"}}
<p class="section-description">Live tail of certd's own audit stream — cert issuance, denial, and
revocation events. Newest first. The buffer caps at the tracker's
MaxEvents (default 500); to dig deeper, query JetStream directly.
(SSH session/access events live in ssh-proxyd's own portal.)</p>
{{if .Events}}
<div class="resource-panel table-wrap">
<table>
<thead>
<tr>
  <th>Time</th>
  <th>Action</th>
  <th>Actor</th>
  <th>Subject</th>
  <th>IP</th>
  <th>Detail</th>
</tr>
</thead>
<tbody>
{{range .Events}}
<tr>
  <td class="nowrap">{{fmtTime .OccurredAt}}</td>
  <td><code>{{.Action}}</code></td>
  <td>{{if .Actor}}<code>{{.Actor}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Subject}}<code>{{.Subject}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .IP}}<code>{{.IP}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Detail}}<pre class="audit-detail">{{.Detail}}</pre>{{else}}<em>-</em>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="resource-panel empty-state"><em>No audit events yet. Events appear here once certd starts emitting.</em></div>
{{end}}
{{end}}`

const revocationsTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}revocations{{end}}
{{define "pagetitle"}}Revocations{{end}}
{{define "body"}}
<p class="section-description">Revoked SSH certs. ssh-proxyd polls this set every
<code>CERTD_REVOCATIONS_POLL_SECONDS</code> (default 30s) and refuses
any matching cert at handshake. Either Serial or Key ID is enough;
provide both when you have them so the revocation matches regardless
of which field a consumer keys on.</p>

<h2 class="section-heading">Revoke a cert</h2>
<p class="section-description">Revocation takes effect at the next ssh-proxyd poll and cannot be undone from this portal.</p>
{{if .Error}}<div class="alert alert-error">{{.Error}}</div>{{end}}
<form method="post" action="{{url "/revocations"}}">
<div class="form-width">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <div class="form-group">
    <label for="revoke-serial">Serial</label>
    <input type="text" id="revoke-serial" name="serial" value="{{.FormSerial}}" autocomplete="off">
    <p class="field-help">Decimal; leave blank if revoking by Key ID only.</p>
  </div>
  <div class="form-group">
    <label for="revoke-key-id">Key ID</label>
    <input type="text" id="revoke-key-id" name="key_id" value="{{.FormKeyID}}" autocomplete="off">
    <p class="field-help">E.g. <code>user:alice@example.com</code>; blank if revoking by serial.</p>
  </div>
  <div class="form-group">
    <label for="revoke-reason">Reason</label>
    <input type="text" id="revoke-reason" name="reason" value="{{.FormReason}}" autocomplete="off">
    <p class="field-help">Audit annotation.</p>
  </div>
  <div class="form-actions"><button type="submit" class="btn btn-danger">Revoke certificate</button></div>
</div>
</form>

<h2 class="section-heading">Current revocations ({{len .Entries}})</h2>
{{if .Entries}}
<div class="resource-panel table-wrap">
<table>
<thead>
<tr>
  <th>Revoked at</th>
  <th>Serial</th>
  <th>Key ID</th>
  <th>Reason</th>
  <th>Revoker</th>
</tr>
</thead>
<tbody>
{{range .Entries}}
<tr>
  <td>{{fmtTime .Revoked}}</td>
  <td>{{if .Serial}}<code>{{.Serial}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .KeyID}}<code>{{.KeyID}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Reason}}{{.Reason}}{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Revoker}}<code>{{.Revoker}}</code>{{else}}<em>-</em>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="resource-panel empty-state"><em>No revocations recorded.</em></div>
{{end}}
{{end}}`
