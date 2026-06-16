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
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/httpauth"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
)

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
}

// Config wires a [Server]. Optional fields default sensibly.
type Config struct {
	// Version is the build-time semver / commit identifier surfaced
	// in the page footer. Empty acceptable but discouraged in
	// deployed builds.
	Version string

	// Log is the structured logger used for request-time events.
	// nil ⇒ slog.Default.
	Log *slog.Logger

	// Now is the clock used for the "rendered at" footer. nil ⇒
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
	return &Server{cfg: cfg, pages: pages}, nil
}

// render dispatches to the per-page template set keyed by name and
// executes its "page" entry — the in-set wrapper that pulls the
// page-specific title/body into the shared base layout.
func (s *Server) render(w http.ResponseWriter, page string, data any) {
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
	if s.cfg.OIDC.enabled() {
		mux.HandleFunc("GET /auth/login", s.handleAuthLogin)
		mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
		mux.HandleFunc("POST /auth/logout", s.handleAuthLogout)
		return s.requirePortalAuth(mux)
	}
	return httpauth.BasicAuth(s.cfg.BasicAuth, mux, "/healthz")
}

// indexData is the model passed to the landing page template.
type indexData struct {
	Version    string
	RenderedAt time.Time
	Pages      []pageEntry
}

type pageEntry struct {
	Name        string
	Path        string
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
		{Name: "Roles", Path: "/roles", Description: "Role-table viewer: group → principals + host patterns", Status: status(s.cfg.RoleStore != nil)},
		{Name: "Hosts", Path: "/hosts", Description: "Registered workload mTLS principals (SPIFFE / email SANs → group claims)", Status: status(s.cfg.HostStore != nil)},
		{Name: "Audit", Path: "/audit", Description: "Live audit-event viewer (NATS JetStream tail)", Status: status(s.cfg.AuditStore != nil)},
		{Name: "Revocations", Path: "/revocations", Description: "Revoked SSH certs (ssh-proxyd polls this set to refuse handshakes)", Status: status(s.cfg.RevocationStore != nil)},
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "index", indexData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Pages:      s.landingPages(),
	})
}

// rolesIndexData is the model passed to the roles list template.
type rolesIndexData struct {
	Version    string
	RenderedAt time.Time
	Roles      []policy.Role
}

func (s *Server) handleRolesIndex(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.RoleStore == nil {
		http.Error(w, "role store not configured", http.StatusServiceUnavailable)
		return
	}
	s.render(w, "roles", rolesIndexData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Roles:      s.cfg.RoleStore.All(),
	})
}

// roleDetailData is the model for a single-role page. Found indicates
// whether the requested role exists; templates render a 404-style
// message when false.
type roleDetailData struct {
	Version    string
	RenderedAt time.Time
	Name       string
	Role       policy.Role
	Found      bool
	CSRFToken  string // for the inline delete form
}

func (s *Server) handleRoleDetail(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RoleStore == nil {
		http.Error(w, "role store not configured", http.StatusServiceUnavailable)
		return
	}
	name := r.PathValue("name")
	data := roleDetailData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Name:       name,
		CSRFToken:  ensureCSRFToken(w, r),
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
	Version    string
	RenderedAt time.Time

	Mode       string // "create" or "edit"
	FormAction string
	Submit     string // submit-button label
	Error      string // validation error to surface above the form
	CSRFToken  string // double-submit-cookie value embedded as a hidden input

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
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Mode:       "create",
		FormAction: "/roles/new",
		Submit:     "Create role",
		CSRFToken:  ensureCSRFToken(w, r),
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
	if !validateCSRF(r) {
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
	http.Redirect(w, r, "/roles/"+role.Name, http.StatusSeeOther)
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
		Version:      s.cfg.Version,
		RenderedAt:   s.cfg.Now(),
		Mode:         "edit",
		FormAction:   "/roles/" + name + "/edit",
		Submit:       "Save changes",
		OriginalName: name,
		Form:         roleToForm(role),
		CSRFToken:    ensureCSRFToken(w, r),
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
	if !validateCSRF(r) {
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
	http.Redirect(w, r, "/roles/"+role.Name, http.StatusSeeOther)
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
	if !validateCSRF(r) {
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
	http.Redirect(w, r, "/roles", http.StatusSeeOther)
}

// hostsIndexData is the model for the hosts page.
type hostsIndexData struct {
	Version    string
	RenderedAt time.Time
	Hosts      []mtls.Principal
}

func (s *Server) handleHostsIndex(w http.ResponseWriter, _ *http.Request) {
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
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Hosts:      hosts,
	})
}

// revocationsIndexData is the model for the revocations list +
// create form. Error is non-empty when a POST validation failed.
// FormSerial / FormKeyID / FormReason preserve the user's typed
// input on validation failure (just like the role form does).
type revocationsIndexData struct {
	Version    string
	RenderedAt time.Time
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
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Entries:    s.cfg.RevocationStore.Snapshot().Entries,
		CSRFToken:  ensureCSRFToken(w, r),
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
	if !validateCSRF(r) {
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
	http.Redirect(w, r, "/revocations", http.StatusSeeOther)
}

func (s *Server) renderRevocationError(w http.ResponseWriter, r *http.Request, msg, serial, keyID, reason string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "revocations", revocationsIndexData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Entries:    s.cfg.RevocationStore.Snapshot().Entries,
		Error:      msg,
		CSRFToken:  ensureCSRFToken(w, r),
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
	Version    string
	RenderedAt time.Time
	Events     []AuditEvent
}

func (s *Server) handleAuditIndex(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.AuditStore == nil {
		http.Error(w, "audit store not configured", http.StatusServiceUnavailable)
		return
	}
	s.render(w, "audit", auditIndexData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Events:     s.cfg.AuditStore.Events(),
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
		Version:      s.cfg.Version,
		RenderedAt:   s.cfg.Now(),
		Mode:         mode,
		FormAction:   action,
		Submit:       submit,
		Error:        err.Error(),
		OriginalName: originalName,
		Form:         fields,
		CSRFToken:    ensureCSRFToken(w, r),
	})
}

// handleHealthz lets external watchdogs probe the portal without
// triggering a full render. Returns 200 with a tiny plaintext body.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
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

// parsePages builds one *template.Template per page. Each set
// contains the shared base layout plus that page's specific
// {{define "title"}} / {{define "body"}} blocks. Per-set isolation
// avoids the "last-parsed wins" problem that bites you when multiple
// pages share template names in a single set.
func parsePages() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
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
		if t.Lookup("page") == nil || t.Lookup("title") == nil || t.Lookup("body") == nil {
			return nil, fmt.Errorf("%s missing required define{}: page/title/body", name)
		}
		out[name] = t
	}
	return out, nil
}

const baseTemplate = `{{define "base"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{template "title" .}} · certd</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 60em; margin: 2em auto; padding: 0 1em; color: #1a1a1a; }
header, footer { padding: 0.5em 0; border-bottom: 1px solid #ddd; }
footer { border-bottom: none; border-top: 1px solid #ddd; margin-top: 2em; padding-top: 0.5em; font-size: 0.85em; color: #666; }
h1 { margin-top: 0.5em; }
table { border-collapse: collapse; width: 100%; margin-top: 1em; }
th, td { text-align: left; padding: 0.4em 0.6em; border-bottom: 1px solid #eee; }
.status-planned { color: #888; }
.status-ready { color: #1a7f37; font-weight: 600; }
form label { display: block; margin-top: 0.8em; font-weight: 600; }
form input[type=text], form textarea { width: 100%; max-width: 40em; box-sizing: border-box; font: inherit; padding: 0.3em 0.5em; }
form textarea { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; min-height: 5em; }
form button, .link-button { font: inherit; padding: 0.4em 0.9em; cursor: pointer; }
.link-button { background: none; border: none; color: #b21f1f; padding: 0; text-decoration: underline; }
.error { padding: 0.6em 0.8em; margin: 0.5em 0 1em; background: #fff3f3; border: 1px solid #f3b8b8; color: #b21f1f; border-radius: 4px; }
</style>
</head>
<body>
<header><strong>certd admin portal</strong></header>
<main>{{template "body" .}}</main>
<footer>certd {{.Version}} · rendered {{fmtTime .RenderedAt}}</footer>
</body>
</html>{{end}}`

const indexTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}home{{end}}
{{define "body"}}
<h1>Welcome</h1>
<p>The certd admin portal exposes the platform's identity-and-access state.
Pages below are mounted as later slices land them — this scaffold proves the
chrome works end-to-end.</p>
<table>
<thead><tr><th>Page</th><th>Description</th><th>Status</th></tr></thead>
<tbody>
{{range .Pages}}
<tr>
  <td>{{if eq .Status "ready"}}<a href="{{.Path}}">{{.Name}}</a>{{else}}{{.Name}}{{end}}</td>
  <td>{{.Description}}</td>
  <td class="status-{{.Status}}">{{.Status}}</td>
</tr>
{{end}}
</tbody>
</table>
{{end}}`

const rolesTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}roles{{end}}
{{define "body"}}
<p><a href="/">&larr; home</a></p>
<h1>Roles</h1>
<p>Every configured role. Click a name for principals, host patterns,
and TTL caps. The role table is in-memory — restarting certd resets
it unless backed by a JSON file via <code>CERTD_ROLES_FILE</code>.</p>
<p><a href="/roles/new">+ New role</a></p>
{{if .Roles}}
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
  <td><a href="/roles/{{.Name}}">{{.Name}}</a></td>
  <td><code>{{.GroupClaim}}</code></td>
  <td>{{if .AllowedPrincipals}}{{range $i, $p := .AllowedPrincipals}}{{if $i}}, {{end}}<code>{{$p}}</code>{{end}}{{else}}<em>none</em>{{end}}</td>
  <td>{{if .HostPatterns}}{{range $i, $p := .HostPatterns}}{{if $i}}, {{end}}<code>{{$p}}</code>{{end}}{{else}}<em>none</em>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p><em>No roles configured.</em></p>
{{end}}
{{end}}`

const roleDetailTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}role · {{.Name}}{{end}}
{{define "body"}}
<p><a href="/roles">&larr; roles</a></p>
{{if not .Found}}
<h1>Not found</h1>
<p>No role named <code>{{.Name}}</code> is configured.</p>
{{else}}
<h1>Role: {{.Role.Name}}</h1>
<p>
  <a href="/roles/{{.Role.Name}}/edit">Edit</a> ·
  <form method="post" action="/roles/{{.Role.Name}}/delete" style="display:inline" onsubmit="return confirm('Delete role {{.Role.Name}}?');">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <button type="submit" class="link-button">Delete</button>
  </form>
</p>
<table>
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
{{end}}
{{end}}`

const roleFormTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}{{if eq .Mode "create"}}new role{{else}}edit · {{.OriginalName}}{{end}}{{end}}
{{define "body"}}
<p><a href="/roles">&larr; roles</a></p>
<h1>{{if eq .Mode "create"}}New role{{else}}Edit role: {{.OriginalName}}{{end}}</h1>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<form method="post" action="{{.FormAction}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <label>Name
    <input type="text" name="name" value="{{.Form.Name}}" required autocomplete="off">
  </label>
  <label>Group claim
    <input type="text" name="group_claim" value="{{.Form.GroupClaim}}" required autocomplete="off">
  </label>
  <label>Allowed principals (one per line)
    <textarea name="allowed_principals" rows="4">{{.Form.AllowedPrincipals}}</textarea>
  </label>
  <label>Host patterns (one per line)
    <textarea name="host_patterns" rows="4">{{.Form.HostPatterns}}</textarea>
  </label>
  <label>SPIFFE patterns (one per line)
    <textarea name="spiffe_patterns" rows="4">{{.Form.SPIFFEPatterns}}</textarea>
  </label>
  <label>Max user-cert TTL (seconds, e.g., <code>14400</code>; blank = role default)
    <input type="text" name="max_user_cert_ttl_seconds" value="{{.Form.MaxUserCertTTLSeconds}}" autocomplete="off">
  </label>
  <label>Max host-cert TTL (seconds; blank = role default)
    <input type="text" name="max_host_cert_ttl_seconds" value="{{.Form.MaxHostCertTTLSeconds}}" autocomplete="off">
  </label>
  <label>Max X.509-cert TTL (seconds, e.g., <code>86400</code>; blank = role default)
    <input type="text" name="max_x509_cert_ttl_seconds" value="{{.Form.MaxX509CertTTLSeconds}}" autocomplete="off">
  </label>
  <label>Default extensions (one <code>key=value</code> per line; bare keys allowed)
    <textarea name="default_extensions" rows="4">{{.Form.DefaultExtensions}}</textarea>
  </label>
  <p><button type="submit">{{.Submit}}</button></p>
</form>
{{end}}`

const hostsTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}hosts{{end}}
{{define "body"}}
<p><a href="/">&larr; home</a></p>
<h1>Hosts</h1>
<p>Workload mTLS principals registered with certd. Each entry maps a
TLS SAN (SPIFFE URI or email) to a workload identity + the group
claims it inherits. Authentication-time lookups consult this set on
every signing request that traverses the mTLS path.</p>
{{if .Hosts}}
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
  <td>{{.Name}}</td>
  <td>{{if .Groups}}{{range $i, $g := .Groups}}{{if $i}}, {{end}}<code>{{$g}}</code>{{end}}{{else}}<em>none</em>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p><em>No hosts registered.</em></p>
{{end}}
{{end}}`

const auditTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}audit{{end}}
{{define "body"}}
<p><a href="/">&larr; home</a></p>
<h1>Audit</h1>
<p>Live tail of certd's own audit stream — cert issuance, denial, and
revocation events. Newest first. The buffer caps at the tracker's
MaxEvents (default 500); to dig deeper, query JetStream directly.
(SSH session/access events live in ssh-proxyd's own portal.)</p>
{{if .Events}}
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
  <td>{{fmtTime .OccurredAt}}</td>
  <td><code>{{.Action}}</code></td>
  <td>{{if .Actor}}<code>{{.Actor}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Subject}}<code>{{.Subject}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .IP}}<code>{{.IP}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Detail}}<details><summary>view</summary><pre>{{.Detail}}</pre></details>{{else}}<em>-</em>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p><em>No audit events yet. Events appear here once certd starts emitting.</em></p>
{{end}}
{{end}}`

const revocationsTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}revocations{{end}}
{{define "body"}}
<p><a href="/">&larr; home</a></p>
<h1>Revocations</h1>
<p>Revoked SSH certs. ssh-proxyd polls this set every
<code>CERTD_REVOCATIONS_POLL_SECONDS</code> (default 30s) and refuses
any matching cert at handshake. Either Serial or Key ID is enough;
provide both when you have them so the revocation matches regardless
of which field a consumer keys on.</p>

<h2>Revoke a cert</h2>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<form method="post" action="/revocations">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <label>Serial (decimal; leave blank if revoking by Key ID only)
    <input type="text" name="serial" value="{{.FormSerial}}" autocomplete="off">
  </label>
  <label>Key ID (e.g., <code>user:alice@example.com</code>; blank if revoking by serial)
    <input type="text" name="key_id" value="{{.FormKeyID}}" autocomplete="off">
  </label>
  <label>Reason (audit annotation)
    <input type="text" name="reason" value="{{.FormReason}}" autocomplete="off">
  </label>
  <p><button type="submit">Revoke</button></p>
</form>

<h2>Current revocations ({{len .Entries}})</h2>
{{if .Entries}}
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
{{else}}
<p><em>No revocations recorded.</em></p>
{{end}}
{{end}}`
