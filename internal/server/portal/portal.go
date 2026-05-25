// Package portal serves the certd admin web UI — role-table CRUD,
// host registry browser, session list with asciinema-player replay,
// and audit viewer. Server-rendered HTML, no client-side framework;
// pages render fully on the server and submit via standard form
// posts.
//
// The portal is mounted by [Server.Routes] at /portal/. Each page is
// a single template inheriting from [baseTemplate] so the nav and
// chrome stay consistent. This first slice ships only the scaffold +
// a landing page that lists what the portal will eventually do —
// later slices fill in role-table, sessions, hosts, and audit pages.
package portal

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/policy"
)

// RoleStore is the subset of [policy.Store] the roles page needs.
// Defined here (and not as an alias) so tests can stub the source
// without spinning up the full policy.Engine.
type RoleStore interface {
	All() []policy.Role
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
	RoleStore RoleStore
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
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /roles", s.handleRolesIndex)
	mux.HandleFunc("GET /roles/{name}", s.handleRoleDetail)
	return mux
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

// landingPages returns the dashboard's nav entries. The Roles page
// flips to "ready" when RoleStore is wired; the others remain
// placeholders until their slices land.
func (s *Server) landingPages() []pageEntry {
	roleStatus := "planned"
	if s.cfg.RoleStore != nil {
		roleStatus = "ready"
	}
	return []pageEntry{
		{Name: "Roles", Path: "/roles", Description: "Role-table viewer: group → principals + host patterns", Status: roleStatus},
		{Name: "Hosts", Path: "/hosts", Description: "Host registry: registered tunnels and their certs", Status: "planned"},
		{Name: "Sessions", Path: "/sessions", Description: "Session list + asciinema-player replay", Status: "planned"},
		{Name: "Audit", Path: "/audit", Description: "Live audit-event viewer (NATS JetStream tail)", Status: "planned"},
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

// handleHealthz lets external watchdogs probe the portal without
// triggering a full render. Returns 200 with a tiny plaintext body.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
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
		"fmtDuration": func(d time.Duration) string {
			if d == 0 {
				return "(role default)"
			}
			return d.String()
		},
	}
	pages := map[string]string{
		"index":       indexTemplate,
		"roles":       rolesTemplate,
		"role_detail": roleDetailTemplate,
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
and TTL caps. The role table is currently in-memory only —
changes require restarting certd. CRUD writes land in a later slice.</p>
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
<tr><th>Max user-cert TTL</th><td>{{fmtDuration .Role.MaxUserCertTTL}}</td></tr>
<tr><th>Max host-cert TTL</th><td>{{fmtDuration .Role.MaxHostCertTTL}}</td></tr>
<tr><th>Max X.509-cert TTL</th><td>{{fmtDuration .Role.MaxX509CertTTL}}</td></tr>
<tr><th>Default extensions</th><td>
{{if .Role.DefaultExtensions}}{{range $k, $v := .Role.DefaultExtensions}}<code>{{$k}}{{if $v}}={{$v}}{{end}}</code><br>{{end}}{{else}}<em>none</em>{{end}}
</td></tr>
</tbody>
</table>
{{end}}
{{end}}`
