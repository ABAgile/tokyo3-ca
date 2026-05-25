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
)

// Server is the portal's HTTP handler. Construct via [New] and mount
// the result of [Server.Routes] under the prefix you want (typically
// "/portal/" — the routes are absolute internally so the prefix is
// caller-chosen).
type Server struct {
	cfg   Config
	tmpls *template.Template
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
	tmpls, err := parseTemplates()
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{cfg: cfg, tmpls: tmpls}, nil
}

// Routes returns the portal's handler tree. Mount under any prefix;
// the routes use a relative path so the prefix is caller-chosen.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
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

// landingPages is the static list of portal pages, including the
// not-yet-implemented ones so operators see what's coming. As later
// slices ship pages, their entries flip to Status: "ready".
var landingPages = []pageEntry{
	{Name: "Roles", Path: "/roles", Description: "Role-table CRUD: group → principals + host patterns", Status: "planned"},
	{Name: "Hosts", Path: "/hosts", Description: "Host registry: registered tunnels and their certs", Status: "planned"},
	{Name: "Sessions", Path: "/sessions", Description: "Session list + asciinema-player replay", Status: "planned"},
	{Name: "Audit", Path: "/audit", Description: "Live audit-event viewer (NATS JetStream tail)", Status: "planned"},
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := indexData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Pages:      landingPages,
	}
	if err := s.tmpls.ExecuteTemplate(w, "index.html", data); err != nil {
		s.cfg.Log.Error("portal index render", "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

// handleHealthz lets external watchdogs probe the portal without
// triggering a full render. Returns 200 with a tiny plaintext body.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

// parseTemplates is the single source of truth for the portal's
// HTML. Inline templates keep the embed-asset surface minimal —
// later slices may move pages into separate files under a //go:embed
// FS, but the scaffold doesn't need it yet.
func parseTemplates() (*template.Template, error) {
	root := template.New("").Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string {
			return t.UTC().Format(time.RFC3339)
		},
	})
	var err error
	if root, err = root.Parse(baseTemplate); err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	if root, err = root.Parse(indexTemplate); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	return root, nil
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

const indexTemplate = `{{define "index.html"}}{{template "base" .}}{{end}}
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
