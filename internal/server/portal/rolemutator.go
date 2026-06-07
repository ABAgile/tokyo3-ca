package portal

import (
	"net/http"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/store"
)

// sourcedRoleStore is the DB role store's write surface (the subset of
// [store.RoleStore] the portal mutates). When the configured RoleStore
// implements it, portal edits are stamped source="portal" so `certd reconcile`
// never prunes them. The plain in-memory [MutableRoleStore] path (dev / no DB)
// has no source column.
//
// Defined here as a minimal interface (not store.RoleStore directly) so the
// portal depends only on the methods it calls, matching the package's
// stub-friendly RoleStore/HostStore/RevocationStore convention.
type sourcedRoleStore interface {
	ByName(name string) (policy.Role, bool)
	Add(role policy.Role, source string) error
	Replace(oldName string, newRole policy.Role, source string) error
	Delete(name string) error
}

// roleWriter is the portal's uniform role-mutation surface. It wraps whichever
// write-capable store backs the portal: the DB store (stamps source="portal")
// or the plain in-memory store (no source column). Construct via
// [Server.roleWriter]; a nil return means the store is read-only and the write
// routes answer 405.
type roleWriter struct {
	sourced sourcedRoleStore // DB-backed; nil when in-memory
	plain   MutableRoleStore // in-memory; nil when DB-backed
	caller  string           // audit caller for the change log (oidc:<email> / portal:<user>)
}

// roleWriter returns the request-scoped mutation surface, or nil when the
// configured role store is read-only (neither sourced nor plain-mutable).
func (s *Server) roleWriter(r *http.Request) *roleWriter {
	rw := &roleWriter{caller: s.portalCaller(r)}
	if a, ok := s.cfg.RoleStore.(sourcedRoleStore); ok {
		rw.sourced = a
		return rw
	}
	if m, ok := s.cfg.RoleStore.(MutableRoleStore); ok {
		rw.plain = m
		return rw
	}
	return nil
}

func (rw *roleWriter) byName(name string) (policy.Role, bool) {
	if rw.sourced != nil {
		return rw.sourced.ByName(name)
	}
	return rw.plain.ByName(name)
}

func (rw *roleWriter) Add(role policy.Role) error {
	if rw.sourced != nil {
		return rw.sourced.Add(role, store.SourcePortal)
	}
	return rw.plain.Add(role)
}

func (rw *roleWriter) Replace(oldName string, newRole policy.Role) error {
	if rw.sourced != nil {
		return rw.sourced.Replace(oldName, newRole, store.SourcePortal)
	}
	return rw.plain.Replace(oldName, newRole)
}

func (rw *roleWriter) Delete(name string) error {
	if rw.sourced != nil {
		return rw.sourced.Delete(name)
	}
	return rw.plain.Delete(name)
}

// portalCaller derives the actor for a portal change log. The native-OIDC
// session wins (oidc:<email>); otherwise, over HTTP Basic auth there is no
// per-user identity beyond the configured username, so it attributes to
// "portal:<user>" (or "portal:portal" when the gate is open).
func (s *Server) portalCaller(r *http.Request) string {
	if c := s.oidcCaller(r); c != "" {
		return c
	}
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		return audit.CallerPrefixPortal + u
	}
	return audit.CallerPrefixPortal + "portal"
}
