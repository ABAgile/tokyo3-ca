// Package reconcile diffs the config files (CERTD_ROLES_FILE /
// CERTD_MTLS_PRINCIPALS_FILE) against the persistent store and applies the
// difference, so config edits take effect after the seed-on-first-boot. It
// implements the owner-marker model: config is authoritative over rows marked
// source="config" (add / update / prune to match the files), while rows marked
// source="portal" (created in the admin portal) are never pruned and a
// name/SAN collision is reported as a conflict — unless --adopt is set, which
// takes ownership of the colliding row.
//
// The diff (DiffRoles / DiffPrincipals) is pure; Apply performs the writes
// through the audited store mutation methods, so every change lands with its
// audit Entry in the same transaction.
package reconcile

import (
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/store"
)

// RolePlan is the classified set of role changes a reconcile would apply.
// Update/Add carry the desired (file) value; Prune/Conflict carry names.
type RolePlan struct {
	Add       []policy.Role
	Update    []policy.Role
	Prune     []string
	Conflicts []string // file roles colliding with portal-owned rows (skipped)
}

// PrincipalPlan mirrors [RolePlan] for principals, keyed by SAN.
type PrincipalPlan struct {
	Add       []mtls.Principal
	Update    []mtls.Principal
	Prune     []string // SANs
	Conflicts []string // SANs
}

// Empty reports whether the plan would change nothing (conflicts aside).
func (p RolePlan) Empty() bool {
	return len(p.Add) == 0 && len(p.Update) == 0 && len(p.Prune) == 0
}

// Empty reports whether the plan would change nothing (conflicts aside).
func (p PrincipalPlan) Empty() bool {
	return len(p.Add) == 0 && len(p.Update) == 0 && len(p.Prune) == 0
}

// DiffRoles classifies the file roles against the DB records. With adopt set, a
// file role colliding with a portal-owned row is taken over (Update, rewriting
// source to config) instead of reported as a Conflict.
func DiffRoles(file []policy.Role, db []store.RoleRecord, adopt bool) RolePlan {
	dbByName := make(map[string]store.RoleRecord, len(db))
	for _, rec := range db {
		dbByName[rec.Role.Name] = rec
	}
	inFile := make(map[string]bool, len(file))
	var plan RolePlan
	for _, r := range file {
		inFile[r.Name] = true
		rec, ok := dbByName[r.Name]
		switch {
		case !ok:
			plan.Add = append(plan.Add, r)
		case rec.Source == store.SourcePortal:
			if !adopt {
				plan.Conflicts = append(plan.Conflicts, r.Name)
				continue
			}
			plan.Update = append(plan.Update, r) // take ownership: rewrite as source=config
		case !RoleEqual(rec.Role, r):
			plan.Update = append(plan.Update, r)
		}
	}
	for _, rec := range db {
		if rec.Source == store.SourceConfig && !inFile[rec.Role.Name] {
			plan.Prune = append(plan.Prune, rec.Role.Name)
		}
	}
	sort.Strings(plan.Prune)
	sort.Strings(plan.Conflicts)
	return plan
}

// DiffPrincipals classifies the file principals (keyed by MatchedSAN) against
// the DB records, mirroring [DiffRoles].
func DiffPrincipals(file []mtls.Principal, db []store.PrincipalRecord, adopt bool) PrincipalPlan {
	dbBySAN := make(map[string]store.PrincipalRecord, len(db))
	for _, rec := range db {
		dbBySAN[rec.Principal.MatchedSAN] = rec
	}
	inFile := make(map[string]bool, len(file))
	var plan PrincipalPlan
	for _, p := range file {
		if p.MatchedSAN == "" {
			continue // matches the seed/registry rule: a SAN is the key
		}
		inFile[p.MatchedSAN] = true
		rec, ok := dbBySAN[p.MatchedSAN]
		switch {
		case !ok:
			plan.Add = append(plan.Add, p)
		case rec.Source == store.SourcePortal:
			if !adopt {
				plan.Conflicts = append(plan.Conflicts, p.MatchedSAN)
				continue
			}
			plan.Update = append(plan.Update, p)
		case !PrincipalEqual(rec.Principal, p):
			plan.Update = append(plan.Update, p)
		}
	}
	for _, rec := range db {
		if rec.Source == store.SourceConfig && !inFile[rec.Principal.MatchedSAN] {
			plan.Prune = append(plan.Prune, rec.Principal.MatchedSAN)
		}
	}
	sort.Strings(plan.Prune)
	sort.Strings(plan.Conflicts)
	return plan
}

// Applied counts what Apply changed, for the summary line + audit event.
type Applied struct {
	Added, Updated, Pruned int
}

// ApplyRoles applies the role plan, stamping config-sourced rows. prune gates
// the delete phase (false leaves config-orphans in place, logged by the
// caller).
func (p RolePlan) ApplyRoles(rs store.RoleStore, prune bool) (Applied, error) {
	var ap Applied
	for _, r := range p.Add {
		if err := rs.Add(r, store.SourceConfig); err != nil {
			return ap, fmt.Errorf("add role %q: %w", r.Name, err)
		}
		ap.Added++
	}
	for _, r := range p.Update {
		// No renames in reconcile: the file is keyed by name, so oldName == name.
		if err := rs.Replace(r.Name, r, store.SourceConfig); err != nil {
			return ap, fmt.Errorf("update role %q: %w", r.Name, err)
		}
		ap.Updated++
	}
	if prune {
		for _, name := range p.Prune {
			if err := rs.Delete(name); err != nil {
				return ap, fmt.Errorf("prune role %q: %w", name, err)
			}
			ap.Pruned++
		}
	}
	return ap, nil
}

// ApplyPrincipals mirrors [RolePlan.ApplyRoles] for principals (keyed by SAN).
func (p PrincipalPlan) ApplyPrincipals(ps store.PrincipalStore, prune bool) (Applied, error) {
	var ap Applied
	for _, pr := range p.Add {
		if err := ps.Add(pr, store.SourceConfig); err != nil {
			return ap, fmt.Errorf("add principal %q: %w", pr.MatchedSAN, err)
		}
		ap.Added++
	}
	for _, pr := range p.Update {
		if err := ps.Replace(pr.MatchedSAN, pr, store.SourceConfig); err != nil {
			return ap, fmt.Errorf("update principal %q: %w", pr.MatchedSAN, err)
		}
		ap.Updated++
	}
	if prune {
		for _, san := range p.Prune {
			if err := ps.Delete(san); err != nil {
				return ap, fmt.Errorf("prune principal %q: %w", san, err)
			}
			ap.Pruned++
		}
	}
	return ap, nil
}

// RoleEqual reports whether two roles are equivalent for reconcile purposes:
// scalar fields equal, and the multi-valued fields equal as sets (order- and
// nil/empty-insensitive) so a re-ordered or JSON-round-tripped file role does
// not produce a spurious update.
func RoleEqual(a, b policy.Role) bool {
	return a.Name == b.Name &&
		a.GroupClaim == b.GroupClaim &&
		a.MaxUserCertTTLSeconds == b.MaxUserCertTTLSeconds &&
		a.MaxHostCertTTLSeconds == b.MaxHostCertTTLSeconds &&
		a.MaxX509CertTTLSeconds == b.MaxX509CertTTLSeconds &&
		sameSet(a.AllowedPrincipals, b.AllowedPrincipals) &&
		sameSet(a.HostPatterns, b.HostPatterns) &&
		sameSet(a.SPIFFEPatterns, b.SPIFFEPatterns) &&
		maps.Equal(a.DefaultExtensions, b.DefaultExtensions)
}

// PrincipalEqual reports whether two principals are equivalent (same SAN key,
// same name, same group set).
func PrincipalEqual(a, b mtls.Principal) bool {
	return a.Name == b.Name &&
		a.MatchedSAN == b.MatchedSAN &&
		sameSet(a.Groups, b.Groups)
}

// sameSet compares two string slices as sets (sorted, length-equal). Treats
// nil and empty as equal, so a missing vs empty JSON array does not churn.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := slices.Clone(a)
	y := slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}
