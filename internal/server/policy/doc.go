// Package policy owns the SSH role table — mappings from OIDC group claims
// to allowed Unix principals and host-label patterns. Enforcement runs at
// sign time inside certd; the resulting cert carries the allowed
// principals + host-pattern extensions, which ssh-proxyd later re-checks
// at session time as defense in depth.
package policy
