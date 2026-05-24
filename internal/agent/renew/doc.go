// Package renew is cert-agentd's renewal scheduler. Tracks each managed
// credential's expiry, triggers renewal at ~60% of TTL, retries with
// exponential backoff on failure, and surfaces structured alerts when
// the remaining lifetime drops below the configured floor.
package renew
