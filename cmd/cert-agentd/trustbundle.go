package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/abagile/tokyo3-base/guard"

	"github.com/abagile/tokyo3-ca/internal/agent/output"
	"github.com/abagile/tokyo3-ca/internal/client"
)

// defaultTrustBundleRefresh is the pull cadence when
// CERT_AGENTD_TRUST_BUNDLE_REFRESH_SECONDS is unset. Trust anchors change
// only on a CA rotation, so an hour is ample — far looser than the leaf
// renewer's ~60%-TTL cadence.
const defaultTrustBundleRefresh = time.Hour

// buildTrustBundleRefresher returns a runner that periodically pulls certd's
// trust bundle (GET /api/v1/x509/trust-bundle) and writes it to
// CERT_AGENTD_TRUST_BUNDLE_PATH, so the agent and the sibling workloads it
// provisions pick up a CA rotation without an out-of-band push — the trust
// counterpart to leaf renewal. Returns (nil, nil) when the path is unset
// (feature off).
//
// The write is atomic and skipped when the bundle is byte-for-byte unchanged,
// so a reloading consumer (or the agent's own mtime-polled CA pool) sees one
// clean swap rather than churn. A fetch/write error is logged and retried
// next tick; the bundle already on disk is left intact (fail-safe — a certd
// blip never empties a workload's trust store).
func buildTrustBundleRefresher(c *client.Client, log *slog.Logger) (func(context.Context) error, error) {
	path := os.Getenv("CERT_AGENTD_TRUST_BUNDLE_PATH")
	if path == "" {
		return nil, nil
	}
	interval := defaultTrustBundleRefresh
	if v := os.Getenv("CERT_AGENTD_TRUST_BUNDLE_REFRESH_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("CERT_AGENTD_TRUST_BUNDLE_REFRESH_SECONDS %q: must be positive integer", v)
		}
		interval = time.Duration(n) * time.Second
	}

	refresh := func(ctx context.Context) {
		pem, err := c.FetchTrustBundle(ctx)
		if err != nil {
			log.Warn("trust-bundle fetch failed; keeping current bundle", "path", path, "err", err)
			return
		}
		if pem == "" {
			log.Warn("trust-bundle fetch returned empty; keeping current bundle", "path", path)
			return
		}
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, []byte(pem)) {
			return // unchanged — no write, no churn
		}
		if err := output.WriteAtomic(path, []byte(pem), 0o644); err != nil {
			log.Warn("trust-bundle write failed", "path", path, "err", err)
			return
		}
		log.Info("trust bundle refreshed", "path", path, "bytes", len(pem))
	}

	return func(ctx context.Context) error {
		// once up front: catch a rotation that landed while the agent was down
		guard.Tick(log, "trust-bundle-refresh", func() { refresh(ctx) })
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				guard.Tick(log, "trust-bundle-refresh", func() { refresh(ctx) })
			}
		}
	}, nil
}
