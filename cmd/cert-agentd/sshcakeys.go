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

// buildSSHCAKeysRefresher returns a runner that periodically pulls certd's
// trusted SSH CA key set (GET /api/v1/ssh/ca-keys) and writes it to
// CERT_AGENTD_SSH_CA_KEYS_PATH — a TrustedUserCAKeys file an sshd (or
// ssh-proxyd) verifies user certs against. So an SSH CA rotation propagates as
// an automated overlap (the served set lists old⊕new while leaves drain) with
// no out-of-band push, mirroring the X.509 trust-bundle refresher. Returns
// (nil, nil) when the path is unset (feature off).
//
// stock sshd re-reads the TrustedUserCAKeys file contents at authentication
// time, so a refreshed file is picked up for new connections without a reload;
// servers that cache the set need their own watch.
//
// The write is atomic and skipped when the set is byte-for-byte unchanged. A
// fetch/write error is logged and retried next tick; the set already on disk is
// left intact (fail-safe — a certd blip never empties a verifier's
// TrustedUserCAKeys and locks SSH out).
func buildSSHCAKeysRefresher(c *client.Client, log *slog.Logger) (func(context.Context) error, error) {
	path := os.Getenv("CERT_AGENTD_SSH_CA_KEYS_PATH")
	if path == "" {
		return nil, nil
	}
	interval := defaultTrustBundleRefresh
	if v := os.Getenv("CERT_AGENTD_SSH_CA_KEYS_REFRESH_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("CERT_AGENTD_SSH_CA_KEYS_REFRESH_SECONDS %q: must be positive integer", v)
		}
		interval = time.Duration(n) * time.Second
	}

	refresh := func(ctx context.Context) {
		keys, err := c.FetchSSHCAKeys(ctx)
		if err != nil {
			log.Warn("ssh ca-keys fetch failed; keeping current set", "path", path, "err", err)
			return
		}
		if keys == "" {
			log.Warn("ssh ca-keys fetch returned empty; keeping current set", "path", path)
			return
		}
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, []byte(keys)) {
			return // unchanged — no write, no churn
		}
		if err := output.WriteAtomic(path, []byte(keys), 0o644); err != nil {
			log.Warn("ssh ca-keys write failed", "path", path, "err", err)
			return
		}
		log.Info("ssh ca-keys refreshed", "path", path, "bytes", len(keys))
	}

	return func(ctx context.Context) error {
		// once up front: catch a rotation that landed while the agent was down
		guard.Tick(log, "ssh-ca-keys-refresh", func() { refresh(ctx) })
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				guard.Tick(log, "ssh-ca-keys-refresh", func() { refresh(ctx) })
			}
		}
	}, nil
}
