package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/abagile/tokyo3-base/cli"
	"github.com/abagile/tokyo3-base/guard"
	"github.com/spf13/cobra"
)

// activeCertsCmd groups operator actions on the X.509 renewal/anti-theft
// guard's per-identity state (the active_workload_cert table).
func activeCertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "active-certs",
		Short: "Operate on the X.509 anti-theft guard's per-identity state",
	}
	cmd.AddCommand(activeCertsClearCmd())
	return cmd
}

func activeCertsClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear <spiffe-uri>",
		Short: "Delete an identity's active-cert record so it can re-enroll",
		Long: "Delete the anti-theft guard's record for one identity — the documented\n" +
			"recovery for a LOCKED identity (suspected clone) and for any state where\n" +
			"an agent legitimately lost its credentials and must re-enroll before the\n" +
			"recorded cert expires. The next sign request for the SPIFFE URI is then\n" +
			"treated as a first issuance (caller auth + role policy still apply).\n\n" +
			"Requires CERTD_DATABASE_URL (the guard only runs with a persistent store).\n" +
			"The cleared record — including any lock state — is written to the\n" +
			"structured log as the audit trail for the operator action.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runActiveCertsClear(cmd.Context(), args[0])
		},
	}
}

func runActiveCertsClear(ctx context.Context, identity string) error {
	rt := cli.App{Name: appName, EnvPrefix: "CERTD"}.Setup(ctx)
	defer rt.Shutdown()
	log := rt.Log

	db, err := openStore(ctx, rt.DB, log)
	if err != nil {
		return fmt.Errorf("open store database: %w", err)
	}
	if db == nil {
		return errors.New("active-certs clear requires CERTD_DATABASE_URL (no persistent store configured)")
	}
	defer guard.Close(db)

	acs := db.ActiveCerts()
	existing, ok, err := acs.Get(identity)
	if err != nil {
		return fmt.Errorf("read active-cert record: %w", err)
	}
	if !ok {
		log.Info("active-certs: no record for identity — nothing to clear", "identity", identity)
		return nil
	}
	if err := acs.Delete(identity); err != nil {
		return fmt.Errorf("delete active-cert record: %w", err)
	}

	// The cleared state is recorded in the structured log (shipped to NATS
	// via applog when configured) — the audit trail for CLI runs, mirroring
	// the reconcile command's convention.
	attrs := []any{
		"identity", identity,
		"current_serial", existing.CurrentSerial,
		"current_not_after", existing.CurrentNotAfter,
	}
	if !existing.LockedAt.IsZero() {
		attrs = append(attrs,
			"locked_at", existing.LockedAt,
			"locked_serial", existing.LockedSerial,
		)
	}
	log.Info("active-certs: record cleared — identity re-enrolls on its next sign request", attrs...)
	return nil
}
