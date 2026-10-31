// Package bootstrap checks, before the server takes traffic, that the
// database has what this build reads. Migrations run as their own step
// (cmd/migrate-postgres), so a rollout can put a new binary in front of an
// old database; the probes say which way that breaks.
package bootstrap

import (
	"context"
	"fmt"
	"strings"

	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// schemaProbe is a structure this build reads and a query that touches it
// without returning rows.
type schemaProbe struct {
	// what names the structure in operator terms.
	what string
	// query must be cheap and side-effect free; LIMIT 0 still parses and
	// plans, so a missing table or column fails here as it would on the
	// first real request.
	query string
	// required marks a structure the server cannot run without. When false
	// a missing structure costs a feature (logged), not the process.
	required bool
	// consequence says what breaks.
	consequence string
}

// schemaProbes lists what the running code assumes exists. Add a line when
// a migration introduces something the code then depends on.
var schemaProbes = []schemaProbe{
	{
		what:        "audit_events and audit_outbox",
		query:       "SELECT e.event_id, e.severity, o.status FROM audit_events e, audit_outbox o LIMIT 0",
		required:    true,
		consequence: "no change can be audited, so every write is refused",
	},
	{
		what:        "encryption_keys",
		query:       "SELECT kid, purpose, state, key_ref FROM encryption_keys LIMIT 0",
		required:    true,
		consequence: "credentials, DKIM keys and webhook secrets cannot be sealed or opened",
	},
	{
		what:        "tenant_settings",
		query:       "SELECT org_id, four_eyes_publish, message_retention_days FROM tenant_settings LIMIT 0",
		required:    true,
		consequence: "four-eyes publishing and tenant retention cannot be read",
	},
}

// Register adds the probes of a feature (called from the container while
// wiring the feature).
func Register(what, query string, required bool, consequence string) {
	schemaProbes = append(schemaProbes, schemaProbe{what: what, query: query, required: required, consequence: consequence})
}

// CheckSchema runs every probe. A missing required structure stops startup
// with the migration to run; an optional one is logged.
func CheckSchema(ctx context.Context, db *postgres.Pool) error {
	var missing []string
	for _, p := range schemaProbes {
		rows, err := db.Query(ctx, p.query)
		if err == nil {
			rows.Close()
			err = rows.Err()
		}
		if err == nil {
			continue
		}
		if p.required {
			logger.Error("schema probe failed", logger.String("structure", p.what), logger.String("consequence", p.consequence), logger.Err(err))
			missing = append(missing, p.what)
			continue
		}
		logger.Warn("optional schema probe failed", logger.String("structure", p.what), logger.String("consequence", p.consequence), logger.Err(err))
	}
	if len(missing) > 0 {
		return fmt.Errorf("database is missing %s: run migrate-postgres up before starting this build", strings.Join(missing, ", "))
	}
	return nil
}
