package postgres

import (
	"context"
	"time"

	"github.com/razatechofficial/mail-os/application/platform"
)

// PlatformRepository reads the platform API's aggregates across tenants.
// It selects counts and identifiers only: no column of a message, a
// provider's configuration or credentials, or a template is read.
type PlatformRepository struct {
	db *Pool
}

var _ platform.Repository = (*PlatformRepository)(nil)

// NewPlatformRepository returns the repository.
func NewPlatformRepository(db *Pool) *PlatformRepository { return &PlatformRepository{db: db} }

// TenantAggregates lists tenants (not deleted) in (created_at, id) order
// after the given position, with their application and sending-domain
// counts and the messages created since since.
func (r *PlatformRepository) TenantAggregates(ctx context.Context, afterCreated time.Time, afterID string, limit int, since time.Time) ([]platform.TenantAggregate, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `
		SELECT o.id, o.is_active, o.created_at,
			(SELECT count(*) FROM applications a WHERE a.org_id = o.id),
			(SELECT count(*) FROM sending_domains d WHERE d.org_id = o.id AND d.deleted_at IS NULL),
			(SELECT count(*) FROM messages m WHERE m.org_id = o.id AND m.created_at >= $4)
		FROM organizations o
		WHERE o.deleted_at IS NULL AND ($1::timestamptz IS NULL OR (o.created_at, o.id) > ($1, $2))
		ORDER BY o.created_at, o.id
		LIMIT $3`, nullTime(afterCreated), afterID, limit, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []platform.TenantAggregate
	for rows.Next() {
		var t platform.TenantAggregate
		if err := rows.Scan(&t.ID, &t.Active, &t.CreatedAt, &t.Applications, &t.Domains, &t.Messages30d); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ProviderKindsInUse lists the provider kinds at least one tenant has an
// active provider of.
func (r *PlatformRepository) ProviderKindsInUse(ctx context.Context) ([]string, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx,
		`SELECT DISTINCT type FROM providers WHERE is_active AND deleted_at IS NULL ORDER BY type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
