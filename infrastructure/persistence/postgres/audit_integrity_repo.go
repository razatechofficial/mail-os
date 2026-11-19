package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/razatechofficial/mail-os/application/auditintegrity"
)

// AuditIntegrityRepository reads audit rows in sequence and keeps the
// signed digests over them.
type AuditIntegrityRepository struct {
	db *Pool
}

var _ auditintegrity.Store = (*AuditIntegrityRepository)(nil)

// NewAuditIntegrityRepository returns the repository.
func NewAuditIntegrityRepository(db *Pool) *AuditIntegrityRepository {
	return &AuditIntegrityRepository{db: db}
}

// recordCols are the hashed fields, as text, in auditintegrity.Record's
// order. metadata::text is Postgres's canonical jsonb output.
const recordCols = `seq, event_id::text, service, tier, severity, COALESCE(actor_uuid::text, ''), actor_type,
	COALESCE(tenant_uuid::text, ''), COALESCE(organization_uuid::text, ''), resource_type, resource_id, action,
	COALESCE(host(ip_address), ''), COALESCE(user_agent, ''), metadata::text, created_at`

func (r *AuditIntegrityRepository) records(ctx context.Context, sql string, args ...any) ([]auditintegrity.Record, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auditintegrity.Record
	for rows.Next() {
		var rec auditintegrity.Record
		if err := rows.Scan(&rec.Seq, &rec.EventID, &rec.Service, &rec.Tier, &rec.Severity, &rec.ActorUUID, &rec.ActorType,
			&rec.TenantUUID, &rec.OrgUUID, &rec.ResourceType, &rec.ResourceID, &rec.Action, &rec.IP, &rec.UserAgent,
			&rec.Metadata, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// RecordsAfter returns rows with seq > afterSeq written before `before`. It
// stops at the first row still too new, so a digest never skips a row.
func (r *AuditIntegrityRepository) RecordsAfter(ctx context.Context, afterSeq int64, before time.Time, limit int) ([]auditintegrity.Record, error) {
	return r.records(ctx, `SELECT `+recordCols+` FROM audit_events
		WHERE seq > $1 AND seq < COALESCE((SELECT min(seq) FROM audit_events WHERE seq > $1 AND created_at >= $2), 9223372036854775807)
		ORDER BY seq LIMIT $3`, afterSeq, before, limit)
}

// RecordsInRange returns rows with from <= seq <= to.
func (r *AuditIntegrityRepository) RecordsInRange(ctx context.Context, from, to int64) ([]auditintegrity.Record, error) {
	return r.records(ctx, `SELECT `+recordCols+` FROM audit_events WHERE seq BETWEEN $1 AND $2 ORDER BY seq`, from, to)
}

// MinSeq is the oldest row still kept, 0 when there is none.
func (r *AuditIntegrityRepository) MinSeq(ctx context.Context) (int64, error) {
	var n *int64
	if err := QuerierFromContext(ctx, r.db).QueryRow(ctx, `SELECT min(seq) FROM audit_events`).Scan(&n); err != nil || n == nil {
		return 0, err
	}
	return *n, nil
}

const digestCols = `seq, from_seq, to_seq, record_count, records_hash, previous_digest, digest_hash, signature, key_id, created_at`

func scanDigest(row pgx.Row) (auditintegrity.Digest, error) {
	var d auditintegrity.Digest
	err := row.Scan(&d.Seq, &d.FromSeq, &d.ToSeq, &d.RecordCount, &d.RecordsHash, &d.PreviousDigest, &d.DigestHash,
		&d.Signature, &d.KeyID, &d.CreatedAt)
	return d, err
}

// LastDigest is the newest digest, nil when none was written.
func (r *AuditIntegrityRepository) LastDigest(ctx context.Context) (*auditintegrity.Digest, error) {
	d, err := scanDigest(QuerierFromContext(ctx, r.db).QueryRow(ctx, `SELECT `+digestCols+` FROM audit_digests ORDER BY seq DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// InsertDigest stores d and sets its seq.
func (r *AuditIntegrityRepository) InsertDigest(ctx context.Context, d *auditintegrity.Digest) error {
	return QuerierFromContext(ctx, r.db).QueryRow(ctx, `
		INSERT INTO audit_digests (from_seq, to_seq, record_count, records_hash, previous_digest, digest_hash, signature, key_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING seq`,
		d.FromSeq, d.ToSeq, d.RecordCount, d.RecordsHash, d.PreviousDigest, d.DigestHash, d.Signature, d.KeyID, d.CreatedAt).Scan(&d.Seq)
}

// Digests returns digests with seq > after, in order.
func (r *AuditIntegrityRepository) Digests(ctx context.Context, after int64, limit int) ([]auditintegrity.Digest, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `SELECT `+digestCols+` FROM audit_digests WHERE seq > $1 ORDER BY seq LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auditintegrity.Digest
	for rows.Next() {
		d, err := scanDigest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
