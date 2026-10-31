package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	app "github.com/razatechofficial/mail-os/application/provider"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/provider"
)

// ProviderRepository stores providers: non-secret settings in
// configuration, credentials sealed in credentials_sealed.
type ProviderRepository struct {
	db       *Pool
	messages *MessageRepository
}

var _ app.Repository = (*ProviderRepository)(nil)

// NewProviderRepository returns the repository.
func NewProviderRepository(db *Pool) *ProviderRepository {
	return &ProviderRepository{db: db, messages: NewMessageRepository(db)}
}

// SealedColumn is credentials_sealed, for the key schedule.
func (r *ProviderRepository) SealedColumn() appkm.SealedColumn {
	return sealedColumn{db: r.db, purpose: domainkm.PurposeProvider, table: "providers", column: "credentials_sealed"}
}

const providerCols = `id, org_id, name, type, configuration, priority, weight, daily_limit, is_active, has_credentials,
	credential_hints, COALESCE(credentials_sealed, ''), COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at`

func scanProvider(row pgx.Row) (app.Stored, error) {
	var s app.Stored
	p := &s.Provider
	var kind string
	var cfg, hints []byte
	err := row.Scan(&p.ID, &p.OrgID, &p.Name, &kind, &cfg, &p.Priority, &p.Weight, &p.DailyLimit, &p.Active, &p.HasCredentials,
		&hints, &s.Sealed, &p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return s, err
	}
	p.Kind = domain.Kind(kind)
	_ = json.Unmarshal(cfg, &p.Settings)
	if len(hints) > 0 && string(hints) != "{}" {
		_ = json.Unmarshal(hints, &p.CredentialHints)
	}
	return s, nil
}

func hintsJSON(h domain.Hints) []byte {
	if h == nil {
		return []byte("{}")
	}
	raw, _ := json.Marshal(h)
	return raw
}

// Create inserts a provider.
func (r *ProviderRepository) Create(ctx context.Context, s app.Stored) error {
	p := s.Provider
	settings, _ := json.Marshal(p.Settings)
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO providers (id, org_id, name, type, configuration, priority, weight, daily_limit, is_active,
			credentials_sealed, has_credentials, credential_hints, created_by, updated_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), $11, $12, NULLIF($13, ''), NULLIF($14, ''), $15, $16)`,
		p.ID, p.OrgID, p.Name, string(p.Kind), settings, p.Priority, p.Weight, p.DailyLimit, p.Active, s.Sealed,
		p.HasCredentials, hintsJSON(p.CredentialHints), p.CreatedBy, p.UpdatedBy, p.CreatedAt, p.UpdatedAt)
	return err
}

// Update saves p, and the credentials when sealed is set.
func (r *ProviderRepository) Update(ctx context.Context, p domain.Provider, sealed *string) error {
	settings, _ := json.Marshal(p.Settings)
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE providers SET name = $3, type = $4, configuration = $5, priority = $6, weight = $7, daily_limit = $8,
			is_active = $9, has_credentials = $10, credential_hints = $11, updated_by = NULLIF($12, ''), updated_at = $13,
			credentials_sealed = CASE WHEN $14::boolean THEN NULLIF($15, '') ELSE credentials_sealed END
		WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
		p.ID, p.OrgID, p.Name, string(p.Kind), settings, p.Priority, p.Weight, p.DailyLimit, p.Active, p.HasCredentials,
		hintsJSON(p.CredentialHints), p.UpdatedBy, p.UpdatedAt, sealed != nil, deref(sealed))
	return err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Delete soft-deletes a provider and drops its credentials.
func (r *ProviderRepository) Delete(ctx context.Context, tenantID, id string, at time.Time) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `UPDATE providers SET deleted_at = $3, is_active = false,
		credentials_sealed = NULL, has_credentials = false, credential_hints = '{}', updated_at = $3
		WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, id, tenantID, at)
	return err
}

// Get reads one of the tenant's providers.
func (r *ProviderRepository) Get(ctx context.Context, tenantID, id string) (app.Stored, error) {
	s, err := scanProvider(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+providerCols+` FROM providers WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, id, tenantID))
	return s, notFound(err, "provider")
}

func (r *ProviderRepository) scan(ctx context.Context, sql string, args ...any) ([]app.Stored, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.Stored
	for rows.Next() {
		s, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// List returns a page of providers, highest priority first.
func (r *ProviderRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Provider, int, error) {
	var total int
	if err := QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT count(*) FROM providers WHERE org_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	list, err := r.scan(ctx, `SELECT `+providerCols+` FROM providers WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY priority DESC, created_at LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	out := make([]domain.Provider, len(list))
	for i, s := range list {
		out[i] = s.Provider
	}
	return out, total, err
}

// ListActive returns the tenant's active providers with their sealed
// credentials.
func (r *ProviderRepository) ListActive(ctx context.Context, tenantID string) ([]app.Stored, error) {
	return r.scan(ctx, `SELECT `+providerCols+` FROM providers WHERE org_id = $1 AND is_active AND deleted_at IS NULL
		ORDER BY priority DESC`, tenantID)
}

// SentSince counts the providers' sends since t.
func (r *ProviderRepository) SentSince(ctx context.Context, ids []string, t time.Time) (map[string]int, error) {
	return r.messages.SentSince(ctx, ids, t)
}

// Legacy lists providers whose configuration still holds secret keys.
func (r *ProviderRepository) Legacy(ctx context.Context) ([]app.LegacyRow, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx,
		`SELECT id, type, configuration FROM providers WHERE configuration ?| $1::text[]`, app.LegacySecretKeys())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.LegacyRow
	for rows.Next() {
		var lr app.LegacyRow
		var kind string
		var cfg []byte
		if err := rows.Scan(&lr.ID, &kind, &cfg); err != nil {
			return nil, err
		}
		lr.Kind = domain.Kind(kind)
		_ = json.Unmarshal(cfg, &lr.Configuration)
		out = append(out, lr)
	}
	return out, rows.Err()
}

// ReplaceLegacy writes the split settings and sealed credentials.
func (r *ProviderRepository) ReplaceLegacy(ctx context.Context, id string, settings domain.Settings, sealed string, hints domain.Hints) error {
	raw, _ := json.Marshal(settings)
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `UPDATE providers SET configuration = $2,
		credentials_sealed = NULLIF($3, ''), has_credentials = $3 <> '', credential_hints = $4 WHERE id = $1`,
		id, raw, sealed, hintsJSON(hints))
	return err
}

// WithLock runs fn under the provider conversion's advisory lock.
func (r *ProviderRepository) WithLock(ctx context.Context, fn func(ctx context.Context) error) (bool, error) {
	return withAdvisoryLock(ctx, r.db, providerLegacyLock, fn)
}
