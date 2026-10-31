package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/keymanager"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// sealedColumn is one column of key-manager values, for the key schedule
// to count and re-encrypt what each key sealed. table and column are
// constants of this package, never input.
type sealedColumn struct {
	db      *Pool
	purpose domain.Purpose
	table   string
	column  string
}

var _ app.SealedColumn = sealedColumn{}

func (c sealedColumn) Purpose() domain.Purpose { return c.purpose }
func (c sealedColumn) Name() string            { return c.table + "." + c.column }

// kidPattern matches values sealed by kid ("km1.<kid>.…"). A kid holds
// only base64url characters; '_' is a LIKE wildcard, so it is escaped.
func kidPattern(kid string) string {
	escaped := make([]byte, 0, len(kid)+4)
	for i := 0; i < len(kid); i++ {
		if kid[i] == '_' || kid[i] == '%' || kid[i] == '\\' {
			escaped = append(escaped, '\\')
		}
		escaped = append(escaped, kid[i])
	}
	return domain.CiphertextVersion + "." + string(escaped) + ".%"
}

// CountByKID counts the values kid sealed.
func (c sealedColumn) CountByKID(ctx context.Context, kid string) (int, error) {
	var n int
	err := QuerierFromContext(ctx, c.db).QueryRow(ctx,
		`SELECT count(*) FROM `+c.table+` WHERE `+c.column+` LIKE $1`, kidPattern(kid)).Scan(&n)
	return n, err
}

// Reencrypt rewraps up to limit values, each only if unchanged since read.
func (c sealedColumn) Reencrypt(ctx context.Context, kid string, limit int, rewrap func(old string) (string, error)) (int, error) {
	q := QuerierFromContext(ctx, c.db)
	rows, err := q.Query(ctx, `SELECT id, `+c.column+` FROM `+c.table+` WHERE `+c.column+` LIKE $1 LIMIT $2`, kidPattern(kid), limit)
	if err != nil {
		return 0, err
	}
	type row struct{ id, value string }
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.value); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range list {
		next, err := rewrap(r.value)
		if err != nil {
			return n, err
		}
		tag, err := q.Exec(ctx, `UPDATE `+c.table+` SET `+c.column+` = $1 WHERE id = $2 AND `+c.column+` = $3`, next, r.id, r.value)
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}

// withAdvisoryLock runs fn in a transaction holding lock (try-lock), so
// one replica converts legacy secrets at a time.
func withAdvisoryLock(ctx context.Context, db *Pool, lock int64, fn func(ctx context.Context) error) (bool, error) {
	ran := false
	err := db.InTx(ctx, func(ctx context.Context) error {
		var got bool
		if err := QuerierFromContext(ctx, db).QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lock).Scan(&got); err != nil {
			return err
		}
		if !got {
			return nil
		}
		ran = true
		return fn(ctx)
	})
	return ran, err
}

// Advisory lock ids of the legacy secret conversions ("mailos" + n).
const (
	providerLegacyLock int64 = 0x6d61696c6f73_10
	domainLegacyLock   int64 = 0x6d61696c6f73_11
	webhookLegacyLock  int64 = 0x6d61696c6f73_12
)

// notFound maps no rows to a 404 naming what was missing.
func notFound(err error, what string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return apperrors.NotFound(what + " not found")
	}
	return err
}
