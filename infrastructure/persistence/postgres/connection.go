// Package postgres provides PostgreSQL connectivity using pgx, and the
// repositories of every MailOS aggregate. It is the only place in the
// application that imports pgx: use cases see their own ports.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/razatechofficial/mail-os/config"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Pool wraps pgxpool.Pool. Repositories receive *Pool and use
// QuerierFromContext(ctx, pool), so they work with or without a
// transaction in the context.
type Pool struct {
	*pgxpool.Pool
}

// NewConnection creates the pool and pings it, retrying for a short while
// so a pod that starts with the database fails fast but not on a blip.
func NewConnection(ctx context.Context, cfg *config.Config) (*Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.Postgres.DSN())
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}
	pc.MaxConns = cfg.Postgres.MaxConns
	pc.MinConns = cfg.Postgres.MinConns
	pc.MaxConnLifetime = time.Hour
	pc.MaxConnIdleTime = 15 * time.Minute
	pc.HealthCheckPeriod = time.Minute
	pc.ConnConfig.ConnectTimeout = 10 * time.Second
	appName := strings.ReplaceAll(cfg.App.Name, "'", "''")
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET application_name = '%s'", appName))
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		last = pool.Ping(pingCtx)
		cancel()
		if last == nil {
			return &Pool{Pool: pool}, nil
		}
		logger.Warn("postgres not reachable yet", logger.Int("attempt", attempt+1), logger.Err(last))
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	pool.Close()
	return nil, fmt.Errorf("postgres ping: %w", last)
}

// Health pings the database.
func (p *Pool) Health(ctx context.Context) error { return p.Ping(ctx) }

// uniqueViolation is SQLSTATE 23505.
const uniqueViolation = "23505"

// foreignKeyViolation is SQLSTATE 23503.
const foreignKeyViolation = "23503"

// IsUniqueViolation reports a duplicate key.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation
}

// IsForeignKeyViolation reports a missing referenced row.
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == foreignKeyViolation
}

// NotFound maps pgx.ErrNoRows to apperrors.ErrNotFound and passes other
// errors through.
func NotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return apperrors.ErrNotFound
	}
	return err
}
