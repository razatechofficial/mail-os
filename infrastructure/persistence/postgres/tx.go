package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the interface used for all DB operations (pool or transaction).
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var _ Querier = (*Pool)(nil)

type txKey struct{}

// WithTx attaches a transaction to the context; repositories using
// QuerierFromContext join it.
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// QuerierFromContext returns the context's transaction, or the pool.
func QuerierFromContext(ctx context.Context, pool *Pool) Querier {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok && tx != nil {
		return tx
	}
	return pool
}

// InTx runs fn in a transaction carried by ctx, committing when fn returns
// nil. A transaction already in ctx is joined instead (no nesting), so a use
// case can group repository calls without knowing whether its caller did.
func (p *Pool) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok && tx != nil {
		return fn(ctx)
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(WithTx(ctx, tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
