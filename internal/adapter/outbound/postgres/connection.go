package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Pool struct {
	*pgxpool.Pool
}

func NewConnection(ctx context.Context, dsn string, maxConns, minConns int32) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres.NewConnection: parse config: %w", err)
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = minConns

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres.NewConnection: connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("postgres.NewConnection: ping: %w", err)
	}

	return &Pool{pool}, nil
}

func (p *Pool) Health(ctx context.Context) error {
	return p.Ping(ctx)
}
