package pgqueue

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/lib/pq"

	"github.com/google/uuid"
	"github.com/razatechofficial/mail-os/internal/port"
)

var (
	_ port.Publisher = (*publisher)(nil)
	_ port.Consumer  = (*consumer)(nil)
)

type publisher struct {
	dsn string
	db  *sql.DB
}

type consumer struct {
	dsn string
	db  *sql.DB
}

func NewPublisher(dsn string) port.Publisher {
	db, _ := sql.Open("postgres", dsn)
	return &publisher{dsn: dsn, db: db}
}

func NewConsumer(dsn string) port.Consumer {
	db, _ := sql.Open("postgres", dsn)
	return &consumer{dsn: dsn, db: db}
}

func (p *publisher) Publish(ctx context.Context, topic string, payload []byte, opts ...port.PublishOption) error {
	if p.db == nil {
		var err error
		p.db, err = sql.Open("postgres", p.dsn)
		if err != nil {
			return err
		}
	}
	o := port.ApplyPublishOptions(opts...)
	runAt := time.Now().Add(o.Delay)
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO queue_jobs (id, topic, payload, status, created_at, run_at)
		 VALUES ($1, $2, $3, 'pending', NOW(), $4)`,
		uuid.New().String(), topic, payload, runAt)
	return err
}

func (p *publisher) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (c *consumer) Subscribe(ctx context.Context, topic string, handler port.JobHandler) error {
	if c.db == nil {
		var err error
		c.db, err = sql.Open("postgres", c.dsn)
		if err != nil {
			return err
		}
	}
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.poll(ctx, topic, handler)
			}
		}
	}()
	return nil
}

func (c *consumer) poll(ctx context.Context, topic string, handler port.JobHandler) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var id string
	var payload []byte
	err = tx.QueryRowContext(ctx,
		`SELECT id, payload FROM queue_jobs
		 WHERE topic = $1 AND status = 'pending' AND run_at <= NOW()
		 ORDER BY run_at ASC
		 LIMIT 1
		 FOR UPDATE SKIP LOCKED`,
		topic).Scan(&id, &payload)
	if err != nil {
		if err == sql.ErrNoRows {
			return
		}
		return
	}
	if err := handler(ctx, payload); err != nil {
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM queue_jobs WHERE id = $1`, id); err != nil {
		return
	}
	tx.Commit()
}

func (c *consumer) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
