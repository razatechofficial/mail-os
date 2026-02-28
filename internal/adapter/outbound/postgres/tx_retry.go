package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/razatechofficial/mail-os/internal/port"
)

const (
	maxRetries           = 3
	retryDelay           = 50 * time.Millisecond
	serializationFailure = "40001"
	deadlockDetected     = "40P01"
)

func RunWithRetry(ctx context.Context, txMgr port.TxManager, fn func(ctx context.Context) error) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay * time.Duration(attempt)):
			}
		}

		lastErr = txMgr.RunInTx(ctx, fn)
		if lastErr == nil {
			return nil
		}

		if !isRetryable(lastErr) {
			return lastErr
		}
	}
	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

func isRetryable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == serializationFailure || pgErr.Code == deadlockDetected
	}
	return false
}
