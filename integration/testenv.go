//go:build integration

// Package integration tests the repositories, the use cases and the HTTP
// stack against a real Postgres and Redis (docker-compose.test.yaml, or a
// private stack), never the developer configuration. IAM is faked with
// internal/testutil/fakeiam.
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/infrastructure/cache/redis"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// testConfig points at the test stack on MAILOS_TEST_PG_PORT /
// MAILOS_TEST_REDIS_PORT (defaults 5434 / 6381).
func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.App.Env, cfg.App.Name = "test", "mailos-integration"
	cfg.Postgres.Host = "127.0.0.1"
	cfg.Postgres.Port = testPort("MAILOS_TEST_PG_PORT", 5434)
	cfg.Postgres.User = "postgres"
	cfg.Postgres.Password = envOr("MAILOS_TEST_PG_PASSWORD", "postgres")
	cfg.Postgres.Database = envOr("MAILOS_TEST_PG_DB", "mail_os")
	cfg.Postgres.SSLMode = "disable"
	cfg.Postgres.MaxConns, cfg.Postgres.MinConns = 8, 1
	cfg.Redis.Host = "127.0.0.1"
	cfg.Redis.Port = testPort("MAILOS_TEST_REDIS_PORT", 6381)
	cfg.Redis.PoolSize = 8
	cfg.Redis.DB = 3
	return cfg
}

func migrationsPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "migrations", "postgres")
}

var (
	poolOnce sync.Once
	pool     *postgres.Pool
	poolErr  error
)

// connectPostgres creates the test database if needed, migrates it up once
// per process, and returns a shared pool.
func connectPostgres(t *testing.T) *postgres.Pool {
	t.Helper()
	if logger.Log == nil {
		_ = logger.InitSimple("error", "json")
	}
	poolOnce.Do(func() {
		cfg := testConfig()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if poolErr = createDatabase(ctx, cfg); poolErr != nil {
			return
		}
		m, err := postgres.NewMigrator(cfg.Postgres.DSN(), migrationsPath())
		if err != nil {
			poolErr = err
			return
		}
		if poolErr = m.Up(); poolErr != nil {
			_ = m.Close()
			return
		}
		_ = m.Close()
		pool, poolErr = postgres.NewConnection(ctx, cfg)
	})
	if poolErr != nil {
		t.Fatalf("postgres setup: %v", poolErr)
	}
	return pool
}

func createDatabase(ctx context.Context, cfg *config.Config) error {
	admin := cfg.Postgres
	admin.Database = "postgres"
	conn, err := pgx.Connect(ctx, admin.DSN())
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, cfg.Postgres.Database).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{cfg.Postgres.Database}.Sanitize())
	return err
}

// connectRedis returns a client on the test Redis.
func connectRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb, err := redis.NewClient(testConfig().Redis)
	if err != nil {
		t.Fatal(err)
	}
	if err := rdb.Health(context.Background()); err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func testPort(env string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(env)); err == nil && n > 0 {
		return n
	}
	return def
}

func envOr(env, def string) string {
	if v, ok := os.LookupEnv(env); ok {
		return v
	}
	return def
}
