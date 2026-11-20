//go:build e2e

package harness

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// SearchPostgres returns "table" for every row of every table in the
// public schema whose text holds one of needles.
func (e *Env) SearchPostgres(t T, needles ...string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, e.PostgresDSN)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	rows, err := conn.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	var hits []string
	for _, table := range tables {
		for _, n := range needles {
			var count int
			// table names come from the catalogue, never input.
			if err := conn.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()+` r WHERE strpos(r::text, $1) > 0`, n).
				Scan(&count); err != nil {
				t.Fatalf("search %s: %v", table, err)
			}
			if count > 0 {
				hits = append(hits, table)
			}
		}
	}
	return hits
}

// SearchRedis returns every key, but those in skip, whose value (any type)
// holds one of needles.
func (e *Env) SearchRedis(t T, skip []string, needles ...string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rdb := redis.NewClient(&redis.Options{Addr: e.RedisAddr})
	defer func() { _ = rdb.Close() }()
	var hits []string
	iter := rdb.Scan(ctx, 0, "*", 500).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		if slices.Contains(skip, key) {
			continue
		}
		var text string
		switch typ, _ := rdb.Type(ctx, key).Result(); typ {
		case "string":
			text, _ = rdb.Get(ctx, key).Result()
		case "hash":
			m, _ := rdb.HGetAll(ctx, key).Result()
			for k, v := range m {
				text += k + "=" + v + "\n"
			}
		case "list":
			l, _ := rdb.LRange(ctx, key, 0, -1).Result()
			text = strings.Join(l, "\n")
		case "set":
			l, _ := rdb.SMembers(ctx, key).Result()
			text = strings.Join(l, "\n")
		case "zset":
			l, _ := rdb.ZRange(ctx, key, 0, -1).Result()
			text = strings.Join(l, "\n")
		case "stream":
			msgs, _ := rdb.XRange(ctx, key, "-", "+").Result()
			for _, m := range msgs {
				for k, v := range m.Values {
					text += k + "=" + toString(v) + "\n"
				}
			}
		}
		for _, n := range needles {
			if strings.Contains(text, n) {
				hits = append(hits, key)
			}
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("redis scan: %v", err)
	}
	return hits
}

// SearchLogs returns every server or worker log file holding one of
// needles.
func (e *Env) SearchLogs(t T, needles ...string) []string {
	t.Helper()
	var hits []string
	for _, name := range []string{"server.log", "worker.log"} {
		raw, err := os.ReadFile(filepath.Join(e.LogDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, n := range needles {
			if strings.Contains(string(raw), n) {
				hits = append(hits, name)
			}
		}
	}
	return hits
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
