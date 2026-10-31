#!/usr/bin/env bash
# Black-box e2e suite: build and start the real MailOS binaries against the
# test stack (docker-compose.test.yaml, or any Postgres/Redis named below)
# and a fake IAM (e2e/cmd/fakeiam), then run the e2e packages against them.
#
#   e2e/run.sh up     build, write keys and env, start fake IAM, migrate, start server and worker
#   e2e/run.sh test   run the e2e packages (skipgate: a skipped test fails)
#   e2e/run.sh down   stop the server, worker and fake IAM
#   e2e/run.sh all    up, test, down (the CI gate)
#   e2e/run.sh env    print the variables a client (the harness, Playwright) needs
#
# The database must be fresh (the CI stack is; locally recreate it).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORK="${MAILOS_E2E_WORK:-$ROOT/e2e/.work}"
PG_HOST="${MAILOS_E2E_PG_HOST:-127.0.0.1}"
PG_PORT="${MAILOS_E2E_PG_PORT:-5434}"
PG_USER="${MAILOS_E2E_PG_USER:-postgres}"
PG_PASSWORD="${MAILOS_E2E_PG_PASSWORD:-postgres}"
PG_DB="${MAILOS_E2E_PG_DB:-mail_os}"
REDIS_HOST="${MAILOS_E2E_REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${MAILOS_E2E_REDIS_PORT:-6381}"
HTTP_PORT="${MAILOS_E2E_HTTP_PORT:-18180}"
GRPC_PORT="${MAILOS_E2E_GRPC_PORT:-18181}"
IAM_PORT="${MAILOS_E2E_IAM_PORT:-18190}"
METRICS_PORT="${MAILOS_E2E_METRICS_PORT:-18182}"
WORKER_METRICS_PORT="${MAILOS_E2E_WORKER_METRICS_PORT:-18183}"
CONSOLE_ORIGIN="${MAILOS_E2E_CONSOLE_ORIGIN:-http://localhost:3200}"
PKGS="${MAILOS_E2E_PKGS:-./e2e/...}"
BASE_URL="http://127.0.0.1:${HTTP_PORT}"
IAM_URL="http://127.0.0.1:${IAM_PORT}"
# The service client IAM calls MailOS as (contract §1, §4).
IAM_SERVICE_CLIENT="mailos-iam"

mkdir -p "$WORK/bin" "$WORK/keys"
chmod 700 "$WORK/keys"

secret() { head -c "${1:-32}" /dev/urandom | base64 | tr -d '\n'; }

build() {
  echo "e2e: building binaries"
  go build -o "$WORK/bin/" ./cmd/server ./cmd/worker ./cmd/migrate-postgres
  go build -tags e2e -o "$WORK/bin/" ./e2e/cmd/fakeiam
  go build -o "$WORK/bin/" ./scripts/ci/skipgate
}

# keys writes the run's secrets once: the master key, the hook token and the
# fake IAM's mint token. The fake IAM's signing keys live in its memory.
keys() {
  local k="$WORK/keys"
  [ -f "$k/master.key" ] || secret 32 > "$k/master.key"
  [ -f "$k/hooks.token" ] || secret 36 > "$k/hooks.token"
  [ -f "$k/iam-mint.token" ] || secret 36 > "$k/iam-mint.token"
  chmod 600 "$k"/*
}

# write_env writes the environment the server, worker and migrations share:
# plaintext transports (APP_ENV=e2e), the fake IAM as issuer, the test-only
# hooks, and no Kafka.
write_env() {
  local k="$WORK/keys"
  cat > "$WORK/server.env" <<EOF
APP_ENV=e2e
CONFIG_DIR=$WORK/no-config
APP_LOG_LEVEL=info
APP_LOG_FORMAT=json
HTTP_HOST=127.0.0.1
HTTP_PORT=$HTTP_PORT
GRPC_HOST=127.0.0.1
GRPC_PORT=$GRPC_PORT
METRICS_ADDR=127.0.0.1:$METRICS_PORT
POSTGRES_HOST=$PG_HOST
POSTGRES_PORT=$PG_PORT
POSTGRES_USER=$PG_USER
POSTGRES_PASSWORD=$PG_PASSWORD
POSTGRES_DB=$PG_DB
POSTGRES_SSL_MODE=disable
REDIS_HOST=$REDIS_HOST
REDIS_PORT=$REDIS_PORT
IAM_ISSUER=$IAM_URL
IAM_AUDIENCE=mailos
IAM_CONSOLE_AUDIENCES=mailos-console
IAM_JWKS_CACHE_TTL=1m
MAILOS_SERVICE_CLIENTS=$IAM_SERVICE_CLIENT=iam.*
KEY_MANAGER_MASTER_KEY=$(cat "$k/master.key")
CORS_ORIGINS=$CONSOLE_ORIGIN
FEATURE_PUBSUB_INGEST=false
FEATURE_AUDIT_STREAM=false
FEATURE_RAW_HTML_BLOCKS=true
RATE_LIMIT_ENABLED=false
SMTP_ENABLED=false
WORKER_SCHEDULER_INTERVAL=1s
MAILOS_E2E_HOOKS=true
MAILOS_E2E_HOOKS_TOKEN=$(cat "$k/hooks.token")
EOF
  chmod 600 "$WORK/server.env"
}

load_env() {
  set -a; . "$WORK/server.env"; set +a
}

# wait_http waits for url to answer 2xx while the process in pidfile lives.
wait_http() {
  local name="$1" url="$2" pidfile="$3" log="$4"
  for _ in $(seq 1 120); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      echo "e2e: $name exited:"; tail -30 "$log"; exit 1
    fi
    sleep 0.5
  done
  echo "e2e: $name not ready at $url"; tail -30 "$log"; exit 1
}

start() {
  local name="$1"; shift
  "$@" > "$WORK/$name.log" 2>&1 &
  echo $! > "$WORK/$name.pid"
}

up() {
  build
  keys
  write_env
  down >/dev/null 2>&1 || true

  echo "e2e: starting the fake IAM on $IAM_URL"
  start fakeiam "$WORK/bin/fakeiam" -addr "127.0.0.1:$IAM_PORT" -mint-token-file "$WORK/keys/iam-mint.token"
  wait_http "fake IAM" "$IAM_URL/.well-known/openid-configuration" "$WORK/fakeiam.pid" "$WORK/fakeiam.log"

  load_env
  echo "e2e: migrating $PG_HOST:$PG_PORT/$PG_DB"
  "$WORK/bin/migrate-postgres" up

  echo "e2e: starting the server on $BASE_URL and the worker"
  start server "$WORK/bin/server"
  # The worker serves its own metrics; give it a port of its own.
  METRICS_ADDR="127.0.0.1:$WORKER_METRICS_PORT" start worker "$WORK/bin/worker"
  wait_http server "$BASE_URL/ready" "$WORK/server.pid" "$WORK/server.log"
  if ! kill -0 "$(cat "$WORK/worker.pid")" 2>/dev/null; then
    echo "e2e: the worker exited:"; tail -30 "$WORK/worker.log"; exit 1
  fi
  echo "e2e: ready"
}

print_env() {
  echo "MAILOS_E2E_BASE_URL=$BASE_URL"
  echo "MAILOS_E2E_GRPC_ADDR=127.0.0.1:$GRPC_PORT"
  echo "MAILOS_E2E_HOOK_TOKEN=$(cat "$WORK/keys/hooks.token")"
  echo "MAILOS_E2E_IAM_URL=$IAM_URL"
  echo "MAILOS_E2E_IAM_TOKEN=$(cat "$WORK/keys/iam-mint.token")"
}

run_tests() {
  [ -x "$WORK/bin/skipgate" ] || go build -o "$WORK/bin/" ./scripts/ci/skipgate
  set -a; eval "$(print_env)"; set +a
  # Tests that start their own server process (for example to prove the
  # hooks are refused in production) use this binary and environment.
  export MAILOS_E2E_SERVER_BIN="$WORK/bin/server" MAILOS_E2E_SERVER_ENV="$WORK/server.env"
  # shellcheck disable=SC2086 # PKGS is a list of package patterns
  go test -tags e2e -count=1 -timeout 15m -json $PKGS | tee "$WORK/e2e.json" | "$WORK/bin/skipgate"
}

stop() {
  local pidfile="$WORK/$1.pid"
  if [ -f "$pidfile" ]; then
    kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"
  fi
}

down() {
  stop worker
  stop server
  stop fakeiam
}

case "${1:-all}" in
  up) up ;;
  test) run_tests ;;
  down) down ;;
  env) print_env ;;
  all)
    trap down EXIT
    up
    run_tests ;;
  *) echo "usage: e2e/run.sh up|test|down|all|env"; exit 2 ;;
esac
