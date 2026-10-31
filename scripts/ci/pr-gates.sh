#!/usr/bin/env bash
# PR gates, one per argument, run by Jenkinsfile.pr inside the Go image and
# runnable on a laptop (the same gates as IAM's). Every test gate goes
# through skipgate: a skipped test fails it.
#
#   scripts/ci/pr-gates.sh vet            go vet: default, integration and e2e tags
#   scripts/ci/pr-gates.sh gosec          SAST, HIGH and above (G115 excluded)
#   scripts/ci/pr-gates.sh govulncheck    known vulnerabilities on the call graph
#   scripts/ci/pr-gates.sh unit           go test -race ./...
#   scripts/ci/pr-gates.sh migrations     migrations up, down to zero, up again
#   scripts/ci/pr-gates.sh integration    migrations, then -tags integration ./integration/
#   scripts/ci/pr-gates.sh e2e            e2e/run.sh all (black-box suite against the binaries)
#
# The stack gates need Postgres and Redis: docker-compose.test.yaml, reached
# on MAILOS_TEST_PG_PORT / MAILOS_TEST_REDIS_PORT (defaults 5434 / 6381),
# database mail_os. The database must be fresh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

GOSEC_VERSION="${GOSEC_VERSION:-v2.22.10}"
GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-v1.9.0}"
PG_PORT="${MAILOS_TEST_PG_PORT:-5434}"
REDIS_PORT="${MAILOS_TEST_REDIS_PORT:-6381}"
PG_PASSWORD="${MAILOS_TEST_PG_PASSWORD-postgres}"
OUT="${CI_REPORT_DIR:-$ROOT/ci-reports}"
mkdir -p "$OUT"

skipgate() {
  [ -x "$OUT/skipgate" ] || go build -o "$OUT/skipgate" ./scripts/ci/skipgate
  "$OUT/skipgate" "$@"
}

# migrate runs cmd/migrate-postgres against the test database only. Config
# validation needs an issuer and a master key even here; both are throwaway.
migrate() {
  APP_ENV=test CONFIG_DIR="$OUT/no-config" POSTGRES_HOST=127.0.0.1 POSTGRES_PORT="$PG_PORT" \
    POSTGRES_USER=postgres POSTGRES_PASSWORD="$PG_PASSWORD" POSTGRES_DB=mail_os POSTGRES_SSL_MODE=disable \
    REDIS_HOST=127.0.0.1 REDIS_PORT="$REDIS_PORT" \
    IAM_ISSUER=http://127.0.0.1 KEY_MANAGER_MASTER_KEY="$(head -c 32 /dev/urandom | base64 | tr -d '\n')" \
    go run ./cmd/migrate-postgres "$@"
}

gate_vet() {
  go vet ./...
  go vet -tags integration ./...
  go vet -tags e2e ./...
}

gate_gosec() {
  go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
  # G115 (integer conversion) is excluded as in IAM; every other HIGH rule fails.
  "$(go env GOPATH)/bin/gosec" -fmt text -out "$OUT/gosec.txt" -stdout -exclude=G115 -severity high -confidence medium ./...
}

gate_govulncheck() {
  go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
  "$(go env GOPATH)/bin/govulncheck" ./... | tee "$OUT/govulncheck.txt"
}

gate_unit() {
  go test -race -count=1 -timeout 20m -json ./... | tee "$OUT/unit.json" | skipgate
}

gate_migrations() {
  migrate up
  migrate down-all
  migrate up
  migrate version
}

gate_integration() {
  gate_migrations
  MAILOS_TEST_PG_PORT="$PG_PORT" MAILOS_TEST_REDIS_PORT="$REDIS_PORT" MAILOS_TEST_PG_PASSWORD="$PG_PASSWORD" \
    go test -tags integration -p 1 -count=1 -timeout 20m -json ./integration/ | tee "$OUT/integration.json" | skipgate
}

gate_e2e() {
  MAILOS_E2E_PG_PORT="$PG_PORT" MAILOS_E2E_PG_PASSWORD="$PG_PASSWORD" MAILOS_E2E_REDIS_PORT="$REDIS_PORT" \
    MAILOS_E2E_WORK="$OUT/e2e-work" e2e/run.sh all
}

[ $# -gt 0 ] || { sed -n '2,16p' "$0"; exit 2; }
for g in "$@"; do
  echo "=== gate: $g"
  case "$g" in
    vet|gosec|govulncheck|unit|migrations|integration|e2e) "gate_$g" ;;
    *) echo "unknown gate $g"; exit 2 ;;
  esac
done
