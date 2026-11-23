#!/bin/bash
# The cross-repo end-to-end test of MailOS Phase 1 slice 1 (a platform
# administrator signs in to the MailOS Platform Console) with the real IAM,
# IAM console, ACS, MailOS server and MailOS console. Runs on the test VPS
# from $CROSS_HOME/src/mailos-server/e2e/cross (push.sh puts the sources
# there); every port is 127.0.0.1:276xx; compose project mailos-p1-cross.
#
#   run.sh up      secrets, images and builds, then the IAM, ACS and the IAM
#                  console on fresh stores
#   run.sh test    setup through the IAM's API (project iam-setup), then the
#                  MailOS server and console, then the PIM activation and the
#                  specs (project cross)
#   run.sh down    stop everything and drop its volumes
#   run.sh clean   down, then remove the ACS image this stack built
#   run.sh all     up, test, down
#   run.sh logs [service]
set -euo pipefail
cd "$(dirname "$0")"
export CROSS_HOME=${CROSS_HOME:-/opt/mailos-p1-test/cross}
export CROSS_UID=${CROSS_UID:-$(id -u)} CROSS_GID=${CROSS_GID:-$(id -g)}
export ACS_COMMIT=${ACS_COMMIT:-$(cat "$CROSS_HOME/src/acs/.commit" 2>/dev/null || echo unknown)}
PROJECT=mailos-p1-cross
DC=(docker compose -p "$PROJECT" -f compose.yaml)
DCA=("${DC[@]}" --profile lenient --profile mailos --profile test)
PW_IMAGE=mcr.microsoft.com/playwright:v1.64.1-noble

# waitload: heavy steps wait while the VPS's 1-minute load is above 6.
waitload() {
  local l
  while :; do
    l=$(cut -d' ' -f1 /proc/loadavg)
    awk "BEGIN{exit !($l < 6)}" && return 0
    echo "load $l: waiting"
    sleep 30
  done
}

secrets() {
  [ -s "$CROSS_HOME/secrets/env/ms.env" ] && return 0
  mkdir -p "$CROSS_HOME/secrets"
  docker run --rm --name "$PROJECT-secrets" --user 0 -e HOST_UID="$CROSS_UID" -e HOST_GID="$CROSS_GID" \
    -v "$PWD/gen-secrets.sh:/gen.sh:ro" -v "$CROSS_HOME/secrets:/out" alpine:3.22 \
    sh -c 'apk add -q --no-cache bash openssl >/dev/null && bash /gen.sh'
}

# node_build runs npm in the Playwright image on a source directory.
node_build() {
  local name=$1 dir=$2 cmd=$3
  waitload
  docker run --rm --name "$PROJECT-build-$name" --network host --user "$CROSS_UID:$CROSS_GID" \
    -e HOME=/tmp/home -e NEXT_TELEMETRY_DISABLED=1 -e NODE_OPTIONS=--max-old-space-size=4096 \
    -v "$dir:/app" -w /app "$PW_IMAGE" bash -c "$cmd" ||
    { echo "$name: retrying once (a registry hiccup)"; sleep 20; docker run --rm --name "$PROJECT-build-$name" --network host \
      --user "$CROSS_UID:$CROSS_GID" -e HOME=/tmp/home -e NEXT_TELEMETRY_DISABLED=1 -e NODE_OPTIONS=--max-old-space-size=4096 \
      -v "$dir:/app" -w /app "$PW_IMAGE" bash -c "$cmd"; }
}

build() {
  waitload
  "${DC[@]}" build acs-core
  # Next prints a one-time notice that can fail the first build; the retry builds.
  [ -f "$CROSS_HOME/src/iam-console/.next/BUILD_ID" ] ||
    node_build ic "$CROSS_HOME/src/iam-console" "npm ci --no-audit --no-fund && (npm run build || npm run build)"
  [ -f "$CROSS_HOME/src/mailos-console/.next/BUILD_ID" ] ||
    node_build mc "$CROSS_HOME/src/mailos-console" "npm ci --no-audit --no-fund && (npm run build || npm run build)"
  [ -d "$CROSS_HOME/src/mailos-console/e2e/cross/node_modules" ] ||
    node_build pw "$CROSS_HOME/src/mailos-console" "npm ci --no-audit --no-fund --prefix e2e/cross"
}

job_ok() { # a one-shot service ran to completion and exited 0
  local id code
  id=$("${DC[@]}" ps -aq "$1")
  code=$(docker wait "$id")
  [ "$code" = 0 ] || { echo "$1 exited $code" >&2; "${DC[@]}" logs --tail 60 "$1" >&2; return 1; }
}

ready() { # wait for an HTTP answer from 127.0.0.1:port
  local port=$1 path=$2 name=$3 i
  for i in $(seq 1 120); do
    if curl -fsS -o /dev/null "http://127.0.0.1:$port$path" 2>/dev/null; then echo "$name ready"; return 0; fi
    sleep 3
  done
  echo "$name not ready" >&2
  "${DC[@]}" logs --tail 60 "$name" >&2
  return 1
}

up() {
  secrets
  build
  # Fresh run state: the stores are tmpfs, so the work directories go too.
  "${DCA[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$CROSS_HOME/work/iam" "$CROSS_HOME/work/ms" "$CROSS_HOME/work/mc" "$CROSS_HOME/work/state" "$CROSS_HOME/work/results"
  mkdir -p "$CROSS_HOME/go" "$CROSS_HOME/work/iam" "$CROSS_HOME/work/ms" "$CROSS_HOME/work/mc" "$CROSS_HOME/work/state" \
    "$CROSS_HOME/work/results"
  waitload
  "${DC[@]}" up -d --wait --wait-timeout 300 pg spicedb redis redis-ms
  # ACS's schema writer first, into the empty SpiceDB (its core v3), then the IAM.
  "${DC[@]}" up -d --no-deps acs-migrate-db
  job_ok acs-migrate-db
  "${DC[@]}" up -d --no-deps acs-migrate-schema
  job_ok acs-migrate-schema
  "${DC[@]}" up -d --wait --wait-timeout 900 --no-deps iam
  "${DC[@]}" up -d iam-tls
  "${DC[@]}" up -d --no-deps acs-core acs-applier
  ready 27692 /readyz acs-core
  "${DC[@]}" up -d --no-deps acs
  ready 27694 /readyz acs
  "${DC[@]}" up -d --wait --wait-timeout 300 ic
  "${DC[@]}" ps
}

pw() { # Playwright in the pw service: run.sh's project, then a JSON report
  local project=$1
  "${DCA[@]}" run --rm --no-deps -e PLAYWRIGHT_JSON_OUTPUT_NAME="/work/results/$project.json" pw \
    npx playwright test -c e2e/cross/playwright.config.ts --project="$project" --reporter=list,json
}

test_() {
  "${DCA[@]}" up -d --wait --wait-timeout 300 iam-lenient
  local status=0
  pw iam-setup || status=$?
  "${DCA[@]}" stop iam-lenient >/dev/null
  "${DCA[@]}" rm -f iam-lenient >/dev/null
  [ "$status" = 0 ] || { echo "setup failed" >&2; return "$status"; }
  waitload
  "${DCA[@]}" up -d --wait --wait-timeout 900 ms mc
  pw cross
}

down() { "${DCA[@]}" down -v --remove-orphans; }

case "${1:-all}" in
  up) up ;;
  test) test_ ;;
  down) down ;;
  clean) down; docker image rm mailos-p1-cross/acs:local 2>/dev/null || true ;;
  logs) shift; "${DCA[@]}" logs --tail "${TAIL:-80}" "$@" ;;
  all) up; trap down EXIT; test_ ;;
  *) echo "usage: run.sh up|test|down|clean|all|logs [service]" >&2; exit 2 ;;
esac
