# MailOS server. Configuration is env-driven (.env, see .env.example); the
# CI gates are scripts/ci/pr-gates.sh, so `make vet test integration e2e`
# runs on a laptop what Jenkinsfile.pr runs.

MIGRATE_POSTGRES = go run ./cmd/migrate-postgres
COMPOSE_TEST     = docker compose -f docker-compose.test.yaml
GATES            = scripts/ci/pr-gates.sh
IMAGE            ?= mailos:latest
VERSION          ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
COMMIT           ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS          = -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)

.PHONY: help build run run-worker test vet gosec govulncheck gates integration e2e e2e-up e2e-test e2e-down e2e-env \
	stack-up stack-down stack-fresh migrate-postgres-up migrate-postgres-down migrate-postgres-down-all \
	migrate-postgres-version migrate-postgres-create proto openapi docker-build tidy clean

## help: list the targets
help:
	@grep -E '^## ' Makefile | sed 's/## //'

# ── build and run ─────────────────────────────────────────────────────────

## build: build the server, worker and migrator into bin/
build:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/server ./cmd/worker ./cmd/migrate-postgres

## run: start the HTTP/gRPC server (env from .env)
run:
	go run ./cmd/server

## run-worker: start the asynq worker (env from .env)
run-worker:
	go run ./cmd/worker

## docker-build: build the image (server, worker, migrator) from deployments/Dockerfile
docker-build:
	docker build -f deployments/Dockerfile --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .

# ── gates (the same commands as Jenkinsfile.pr) ───────────────────────────

## vet: go vet with no tag, -tags integration and -tags e2e
vet:
	$(GATES) vet

## test: unit tests with the race detector (a skipped test fails)
test:
	$(GATES) unit

## gosec: SAST, HIGH and above (G115 excluded)
gosec:
	$(GATES) gosec

## govulncheck: known vulnerabilities on the call graph
govulncheck:
	$(GATES) govulncheck

## integration: fresh test stack, migrations up/down-all/up, -tags integration ./integration/
integration: stack-fresh
	$(GATES) integration

## e2e: fresh test stack, then e2e/run.sh all (fake IAM, server, worker, -tags e2e ./e2e/...)
e2e: stack-fresh
	$(GATES) e2e

## gates: every gate in CI order (needs Docker for the stack gates)
gates: vet gosec govulncheck test integration e2e

## e2e-up: start fake IAM, server and worker against the running stack (for iterating on tests)
e2e-up:
	e2e/run.sh up

## e2e-test: run the e2e packages against e2e-up (MAILOS_E2E_PKGS=./e2e/smoke/... narrows)
e2e-test:
	e2e/run.sh test

## e2e-down: stop what e2e-up started
e2e-down:
	e2e/run.sh down

## e2e-env: print the variables the harness (or Playwright) needs
e2e-env:
	@e2e/run.sh env

## stack-up: start the test stack (Postgres 18 tmpfs, Redis 7)
stack-up:
	$(COMPOSE_TEST) up -d --wait

## stack-down: stop the test stack and drop its data
stack-down:
	$(COMPOSE_TEST) down -v --remove-orphans

## stack-fresh: recreate the test stack with an empty database
stack-fresh: stack-down stack-up

# ── migrations (env from .env) ────────────────────────────────────────────

## migrate-postgres-up: apply every pending migration
migrate-postgres-up:
	$(MIGRATE_POSTGRES) up

## migrate-postgres-down: roll back the last migration
migrate-postgres-down:
	$(MIGRATE_POSTGRES) down

## migrate-postgres-down-all: roll back every migration (dev only)
migrate-postgres-down-all:
	$(MIGRATE_POSTGRES) down-all

## migrate-postgres-version: show the current migration version
migrate-postgres-version:
	$(MIGRATE_POSTGRES) version

## migrate-postgres-create name=<name>: create a timestamped migration pair in migrations/postgres
migrate-postgres-create:
	@if [ -z "$(name)" ]; then echo "Usage: make migrate-postgres-create name=<migration_name>"; exit 1; fi
	@TS=$$(date +%Y%m%d%H%M%S); mkdir -p migrations/postgres; \
	touch migrations/postgres/$${TS}_$(name).up.sql migrations/postgres/$${TS}_$(name).down.sql; \
	echo "created migrations/postgres/$${TS}_$(name).{up,down}.sql"

# ── code generation ───────────────────────────────────────────────────────

## proto: generate gRPC code (installs protoc into bin/ when missing)
proto:
	@./scripts/get-protoc.sh
	@./scripts/generate-proto.sh

## openapi: update the OpenAPI spec from the registered routes
openapi:
	go test ./transport/http -run TestOpenAPISpec -count=1 -update-openapi

## tidy: go mod tidy
tidy:
	go mod tidy

## clean: remove build and CI output
clean:
	rm -rf bin/ ci-reports/ e2e/.work/ coverage.* *.coverprofile
