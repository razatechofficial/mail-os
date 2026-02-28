.PHONY: build run run-worker migrate-up migrate-down migrate-version test lint proto clean help

CONFIG ?= environments/local.yaml

build:
	go build -o bin/server ./cmd/server
	go build -o bin/worker ./cmd/worker
	go build -o bin/migrate ./cmd/migrate

run:
	go run ./cmd/server -config=$(CONFIG)

run-worker:
	go run ./cmd/worker -config=$(CONFIG)

migrate-up:
	go run ./cmd/migrate -config=$(CONFIG) up

migrate-down:
	go run ./cmd/migrate -config=$(CONFIG) down

migrate-version:
	go run ./cmd/migrate -config=$(CONFIG) version

test:
	go test ./... -race -count=1

test-coverage:
	go test ./... -race -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

proto:
	./scripts/generate-proto.sh

tidy:
	go mod tidy

clean:
	rm -rf bin/ tmp/ coverage.* *.coverprofile

help:
	@echo "Available targets:"
	@echo "  build           - Build server, worker, and migrate binaries"
	@echo "  run             - Run the HTTP/gRPC server"
	@echo "  run-worker      - Run the background worker"
	@echo "  migrate-up      - Run database migrations up"
	@echo "  migrate-down    - Run database migrations down one step"
	@echo "  migrate-version - Show current migration version"
	@echo "  test            - Run all tests with race detector"
	@echo "  test-coverage   - Run tests with coverage report"
	@echo "  lint            - Run golangci-lint"
	@echo "  proto           - Generate protobuf Go code"
	@echo "  tidy            - Run go mod tidy"
	@echo "  clean           - Remove build artifacts"
