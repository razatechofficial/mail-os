# syntax=docker/dockerfile:1.7
# MailOS image: the server, the worker, the Postgres migrator and the
# bootstrap in one distroless nonroot image, so every Deployment and Job run
# the same digest. The entrypoint is the server; the others are chosen with
# `command`:
#
#   docker build -f deployments/Dockerfile -t mailos:dev --build-arg VERSION=$(git describe --tags --always) .
#   command: ["/app/mailos-worker"]
#   command: ["/app/mailos-migrate-postgres", "up"]
#   command: ["/app/mailos-bootstrap"]   (default templates, sending domain, test send)
#
# Read-only root filesystem friendly: nothing is written at runtime. Mount an
# emptyDir at /tmp only if a future feature needs scratch space.

# -------- Build stage --------
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /src

# Package set is constrained by golang:1.26-alpine; exact apk=versions churn on every base rebuild.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates tzdata git

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    for b in server worker migrate-postgres bootstrap; do \
      CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath \
        -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" \
        -o "/out/mailos-${b}" "./cmd/${b}"; \
    done

# -------- Runtime stage --------
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /app

COPY --from=builder /out/mailos-server /app/mailos-server
COPY --from=builder /out/mailos-worker /app/mailos-worker
COPY --from=builder /out/mailos-migrate-postgres /app/mailos-migrate-postgres
COPY --from=builder /out/mailos-bootstrap /app/mailos-bootstrap
# The migrator reads migrations/postgres relative to the working directory.
COPY --from=builder /src/migrations /app/migrations
COPY --from=builder /src/environments /app/environments

USER nonroot:nonroot

# HTTP, gRPC, metrics (METRICS_ADDR).
EXPOSE 8080 9090 9102

ENV APP_ENV=production \
    CONFIG_DIR=/app/environments

LABEL org.opencontainers.image.title="mailos" \
      org.opencontainers.image.description="Razatech MailOS email service" \
      org.opencontainers.image.source="https://github.com/razatechofficial/mail-os" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.vendor="razatechofficial"

ENTRYPOINT ["/app/mailos-server"]
