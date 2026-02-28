FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/migrate ./cmd/migrate

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/server /bin/server
COPY --from=builder /bin/migrate /bin/migrate
COPY --from=builder /app/environments /app/environments
COPY --from=builder /app/migrations /app/migrations

WORKDIR /app

EXPOSE 8080 9090

ENTRYPOINT ["/bin/server"]
CMD ["-config", "environments/production.yaml"]
