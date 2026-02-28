#!/usr/bin/env bash
set -euo pipefail

PROTO_DIR="api/proto/v1"
OUT_DIR="api/proto/v1"

protoc \
  --proto_path="${PROTO_DIR}" \
  --go_out="${OUT_DIR}" --go_opt=paths=source_relative \
  --go-grpc_out="${OUT_DIR}" --go-grpc_opt=paths=source_relative \
  "${PROTO_DIR}"/*.proto

echo "protobuf generation complete"
