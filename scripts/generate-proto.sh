#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SERVER_DIR"

# Ensure protoc and go plugins are available
if ! command -v protoc &>/dev/null; then
  [[ -x "$SERVER_DIR/bin/protoc" ]] && export PATH="$SERVER_DIR/bin:$PATH"
fi
export PATH="$HOME/go/bin:$PATH"
if ! command -v protoc &>/dev/null; then
  echo "protoc not found. Run: ./scripts/get-protoc.sh"
  exit 1
fi

PROTO_DIR="api/proto/v1"
OUT_DIR="api/proto/v1"

protoc \
  --proto_path="${PROTO_DIR}" \
  --go_out="${OUT_DIR}" --go_opt=paths=source_relative \
  --go-grpc_out="${OUT_DIR}" --go-grpc_opt=paths=source_relative \
  "${PROTO_DIR}"/*.proto

echo "protobuf generation complete"
