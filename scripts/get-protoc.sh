#!/usr/bin/env bash
# Downloads protoc to ./bin if not in PATH
set -euo pipefail

PROTOC_VERSION="28.3"
ARCH=$(uname -m)
OS="osx"

case "$ARCH" in
  x86_64)  PROTOC_ARCH="x86_64" ;;
  arm64|aarch64) PROTOC_ARCH="aarch_64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$SERVER_DIR/bin"
PROTOC="$BIN_DIR/protoc"

if command -v protoc &>/dev/null; then
  echo "protoc already in PATH: $(which protoc)"
  exit 0
fi

if [[ -x "$PROTOC" ]]; then
  echo "protoc already at $PROTOC"
  exit 0
fi

mkdir -p "$BIN_DIR"
ZIP="protoc-${PROTOC_VERSION}-${OS}-${PROTOC_ARCH}.zip"
URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${ZIP}"

echo "Downloading protoc from $URL ..."
curl -sL -o "$BIN_DIR/$ZIP" "$URL"
unzip -o "$BIN_DIR/$ZIP" -d "$BIN_DIR"
mv "$BIN_DIR/bin/protoc" "$BIN_DIR/"
rm -rf "$BIN_DIR/bin" "$BIN_DIR/include" "$BIN_DIR/$ZIP"
chmod +x "$PROTOC"
echo "Installed $PROTOC"
export PATH="$BIN_DIR:$PATH"
