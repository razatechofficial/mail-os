#!/bin/bash
# The MailOS server of the cross-repo stack, in the Go image (compose
# service ms): build this branch, migrate, serve 127.0.0.1:27681 against
# the real IAM (issuer, JWKS, role attestations) and the real ACS (mutual
# TLS, a token the IAM binds to MailOS's certificate). /work/ms.env comes
# from setup: MailOS's ACS client ID and the tenant console's audience.
set -euo pipefail
cd /src/mailos-server
set -a
. /secrets/env/ms.env
. /work/ms.env
set +a
mkdir -p /work/bin
echo "ms: building"
go build -o /work/bin/ ./cmd/server ./cmd/migrate-postgres
/work/bin/migrate-postgres up
echo "ms: serving on 127.0.0.1:$HTTP_PORT"
exec /work/bin/server
