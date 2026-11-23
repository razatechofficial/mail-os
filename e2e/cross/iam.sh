#!/bin/bash
# The IAM server of the cross-repo stack, in the Go image (compose services
# iam and iam-lenient):
#   iam.sh main      build, migrate Postgres, write the SpiceDB core (before
#                    ACS's schema writer composes it with the app modules),
#                    bootstrap the founding platform owner, serve 127.0.0.1:27680
#   iam.sh lenient   a second server on the same stores and issuer with
#                    MFA_PLATFORM_ADMIN_PHISHING_RESISTANT=false on
#                    127.0.0.1:27688, only while setup enrols an authenticator
#                    app for a platform account (as one from before the rule)
set -euo pipefail
cd /src/iam-server
set -a
. /secrets/env/iam.env
set +a
export SAML_SIGNING_CERTIFICATE="$(cat /secrets/iam/saml.crt)"
export SAML_SIGNING_PRIVATE_KEY="$(cat /secrets/iam/saml.key)"
mkdir -p /work/bin

case "${1:-main}" in
  main)
    export MFA_PLATFORM_ADMIN_PHISHING_RESISTANT="${CROSS_PASSKEY_RULE:-true}"
    echo "iam: building (MFA_PLATFORM_ADMIN_PHISHING_RESISTANT=$MFA_PLATFORM_ADMIN_PHISHING_RESISTANT)"
    go build -o /work/bin/ ./cmd/server ./cmd/migrate-postgres ./cmd/migrate-spicedb ./cmd/init
    /work/bin/migrate-postgres up
    # ACS's schema writer owns the shared SpiceDB: it writes its core (v3)
    # into the empty SpiceDB before the IAM starts. The IAM's core is the
    # same v3 byte for byte now (its write changes nothing), but ACS owns the
    # shared schema, so the write stays off here (IAM_SPICEDB_WRITE=true
    # restores the IAM-only order).
    if [ "${IAM_SPICEDB_WRITE:-false}" = true ]; then
      /work/bin/migrate-spicedb write
    fi
    if [ ! -f /work/bootstrap.sentinel ]; then
      /work/bin/init init --non-interactive --email superadmin@iam.local --password-stdin </secrets/iam/superadmin.pw
    fi
    echo "iam: serving on $JWT_ISSUER"
    exec /work/bin/server
    ;;
  lenient)
    for _ in $(seq 1 600); do
      curl -fsS "http://127.0.0.1:$HTTP_PORT/ready" >/dev/null 2>&1 && break
      sleep 1
    done
    export HTTP_PORT=27688 GRPC_PORT=27689 MFA_PLATFORM_ADMIN_PHISHING_RESISTANT=false
    echo "iam: lenient server on 127.0.0.1:$HTTP_PORT"
    exec /work/bin/server
    ;;
  *)
    echo "usage: iam.sh main|lenient" >&2
    exit 2
    ;;
esac
