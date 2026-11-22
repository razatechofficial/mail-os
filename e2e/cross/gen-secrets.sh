#!/bin/bash
# Secrets of the cross-repo stack (run.sh secrets): a test CA and its
# certificates, every password and key, and the env files each process
# reads. Runs in a throwaway alpine container as root (it hands ACS's
# files to ACS's distroless user). Idempotent: an existing value is kept.
# Prints nothing but its last line.
#   OUT        where to write (/out)
#   HOST_UID   owner of everything but ACS's files (the VPS user)
#   HOST_GID
set -euo pipefail
umask 077
OUT=${OUT:-/out}
HOST_UID=${HOST_UID:?} HOST_GID=${HOST_GID:?}
mkdir -p "$OUT"/{pki,env,acs,iam,nginx,ms,pw}
cd "$OUT/pki"

# Ports (127.0.0.1 only; README lists them).
PG=27632 SPICEDB=27651 REDIS=27679 REDIS_MS=27678
IAM=27680 IAM_GRPC=27686 IAM_TLS=27643 IAM_CONSOLE=27675
ACS=27690 MS=27681 MS_GRPC=27682 MS_METRICS=27683 MC=27685
ISSUER="http://127.0.0.1:$IAM"

pw() {
  [ -s "pw-$1" ] || openssl rand -hex 24 >"pw-$1"
  cat "pw-$1"
}
b64() {
  [ -s "b64-$1" ] || openssl rand -base64 "${2:-32}" | tr -d '\n' >"b64-$1"
  cat "b64-$1"
}

if [ ! -s ca.pem ]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key 2>/dev/null
  openssl req -x509 -new -key ca.key -sha256 -days 30 -subj "/O=razatech/OU=mailos-p1-cross/CN=mailos-p1-cross CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out ca.pem
fi

leaf() {
  local name=$1 eku=$2 san=${3:-}
  [ -s "$name.crt" ] && return 0
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name.key" 2>/dev/null
  openssl req -new -key "$name.key" -subj "/O=razatech/OU=mailos-p1-cross/CN=$name" -out "$name.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=$eku"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } >"$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -set_serial "0x$(openssl rand -hex 16)" -days 30 -sha256 \
    -extfile "$name.ext" -out "$name.crt" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}

# ACS (acs-core and the app gateway); the IAM's TLS terminator (the load
# balancer: it forwards the client certificate for RFC 8705 tokens); the
# IAM's workload certificate (ACS's core principal); MailOS's runtime
# client (ACS calls, tls_client_auth at the IAM) and its CI publisher
# client; the CI's OIDC issuer (served by the Playwright setup).
leaf acs-server serverAuth "DNS:acs,DNS:acs-core,DNS:localhost,IP:127.0.0.1"
leaf iam-tls serverAuth "DNS:localhost,IP:127.0.0.1"
leaf iam-core clientAuth "URI:spiffe://mailos-p1-cross/iam"
leaf mailos-runtime clientAuth
leaf mailos-publisher clientAuth
leaf ci-issuer serverAuth "DNS:localhost,IP:127.0.0.1"
[ -s audit-signing.pem ] || openssl genpkey -algorithm ed25519 -out audit-signing.pem 2>/dev/null
# The IAM's ACS approval key: P-256, signs ACS approvals and MailOS role
# attestations, never tokens.
[ -s acs-approval.pem ] || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out acs-approval.pem 2>/dev/null
if [ ! -s jwt_private.pem ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt_private.pem 2>/dev/null
  openssl pkey -in jwt_private.pem -pubout -out jwt_public.pem
fi
[ -s saml.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=mailos-p1-cross SAML" \
  -keyout saml.key -out saml.crt 2>/dev/null
[ -s superadmin.pw ] || echo "Cross-Superadmin-$(openssl rand -hex 8)-9!" >superadmin.pw
[ -s hooks.token ] || openssl rand -hex 32 >hooks.token
[ -s iam-tenant ] || cat /proc/sys/kernel/random/uuid >iam-tenant

cp ca.pem acs-server.crt acs-server.key audit-signing.pem "$OUT/acs/"
cp ca.pem iam-core.crt iam-core.key acs-approval.pem jwt_private.pem jwt_public.pem saml.crt saml.key superadmin.pw "$OUT/iam/"
cp iam-tls.crt iam-tls.key "$OUT/nginx/"
cp ca.pem mailos-runtime.crt mailos-runtime.key "$OUT/ms/"
cp ca.pem mailos-runtime.crt mailos-runtime.key mailos-publisher.crt mailos-publisher.key ci-issuer.crt ci-issuer.key \
  superadmin.pw hooks.token "$OUT/pw/"

pgurl() { echo "postgres://$1:$(pw "$2")@127.0.0.1:$PG/$3?sslmode=disable"; }
cd "$OUT/env"
cat >pg.env <<EOT
POSTGRES_PASSWORD=$(pw pg-super)
PGPORT=$PG
ACS_MIGRATE_PASSWORD=$(pw acs-migrate)
ACS_APP_PASSWORD=$(pw acs-app)
ACS_APPLIER_PASSWORD=$(pw acs-applier)
SPICEDB_DB_PASSWORD=$(pw spicedb-db)
EOT
cat >spicedb.env <<EOT
SPICEDB_DATASTORE_CONN_URI=$(pgurl spicedb spicedb-db spicedb)
SPICEDB_GRPC_PRESHARED_KEY=$(pw spicedb-key-iam),$(pw spicedb-key-acs-core),$(pw spicedb-key-acs),$(pw spicedb-key-migrate)
EOT
echo "REDIS_PASSWORD=$(pw redis)" >redis.env
printf 'ACS_DB_URL=%s\nSPICEDB_TOKEN=%s\n' "$(pgurl acs_migrate acs-migrate acs)" "$(pw spicedb-key-migrate)" >acs-migrate.env
# acs_applier and the migrate key: acs-migrate's schema write and apply
# loop, ACS's only schema writer.
printf 'ACS_DB_URL=%s\nSPICEDB_TOKEN=%s\n' "$(pgurl acs_applier acs-applier acs)" "$(pw spicedb-key-migrate)" >acs-applier.env
printf 'ACS_DB_URL=%s\nSPICEDB_TOKEN=%s\n' "$(pgurl acs_app acs-app acs)" "$(pw spicedb-key-acs-core)" >acs-core.env
printf 'ACS_DB_URL=%s\nSPICEDB_TOKEN=%s\nREDIS_PASSWORD=%s\n' "$(pgurl acs_app acs-app acs)" "$(pw spicedb-key-acs)" "$(pw redis)" >acs.env

# The IAM server (iam.sh sources it; the SAML pair is read from files).
# APP_ENV=e2e with the test-only hooks (mail kept, never sent); the
# feature set of the IAM's own e2e/run.sh; ACS beside it; platform
# administrators sign in with a passkey (MFA_PLATFORM_ADMIN_PHISHING_RESISTANT).
cat >iam.env <<EOT
APP_ENV=e2e
CONFIG_DIR=/work/no-config
APP_LOG_LEVEL=info
APP_LOG_FORMAT=json
HTTP_HOST=127.0.0.1
HTTP_PORT=$IAM
GRPC_HOST=127.0.0.1
GRPC_PORT=$IAM_GRPC
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=$PG
POSTGRES_USER=postgres
POSTGRES_PASSWORD=$(pw pg-super)
POSTGRES_DB=iam
POSTGRES_SSL_MODE=disable
REDIS_HOST=127.0.0.1
REDIS_PORT=$REDIS
REDIS_PASSWORD=$(pw redis)
REDIS_DB=0
SPICEDB_ENDPOINT=127.0.0.1:$SPICEDB
SPICEDB_TOKEN=$(pw spicedb-key-iam)
SPICEDB_INSECURE=true
SPICEDB_CACHE_TTL=1s
SPICEDB_NEGATIVE_CACHE_TTL=1s
SPICEDB_OUTBOX_RELAY_INTERVAL=200ms
IAM_BOOTSTRAP_SENTINEL_PATH=/work/bootstrap.sentinel
JWT_ISSUER=$ISSUER
JWT_PRIVATE_KEY_PATH=/secrets/iam/jwt_private.pem
JWT_PUBLIC_KEY_PATH=/secrets/iam/jwt_public.pem
JWT_ACCESS_TTL=1h
JWT_REFRESH_REUSE_GRACE=2s
SAML_BASE_URL=$ISSUER
MFA_TOTP_ENCRYPTION_KEY=$(b64 totp)
MFA_PLATFORM_ADMIN_PHISHING_RESISTANT=true
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGINS=http://localhost:$IAM_CONSOLE
WEBAUTHN_MDS_URL=
AUTH_CLIENT_BASE_URL=http://localhost:$IAM_CONSOLE
AUTH_REQUIRE_EMAIL_VERIFICATION=false
AUTH_ARGON2_MEMORY_KIB=4096
AUTH_ARGON2_ITERATIONS=1
AUTH_ARGON2_PARALLELISM=1
CORS_ORIGINS=http://localhost:$IAM_CONSOLE
EVENTBUS_DRIVER=noop
MAILOS_TRANSPORT=http
MAILOS_HTTP_URL=http://127.0.0.1:$MS
WORKER_EMAIL_ENABLED=true
RATE_LIMIT_ENABLED=false
IAM_E2E_HOOKS=true
IAM_E2E_HOOKS_TOKEN=$(cat "$OUT/pki/hooks.token")
FEATURE_FOUR_EYES=true
FEATURE_TOKEN_EXCHANGE=true
FEATURE_BRANDING=true
FEATURE_USER_PROFILE=true
FEATURE_KEY_MANAGER=true
KEY_MANAGER_PROVIDER=software
KEY_MANAGER_MASTER_KEY=$(b64 iam-master)
FEATURE_SIGNED_RESPONSES=true
FEATURE_JAR=true
FEATURE_RAR=true
FEATURE_MULTI_TOTP=true
FEATURE_EMAIL_OTP=true
AUDIT_DIGEST_SIGNING_KEY=$(b64 iam-audit)
SIGNIN_CAPTCHA_PROVIDER=altcha
SIGNIN_CAPTCHA_HMAC_KEY=$(b64 iam-captcha)
ACS_APPROVAL_KEY_FILE=/secrets/iam/acs-approval.pem
HTTP_CLIENT_CERT_PROXY_CIDRS=127.0.0.1/32
HTTP_METRICS_ALLOWED_IPS=127.0.0.1/32
ACS_MIGRATION_MODE=shadow
ACS_SHADOW_SAMPLE_PERCENT=100
ACS_CORE_ADDR=127.0.0.1:27691
ACS_CORE_SERVER_NAME=acs-core
ACS_CORE_CA_FILE=/secrets/iam/ca.pem
ACS_CORE_CERT_FILE=/secrets/iam/iam-core.crt
ACS_CORE_KEY_FILE=/secrets/iam/iam-core.key
ACS_CI_JWKS_CA_FILE=/secrets/iam/ca.pem
ACS_POLL_INTERVAL=5s
EOT

# MailOS server; setup adds ACS_CLIENT_ID, IAM_AUDIENCE and
# IAM_CONSOLE_AUDIENCES (/work/ms.env) once the IAM holds MailOS's clients.
cat >ms.env <<EOT
APP_ENV=e2e
CONFIG_DIR=/work/no-config
APP_LOG_LEVEL=info
APP_LOG_FORMAT=json
HTTP_HOST=127.0.0.1
HTTP_PORT=$MS
GRPC_HOST=127.0.0.1
GRPC_PORT=$MS_GRPC
METRICS_ADDR=127.0.0.1:$MS_METRICS
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=$PG
POSTGRES_USER=postgres
POSTGRES_PASSWORD=$(pw pg-super)
POSTGRES_DB=mail_os
POSTGRES_SSL_MODE=disable
REDIS_HOST=127.0.0.1
REDIS_PORT=$REDIS_MS
IAM_ISSUER=$ISSUER
IAM_JWKS_CACHE_TTL=1m
IAM_SERVICE_CLIENT_ID=mailos-iam
IAM_SERVICE_TENANT_ID=$(cat "$OUT/pki/iam-tenant")
IAM_SERVICE_TOPICS=iam.*
KEY_MANAGER_MASTER_KEY=$(b64 ms-master)
CORS_ORIGINS=http://localhost:$MC
FEATURE_PUBSUB_INGEST=false
FEATURE_AUDIT_STREAM=false
RATE_LIMIT_ENABLED=false
SMTP_ENABLED=false
SMTP_FROM_NAME=MailOS
SMTP_FROM_ADDR=no-reply@mailos.test
ACS_ENDPOINT=127.0.0.1:$ACS
ACS_SERVER_NAME=acs
ACS_CA_FILE=/secrets/ms/ca.pem
ACS_CERT_FILE=/secrets/ms/mailos-runtime.crt
ACS_KEY_FILE=/secrets/ms/mailos-runtime.key
ACS_TOKEN_URL=https://127.0.0.1:$IAM_TLS/oauth/token
ACS_TIMEOUT=3s
EOT

chown -R 65532:65532 "$OUT/acs"
chown -R "$HOST_UID:$HOST_GID" "$OUT/pki" "$OUT/env" "$OUT/iam" "$OUT/ms" "$OUT/pw"
find "$OUT" -type d -exec chmod 0700 {} +
find "$OUT" -type f -exec chmod 0600 {} +
chmod 0755 "$OUT" "$OUT/nginx"
chmod 0644 "$OUT/nginx/iam-tls.crt"
echo "mailos-p1-cross secrets ready"
