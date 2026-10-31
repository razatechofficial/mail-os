# Black-box e2e suite and test stack

The suite in `e2e/` drives the real MailOS binaries over HTTP, the way IAM's e2e suite does. It never imports the server's packages to reach inside. The only product code it uses is `internal/testutil/fakeiam`, which the fake IAM binary wraps.

## Running it

```bash
docker compose -f docker-compose.test.yaml up -d --wait   # Postgres 18 (tmpfs), Redis 7
e2e/run.sh all                                           # build, start, test, stop
docker compose -f docker-compose.test.yaml down -v
```

`make e2e` does the same with a fresh stack.

`e2e/run.sh` can also run one step at a time:

| Command | What it does |
|---|---|
| `e2e/run.sh up` | Builds `cmd/server`, `cmd/worker`, `cmd/migrate-postgres`, `e2e/cmd/fakeiam` and skipgate. Writes the run's secrets and `server.env`. Starts the fake IAM and waits for its discovery document. Migrates. Starts the server and the worker, and waits for `GET /ready` |
| `e2e/run.sh test` | Runs `go test -tags e2e ./e2e/...` through `skipgate`: a skipped test fails. `MAILOS_E2E_PKGS=./e2e/smoke/...` narrows it |
| `e2e/run.sh env` | Prints the variables the harness reads (below), for running `go test` by hand or for a console Playwright suite |
| `e2e/run.sh down` | Stops the worker, the server and the fake IAM |

**Iterating.** Run `e2e/run.sh up` once, then `e2e/run.sh test` or `go test -tags e2e ./e2e/smoke/` with `eval "$(e2e/run.sh env)"` exported.

**Where things live.** Binaries, secrets, `server.env` and the logs (`server.log`, `worker.log`, `fakeiam.log`) go to `e2e/.work`, which is git-ignored. Set `MAILOS_E2E_WORK` to move it; CI uses `ci-reports/e2e-work`.

**The database must be fresh.** The CI stack is always fresh. Locally, run `make stack-fresh`.

**Pointing at another stack.** These variables override the defaults:
- `MAILOS_E2E_PG_HOST`, `MAILOS_E2E_PG_PORT` (default 5434), `MAILOS_E2E_PG_USER`, `MAILOS_E2E_PG_PASSWORD`, `MAILOS_E2E_PG_DB` (default `mail_os`)
- `MAILOS_E2E_REDIS_HOST`, `MAILOS_E2E_REDIS_PORT` (default 6381)
- `MAILOS_E2E_HTTP_PORT` (18180), `MAILOS_E2E_GRPC_PORT` (18181), `MAILOS_E2E_IAM_PORT` (18190), `MAILOS_E2E_METRICS_PORT` (18182), `MAILOS_E2E_WORKER_METRICS_PORT` (18183)
- `MAILOS_E2E_CONSOLE_ORIGIN` (default `http://localhost:3200`), the CORS origin

## The server's environment

`e2e/run.sh` writes `server.env`, which the server, the worker and the migrator share:

| Setting | Value | Why |
|---|---|---|
| `APP_ENV` | `e2e` | Allows plaintext HTTP, gRPC and Postgres, and the hooks. `e2e` is in both `plaintextEnvironments` and `e2eHookEnvironments` in `config` |
| `IAM_ISSUER` | the fake IAM, `http://127.0.0.1:18190` | Tokens and signatures verify against its discovery document and JWKS over HTTP |
| `IAM_AUDIENCE`, `IAM_CONSOLE_AUDIENCES` | `mailos`, `mailos-console` | The fake IAM's defaults for `aud` and `client_id` |
| `MAILOS_SERVICE_CLIENTS` | `mailos-iam=iam.*` | IAM's service client (contract §4) |
| `KEY_MANAGER_MASTER_KEY` | random per work dir | Required everywhere |
| `MAILOS_E2E_HOOKS`, `MAILOS_E2E_HOOKS_TOKEN` | `true`, random 48 characters | Capture mail, serve `/e2e/v1` |
| `FEATURE_PUBSUB_INGEST`, `FEATURE_AUDIT_STREAM` | `false` | There is no broker in the stack (yet) |
| `FEATURE_RAW_HTML_BLOCKS` | `true` | The suite covers it |
| `RATE_LIMIT_ENABLED`, `SMTP_ENABLED` | `false` | Tests must not be throttled, and nothing leaves the machine |
| `WORKER_SCHEDULER_INTERVAL` | `1s` | Scheduled messages release quickly |

The worker gets its own `METRICS_ADDR`, so the two processes do not fight over one port.

## The fake IAM (`e2e/cmd/fakeiam`)

The suite never needs a running IAM. `e2e/cmd/fakeiam` (build tag `e2e`) wraps `internal/testutil/fakeiam` in a process. Its signing keys (PS256 and ES256) live only in its memory, and it serves:

| Route | Returns |
|---|---|
| `GET /.well-known/openid-configuration` | `{issuer, jwks_uri}` |
| `GET /.well-known/jwks.json` | the published keys |
| `GET /healthz` | 204 |
| `POST /test/tokens/user` | `{access_token, sub}` for `{sub, tid, org_id, roles, acr, auth_age_seconds, aud, client_id, jkt, extra}` |
| `POST /test/tokens/service` | `{access_token}` for `{client_id, tid}` |
| `POST /test/signatures` | `{signature}`: an `iam-msg-sig` JWS for `{client_id, topic, value}`, where `value` is the standard base64 of the exact message bytes |

**The mint routes are guarded twice.**
- They exist only with `-mint-token-file`, and need `Authorization: Bearer <that token>` (at least 32 characters).
- The binary refuses a non-loopback address unless given `-allow-remote`.

Tokens live 10 minutes. `extra` overrides any claim, for example an `exp` in the past.

## How a test package is built

```go
//go:build e2e

package templates

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "templates", &fx) }

func TestEditorCreatesDraft(t *testing.T) {
	editor, _ := fx.NewUser(t, harness.RoleTemplateEditor)
	r := editor.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", map[string]any{"name": "Welcome"})
	var tpl struct{ ID string `json:"id"` }
	r.Decode(t, &tpl)
}
```

- **Its own tenant.** MailOS has no tenant table to provision: a tenant is the `tid` claim IAM puts in the token. `harness.Main` therefore gives each package a fresh tenant UUID and organization UUID, and packages never see each other's data. `go test` runs them in parallel against one server.
- **Callers.**
  - `fx.Admin(t)` is the tenant administrator (`mailos_admin`, fresh MFA).
  - `fx.NewUser(t, roles...)` is a new user holding those roles.
  - `fx.As(t, harness.User{...})` is a user with any claims you set: ACR, auth age, audience, DPoP `jkt`, extra.
  - `fx.Service(t, clientID)` is an IAM service client scoped to the tenant.
  - Each call mints a new token, so take a client per test.
- **Responses.** The client sends JSON and reads the `{success, data, meta, error}` envelope:
  - `r.Decode(t, &v)` unmarshals `data`, and fails unless `success` is true
  - `r.Items()` returns `data` as a list
  - `r.ErrorCode()` returns the error code
  - `c.ExpectError(t, status, code, ...)` checks both the status and the error code
- **Mail.** Mail goes through the worker, so it lags the request that caused it:
  - `fx.Env.NewMailbox("owner")` gives an address unique to the run, at `mailos.test`
  - `mb.Wait`, `mb.WaitSubject` and `mb.WaitAfter` poll the hook for up to 20 s
  - `mb.Empty(t, d)` proves nothing was sent (suppressions, refusals)
- **Never a skip.** A missing environment variable is a failure in `TestMain`, not a skip.

## Test-only hooks (`MAILOS_E2E_HOOKS`)

With `MAILOS_E2E_HOOKS=true` and `MAILOS_E2E_HOOKS_TOKEN` (at least 32 characters), the server changes two things:
- **Capture.** The server captures outgoing mail instead of sending it.
- **The hook route.** It serves this route, which needs `Authorization: Bearer <token>`:

| Route | Returns |
|---|---|
| `GET /e2e/v1/messages?to=<email>` | `{"success":true,"data":[{"id","to","from","subject","html","text","tags","sent_at"}]}`, oldest first. `tags` is a list of strings and `sent_at` is RFC 3339 |

**The hooks are refused outside test environments.** `config` refuses them unless `APP_ENV` is `e2e`, `test`, `local` or `development`, so the binary does not start in production or staging. `MAILOS_E2E_SERVER_BIN` and `MAILOS_E2E_SERVER_ENV` are exported to the tests, so that a test can start the real binary with a production `APP_ENV` and prove that it exits.

## What the suite covers

| Package | Covers |
|---|---|
| `e2e/smoke` | `/health` and `/ready`; `/api/v1/templates` without a token is 401; a forged signature is 401; the administrator's token is accepted |

Feature packages come with the features. Each package uses its own `TestMain` and fixture, as above.

## Test stack (`docker-compose.test.yaml`)

| Service | Included | Notes |
|---|---|---|
| Postgres 18 | yes | tmpfs, so every stack is fresh; database `mail_os`; host port `MAILOS_TEST_PG_PORT` (5434) |
| Redis 7 | yes | no persistence; host port `MAILOS_TEST_REDIS_PORT` (6381) |
| IAM | in-process fake | `e2e/cmd/fakeiam` (above) |
| Mail sink | in-process | the e2e hooks above. No SMTP server is needed, because nothing is sent |
| Kafka | no | `FEATURE_PUBSUB_INGEST` and `FEATURE_AUDIT_STREAM` are off. Signed-event ingestion needs a broker in the stack, a topic set and `KAFKA_*` in `server.env`. The fake IAM already signs messages (`/test/signatures`) |

## Without Docker

Any Postgres 18 and Redis 7 will do. Create the database `mail_os` and point the `MAILOS_E2E_*` variables at it.
