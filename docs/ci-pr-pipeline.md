# PR pipeline: setup

MailOS gets the same PR gates as IAM. The PR job is a Multibranch job (`Jenkinsfile.pr`). It runs on every branch and pull request and blocks merging. It builds nothing for release and pushes nothing.

Nothing in Jenkins or gitops was changed: the steps below are for a Jenkins administrator.

## Gates (`Jenkinsfile.pr`)

Each gate is `scripts/ci/pr-gates.sh <gate>`, run in `golang:1.26-bookworm` on the host network. A developer runs the same command locally, directly or through `make`.

| Stage | Gate | `make` | Fails on |
|---|---|---|---|
| Static (parallel) | `vet` | `make vet` | `go vet` with no tag, `-tags integration` and `-tags e2e` |
| | `gosec` | `make gosec` | HIGH, medium confidence or higher; G115 excluded, as in IAM |
| | `govulncheck` | `make govulncheck` | any reachable known vulnerability (govulncheck v1.9.0) |
| Unit | `unit` | `make test` | `go test -race ./...`: a failure, a race, or a skipped test |
| Integration | `integration` | `make integration` | Starts a fresh `docker-compose.test.yaml` stack. Runs `cmd/migrate-postgres` up, then down to zero (`down-all`), then up, then `version`. Runs `go test -tags integration -p 1 ./integration/`. Fails on a failure or a skip |
| E2E (API) | `e2e` | `make e2e` | Starts a fresh stack and runs `e2e/run.sh all`, which brings up the fake IAM, server and worker binaries and runs `-tags e2e ./e2e/...` (see `docs/testing-e2e.md`). Fails on a failure or a skip |

`scripts/ci/pr-gates.sh migrations` runs the migration round trip on its own.

**Skipped tests fail the gate.** `scripts/ci/skipgate` (copied from IAM) reads `go test -json`. It fails on any skipped test, any package that fails without a failed test (a build error or `TestMain`), or a run in which nothing ran. A test that needs something the stack lacks must fail, not skip. `skipgate -defer <regexp>` exists for a test that needs a process of its own (see the comment in `scripts/ci/skipgate/main.go`); no MailOS gate uses it yet.

**Integration tests read** `MAILOS_TEST_PG_PORT` (default 5434), `MAILOS_TEST_REDIS_PORT` (default 6381) and `MAILOS_TEST_PG_PASSWORD` (default `postgres`), against database `mail_os` on 127.0.0.1.

**The migration gate's configuration.** `config.Load` validates everything, even for the migrator. The gate therefore runs it with `APP_ENV=test`, a throwaway `IAM_ISSUER` and a random `KEY_MANAGER_MASTER_KEY`.

**Ports.** Each executor gets its own block of host ports, `21000 + 10 × executor`, and its own compose project (`mailos-pr-<executor>`):

| Offset | Variable | Default |
|---|---|---|
| +1 | `MAILOS_TEST_PG_PORT` | 5434 |
| +2 | `MAILOS_TEST_REDIS_PORT` | 6381 |
| +4 | `MAILOS_E2E_HTTP_PORT` | 18180 |
| +5 | `MAILOS_E2E_GRPC_PORT` | 18181 |
| +6 | `MAILOS_E2E_IAM_PORT` (fake IAM) | 18190 |
| +7 | `MAILOS_E2E_METRICS_PORT` | 18182 |
| +8 | `MAILOS_E2E_WORKER_METRICS_PORT` | 18183 |

IAM's PR job uses `20000 + 10 × executor`, so both jobs share an agent without colliding. The local defaults also differ from IAM's (5433 / 6380), so both stacks can run side by side on a laptop.

**Artifacts.** Everything lands in `ci-reports/` and is archived:
- `gosec.txt`, `govulncheck.txt`
- `unit.json`, `integration.json`
- `e2e-server.log`, `e2e-worker.log`, `e2e-fakeiam.log`
- the stack logs of each stage

## Creating the PR job

1. **Install the plugins.** Pipeline: Multibranch, GitHub Branch Source, Timestamper, and Docker on the agent.
2. **Create the job.** New Item → Multibranch Pipeline, named for example `mailos-pr`.
3. **Branch source.** Choose GitHub with repository `razatechofficial/mail-os` and a read-only token (or the credentials the IAM job uses).
   - Discover branches: all branches.
   - Discover pull requests from origin: merging the pull request with the current target branch.
4. **Build configuration.** By Jenkinsfile, with script path `Jenkinsfile.pr`. The file finds the module root itself (`go.mod` at the root, or under `server/`).
5. **Scan triggers.** Use the GitHub webhook, plus a periodic scan every hour as a fallback.
6. **Protect `main` and `dev` in GitHub.** Require the status check `continuous-integration/jenkins/pr-merge` and an up-to-date branch.
7. **Agent label.** `linux && docker && amd64 && builder`, the same as IAM's. The agent needs:
   - Docker with the compose plugin (`docker compose`)
   - network access to Docker Hub and `proxy.golang.org`
   - the Docker volumes `mailos-go-mod-cache` and `mailos-go-build-cache`, which the job creates itself

The Go image runs with `GOTOOLCHAIN=local`. `go.mod` needs Go 1.26.4 or later, which `golang:1.26-bookworm` provides, so nothing is downloaded at build time.

## Console

When the MailOS console has a Playwright suite, its PR job can start this repository's e2e stack the same way IAM's console does:
1. start this repository's compose stack
2. run `e2e/run.sh up` in the Go image
3. read the variables with `e2e/run.sh env`
