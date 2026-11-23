# Cross-repo e2e: MailOS Phase 1 slice 1

A platform administrator signs in to the MailOS Platform Console, with the
real components: IAM server, IAM console (hosted sign-in), ACS, MailOS server
and the MailOS console in its platform plane. The Playwright side lives in the
console repo under `e2e/cross/`.

## Run

From a workstation with the five worktrees checked out side by side:

```sh
e2e/cross/push.sh all        # copy the sources to the VPS, then run.sh all there
e2e/cross/push.sh up         # or step by step: up, test, down
e2e/cross/push.sh test
e2e/cross/push.sh clean      # down, and remove the ACS image the stack built
```

`CROSS_PASSKEY_RULE=false` (set for `up` and `test` alike) runs the IAM with
`MFA_PLATFORM_ADMIN_PHISHING_RESISTANT=false`: a platform account with only an
authenticator app then signs in to the Platform Console with it.

On the VPS, `run.sh up|test|down|clean|all|logs [service]` from
`$CROSS_HOME/src/mailos-server/e2e/cross` (default `CROSS_HOME=/opt/mailos-p1-test/cross`).
The compose project is `mailos-p1-cross`; heavy steps wait while the 1-minute load is above 6.

## What runs

| Service | 127.0.0.1 port | What |
|---|---|---|
| pg | 27632 | Postgres: iam, acs, spicedb, mail_os |
| spicedb | 27651 | one SpiceDB for the IAM and ACS |
| redis, redis-ms | 27679, 27678 | the IAM's and ACS's Redis; MailOS's |
| iam | 27680 | IAM server (`iam.sh main`), `MFA_PLATFORM_ADMIN_PHISHING_RESISTANT=true` (`CROSS_PASSKEY_RULE`) |
| iam-lenient | 27688 | the same IAM without the passkey rule, during setup only |
| iam-tls | 27643 | TLS in front of the IAM (client certificates for ACS tokens) |
| ic | 27675 | IAM console: the hosted sign-in (WebAuthn RP `localhost`) |
| acs-core, acs | 27691, 27690 | ACS core (the IAM's) and app gateway (MailOS's) |
| ms | 27681 | MailOS server (`ms.sh`) |
| mc | 27685 | MailOS console, `CONSOLE_PLANE=platform` |
| pw | | Playwright (`e2e/cross` of the console) |

`gen-secrets.sh` makes a test CA, certificates and every secret under
`$CROSS_HOME/secrets`; nothing is printed. The IAM runs with `APP_ENV=e2e` and
its test-only mail sink (invitations are read from it, never sent).

## Order

`run.sh up` starts the stores, then ACS's `acs-migrate db up` and `schema write`
into the empty SpiceDB (ACS core v3), then the IAM without its own SpiceDB write
(`IAM_SPICEDB_WRITE=false`: the IAM branch's core is ACS's core v3 byte for byte,
so its write would change nothing, but ACS owns the shared schema), then acs-core,
the applier, the gateway and the IAM console.

`run.sh test` runs the console's Playwright project `iam-setup` (platform
owners and accounts, the platform application, MailOS's home workspace, ACS
registration, module, grant and platform binding, all through the IAM's API),
then starts the MailOS server and console with the settings it wrote, then
the project `cross`: `pim-setup` (eligibility and activation in the IAM's PIM,
delivered to MailOS, written to ACS) and the specs.
