# Key manager providers

MailOS seals stored secrets (provider API keys and SMTP passwords, DKIM private keys, webhook signing secrets) with
envelope encryption, following IAM's key manager:

- **Data keys (DEKs)**: one active AES-256 key per purpose (`provider`, `dkim`, `webhook`), rotated every
  `KEY_MANAGER_ENCRYPTION_ROTATION_PERIOD`. A sealed value is `km1.<kid>.<nonce||AES-256-GCM>` and names its DEK.
- **Key-encryption key (KEK)**: wraps every DEK. It never leaves where it lives: configuration (Vault), an HSM, or a
  cloud KMS. `KEY_MANAGER_PROVIDER` chooses which.

## Where keys live

| What | Where |
|---|---|
| DEKs | Postgres `encryption_keys.key_ref` (BYTEA), **wrapped** under the KEK, bound to `mailos/key/<kid>` as additional data (GCM AAD or KMS encryption context). Never stored in the clear. Each replica unwraps a DEK once and keeps it in memory. |
| Which KEK wraps a DEK | `encryption_keys.kek_id`: `software:<fingerprint>`, `pkcs11:<HSM key label>` or `kms:<KMS key ARN>`; `provider` is its prefix. |
| KEK rotations | `kek_rotations` (from, to, state, progress, last error); one runs at a time. |
| Software KEK | `KEY_MANAGER_MASTER_KEY` (base64 32 bytes, from Vault). Its id is the first 8 bytes of HMAC-SHA256(key, "mailos/master-key-id"), so the key is never shown. |
| HSM KEK | An AES-256 token object on the HSM, `CKA_SENSITIVE`, not `CKA_EXTRACTABLE`, found by token label + key label. DEKs are wrapped with `CKM_AES_GCM` (12-byte nonce, 128-bit tag) through `C_Encrypt`/`C_Decrypt`. |
| KMS KEK | A symmetric (`SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT`) AWS KMS key. DEKs are encrypted with `Encrypt`/`Decrypt` and the encryption context `{"mailos": "mailos/key/<kid>"}`. An alias is resolved to its ARN at start; the ARN is what `kek_id` records. |

## Settings

| Setting | Meaning |
|---|---|
| `KEY_MANAGER_PROVIDER` | `software` (default), `pkcs11` or `kms` |
| `KEY_MANAGER_MASTER_KEY` | software KEK; required with `software`, refused with any other provider |
| `KEY_MANAGER_PKCS11_MODULE` | absolute path of the HSM's PKCS#11 library |
| `KEY_MANAGER_PKCS11_TOKEN_LABEL` | token label |
| `KEY_MANAGER_PKCS11_PIN` / `KEY_MANAGER_PKCS11_PIN_FILE` | user PIN, or a file holding it (Vault agent); the file wins |
| `KEY_MANAGER_PKCS11_KEK_LABEL` | label of the AES-256 KEK (default `mailos-kek`) |
| `KEY_MANAGER_KMS_KEK_KEY_ID` | KMS key id, ARN or alias; required with `kms` |
| `KEY_MANAGER_KMS_REGION` | region; empty uses `AWS_REGION` |
| `KEY_MANAGER_KMS_ENDPOINT` | optional https endpoint (VPC interface endpoint) |
| `KEY_MANAGER_NEW_MASTER_KEY` / `KEY_MANAGER_PKCS11_NEW_KEK_LABEL` / `KEY_MANAGER_KMS_NEW_KEK_KEY_ID` | the KEK a rotation moves DEKs to (at most one; see below) |

Startup fails with an error naming the setting when one is missing or malformed. If the HSM or KMS can't be
reached at start, the server stops; it never falls back to the software KEK.

**PKCS#11 build.** The PKCS#11 binding (`github.com/miekg/pkcs11`, as IAM) needs cgo. It is compiled only with
`go build -tags pkcs11` (cgo on). Any other build refuses `KEY_MANAGER_PROVIDER=pkcs11` with "this server was built
without -tags pkcs11". If the label has no key, MailOS creates one (AES-256, sensitive, non-extractable). Provision
it in the key ceremony instead when several replicas start together, because two keys under one label are refused.

**KMS credentials** come from the default AWS chain (IRSA, ECS task role, instance role). There is no setting for
static keys. The role needs `kms:DescribeKey`, `kms:Encrypt` and `kms:Decrypt` on the KEK ARNs, conditioned on
`kms:EncryptionContext:mailos` like `mailos/key/*`. KMS automatic key rotation (same ARN) needs nothing from MailOS.

## Rotating the KEK

A KEK rotation re-wraps every DEK under a new KEK. The DEKs themselves (kid and key material) do not change, so
sealed values are not touched and keep opening throughout. Rotations can go between providers too, for example
from the master key into the HSM, from one HSM label to another, or from KMS back to software.

1. **Configure the new KEK on every replica** beside the current one, then deploy:
   `KEY_MANAGER_NEW_MASTER_KEY`, `KEY_MANAGER_PKCS11_NEW_KEK_LABEL` (with the PKCS#11 settings) or
   `KEY_MANAGER_KMS_NEW_KEK_KEY_ID`. Nothing changes yet.
2. **Start**: `POST /api/v1/keys/kek/rotate` with `{"reason": "..."}` (`settings:manage`, step-up). A
   `kek_rotations` row is recorded, and from then on new DEKs are wrapped under the new KEK. Every replica reads
   the latest rotation before wrapping a DEK.
3. **Re-wrap**: the key schedule (every minute, one replica, under the advisory lock) unwraps each DEK whose
   `kek_id` is not the target and wraps it under the new KEK. It stores the result only if the row is unchanged
   (compare-and-swap on `key_ref`). The pass is idempotent and resumable: a failed key is counted
   (`failed`, `last_error`) and retried on the next pass, and a crash or restart just continues from what
   `kek_id` says. The rotation completes when nothing is left, nothing failed, and 2 minutes have passed since it
   started. `GET /api/v1/keys/kek` shows the progress and how many DEKs each KEK wraps.
4. **Promote**: make the new KEK current (for example `KEY_MANAGER_MASTER_KEY=<new>`, or
   `KEY_MANAGER_PROVIDER=pkcs11` with `KEY_MANAGER_PKCS11_KEK_LABEL=<new label>`), remove the `*_NEW_*` setting
   and the old KEK, and deploy. A replica that lacks the KEK named by the latest rotation refuses to start rather
   than run unable to open its keys.

Audit events: `kek.rotation_started`, `kek.rewrapped`, `kek.rotation_error`, `kek.rotation_completed`
(resource `kek_rotation`).

DEKs wrapped before `kek_id` existed have no `kek_id`. They are opened by trying the configured KEKs, and the
first schedule pass re-wraps them under the current KEK and records it.

## Other clouds

`infrastructure/keymanager.RemoteKEKService` has three calls (`Resolve`, `Encrypt`, `Decrypt` of a DEK under a remote
key id with additional data). `ExternalKEK` turns any implementation into a KEK. Only AWS KMS (`AWSKMS`) is built
and tested. The others are not built: to add one, implement the interface and add a provider value.

| Service | Encrypt / Decrypt | AAD |
|---|---|---|
| Google Cloud KMS | `Encrypt` / `Decrypt` on a symmetric `ENCRYPT_DECRYPT` CryptoKey | `additionalAuthenticatedData` |
| Azure Key Vault / Managed HSM | `encrypt`/`decrypt` `A256GCM` on an `oct-HSM` key (Managed HSM), or `wrapKey`/`unwrapKey` `RSA-OAEP-256` | `A256GCM` binds it; with key wrapping, bind the kid separately |
| HashiCorp Vault Transit | `transit/encrypt/<key>` / `transit/decrypt/<key>` (aes256-gcm96) | `associated_data` |

## Tests

SoftHSM is not needed: `infrastructure/keymanager` tests the HSM KEK against a fake device and AWS KMS through the
real SDK client against an in-process fake KMS endpoint (`kms_fake_test.go`). `application/keymanager/kek_test.go`
rotates through software → software → HSM → HSM → KMS, and tests resumption after failures and the refusals.
`integration/core_test.go` (`-tags integration`) runs a rotation against Postgres.
