# Key manager providers

MailOS seals stored secrets (provider API keys and SMTP passwords, DKIM private keys, webhook signing secrets) with
envelope encryption, following IAM's key manager:

- **Data keys (DEKs)**: one active AES-256 key per purpose (`provider`, `dkim`, `webhook`), rotated every
  `KEY_MANAGER_ENCRYPTION_ROTATION_PERIOD`. A sealed value is `km1.<kid>.<nonce||AES-256-GCM>` and names its DEK.
- **Key-encryption key (KEK)**: wraps every DEK. It never leaves where it lives: configuration (Vault), an HSM, or a
  cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault / Managed HSM) or HashiCorp Vault Transit.
  `KEY_MANAGER_PROVIDER` chooses which.

## Where keys live

| What | Where |
|---|---|
| DEKs | Postgres `encryption_keys.key_ref` (BYTEA), **wrapped** under the KEK, bound to `mailos/key/<kid>` as additional data (GCM AAD or KMS encryption context). Never stored in the clear. Each replica unwraps a DEK once and keeps it in memory. |
| Which KEK wraps a DEK | `encryption_keys.kek_id`: `software:<fingerprint>`, `pkcs11:<HSM key label>`, `kms:<KMS key ARN>`, `gcp_kms:<CryptoKey name>`, `azure_key_vault:<key URL>` or `vault_transit:<mount>/<key>`; `provider` is its prefix. |
| KEK rotations | `kek_rotations` (from, to, state, progress, last error); one runs at a time. |
| Software KEK | `KEY_MANAGER_MASTER_KEY` (base64 32 bytes, from Vault). Its id is the first 8 bytes of HMAC-SHA256(key, "mailos/master-key-id"), so the key is never shown. |
| HSM KEK | An AES-256 token object on the HSM, `CKA_SENSITIVE`, not `CKA_EXTRACTABLE`, found by token label + key label. DEKs are wrapped with `CKM_AES_GCM` (12-byte nonce, 128-bit tag) through `C_Encrypt`/`C_Decrypt`. |
| KMS KEK | A symmetric (`SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT`) AWS KMS key. DEKs are encrypted with `Encrypt`/`Decrypt` and the encryption context `{"mailos": "mailos/key/<kid>"}`. An alias is resolved to its ARN at start; the ARN is what `kek_id` records. |
| GCP KMS KEK | A symmetric `ENCRYPT_DECRYPT` CryptoKey with an enabled primary version. DEKs go through `:encrypt`/`:decrypt` with `additionalAuthenticatedData` = `mailos/key/<kid>`. The ciphertext names the key version, so Cloud KMS rotation needs nothing from MailOS. |
| Azure KEK | An enabled `RSA`/`RSA-HSM` key allowed `wrapKey` and `unwrapKey`. DEKs are wrapped with `RSA-OAEP-256`. Key wrapping takes no AAD, so what is wrapped is `SHA-256(mailos/key/<kid>) ‖ DEK`, and unwrapping checks the hash. The stored value is `<key version>:<ciphertext>`, so a key rotated in the vault still opens older DEKs. `kek_id` is the versionless key URL unless a version was configured. |
| Vault Transit KEK | An `aes256-gcm96` or `chacha20-poly1305` Transit key. DEKs go through `encrypt`/`decrypt` with `associated_data`. The stored value is Vault's `vault:v<n>:…` ciphertext, so `transit/keys/<key>/rotate` needs nothing from MailOS. |

## Settings

| Setting | Meaning |
|---|---|
| `KEY_MANAGER_PROVIDER` | `software` (default), `pkcs11`, `kms` (AWS), `gcp_kms`, `azure_key_vault` or `vault_transit` |
| `KEY_MANAGER_MASTER_KEY` | software KEK; required with `software`, refused with any other provider |
| `KEY_MANAGER_PKCS11_MODULE` | absolute path of the HSM's PKCS#11 library |
| `KEY_MANAGER_PKCS11_TOKEN_LABEL` | token label |
| `KEY_MANAGER_PKCS11_PIN` / `KEY_MANAGER_PKCS11_PIN_FILE` | user PIN, or a file holding it (Vault agent); the file wins |
| `KEY_MANAGER_PKCS11_KEK_LABEL` | label of the AES-256 KEK (default `mailos-kek`) |
| `KEY_MANAGER_KMS_KEK_KEY_ID` | KMS key id, ARN or alias; required with `kms` |
| `KEY_MANAGER_KMS_REGION` | region; empty uses `AWS_REGION` |
| `KEY_MANAGER_KMS_ENDPOINT` | optional https endpoint (VPC interface endpoint) |
| `KEY_MANAGER_GCP_KMS_KEK_KEY` | CryptoKey `projects/…/locations/…/keyRings/…/cryptoKeys/…`; required with `gcp_kms` |
| `KEY_MANAGER_GCP_KMS_CREDENTIALS_FILE` | service-account JSON key; empty uses `GOOGLE_APPLICATION_CREDENTIALS`, then the metadata server (GKE workload identity, GCE) |
| `KEY_MANAGER_GCP_KMS_ENDPOINT` | optional https endpoint (Private Service Connect) |
| `KEY_MANAGER_AZURE_VAULT_URL` | `https://<name>.vault.azure.net` or a Managed HSM URL; required with `azure_key_vault` |
| `KEY_MANAGER_AZURE_KEK_KEY` | key name, or `name/version` to pin a version; required with `azure_key_vault` |
| `KEY_MANAGER_AZURE_TENANT_ID` / `KEY_MANAGER_AZURE_CLIENT_ID` / `KEY_MANAGER_AZURE_CLIENT_SECRET(_FILE)` | Entra ID app; without a secret MailOS uses the managed identity (a client id then picks a user-assigned one) |
| `KEY_MANAGER_AZURE_AUTHORITY_HOST` | Entra ID host (default `https://login.microsoftonline.com`) |
| `KEY_MANAGER_VAULT_ADDR` / `KEY_MANAGER_VAULT_NAMESPACE` | Vault's https address and optional namespace; address required with `vault_transit` |
| `KEY_MANAGER_VAULT_TRANSIT_MOUNT` / `KEY_MANAGER_VAULT_KEK_KEY` | Transit mount (default `transit`) and key; key required with `vault_transit` |
| `KEY_MANAGER_VAULT_TOKEN(_FILE)` or `KEY_MANAGER_VAULT_ROLE_ID` + `KEY_MANAGER_VAULT_SECRET_ID(_FILE)` | a token (the agent's sink file is re-read when Vault refuses it) or AppRole (`KEY_MANAGER_VAULT_APPROLE_MOUNT`, default `approle`) |
| `KEY_MANAGER_NEW_MASTER_KEY` / `KEY_MANAGER_PKCS11_NEW_KEK_LABEL` / `KEY_MANAGER_KMS_NEW_KEK_KEY_ID` / `KEY_MANAGER_GCP_KMS_NEW_KEK_KEY` / `KEY_MANAGER_AZURE_NEW_KEK_KEY` / `KEY_MANAGER_VAULT_NEW_KEK_KEY` | the KEK a rotation moves DEKs to (at most one; see below) |

Startup fails with an error naming the setting when one is missing or malformed. If the HSM or KMS can't be
reached at start, the server stops; it never falls back to the software KEK.

**PKCS#11 build.** The PKCS#11 binding (`github.com/miekg/pkcs11`, as IAM) needs cgo. It is compiled only with
`go build -tags pkcs11` (cgo on). Any other build refuses `KEY_MANAGER_PROVIDER=pkcs11` with "this server was built
without -tags pkcs11". If the label has no key, MailOS creates one (AES-256, sensitive, non-extractable). Provision
it in the key ceremony instead when several replicas start together, because two keys under one label are refused.

**KMS credentials** come from the default AWS chain (IRSA, ECS task role, instance role). There is no setting for
static keys. The role needs `kms:DescribeKey`, `kms:Encrypt` and `kms:Decrypt` on the KEK ARNs, conditioned on
`kms:EncryptionContext:mailos` like `mailos/key/*`. KMS automatic key rotation (same ARN) needs nothing from MailOS.

**GCP, Azure and Vault** are called over their HTTPS APIs with the Go standard library (no SDK). Tokens are cached
until a minute before they expire, and a refused token is replaced once. Errors name the service and HTTP status,
never a token or secret. Grant only what the KEK needs: `roles/cloudkms.cryptoKeyEncrypterDecrypter` plus
`cloudkms.cryptoKeys.get` on the key; Key Vault `get`, `wrapKey` and `unwrapKey` (or "Key Vault Crypto Service
Encryption User" plus key read); a Vault policy with `read` on `<mount>/keys/<key>` and `update` on
`<mount>/encrypt/<key>` and `<mount>/decrypt/<key>`.

## Rotating the KEK

A KEK rotation re-wraps every DEK under a new KEK. The DEKs themselves (kid and key material) do not change, so
sealed values are not touched and keep opening throughout. Rotations can go between providers too, for example
from the master key into the HSM, from one HSM label to another, or from KMS back to software.

1. **Configure the new KEK on every replica** beside the current one, then deploy:
   `KEY_MANAGER_NEW_MASTER_KEY`, `KEY_MANAGER_PKCS11_NEW_KEK_LABEL` (with the PKCS#11 settings),
   `KEY_MANAGER_KMS_NEW_KEK_KEY_ID`, `KEY_MANAGER_GCP_KMS_NEW_KEK_KEY`, `KEY_MANAGER_AZURE_NEW_KEK_KEY` or
   `KEY_MANAGER_VAULT_NEW_KEK_KEY` (with that service's connection settings). Nothing changes yet.
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

## Other key services

`infrastructure/keymanager.RemoteKEKService` has three calls (`Resolve`, `Encrypt`, `Decrypt` of a DEK under a remote
key id with additional data). `ExternalKEK` turns any implementation into a KEK. AWS KMS (`AWSKMS`), Google Cloud KMS
(`GCPKMS`), Azure Key Vault (`AzureKeyVault`) and Vault Transit (`VaultTransit`) are built. To add another,
implement the interface and add a provider value.

## Tests

SoftHSM is not needed: `infrastructure/keymanager` tests the HSM KEK against a fake device and AWS KMS through the
real SDK client against an in-process fake KMS endpoint (`kms_fake_test.go`). GCP KMS, Azure Key Vault and Vault
Transit are tested against in-process HTTPS fakes (`kms_remote_fake_test.go`) that check tokens and authenticate
ciphertexts: round trips, key rotation in the service, token refresh and refused credentials. `application/keymanager/kek_test.go`
rotates through software → software → HSM → HSM → KMS, and tests resumption after failures and the refusals.
`integration/core_test.go` (`-tags integration`) runs a rotation against Postgres.
