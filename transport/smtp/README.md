# SMTP submission

MailOS accepts mail over SMTP from software that cannot call the HTTP API, the way the SMTP interfaces of AWS SES, SendGrid and Postmark do. Every session acts as one MailOS application, and the application's rules apply exactly as they do for `POST /api/v1/messages/send`: tenant, senders on verified domains, message type `raw`, stream, sandbox or live, rate and daily quota, suppressions, audit.

The design and the standards it follows are in the package documentation (`doc.go`).

## Turning it on

The listener is off by default. It runs in the server process (`cmd/server`), never in the worker.

| Setting | Default | Meaning |
|---|---|---|
| `SMTP_SUBMISSION_ENABLED` | `false` | Starts the listener |
| `SMTP_SUBMISSION_HOST` | `0.0.0.0` | Bind address |
| `SMTP_SUBMISSION_PORT` | `587` | Submission with STARTTLS (RFC 6409, RFC 3207) |
| `SMTP_SUBMISSION_IMPLICIT_TLS_PORT` | `0` (off) | Submission over implicit TLS (RFC 8314), normally `465` |
| `SMTP_SUBMISSION_HOSTNAME` | `localhost` | Name in the greeting; the certificate's name |
| `SMTP_SUBMISSION_TLS_CERT_FILE`, `_KEY_FILE` | | Required. Reloaded on each handshake (cert-manager rotation) |
| `SMTP_SUBMISSION_TLS_MIN_VERSION` | `1.2` | `1.2` or `1.3` |
| `SMTP_SUBMISSION_PASSWORD_AUTH` | `true` | Offer AUTH PLAIN and LOGIN to applications opted in to SMTP credentials. `false` accepts IAM tokens only |
| `SMTP_SUBMISSION_MAX_MESSAGE_BYTES` | `4194304` | SIZE limit, 64 KiB to 16 MiB |
| `SMTP_SUBMISSION_MAX_RECIPIENTS` | `50` | RCPT TO per message, 1 to 1000 |
| `SMTP_SUBMISSION_MAX_CONNECTIONS` | `200` | Open connections per listener |
| `SMTP_SUBMISSION_MAX_CONNECTIONS_PER_IP` | `20` | Open connections per client address |
| `SMTP_SUBMISSION_READ_TIMEOUT` | `2m` | Idle time between commands |
| `SMTP_SUBMISSION_WRITE_TIMEOUT` | `1m` | One reply |
| `SMTP_SUBMISSION_MAX_SESSION_DURATION` | `30m` | A connection is closed after this, however busy |
| `SMTP_SUBMISSION_AUTH_FAILURES_PER_IP` | `10` | Failed AUTH attempts per address per window (counted in Redis) before AUTH is refused |
| `SMTP_SUBMISSION_AUTH_FAILURE_WINDOW` | `15m` | That window |

There is no plaintext mode, in any environment. Run `migrate-postgres up` first: migration `20261103100000_smtp_submission` adds `smtp_credentials`, `applications.smtp_password_auth` and `messages.headers`. The server refuses to start without it.

**Network.**
- Expose 587 (and 465 when on) through a TCP load balancer that keeps the client address. Use proxy protocol, or `externalTrafficPolicy: Local`. The per-address limits and the audit trail need the real address.
- Allow only the bank's application networks to reach it (NetworkPolicy or firewall).
- The listener is not behind the HTTP ingress.

## Configuring a legacy application

1. **Register the application** in MailOS (Integrations, then Applications), as for the HTTP API:
   - kind `server`;
   - message types including `raw`;
   - its senders on a verified domain;
   - limits.
   It starts in `sandbox`: messages are captured, never delivered. Switch it to `live` after testing.
2. **Choose how it authenticates.**

### Preferred: an IAM token (OAUTHBEARER or XOAUTH2)

The application gets a client-credentials token from IAM (`aud=mailos`; see `docs/mailos-applications.md` §3) and sends it over SMTP. Nothing is issued by MailOS.

| | |
|---|---|
| Host | `SMTP_SUBMISSION_HOSTNAME` |
| Port | 587 with STARTTLS, or 465 with TLS |
| AUTH | `OAUTHBEARER` (RFC 7628) or `XOAUTH2` |
| User | anything (ignored: the token's client decides) |
| Token | the IAM access token; it lives at most 10 minutes, so fetch a new one per connection |

DPoP-bound tokens are refused: SMTP cannot carry the proof. The token is checked again at every `MAIL FROM`. A connection that outlives its token gets `421 4.7.0` and must reconnect.

### Legacy: an SMTP username and password

This is for software that can only be given a username and a password. It is the one secret MailOS issues, and only for applications an administrator opts in.

1. **Opt the application in.** Edit the application and turn on "SMTP credentials" (`smtp_password_auth: true`). This is a server application registered in the console; never the system application.
2. **Create a credential.** In the application's SMTP credentials section, or `POST /api/v1/applications/{id}/smtp-credentials {"description": "core banking batch host"}` (a `mailos_admin`, with step-up).
   - The response holds a generated `username` (`smtp_…`) and a `password` (`mosmtp_…`).
   - **The password is shown once.** Store it in the application's own secret store. MailOS keeps only an Argon2id hash.
3. **Configure the software:**

   | | |
   |---|---|
   | Host | `SMTP_SUBMISSION_HOSTNAME` |
   | Port | 587, security STARTTLS (or "TLS required"); or 465, SSL/TLS |
   | Authentication | PLAIN or LOGIN |
   | Username / password | from step 2 |
   | From | one of the application's senders |

**Rotation.**
- **Without downtime:** an application may hold two active credentials. Create a second, switch the software to it, then revoke the first.
- **In place:** `POST …/smtp-credentials/{credential_id}/rotate` gives the same username a new password, effective at once.

**Revocation.** `DELETE …/smtp-credentials/{credential_id}` stops the credential at once, including open sessions (checked at the next `MAIL FROM`). Turning `smtp_password_auth` off stops every credential of the application without revoking them. Suspending the application stops both kinds of authentication.

## What is sent

**Recipients.** Each envelope recipient (`RCPT TO`) gets their own message. `Bcc`, `Cc` and `To` addresses in the headers are never used as recipients; their display names are kept.

**Sender.** `MAIL FROM` and the header `From` must both be among the application's senders, on a verified domain.

**Content.**
- The text and HTML bodies are kept, decoded to UTF-8. The HTML is sanitised.
- The subject, `Reply-To`, and `List-Unsubscribe` / `List-Unsubscribe-Post` are kept.
- Everything else is dropped.
- MailOS writes its own `Message-ID` and signs with the domain's DKIM key.

**Not supported: attachments and inline images.** They are refused with `554 5.6.1`, never dropped silently. Link to documents instead.

**Broadcast applications.** Their mail must carry `List-Unsubscribe`, and for one-click unsubscribe (RFC 8058) also `List-Unsubscribe-Post: List-Unsubscribe=One-Click`.

**Retries.** Give every message a `Message-ID`. A transaction retried with the same `Message-ID` and the same bytes is not sent twice.

## Replies

| Reply | When |
|---|---|
| `530 5.7.0` | AUTH or MAIL before STARTTLS; MAIL before AUTH |
| `535 5.7.8` | Authentication failed (the reason is in the audit trail only) |
| `454 4.7.0` | Temporary authentication failure, or too many failures from the address |
| `421 4.7.0` | Too many failures on the connection; or authorization ended (token expired, credential revoked, application suspended) |
| `550 5.7.1` | Sender not allowed or on an unverified domain, no `raw` type, stream, broadcast without List-Unsubscribe |
| `451 4.7.1` / `452 4.7.1` | Per-minute rate / daily quota of the application |
| `552 5.3.4` | Message over the size limit |
| `452 4.5.3` / `553 5.1.3` | Too many recipients / invalid recipient |
| `554 5.6.0` / `554 5.6.1` | Malformed message or invalid field / attachments and other unsupported content |
| `451 4.3.0` | MailOS temporarily unable to queue |
| `250 2.0.0` | Queued, with the MailOS message ids |

## Operations

**Audit** (each event carries the client address and the session id as `request_id`):
- `smtp.authenticated`
- `smtp.auth_failed` (critical, with its reason: `bad_password`, `unknown_username`, `credential_revoked`, `smtp_password_auth_off`, `invalid_token`, `dpop_bound_token`, …)
- `smtp.session_refused`
- `smtp.message_refused`
- `smtp_credential.created`, `.rotated` and `.revoked`
- and the pipeline's own `message.queued` and `message.refused`

**Messages.** Each message's metadata holds:
- `source: smtp`;
- the session;
- the authentication method;
- the client's Message-ID.

**Metrics:**
- `mailos_smtp_connections_total{listener,outcome}`
- `mailos_smtp_active_connections`
- `mailos_smtp_auth_total{mechanism,result}`
- `mailos_smtp_messages_total{outcome}`
- `mailos_smtp_recipients_queued_total`

**Shutdown.** On SIGTERM the listeners close. Open sessions may finish their transaction until `SHUTDOWN_TIMEOUT`, then they are closed.
