// Package smtp is MailOS's SMTP submission relay: a bank's legacy software
// that can only send mail over SMTP submits through MailOS, the way it
// would through the SMTP interfaces of AWS SES, SendGrid or Postmark, and
// under the same MailOS application registry as the HTTP API.
//
// # Design
//
// Standards. Message submission (RFC 6409) on port 587 with STARTTLS
// (RFC 3207), and optionally implicit TLS on port 465 (RFC 8314). SMTP AUTH
// (RFC 4954) with OAUTHBEARER (RFC 7628), XOAUTH2, PLAIN (RFC 4616) and
// LOGIN. Enhanced status codes (RFC 3463, RFC 2034), SIZE (RFC 1870),
// PIPELINING, 8BITMIME and CHUNKING as the library offers them. TLS 1.2 or
// later with AEAD suites only (pkg/tlsconfig, PCI DSS 4.0.1 §4.2.1).
//
// Off unless configured. SMTP_SUBMISSION_ENABLED turns the listener on;
// it then needs a certificate and key (reloaded on each handshake). There
// is no plaintext mode in any environment, local included.
//
// TLS first, then AUTH, then MAIL. Before TLS the server advertises
// STARTTLS but not AUTH, and answers AUTH and MAIL with
// "530 5.7.0 Must issue a STARTTLS command first". After TLS, MAIL without
// AUTH is "530 5.7.0 Authentication required". There is no unauthenticated
// path to the message pipeline: never an open relay.
//
// Identity: the application, as for the HTTP API. An authenticated session
// acts as exactly one MailOS application: its tenant, senders, message
// types, stream, environment and limits decide everything that follows.
// Two ways in:
//
//   - IAM access token (preferred), over OAUTHBEARER or XOAUTH2: a
//     client-credentials token of the application's IAM client, verified
//     exactly as the HTTP API verifies it (the same jwt.Verifier: IAM's
//     JWKS, iss, aud mailos, exp), then resolved by
//     applications.ResolveService (a server application, active, of the
//     token's tenant). A DPoP-bound token is refused: SMTP cannot carry the
//     proof, and a sender-constrained token must not work without it. The
//     authorization identity (a= or user=) is not used: the token's client
//     decides.
//   - SMTP credentials (legacy), over PLAIN or LOGIN: a username and
//     password MailOS generates for one server application. This is the
//     one justified exception to "MailOS issues no secret": legacy software
//     can be given a host, a port, a username and a password, and nothing
//     else, which is why SES, SendGrid and Postmark issue SMTP credentials
//     too. It is opt-in per application (smtp_password_auth, server
//     applications registered in the console only, never the system
//     application) and can be switched off platform-wide
//     (SMTP_SUBMISSION_PASSWORD_AUTH). The username is generated, the
//     password is 256 random bits shown once and stored as an Argon2id
//     hash, at most two are active per application (rotation without
//     downtime), and creation, rotation, revocation and every use are
//     audited (domain/smtpcredential, application/smtpcred).
//
// Re-authorization per transaction. SMTP sessions are long. At every MAIL
// FROM the identity is decided again: the token is verified again (so an
// expired token stops), the credential is re-read (so a revocation stops
// an open session), and the application must still be active and opted
// in. A session that fails this check is answered 421 4.7.0 and closed.
//
// Enforcement, in order:
//
//	connection   per-listener and per-address connection limits (421),
//	             idle and write timeouts, a maximum session duration
//	AUTH         3 failures close the connection (421); failures per
//	             client address are counted in Redis across replicas, and
//	             over SMTP_SUBMISSION_AUTH_FAILURES_PER_IP in the window
//	             AUTH is refused (454 4.7.0); without Redis, AUTH is
//	             refused (fail closed)
//	MAIL FROM    applications.AuthorizeSubmission: the application may
//	             send written content ("raw") and the envelope sender is one
//	             of its senders on a domain still verified (550 5.7.1);
//	             a declared SIZE over the limit is 552 5.3.4
//	RCPT TO      a valid address (553 5.1.3), at most MaxRecipients
//	             (452 4.5.3); duplicates count once
//	DATA         at most MaxMessageBytes (552 5.3.4); the message is
//	             parsed (below); a broadcast application's mail needs
//	             List-Unsubscribe (550 5.7.1); then one message per
//	             recipient enters message.Service.Send, the pipeline of
//	             POST /messages/send with written content
//
// The pipeline is the HTTP API's, unchanged: the header From must be one
// of the application's senders on a verified domain (550 5.7.1), the
// stream decides the queue and the type (broadcast mail is marketing, so
// unsubscribes are honoured), the per-minute rate (451 4.7.1) and daily
// quota (452 4.7.1) are taken per message from the same Redis counters,
// suppressions apply (the message is stored as suppressed, as over HTTP),
// HTML is sanitised, a sandbox application's mail is captured and never
// delivered, and every message and refusal is audited with the
// application id. The worker then signs with the verified domain's DKIM
// key and writes MailOS's own Message-ID.
//
// The message, read safely. net/mail and mime/multipart read the message
// within the size limit, at most 16 MIME parts and 4 levels deep. MailOS
// keeps From (exactly one address), Reply-To, the To and Cc display names,
// Subject (RFC 2047 decoded), the text and HTML bodies (base64 or
// quoted-printable, any WHATWG charset converted to UTF-8), and
// List-Unsubscribe and List-Unsubscribe-Post (checked against RFC 2369 and
// RFC 8058). Everything else is dropped: Bcc, Cc and To as addresses (the
// envelope decides the recipients, and each recipient gets their own
// message), Received, Sender, Return-Path, X- headers, and the client's
// own DKIM-Signature and Message-ID. Content MailOS cannot send as written
// (attachments, inline images, a forwarded message) is refused with
// 554 5.6.1, never dropped silently; a message that cannot be read is
// 554 5.6.0.
//
// Retries. SMTP has one reply for a whole transaction. Each recipient's
// message carries an idempotency key made of the application, the client's
// Message-ID, the recipient and the exact message bytes, so a client that
// retries a transaction after a timeout or a 4xx sends nothing twice. A
// message without a Message-ID is new every time.
//
// Replies (RFC 3463 enhanced codes):
//
//	530 5.7.0  STARTTLS first; authentication required
//	535 5.7.8  authentication failed (the reason is audited, never sent)
//	454 4.7.0  temporary authentication failure (IAM, the database or
//	           Redis unreachable; too many failures from the address)
//	421 4.7.0  too many failures on this connection; authorization ended
//	           (token expired, credential revoked, application suspended)
//	550 5.7.1  sender, raw content, stream or List-Unsubscribe refused
//	451 4.7.1  per-minute rate exceeded
//	452 4.7.1  daily quota used up
//	552 5.3.4  message too large
//	553 5.1.3  invalid recipient address
//	554 5.6.0  malformed message or invalid fields (subject, addresses)
//	554 5.6.1  unsupported content (attachments)
//	451 4.3.0  MailOS temporarily unable to queue
//	250 2.0.0  queued, with the MailOS message ids
//
// Observability. Audit events: smtp.authenticated, smtp.auth_failed (with
// its reason), smtp.session_refused, smtp.message_refused, and the
// pipeline's own message.queued and message.refused; each carries the
// client address and the session id (as request_id). Metrics:
// mailos_smtp_connections_total, mailos_smtp_active_connections,
// mailos_smtp_auth_total, mailos_smtp_messages_total and
// mailos_smtp_recipients_queued_total.
//
// Shutdown. The listeners close at once; open sessions finish (a
// transaction in flight completes) until SHUTDOWN_TIMEOUT, then are
// closed.
//
// Library. github.com/emersion/go-smtp is the SMTP server: the most widely
// used Go SMTP server library (the maddy mail server builds on
// it), MIT licensed, maintained, no dependencies beyond go-sasl, and from
// the author of go-msgauth, which MailOS already uses for DKIM. MailOS
// implements the SASL mechanisms itself (sasl.go) so every failure is
// 535 5.7.8 and OAUTHBEARER follows RFC 7628's error exchange.
//
// Not supported: attachments and inline images (the message pipeline
// carries a text and an HTML body only), SMTPUTF8 addresses, DSN, and
// per-recipient replies (LMTP-style) in one transaction.
package smtp
