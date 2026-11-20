package message

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// DigestAlg names how SentDigest's parts are computed.
const DigestAlg = "hmac-sha256"

// MinDigestKey is the shortest message digest key accepted (256 bits).
const MinDigestKey = 32

// SentDigest is evidence that a message was sent exactly as it was: one
// keyed SHA-256 (HMAC-SHA-256, under the deployment's message digest key)
// of each part the provider was handed, before MIME encoding. With the
// template version and the stored non-secret variables it shows that the
// redacted copy represents what was sent (Electronic Transactions
// Ordinance 2002 s.6(b)) without storing the secret (ADR 0001 §3.14 class
// (a)). It is keyed, not a bare hash: the redacted copy and a bare hash
// would let anyone who reads the row try every 6-digit code against it.
// Each part's input is labelled, so equal subject and text still differ.
type SentDigest struct {
	Alg string `json:"alg"`
	// KeyID names the key (DigestKeyID), never reveals it.
	KeyID   string `json:"kid"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

// NewSentDigest digests the subject, text and HTML under key.
func NewSentDigest(key []byte, subject, text, html string) SentDigest {
	return SentDigest{Alg: DigestAlg, KeyID: DigestKeyID(key),
		Subject: partDigest(key, "subject", subject), Text: partDigest(key, "text", text), HTML: partDigest(key, "html", html)}
}

// IsZero reports a message with no digest (not sent, or no key).
func (d SentDigest) IsZero() bool { return d == SentDigest{} }

// Verify reports whether every part matches the content under key: how an
// investigator checks a message reconstructed from its template version
// and variables (with the secret the IAM recorded, as the case may be).
func (d SentDigest) Verify(key []byte, subject, text, html string) bool {
	return d.VerifyPart(key, "subject", subject) && d.VerifyPart(key, "text", text) && d.VerifyPart(key, "html", html)
}

// VerifyPart reports whether one part ("subject", "text" or "html")
// matches value under key.
func (d SentDigest) VerifyPart(key []byte, part, value string) bool {
	if d.Alg != DigestAlg || d.KeyID != DigestKeyID(key) {
		return false
	}
	var want string
	switch part {
	case "subject":
		want = d.Subject
	case "text":
		want = d.Text
	case "html":
		want = d.HTML
	default:
		return false
	}
	return hmac.Equal([]byte(want), []byte(partDigest(key, part, value)))
}

func partDigest(key []byte, part, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("mailos sent " + part + "\x00"))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// DigestKeyID identifies a digest key: the first 8 bytes of a hash of it
// under a label of its own, in hex.
func DigestKeyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("mailos message digest key id\x00"), key...))
	return hex.EncodeToString(sum[:8])
}
