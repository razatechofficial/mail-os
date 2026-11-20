package message

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// digestScheme names how SentDigest is computed.
const digestScheme = "hmac-sha256"

// MinDigestKey is the shortest message digest key accepted (256 bits).
const MinDigestKey = 32

// SentDigest is evidence that a message was sent exactly as it was: an
// HMAC-SHA-256, under the deployment's message digest key, of the subject,
// text and HTML the provider was handed, each length-prefixed so no two
// messages share an input. With the template version and the stored
// non-secret variables it shows the redacted copy represents what was sent
// (Electronic Transactions Ordinance 2002 s.6(b)) without storing the
// secret. It is keyed, not a bare hash: the redacted copy and a bare hash
// would let anyone who reads the row try every 6-digit code against it.
// The result is "hmac-sha256:<key id>:<hex>"; the key id names the key,
// never reveals it.
func SentDigest(key []byte, subject, text, html string) string {
	mac := hmac.New(sha256.New, key)
	for _, part := range []string{subject, text, html} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		mac.Write(n[:])
		mac.Write([]byte(part))
	}
	return digestScheme + ":" + DigestKeyID(key) + ":" + hex.EncodeToString(mac.Sum(nil))
}

// DigestKeyID identifies a digest key: the first 8 bytes of a hash of it
// under a label of its own, in hex.
func DigestKeyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("mailos message digest key id\x00"), key...))
	return hex.EncodeToString(sum[:8])
}

// VerifySentDigest reports whether digest is SentDigest of the content
// under key: how an investigator checks a message reconstructed from its
// template version and variables (with the secret the IAM recorded, or
// none, as the case may be).
func VerifySentDigest(key []byte, digest, subject, text, html string) bool {
	parts := strings.SplitN(digest, ":", 3)
	if len(parts) != 3 || parts[0] != digestScheme || parts[1] != DigestKeyID(key) {
		return false
	}
	return hmac.Equal([]byte(digest), []byte(SentDigest(key, subject, text, html)))
}
