package message

import (
	"context"
	"encoding/hex"
)

// DigestAlg names how SentDigest's parts are computed.
const DigestAlg = "hmac-sha256"

// Evidence computes and checks HMAC-SHA-256 under the key manager's
// evidence keys (purpose evidence). The keys never leave it.
type Evidence interface {
	// MAC returns one MAC per input, all under the active key, and its id.
	MAC(ctx context.Context, inputs ...[]byte) (kid string, macs [][]byte, err error)
	// VerifyMAC checks mac against input under the key kid, active or
	// retired.
	VerifyMAC(ctx context.Context, kid string, input, mac []byte) (bool, error)
}

// SentDigest is evidence that a message was sent exactly as it was: one
// HMAC-SHA-256 of each part the provider was handed, before MIME encoding,
// under a key-manager evidence key. With the template version and the
// stored non-secret variables it shows that the redacted copy represents
// what was sent (Electronic Transactions Ordinance 2002 s.6(b)) without
// storing the secret (ADR 0001 §3.14 class (a)). It is keyed, never a bare
// hash: the redacted copy and a bare hash would let anyone who reads the
// row try every 6-digit code against it. Verifying a copy needs the key,
// so it goes through the key manager (mailos-verify-sent). Each part's
// input is labelled, so equal subject and text still differ.
type SentDigest struct {
	Alg string `json:"alg"`
	// KeyID names the evidence key, never reveals it.
	KeyID   string `json:"kid"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

// Parts of a sent message, as SentDigest labels them.
const (
	PartSubject = "subject"
	PartText    = "text"
	PartHTML    = "html"
)

// NewSentDigest computes the digest of the subject, text and HTML.
func NewSentDigest(ctx context.Context, ev Evidence, subject, text, html string) (SentDigest, error) {
	kid, macs, err := ev.MAC(ctx, digestInput(PartSubject, subject), digestInput(PartText, text), digestInput(PartHTML, html))
	if err != nil {
		return SentDigest{}, err
	}
	return SentDigest{Alg: DigestAlg, KeyID: kid, Subject: hex.EncodeToString(macs[0]), Text: hex.EncodeToString(macs[1]),
		HTML: hex.EncodeToString(macs[2])}, nil
}

// IsZero reports a message with no digest (not sent).
func (d SentDigest) IsZero() bool { return d == SentDigest{} }

// Verify reports whether every part matches the content: how a custodian
// checks a message reconstructed from its template version and variables
// (with the secret the IAM recorded, as the case may be).
func (d SentDigest) Verify(ctx context.Context, ev Evidence, subject, text, html string) (bool, error) {
	for _, p := range [][2]string{{PartSubject, subject}, {PartText, text}, {PartHTML, html}} {
		ok, err := d.VerifyPart(ctx, ev, p[0], p[1])
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// VerifyPart reports whether one part matches value.
func (d SentDigest) VerifyPart(ctx context.Context, ev Evidence, part, value string) (bool, error) {
	if d.Alg != DigestAlg {
		return false, nil
	}
	var want string
	switch part {
	case PartSubject:
		want = d.Subject
	case PartText:
		want = d.Text
	case PartHTML:
		want = d.HTML
	default:
		return false, nil
	}
	mac, err := hex.DecodeString(want)
	if err != nil {
		return false, nil
	}
	return ev.VerifyMAC(ctx, d.KeyID, digestInput(part, value), mac)
}

func digestInput(part, value string) []byte {
	return append([]byte("mailos sent "+part+"\x00"), value...)
}
