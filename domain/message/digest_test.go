package message

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSentDigest(t *testing.T) {
	key := []byte(strings.Repeat("k", MinDigestKey))
	d := NewSentDigest(key, "Your code", "Code: 482913", "<p>482913</p>")
	if d.Alg != DigestAlg || d.KeyID != DigestKeyID(key) || len(d.Subject) != 64 || len(d.Text) != 64 || len(d.HTML) != 64 {
		t.Fatalf("digest %+v", d)
	}
	raw, _ := json.Marshal(d)
	if strings.Contains(string(raw), "482913") {
		t.Fatal("digest holds the code")
	}
	if !d.Verify(key, "Your code", "Code: 482913", "<p>482913</p>") {
		t.Fatal("the message sent does not verify")
	}
	// One hash per part: each verifies on its own, and only its own part.
	if !d.VerifyPart(key, "text", "Code: 482913") || d.VerifyPart(key, "text", "<p>482913</p>") || d.VerifyPart(key, "body", "x") {
		t.Fatal("per-part verification")
	}
	// The redacted copy does not verify, nor does a changed code.
	for _, c := range [][3]string{
		{"Your code", "Code: 482914", "<p>482913</p>"},
		{"Your code", "Code: [redacted: code, 6 characters]", "<p>[redacted: code, 6 characters]</p>"},
	} {
		if d.Verify(key, c[0], c[1], c[2]) {
			t.Errorf("%q verified", c)
		}
	}
	// Equal parts get different digests (labelled input).
	same := NewSentDigest(key, "x", "x", "x")
	if same.Subject == same.Text || same.Text == same.HTML {
		t.Fatal("parts share a digest")
	}
	other := []byte(strings.Repeat("o", MinDigestKey))
	if d.Verify(other, "Your code", "Code: 482913", "<p>482913</p>") || DigestKeyID(other) == DigestKeyID(key) {
		t.Fatal("another key verified")
	}
	if !(SentDigest{}).IsZero() || d.IsZero() {
		t.Fatal("IsZero")
	}
}
