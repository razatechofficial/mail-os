package message

import (
	"strings"
	"testing"
)

func TestSentDigest(t *testing.T) {
	key := []byte(strings.Repeat("k", MinDigestKey))
	d := SentDigest(key, "Your code", "Code: 482913", "<p>482913</p>")
	if !strings.HasPrefix(d, "hmac-sha256:"+DigestKeyID(key)+":") || len(d) != len("hmac-sha256:")+16+1+64 {
		t.Fatalf("digest %q", d)
	}
	if strings.Contains(d, "482913") {
		t.Fatal("digest holds the code")
	}
	if !VerifySentDigest(key, d, "Your code", "Code: 482913", "<p>482913</p>") {
		t.Fatal("the message sent does not verify")
	}
	for _, c := range [][3]string{
		{"Your code", "Code: 482914", "<p>482913</p>"},
		{"Your code", "Code: 482913", "<p>[redacted: code, 6 characters]</p>"},
		// Moving text between parts changes the digest (length prefixes).
		{"Your codeCode: 482913", "", "<p>482913</p>"},
	} {
		if VerifySentDigest(key, d, c[0], c[1], c[2]) {
			t.Errorf("%q verified", c)
		}
	}
	// Another key neither verifies nor shares the key id.
	other := []byte(strings.Repeat("o", MinDigestKey))
	if VerifySentDigest(other, d, "Your code", "Code: 482913", "<p>482913</p>") || DigestKeyID(other) == DigestKeyID(key) {
		t.Fatal("another key verified")
	}
	if VerifySentDigest(key, "sha256:x:y", "a", "b", "c") {
		t.Fatal("foreign scheme verified")
	}
}
