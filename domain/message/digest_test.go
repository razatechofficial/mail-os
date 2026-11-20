package message

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// keyedEvidence is an Evidence with one key.
type keyedEvidence struct{ kid, key string }

func (e keyedEvidence) mac(in []byte) []byte {
	m := hmac.New(sha256.New, []byte(e.key))
	m.Write(in)
	return m.Sum(nil)
}

func (e keyedEvidence) MAC(_ context.Context, inputs ...[]byte) (string, [][]byte, error) {
	out := make([][]byte, len(inputs))
	for i, in := range inputs {
		out[i] = e.mac(in)
	}
	return e.kid, out, nil
}

func (e keyedEvidence) VerifyMAC(_ context.Context, kid string, input, mac []byte) (bool, error) {
	if kid != e.kid {
		return false, fmt.Errorf("unknown evidence key %q", kid)
	}
	return hmac.Equal(e.mac(input), mac), nil
}

func TestSentDigest(t *testing.T) {
	ctx := context.Background()
	ev := keyedEvidence{kid: "k1", key: "evidence-key-0123456789abcdef0123"}
	d, err := NewSentDigest(ctx, ev, "Your code", "Code: 482913", "<p>482913</p>")
	if err != nil || d.Alg != DigestAlg || d.KeyID != "k1" || len(d.Subject) != 64 || len(d.Text) != 64 || len(d.HTML) != 64 {
		t.Fatalf("digest %+v %v", d, err)
	}
	raw, _ := json.Marshal(d)
	if strings.Contains(string(raw), "482913") {
		t.Fatal("digest holds the code")
	}
	if ok, err := d.Verify(ctx, ev, "Your code", "Code: 482913", "<p>482913</p>"); !ok || err != nil {
		t.Fatalf("the message sent does not verify: %v", err)
	}
	// One hash per part: each verifies on its own, and only its own part.
	if ok, _ := d.VerifyPart(ctx, ev, PartText, "Code: 482913"); !ok {
		t.Fatal("text part")
	}
	if ok, _ := d.VerifyPart(ctx, ev, PartText, "<p>482913</p>"); ok {
		t.Fatal("html verified as text")
	}
	for _, c := range [][3]string{
		{"Your code", "Code: 482914", "<p>482913</p>"},
		{"Your code", "Code: [redacted: code, 6 characters]", "<p>[redacted: code, 6 characters]</p>"},
	} {
		if ok, _ := d.Verify(ctx, ev, c[0], c[1], c[2]); ok {
			t.Errorf("%q verified", c)
		}
	}
	// Without the key the stored value cannot be reproduced: the true code
	// and a spread of others, under a bare SHA-256 (with or without the
	// part label) or another key, never give the stored text hash.
	other := keyedEvidence{kid: "k1", key: "another-key"}
	guesses := []string{"Code: 482913"}
	for n := 0; n < 1_000_000; n += 997 {
		guesses = append(guesses, fmt.Sprintf("Code: %06d", n))
	}
	for _, guess := range guesses {
		bare := sha256.Sum256([]byte(guess))
		labelled := sha256.Sum256(digestInput(PartText, guess))
		if hex.EncodeToString(bare[:]) == d.Text || hex.EncodeToString(labelled[:]) == d.Text ||
			hex.EncodeToString(other.mac(digestInput(PartText, guess))) == d.Text {
			t.Fatalf("reproduced without the key: %q", guess)
		}
	}
	if !(SentDigest{}).IsZero() || d.IsZero() {
		t.Fatal("IsZero")
	}
}
