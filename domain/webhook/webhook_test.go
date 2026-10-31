package webhook

import (
	"testing"
	"time"
)

// The signature is the Standard Webhooks one: the specification's own
// test vector verifies.
func TestStandardWebhooksSignature(t *testing.T) {
	const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	const id = "msg_p5jXN8AQM9LWM0D4loKWxJek"
	body := []byte(`{"test": 2432232314}`)
	ts := time.Unix(1614265330, 0)
	if got := Sign(secret, id, ts, body); got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("signature %s", got)
	}
	h := Headers(secret, id, ts, body)
	if h[IDHeader] != id || h[TimestampHeader] != "1614265330" {
		t.Fatalf("headers %v", h)
	}
	if !Verify(secret, id, h[TimestampHeader], "v1,other "+h[SignatureHeader], body, ts.Add(time.Minute), 5*time.Minute) {
		t.Fatal("valid signature refused")
	}
	if Verify(secret, id, h[TimestampHeader], h[SignatureHeader], []byte("{}"), ts, 5*time.Minute) ||
		Verify("whsec_b3RoZXI=", id, h[TimestampHeader], h[SignatureHeader], body, ts, 5*time.Minute) ||
		Verify(secret, "msg_other", h[TimestampHeader], h[SignatureHeader], body, ts, 5*time.Minute) {
		t.Fatal("wrong body, secret or id accepted")
	}
	if Verify(secret, id, h[TimestampHeader], h[SignatureHeader], body, ts.Add(time.Hour), 5*time.Minute) {
		t.Fatal("stale signature accepted")
	}
	// A secret chosen without the prefix signs with its own bytes, as the
	// prefixed base64 of the same bytes does.
	if Sign("plain-secret-1234", id, ts, body) != Sign("whsec_cGxhaW4tc2VjcmV0LTEyMzQ=", id, ts, body) {
		t.Fatal("prefixed and plain forms of one key differ")
	}
}

func TestValidate(t *testing.T) {
	ok := Webhook{URL: "https://hooks.bank.example/mailos", Events: []string{EventSent}}
	if err := ok.Validate(false); err != nil {
		t.Fatal(err)
	}
	for _, w := range []Webhook{
		{URL: "http://hooks.bank.example", Events: []string{EventSent}},
		{URL: "https://user:pw@hooks.bank.example", Events: []string{EventSent}},
		{URL: "https://hooks.bank.example", Events: []string{"message.exploded"}},
		{URL: "https://hooks.bank.example"},
	} {
		if w.Validate(false) == nil {
			t.Errorf("accepted %+v", w)
		}
	}
	if (Webhook{URL: "http://127.0.0.1:9000", Events: []string{EventSent}}).Validate(true) != nil {
		t.Fatal("http refused where plaintext is allowed")
	}
	if ValidateSecret("short") == nil || ValidateSecret("has a space in it!!") == nil {
		t.Fatal("bad secret accepted")
	}
	s, _ := NewSecret()
	if ValidateSecret(s) != nil {
		t.Fatal("generated secret refused")
	}
}
