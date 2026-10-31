package webhook

import (
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	now := time.Unix(1793433600, 0)
	body := []byte(`{"event":"message.sent"}`)
	h := Sign("whsec_test-secret-1234", now, body)
	if !strings.HasPrefix(h, "t=1793433600,v1=") {
		t.Fatal(h)
	}
	if !Verify("whsec_test-secret-1234", h, body, now.Add(time.Minute), 5*time.Minute) {
		t.Fatal("valid signature refused")
	}
	if Verify("whsec_other-secret-123", h, body, now, 5*time.Minute) || Verify("whsec_test-secret-1234", h, []byte("{}"), now, 5*time.Minute) {
		t.Fatal("wrong secret or body accepted")
	}
	if Verify("whsec_test-secret-1234", h, body, now.Add(time.Hour), 5*time.Minute) {
		t.Fatal("stale signature accepted")
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
