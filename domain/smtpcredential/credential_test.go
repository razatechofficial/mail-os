package smtpcredential

import (
	"strings"
	"testing"
)

func TestGeneratedUsernameAndPassword(t *testing.T) {
	u, err := NewUsername()
	if err != nil || !ValidUsername(u) {
		t.Fatalf("username %q %v", u, err)
	}
	u2, _ := NewUsername()
	if u == u2 {
		t.Fatal("usernames repeat")
	}
	p, err := NewPassword()
	if err != nil || !strings.HasPrefix(p, PasswordPrefix) || len(p) != len(PasswordPrefix)+43 {
		t.Fatalf("password %q %v", p, err)
	}
	for _, s := range []string{"", "smtp_", "SMTP_AAAAAAAAAAAAAAAAAAAAAAAA", "smtp_aaaaaaaaaaaaaaaaaaaaaaa1", "admin", p} {
		if ValidUsername(s) {
			t.Errorf("%q is not a generated username", s)
		}
	}
}

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("mosmtp_secret")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash %q %v", h, err)
	}
	if h2, _ := Hash("mosmtp_secret"); h2 == h {
		t.Fatal("the salt is random")
	}
	if ok, err := Verify(h, "mosmtp_secret"); !ok || err != nil {
		t.Fatalf("the right password: %v %v", ok, err)
	}
	if ok, err := Verify(h, "mosmtp_secreT"); ok || err != nil {
		t.Fatalf("a wrong password: %v %v", ok, err)
	}
	for _, bad := range []string{"", "$2a$10$abc", "$argon2id$v=19$m=1,t=1$x$y", "$argon2id$v=19$m=999999999,t=1,p=1$c2FsdA$a2V5",
		"$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$a2V5"} {
		if _, err := Verify(bad, "x"); err == nil {
			t.Errorf("%q is malformed", bad)
		}
	}
}

func TestActive(t *testing.T) {
	c := Credential{}
	if !c.Active() {
		t.Fatal("a new credential is active")
	}
	now := c.CreatedAt
	c.RevokedAt = &now
	if c.Active() {
		t.Fatal("a revoked credential is not")
	}
}
