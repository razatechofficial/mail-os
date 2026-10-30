package stepup

import (
	"testing"
	"time"
)

func TestHeaderAndParse(t *testing.T) {
	c := Challenge{ACRValues: []string{"urn:iam:acr:mfa"}, MaxAge: 300 * time.Second, Description: `A "stronger" sign-in\ is needed`}
	h := c.Header("DPoP")
	want := `DPoP error="insufficient_user_authentication", error_description="A \"stronger\" sign-in\\ is needed", acr_values="urn:iam:acr:mfa", max_age="300"`
	if h != want {
		t.Fatalf("header\n got %s\nwant %s", h, want)
	}
	scheme, got, ok := Parse(h)
	if !ok || scheme != "DPoP" || got.MaxAge != 300*time.Second || len(got.ACRValues) != 1 || got.Description != c.Description {
		t.Fatalf("parse = %s %+v %v", scheme, got, ok)
	}
	if h := (Challenge{}).Header(""); h != `Bearer error="insufficient_user_authentication"` {
		t.Fatalf("bare = %s", h)
	}
	if _, _, ok := Parse(`Bearer error="invalid_token"`); ok {
		t.Fatal("another error read as a step-up challenge")
	}
	if _, c, ok := Parse(`Bearer realm="iam", error=insufficient_user_authentication, max_age=60`); !ok || c.MaxAge != time.Minute {
		t.Fatalf("token values: %+v %v", c, ok)
	}
	if h := (Challenge{Description: "line\nbreak"}).Header("Bearer"); h != `Bearer error="insufficient_user_authentication", error_description="linebreak"` {
		t.Fatalf("control characters kept: %s", h)
	}
}

func TestFresh(t *testing.T) {
	now := time.Now()
	if !Fresh(time.Time{}, now, 0) {
		t.Fatal("no max_age must always pass")
	}
	if Fresh(time.Time{}, now, time.Minute) {
		t.Fatal("a token without auth_time passed a max_age")
	}
	if !Fresh(now.Add(-30*time.Second), now, time.Minute) || Fresh(now.Add(-2*time.Minute), now, time.Minute) {
		t.Fatal("age not enforced")
	}
}
