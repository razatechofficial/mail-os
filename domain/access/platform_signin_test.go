package access

import (
	"errors"
	"testing"
	"time"
)

const platformConsole = "6f1d0c2a-4b7e-4d8a-9a51-3c2e7f0b9d14"

// The platform sign-in rule (contract C2): the platform console's client,
// a phishing-resistant sign-in, no older than the platform session.
func TestPlatformSignIn(t *testing.T) {
	now := time.Now()
	rule := PlatformSignIn{ClientIDs: []string{"other-console", platformConsole}}
	ok := Principal{Kind: KindPlatform, ClientID: platformConsole, ACR: ACRPhishingResistant, AuthTime: now.Add(-time.Hour)}
	if err := rule.Check(ok, now); err != nil {
		t.Fatalf("fresh passkey sign-in through the console refused: %v", err)
	}
	upper := ok
	upper.ClientID = "6F1D0C2A-4B7E-4D8A-9A51-3C2E7F0B9D14"
	if err := rule.Check(upper, now); err != nil {
		t.Fatalf("client UUID in another case refused: %v", err)
	}

	cases := map[string]struct {
		edit func(*Principal)
		want error
	}{
		"another client":          {func(p *Principal) { p.ClientID = "f3b0e1c2-0000-4000-8000-000000000009" }, ErrPlatformClient},
		"no client":               {func(p *Principal) { p.ClientID = "" }, ErrPlatformClient},
		"mfa only":                {func(p *Principal) { p.ACR = ACRMFA }, ErrPlatformWeak},
		"password only":           {func(p *Principal) { p.ACR = ACRPassword }, ErrPlatformWeak},
		"no acr":                  {func(p *Principal) { p.ACR = "" }, ErrPlatformWeak},
		"unknown acr":             {func(p *Principal) { p.ACR = "urn:other:gold" }, ErrPlatformWeak},
		"older than the session":  {func(p *Principal) { p.AuthTime = now.Add(-DefaultPlatformMaxAge - time.Second) }, ErrPlatformStale},
		"no auth_time":            {func(p *Principal) { p.AuthTime = time.Time{} }, ErrPlatformStale},
		"client checked first":    {func(p *Principal) { p.ClientID, p.ACR = "x", ACRMFA }, ErrPlatformClient},
		"weak checked before age": {func(p *Principal) { p.ACR, p.AuthTime = ACRMFA, time.Time{} }, ErrPlatformWeak},
	}
	for name, tc := range cases {
		p := ok
		tc.edit(&p)
		if err := rule.Check(p, now); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	edge := ok
	edge.AuthTime = now.Add(-DefaultPlatformMaxAge)
	if err := rule.Check(edge, now); err != nil {
		t.Fatalf("sign-in exactly MaxAge old refused: %v", err)
	}
	short := PlatformSignIn{ClientIDs: []string{platformConsole}, MaxAge: 30 * time.Minute}
	if err := short.Check(ok, now); !errors.Is(err, ErrPlatformStale) {
		t.Fatalf("configured MaxAge not applied: %v", err)
	}
	if err := (PlatformSignIn{}).Check(ok, now); !errors.Is(err, ErrPlatformClient) {
		t.Fatalf("no configured client: %v (the platform plane fails closed)", err)
	}
}
