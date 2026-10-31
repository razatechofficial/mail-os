package jwt_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

const tenant = "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"

func newVerifier(t *testing.T) (*fakeiam.IAM, *jwt.Verifier) {
	t.Helper()
	iam, _ := fakeiam.NewServer(t)
	return iam, jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos", ConsoleAudiences: []string{"mailos-console"}, MinRefresh: time.Millisecond})
}

func TestUserToken(t *testing.T) {
	iam, v := newVerifier(t)
	raw := iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_admin", "tenant_admin", "mailos_viewer"}, JKT: "thumb"})
	p, err := v.Principal(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != access.KindUser || p.TenantID != tenant || p.ACR != access.ACRMFA || p.DPoPThumbprint != "thumb" || p.AuthTime.IsZero() {
		t.Fatalf("principal %+v", p)
	}
	if len(p.Roles) != 2 || p.Roles[0] != access.RoleAdmin || p.Roles[1] != access.RoleViewer {
		t.Fatalf("roles %v: IAM roles that are not MailOS roles must be dropped", p.Roles)
	}
}

// A browser application's token carries its scopes and the user's
// verified address (IAM releases email and email_verified with the email
// scope).
func TestUserTokenScopesAndEmail(t *testing.T) {
	iam, v := newVerifier(t)
	raw := iam.UserToken(fakeiam.User{Tenant: tenant, ClientID: "portal-web", Extra: map[string]any{
		"scope": "openid email mailos.send.self", "email": "ana@example.com", "email_verified": true}})
	p, err := v.Principal(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasScope("mailos.send.self") || len(p.Scopes) != 3 || p.Email != "ana@example.com" || !p.EmailVerified || p.ClientID != "portal-web" {
		t.Fatalf("principal %+v", p)
	}
	unverified := iam.UserToken(fakeiam.User{Tenant: tenant, Extra: map[string]any{"email": "ana@example.com", "email_verified": "true"}})
	if p, err := v.Principal(context.Background(), unverified); err != nil || p.EmailVerified {
		t.Fatalf("a string email_verified counted as verified: %+v %v", p, err)
	}
}

func TestConsoleAudienceAccepted(t *testing.T) {
	iam, v := newVerifier(t)
	raw := iam.UserToken(fakeiam.User{Tenant: tenant, Audience: []string{"mailos-console"}})
	if _, err := v.Principal(context.Background(), raw); err != nil {
		t.Fatalf("token for the console client refused: %v", err)
	}
}

func TestServiceToken(t *testing.T) {
	iam, v := newVerifier(t)
	p, err := v.Principal(context.Background(), iam.ServiceToken("mailos-iam", tenant))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != access.KindService || p.ClientID != "mailos-iam" || p.TenantID != tenant || len(p.Roles) != 0 {
		t.Fatalf("principal %+v", p)
	}
}

// Every forged, misdirected or expired token is refused.
func TestRefusals(t *testing.T) {
	iam, v := newVerifier(t)
	now := time.Now()
	base := func() map[string]any {
		return map[string]any{"iss": iam.Issuer, "sub": "u1", "aud": "mailos", "tid": tenant,
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	}
	mutate := func(f func(map[string]any)) map[string]any { c := base(); f(c); return c }
	cases := map[string]string{
		"unpublished key":   iam.Sign(iam.Unpublished, "at+jwt", base()),
		"wrong typ":         iam.Sign(iam.Keys[0], "JWT", base()),
		"message signature": iam.Sign(iam.Keys[0], "mailos-msg+jwt", base()),
		"other issuer":      iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { c["iss"] = "https://evil.example" })),
		"expired":           iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() })),
		"no exp":            iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { delete(c, "exp") })),
		"future iat":        iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() })),
		"other audience":    iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { c["aud"] = "xdr" })),
		"user without tid":  iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { delete(c, "tid") })),
		"security event":    iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { c["events"] = map[string]any{} })),
		"service for console audience": iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) {
			c["sub"], c["client_id"], c["aud"] = "client:x", "x", "mailos-console"
		})),
		"service client_id mismatch": iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) {
			c["sub"], c["client_id"] = "client:x", "y"
		})),
		"not a jws": "not.a.token",
	}
	for name, raw := range cases {
		if _, err := v.Principal(context.Background(), raw); !errors.Is(err, jwt.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

// A token whose alg is not its key's algorithm is refused, even when the
// key could verify it: RS256 presented for the PS256 key.
func TestAlgorithmBoundToKey(t *testing.T) {
	iam, v := newVerifier(t)
	k := iam.Keys[0]
	k.Algorithm = jose.RS256
	raw := iam.Sign(k, "at+jwt", map[string]any{"iss": iam.Issuer, "sub": "u", "aud": "mailos", "tid": tenant,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
	if _, err := v.Principal(context.Background(), raw); !errors.Is(err, jwt.ErrInvalid) || !strings.Contains(err.Error(), "alg") {
		t.Fatalf("alg swap: %v", err)
	}
}

// Verify names the kind of a signature refusal beside ErrInvalid.
func TestVerifyRefusalKinds(t *testing.T) {
	iam, v := newVerifier(t)
	claims := map[string]any{"iss": iam.Issuer, "sub": "u", "aud": "mailos",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	swapped := iam.Keys[0]
	swapped.Algorithm = jose.RS256
	good := iam.Sign(iam.Keys[0], "at+jwt", claims)
	other := iam.Sign(iam.Keys[0], "at+jwt", map[string]any{"sub": "other"})
	forged := good[:strings.LastIndex(good, ".")] + other[strings.LastIndex(other, "."):]
	for name, tc := range map[string]struct {
		raw  string
		kind error
	}{
		"typ":         {iam.Sign(iam.Keys[0], "JWT", claims), jwt.ErrType},
		"unknown kid": {iam.Sign(iam.Unpublished, "at+jwt", claims), jwt.ErrUnknownKey},
		"alg swap":    {iam.Sign(swapped, "at+jwt", claims), jwt.ErrAlgorithm},
		"signature":   {forged, jwt.ErrSignature},
	} {
		_, err := v.Verify(context.Background(), tc.raw, "at+jwt")
		if !errors.Is(err, jwt.ErrInvalid) || !errors.Is(err, tc.kind) {
			t.Errorf("%s: err = %v, want ErrInvalid and %v", name, err, tc.kind)
		}
	}
}

// A key IAM adds after MailOS cached the JWKS is picked up by kid.
func TestRotationRefetches(t *testing.T) {
	iam, v := newVerifier(t)
	if _, err := v.Principal(context.Background(), iam.ServiceToken("a", tenant)); err != nil {
		t.Fatal(err)
	}
	iam.Keys = append([]fakeiam.Key{iam.Unpublished}, iam.Keys...)
	if _, err := v.Principal(context.Background(), iam.UserToken(fakeiam.User{Tenant: tenant})); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
}

func TestIAMDownIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer srv.Close()
	iam := fakeiam.New(srv.URL)
	v := jwt.NewVerifier(jwt.Config{Issuer: srv.URL, Audience: "mailos"})
	_, err := v.Principal(context.Background(), iam.ServiceToken("a", tenant))
	if !errors.Is(err, jwt.ErrUnavailable) || errors.Is(err, jwt.ErrInvalid) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestDiscoveryMustNameIssuer(t *testing.T) {
	iam, srv := fakeiam.NewServer(t)
	v := jwt.NewVerifier(jwt.Config{Issuer: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Audience: "mailos"})
	_, err := v.Principal(context.Background(), iam.ServiceToken("a", tenant))
	if !errors.Is(err, jwt.ErrUnavailable) {
		t.Fatalf("discovery for another issuer accepted: %v", err)
	}
}
