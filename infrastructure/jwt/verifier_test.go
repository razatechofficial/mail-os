package jwt_test

import (
	"context"
	"encoding/json"
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
		"tid not a UUID":    iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { c["tid"] = "not-a-uuid" })),
		"org not a UUID":    iam.Sign(iam.Keys[0], "at+jwt", mutate(func(c map[string]any) { c["org_id"] = "../other" })),
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

// TestPlanesMatrix is ADR 0001 §3.3's mutual rejection, every token shape
// against every plane: a platform token (aud exactly mailos-platform, no
// tenant, no act) is accepted on the platform plane only, and every tenant
// plane token is refused there.
func TestPlanesMatrix(t *testing.T) {
	iam, v := newVerifier(t)
	now := time.Now()
	person := "0d6f3a7e-5b1c-4c55-9f61-2f8f1c9b6a11"
	claims := func(kv ...any) map[string]any {
		c := map[string]any{"iss": iam.Issuer, "sub": person, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			"client_id": "mailos-platform-console", "acr": access.ACRPhishingResistant, "auth_time": now.Unix()}
		for i := 0; i < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(c, kv[i].(string))
				continue
			}
			c[kv[i].(string)] = kv[i+1]
		}
		return c
	}
	sign := func(c map[string]any) string { return iam.Sign(iam.Keys[0], "at+jwt", c) }
	const (
		none = iota
		tenantPlane
		platformPlane
	)
	cases := []struct {
		name   string
		token  string
		accept int
	}{
		{"platform user", sign(claims("aud", "mailos-platform")), platformPlane},
		{"platform user, aud array", sign(claims("aud", []string{"mailos-platform"})), platformPlane},
		{"platform user, DPoP-bound", sign(claims("aud", "mailos-platform", "cnf", map[string]any{"jkt": "thumb"})), platformPlane},
		{"platform aud with tid", sign(claims("aud", "mailos-platform", "tid", tenant)), none},
		{"platform aud with tenant_id", sign(claims("aud", "mailos-platform", "tenant_id", tenant)), none},
		{"platform aud with empty tid", sign(claims("aud", "mailos-platform", "tid", "")), none},
		{"platform aud with org_id", sign(claims("aud", "mailos-platform", "org_id", tenant)), none},
		{"platform aud with organization_uuid", sign(claims("aud", "mailos-platform", "organization_uuid", tenant)), none},
		{"platform aud with act", sign(claims("aud", "mailos-platform", "act", map[string]any{"sub": "op"})), none},
		{"platform and tenant audiences", sign(claims("aud", []string{"mailos-platform", "mailos"})), none},
		{"platform and send audiences", sign(claims("aud", []string{"mailos-platform", "mailos-send"})), none},
		{"platform and another resource", sign(claims("aud", []string{"mailos-platform", "xdr"})), none},
		{"platform and console audience", sign(claims("aud", []string{"mailos-platform", "mailos-console"})), none},
		{"platform service token", sign(claims("aud", "mailos-platform", "sub", "client:x", "client_id", "x")), none},
		{"platform sub not a UUID", sign(claims("aud", "mailos-platform", "sub", "alice")), none},
		{"platform token expired", sign(claims("aud", "mailos-platform", "exp", now.Add(-time.Hour).Unix())), none},
		{"platform token other issuer", sign(claims("aud", "mailos-platform", "iss", "https://evil.example")), none},
		{"platform token unpublished key", iam.Sign(iam.Unpublished, "at+jwt", claims("aud", "mailos-platform")), none},
		{"platform token wrong typ", iam.Sign(iam.Keys[0], "JWT", claims("aud", "mailos-platform")), none},
		{"platform security event", sign(claims("aud", "mailos-platform", "events", map[string]any{})), none},
		{"no audience", sign(claims("aud", nil)), none},

		{"tenant user", iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_admin"}}), tenantPlane},
		{"tenant user, console audience", iam.UserToken(fakeiam.User{Tenant: tenant, Audience: []string{"mailos-console"}}), tenantPlane},
		{"tenant user with org", iam.UserToken(fakeiam.User{Tenant: tenant, Org: tenant}), tenantPlane},
		{"service", iam.ServiceToken("mailos-iam", tenant), tenantPlane},
		{"service without tenant", iam.ServiceToken("mailos-iam", ""), tenantPlane},
		{"delegated tenant user", iam.UserToken(fakeiam.User{Tenant: tenant, Extra: map[string]any{"act": map[string]any{"sub": "op"}}}), tenantPlane},
		{"tenant and send audiences", iam.UserToken(fakeiam.User{Tenant: tenant, Audience: []string{"mailos", "mailos-send"}}), none},
		{"tenant and tenant-plane audiences", iam.UserToken(fakeiam.User{Tenant: tenant, Audience: []string{"mailos", "mailos-tenant"}}), none},
		{"send audience only", iam.UserToken(fakeiam.User{Tenant: tenant, Audience: "mailos-send"}), none},
		{"tenant user without tid", sign(claims("aud", "mailos")), none},
	}
	for _, c := range cases {
		_, terr := v.Principal(context.Background(), c.token)
		pp, perr := v.PlatformPrincipal(context.Background(), c.token)
		if (terr == nil) != (c.accept == tenantPlane) {
			t.Errorf("%s on the tenant plane: err = %v", c.name, terr)
		}
		if (perr == nil) != (c.accept == platformPlane) {
			t.Errorf("%s on the platform plane: err = %v", c.name, perr)
		}
		for _, err := range []error{terr, perr} {
			if err != nil && !errors.Is(err, jwt.ErrInvalid) {
				t.Errorf("%s: %v is not ErrInvalid", c.name, err)
			}
		}
		if perr == nil {
			if pp.Kind != access.KindPlatform || pp.Subject != person || pp.TenantID != "" || pp.OrgID != "" ||
				len(pp.Roles) != 0 || pp.Delegated || pp.ClientID != "mailos-platform-console" || pp.ACR != access.ACRPhishingResistant {
				t.Errorf("%s: principal %+v", c.name, pp)
			}
		}
	}
}

// A platform principal carries the token's binding and sign-in facts.
func TestPlatformPrincipalFields(t *testing.T) {
	iam, v := newVerifier(t)
	now := time.Now()
	raw := iam.Sign(iam.Keys[1], "at+jwt", map[string]any{"iss": iam.Issuer, "sub": "0D6F3A7E-5B1C-4C55-9F61-2F8F1C9B6A11",
		"aud": "mailos-platform", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "azp": "pc",
		"auth_time": now.Add(-time.Minute).Unix(), "sid": "s1", "jti": "j1", "email": "ops@example.com",
		"amr": []string{"hwk"}, "scope": "openid email", "cnf": map[string]any{"jkt": "thumb"}, "roles": []string{"mailos_admin"}})
	p, err := v.PlatformPrincipal(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "0d6f3a7e-5b1c-4c55-9f61-2f8f1c9b6a11" || p.ClientID != "pc" || p.SessionID != "s1" || p.TokenID != "j1" ||
		p.Email != "ops@example.com" || p.DPoPThumbprint != "thumb" || p.AuthTime.IsZero() || len(p.Roles) != 0 || !p.HasScope("email") {
		t.Fatalf("principal %+v", p)
	}
}

// With JWKSURL the verifier reads that key set only: the IAM's approval
// keys verify an attestation, and a token signed with the IAM's token key
// (published in the discovery document's JWKS) does not.
func TestFixedJWKSURL(t *testing.T) {
	tokenKeys := fakeiam.New("http://unused")
	approval := fakeiam.New("http://unused")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/acs-approval-jwks.json":
			_ = json.NewEncoder(w).Encode(approval.JWKS())
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(tokenKeys.JWKS())
		case "/.well-known/openid-configuration":
			t.Error("a fixed JWKS URL must not read the discovery document")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	v := jwt.NewVerifier(jwt.Config{Issuer: srv.URL, JWKSURL: srv.URL + "/.well-known/acs-approval-jwks.json", MinRefresh: time.Millisecond})
	claims := map[string]any{"iss": srv.URL, "aud": "mailos", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	if _, err := v.Verify(context.Background(), approval.Sign(approval.Keys[1], "acs-approval+jwt", claims), "acs-approval+jwt"); err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if _, err := v.Verify(context.Background(), tokenKeys.Sign(tokenKeys.Keys[1], "acs-approval+jwt", claims), "acs-approval+jwt"); !errors.Is(err, jwt.ErrUnknownKey) {
		t.Fatalf("token key accepted for an attestation: %v", err)
	}
}
