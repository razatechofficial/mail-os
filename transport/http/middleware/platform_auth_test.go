package middleware

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/dpop"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

// consoleSignIn is the platform sign-in rule with the fake IAM's platform
// console as the only client.
var consoleSignIn = access.PlatformSignIn{ClientIDs: []string{fakeiam.PlatformConsoleClient}}

// planes mounts both planes as the router does: /api/v1 behind Auth,
// /api/platform/v1 behind PlatformAuth, one route each that echoes the
// principal's kind.
func planes(t *testing.T) (*fakeiam.IAM, *gin.Engine, *tenants) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	v := jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos", ConsoleAudiences: []string{"mailos-console"}})
	ten := &tenants{}
	proofs := dpop.NewVerifier(noReplay{}, time.Minute)
	auth := &Auth{Verifier: v, DPoP: proofs, Tenants: ten, Apps: appstest.New(appstest.Server("mailos-iam", tenant, "iam.*"))}
	pauth := &PlatformAuth{Verifier: v, DPoP: proofs, SignIn: consoleSignIn}
	r := gin.New()
	echo := func(c *gin.Context) {
		p := PrincipalFrom(c)
		c.JSON(200, gin.H{"kind": p.Kind, "sub": p.Subject, "tenant": p.TenantID})
	}
	r.Group("/api/v1", auth.Required()).GET("/templates", echo)
	r.Group("/api/platform/v1", pauth.Required()).GET("/me", echo)
	return iam, r, ten
}

// Mutual rejection (ADR 0001 §3.3): a platform token is refused on
// /api/v1; every tenant-plane token is refused on /api/platform/v1.
func TestPlanesRejectEachOther(t *testing.T) {
	iam, r, ten := planes(t)
	platform := iam.PlatformToken(fakeiam.PlatformUser{})
	tenantTokens := map[string]string{
		"tenant admin":    iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_admin"}}),
		"console aud":     iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_admin"}, Audience: "mailos-console"}),
		"service":         iam.ServiceToken("mailos-iam", tenant),
		"lockbox-like":    iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_viewer"}, Extra: map[string]any{"act": map[string]any{"sub": "op"}}}),
		"platform+tid":    iam.PlatformToken(fakeiam.PlatformUser{Extra: map[string]any{"tid": tenant}}),
		"platform+org":    iam.PlatformToken(fakeiam.PlatformUser{Extra: map[string]any{"org_id": tenant}}),
		"platform+act":    iam.PlatformToken(fakeiam.PlatformUser{Extra: map[string]any{"act": map[string]any{"sub": "op"}}}),
		"platform+mailos": iam.PlatformToken(fakeiam.PlatformUser{Extra: map[string]any{"aud": []string{"mailos-platform", "mailos"}}}),
	}

	if w := call(r, "GET", "/api/platform/v1/me", platform); w.Code != 200 || !strings.Contains(w.Body.String(), `"kind":"platform"`) ||
		!strings.Contains(w.Body.String(), `"tenant":""`) {
		t.Fatalf("platform token on the platform plane: %d %s", w.Code, w.Body)
	}
	if w := call(r, "GET", "/api/v1/templates", platform); w.Code != 401 {
		t.Fatalf("platform token on the tenant plane: %d %s", w.Code, w.Body)
	}
	for name, tok := range tenantTokens {
		if w := call(r, "GET", "/api/platform/v1/me", tok); w.Code != 401 {
			t.Errorf("%s on the platform plane: %d %s", name, w.Code, w.Body)
		}
	}
	for _, name := range []string{"tenant admin", "console aud", "lockbox-like"} {
		if w := call(r, "GET", "/api/v1/templates", tenantTokens[name]); w.Code != 200 {
			t.Errorf("%s on the tenant plane: %d %s", name, w.Code, w.Body)
		}
	}
	for _, id := range ten.ensured {
		if id == "" {
			t.Fatal("the platform plane provisioned a tenant")
		}
	}
	if w := call(r, "GET", "/api/platform/v1/me", ""); w.Code != 401 || !strings.Contains(w.Body.String(), MissingTokenMessage) {
		t.Fatalf("no token: %d %s", w.Code, w.Body)
	}
}

func dpopProof(t *testing.T, key *ecdsa.PrivateKey, method, htu, token string) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	sum := crypto.SHA256.New()
	sum.Write([]byte(token))
	payload := `{"jti":"` + uuid.NewString() + `","htm":"` + method + `","htu":"` + htu + `","iat":` +
		strconv.FormatInt(time.Now().Unix(), 10) + `,"ath":"` + base64.RawURLEncoding.EncodeToString(sum.Sum(nil)) + `"}`
	jws, err := sig.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := jws.CompactSerialize()
	return out
}

// A DPoP-bound platform token needs its proof (RFC 9449), as on /api/v1.
func TestPlatformDPoP(t *testing.T) {
	iam, r, _ := planes(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumb, _ := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	tok := iam.PlatformToken(fakeiam.PlatformUser{JKT: jkt})

	if w := call(r, "GET", "/api/platform/v1/me", tok); w.Code != 401 {
		t.Fatalf("bound token without a proof: %d %s", w.Code, w.Body)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/api/platform/v1/me", nil)
	req.Header.Set("Authorization", "DPoP "+tok)
	req.Header.Set("DPoP", dpopProof(t, key, "GET", "http://example.com/api/platform/v1/me", tok))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bound token with its proof: %d %s", w.Code, w.Body)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "http://example.com/api/platform/v1/me", nil)
	req.Header.Set("Authorization", "DPoP "+tok)
	req.Header.Set("DPoP", dpopProof(t, other, "GET", "http://example.com/api/platform/v1/me", tok))
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("proof by another key: %d", w.Code)
	}
}

// The platform sign-in rule (contract C2): a token for another client is
// invalid; a sign-in without a passkey or older than the platform session
// gets the RFC 9470 challenge (401 insufficient_user_authentication with
// acr_values and max_age), so the console signs in to the platform again.
func TestPlatformSignInRule(t *testing.T) {
	iam, r, _ := planes(t)
	if w := call(r, "GET", "/api/platform/v1/me", iam.PlatformToken(fakeiam.PlatformUser{AuthAge: 7 * time.Hour})); w.Code != 200 {
		t.Fatalf("a 7-hour-old passkey sign-in: %d %s", w.Code, w.Body)
	}
	other := iam.PlatformToken(fakeiam.PlatformUser{ClientID: "another-platform-app"})
	w := call(r, "GET", "/api/platform/v1/me", other)
	if w.Code != 401 || code(w) != "UNAUTHORIZED" || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("another platform application's token: %d %s %q", w.Code, w.Body, w.Header().Get("WWW-Authenticate"))
	}
	for name, u := range map[string]fakeiam.PlatformUser{
		"authenticator app": {ACR: access.ACRMFA},
		"password":          {ACR: access.ACRPassword},
		"9 hours old":       {AuthAge: 9 * time.Hour},
	} {
		w := call(r, "GET", "/api/platform/v1/me", iam.PlatformToken(u))
		ch := w.Header().Get("WWW-Authenticate")
		if w.Code != 401 || code(w) != "INSUFFICIENT_USER_AUTHENTICATION" || !strings.HasPrefix(ch, "Bearer ") ||
			!strings.Contains(ch, `error="insufficient_user_authentication"`) ||
			!strings.Contains(ch, `acr_values="urn:iam:acr:phishing-resistant"`) || !strings.Contains(ch, `max_age="28800"`) ||
			!strings.Contains(w.Body.String(), `"acr_values":"urn:iam:acr:phishing-resistant"`) || !strings.Contains(w.Body.String(), `"max_age":28800`) ||
			!strings.Contains(w.Body.String(), PlatformSignInMessage) {
			t.Errorf("%s: %d %s %q", name, w.Code, w.Body, ch)
		}
	}
	// No auth_time at all is never fresh.
	noTime := iam.PlatformToken(fakeiam.PlatformUser{Extra: map[string]any{"auth_time": nil}})
	if w := call(r, "GET", "/api/platform/v1/me", noTime); w.Code != 401 || code(w) != "INSUFFICIENT_USER_AUTHENTICATION" {
		t.Fatalf("no auth_time: %d %s", w.Code, w.Body)
	}

	// A configured shorter window, and a fixed clock.
	v := jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"})
	short := &PlatformAuth{Verifier: v, SignIn: access.PlatformSignIn{ClientIDs: []string{fakeiam.PlatformConsoleClient}, MaxAge: time.Hour},
		Now: func() time.Time { return time.Now().Add(30 * time.Minute) }}
	r2 := gin.New()
	r2.Group("/api/platform/v1", short.Required()).GET("/me", func(c *gin.Context) { c.Status(200) })
	if w := call(r2, "GET", "/api/platform/v1/me", iam.PlatformToken(fakeiam.PlatformUser{AuthAge: 20 * time.Minute})); w.Code != 200 {
		t.Fatalf("50 minutes into a 1-hour window: %d %s", w.Code, w.Body)
	}
	w = call(r2, "GET", "/api/platform/v1/me", iam.PlatformToken(fakeiam.PlatformUser{AuthAge: 40 * time.Minute}))
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `max_age="3600"`) {
		t.Fatalf("70 minutes into a 1-hour window: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}

	// No configured client: the platform plane fails closed.
	closed := &PlatformAuth{Verifier: v}
	r3 := gin.New()
	r3.Group("/api/platform/v1", closed.Required()).GET("/me", func(c *gin.Context) { c.Status(200) })
	if w := call(r3, "GET", "/api/platform/v1/me", iam.PlatformToken(fakeiam.PlatformUser{})); w.Code != 401 {
		t.Fatalf("no platform client configured: %d", w.Code)
	}
}

// A DPoP-bound token's challenge names the DPoP scheme, after its proof.
func TestPlatformSignInRuleDPoP(t *testing.T) {
	iam, r, _ := planes(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumb, _ := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	tok := iam.PlatformToken(fakeiam.PlatformUser{JKT: base64.RawURLEncoding.EncodeToString(thumb), ACR: access.ACRMFA})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/api/platform/v1/me", nil)
	req.Header.Set("Authorization", "DPoP "+tok)
	req.Header.Set("DPoP", dpopProof(t, key, "GET", "http://example.com/api/platform/v1/me", tok))
	r.ServeHTTP(w, req)
	if ch := w.Header().Get("WWW-Authenticate"); w.Code != 401 || !strings.HasPrefix(ch, `DPoP error="insufficient_user_authentication"`) {
		t.Fatalf("weak DPoP-bound sign-in: %d %q", w.Code, ch)
	}
}
