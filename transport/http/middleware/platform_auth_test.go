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
	"github.com/razatechofficial/mail-os/infrastructure/dpop"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

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
	pauth := &PlatformAuth{Verifier: v, DPoP: proofs}
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
