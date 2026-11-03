package mailer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// rsaCert is a self-signed RSA certificate and its key, as PEM.
type rsaCert struct {
	certPEM, keyPEM string
	key             *rsa.PrivateKey
	der             []byte
}

func newRSACert(t *testing.T, cn string) rsaCert {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return rsaCert{
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		key:     key, der: der,
	}
}

// fakeJWT is an unsigned token with claims, for the roles check.
func fakeJWT(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func serviceAccountJSON(t *testing.T, c rsaCert) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "mailos@bank-proj.iam.gserviceaccount.com",
		"private_key_id": "kid-1", "private_key": c.keyPEM, "token_uri": provider.GoogleTokenURI})
	return string(raw)
}

func TestMicrosoftTokenWithSecretIsCached(t *testing.T) {
	srv := newAPIServer(t)
	var calls atomic.Int32
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		if r.URL.Path != "/contoso.example/oauth2/v2.0/token" || r.Form.Get("client_secret") != "s3cret" ||
			r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != scopeOutlookSMTP {
			t.Errorf("%s %v", r.URL.Path, r.Form)
		}
		reply(200, `{"access_token":"tok","expires_in":3599,"token_type":"Bearer"}`)(w, r)
	})
	opts := srv.opts(oauthMicrosoft)
	ts, err := microsoftTokens(provider.KindSMTP, provider.Settings{TenantID: "contoso.example", ClientID: "app", AuthMethod: provider.MicrosoftSecret},
		provider.Credentials{ClientSecret: "s3cret"}, scopeOutlookSMTP, opts)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if tok, err := ts.Token(context.Background()); err != nil || tok != "tok" {
			t.Fatalf("%q %v", tok, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("token fetched %d times", calls.Load())
	}
	ts.Invalidate()
	_, _ = ts.Token(context.Background())
	if calls.Load() != 2 {
		t.Fatal("invalidate kept the token")
	}
}

func TestMicrosoftTokenWithCertificateAssertion(t *testing.T) {
	cert := newRSACert(t, "mailos-app")
	srv := newAPIServer(t)
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "" || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			t.Errorf("form %v", r.Form)
		}
		jws, err := jose.ParseSigned(r.Form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := jws.Verify(&cert.key.PublicKey)
		if err != nil {
			t.Fatalf("assertion not signed by the certificate key: %v", err)
		}
		sum := sha256.Sum256(cert.der)
		if jws.Signatures[0].Protected.ExtraHeaders["x5t#S256"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
			t.Errorf("thumbprint header %v", jws.Signatures[0].Protected.ExtraHeaders)
		}
		var c map[string]any
		_ = json.Unmarshal(payload, &c)
		if c["iss"] != "app-id" || c["sub"] != "app-id" || !strings.HasSuffix(c["aud"].(string), "/tenant-id/oauth2/v2.0/token") {
			t.Errorf("claims %v", c)
		}
		reply(200, `{"access_token":"cert-tok","expires_in":"3600"}`)(w, r)
	})
	ts, err := microsoftTokens(provider.KindMSGraph, provider.Settings{TenantID: "tenant-id", ClientID: "app-id",
		AuthMethod: provider.MicrosoftCertificate, ClientCertificate: cert.certPEM},
		provider.Credentials{CertificateKey: cert.keyPEM}, "https://graph.microsoft.com/.default", srv.opts(oauthMicrosoft))
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ts.Token(context.Background()); err != nil || tok != "cert-tok" {
		t.Fatalf("%q %v", tok, err)
	}
}

func TestOAuthErrorsAreClassified(t *testing.T) {
	cases := []struct {
		body string
		want message.Reason
	}{
		{`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x","error_codes":[7000215]}`, message.ReasonAuth},
		{`{"error":"invalid_request","error_description":"AADSTS90002: Tenant 'x' not found.","error_codes":[90002]}`, message.ReasonConfig},
		{`{"error":"unauthorized_client","error_description":"AADSTS700016: Application not found in the directory.","error_codes":[700016]}`, message.ReasonConfig},
		{`{"error":"invalid_scope","error_description":"bad scope"}`, message.ReasonConfig},
	}
	srv := newAPIServer(t)
	for i, c := range cases {
		srv.handle(reply(400, c.body))
		ts, _ := microsoftTokens(provider.KindMSGraph, provider.Settings{TenantID: "t", ClientID: "c"}, provider.Credentials{ClientSecret: "s"},
			"scope", srv.opts(oauthMicrosoft))
		_, err := ts.Token(context.Background())
		se := sendErr(t, err)
		if se.Reason != c.want || se.Provider != oauthMicrosoft || strings.Contains(se.Detail, "Trace ID") {
			t.Errorf("case %d: %+v", i, se)
		}
	}
}

func TestGoogleJWTBearer(t *testing.T) {
	cert := newRSACert(t, "sa")
	srv := newAPIServer(t)
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/token" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("%s %v", r.URL.Path, r.Form)
		}
		jws, err := jose.ParseSigned(r.Form.Get("assertion"), []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := jws.Verify(&cert.key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		var c map[string]any
		_ = json.Unmarshal(payload, &c)
		if c["sub"] != "noreply@bank.example" || c["scope"] != scopeGmailSend || c["aud"] != provider.GoogleTokenURI ||
			jws.Signatures[0].Header.KeyID != "kid-1" {
			t.Errorf("claims %v", c)
		}
		if c["sub"] == "ghost@bank.example" {
			reply(400, `{"error":"invalid_grant","error_description":"Invalid email or User ID"}`)(w, r)
			return
		}
		reply(200, `{"access_token":"g-tok","expires_in":3599}`)(w, r)
	})
	ts, err := googleTokens(provider.KindGmail, serviceAccountJSON(t, cert), "noreply@bank.example", scopeGmailSend, srv.opts(oauthGoogle))
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ts.Token(context.Background()); err != nil || tok != "g-tok" {
		t.Fatalf("%q %v", tok, err)
	}
	srv.handle(reply(401, `{"error":"unauthorized_client","error_description":"Client is unauthorized to retrieve access tokens using this method."}`))
	ts.Invalidate()
	_, err = ts.Token(context.Background())
	if se := sendErr(t, err); se.Reason != message.ReasonAuth || se.Provider != oauthGoogle {
		t.Fatalf("%+v", se)
	}
	if _, err := googleTokens(provider.KindGmail, `{"type":"authorized_user"}`, "a@b.example", scopeGmailSend, srv.opts(oauthGoogle)); err == nil {
		t.Fatal("a user credential was accepted as a service account")
	}
}

func TestTokenRolesWarning(t *testing.T) {
	srv := newAPIServer(t)
	srv.handle(reply(200, `{"access_token":"`+fakeJWT(map[string]any{"roles": []string{"User.Read.All"}})+`","expires_in":3600}`))
	ts, _ := microsoftTokens(provider.KindMSGraph, provider.Settings{TenantID: "t", ClientID: "c"}, provider.Credentials{ClientSecret: "s"},
		"scope", srv.opts(oauthMicrosoft))
	p := &Probe{}
	if _, err := ts.step(context.Background(), p, "Mail.Send"); err != nil {
		t.Fatal(err)
	}
	if len(p.warnings) != 1 || !strings.Contains(p.warnings[0], "Mail.Send") || len(p.steps) != 1 || p.steps[0].Name != "token" {
		t.Fatalf("%+v %+v", p.steps, p.warnings)
	}
}
