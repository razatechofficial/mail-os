// Package fakeiam is a stand-in for IAM in tests: it serves a discovery
// document and a JWKS, and signs access tokens and message signatures the
// way IAM does (at+jwt access tokens, mailos-msg+jwt message signatures,
// PS256 and ES256 keys with kid and alg). Tests never depend on a running
// IAM. The e2e harness runs it as a binary (e2e/cmd/fakeiam).
package fakeiam

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// Key is one signing key IAM publishes.
type Key struct {
	KID       string
	Algorithm jose.SignatureAlgorithm
	Signer    crypto.Signer
}

// IAM signs tokens and serves its keys.
type IAM struct {
	Issuer string
	// Keys are published in the JWKS; Keys[0] signs unless a token asks.
	Keys []Key
	// Unpublished keys sign but are absent from the JWKS (forgery tests).
	Unpublished Key
}

// New creates an IAM with a PS256 and an ES256 key for issuer.
func New(issuer string) *IAM {
	return &IAM{
		Issuer:      strings.TrimRight(issuer, "/"),
		Keys:        []Key{newKey(jose.PS256), newKey(jose.ES256)},
		Unpublished: newKey(jose.PS256),
	}
}

// NewServer starts IAM on an httptest server, closed at the end of the test.
func NewServer(t testing.TB) (*IAM, *httptest.Server) {
	t.Helper()
	f := &IAM{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.Handler().ServeHTTP(w, r) }))
	*f = *New(srv.URL)
	t.Cleanup(srv.Close)
	return f, srv
}

func newKey(alg jose.SignatureAlgorithm) Key {
	var signer crypto.Signer
	var err error
	switch alg {
	case jose.ES256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	return Key{KID: base64.RawURLEncoding.EncodeToString(sum[:]), Algorithm: alg, Signer: signer}
}

// JWKS is the published key set.
func (f *IAM) JWKS() jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{}
	for _, k := range f.Keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.Signer.Public(), KeyID: k.KID, Algorithm: string(k.Algorithm), Use: "sig"})
	}
	return set
}

// Handler serves discovery and the JWKS.
func (f *IAM) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"issuer": f.Issuer, "jwks_uri": f.Issuer + "/.well-known/jwks.json"})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, f.JWKS())
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Sign signs claims with key under typ.
func (f *IAM) Sign(key Key, typ string, claims map[string]any) string {
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader(jose.HeaderKey("kid"), key.KID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.Algorithm, Key: key.Signer}, opts)
	if err != nil {
		panic(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return out
}

// User describes a console user's access token.
type User struct {
	Subject  string // defaults to a new UUID
	Tenant   string
	Org      string
	Roles    []string
	ACR      string        // defaults to urn:iam:acr:mfa
	AuthAge  time.Duration // how long ago the user signed in (default 1 minute)
	Audience any           // defaults to "mailos"
	ClientID string        // defaults to "mailos-console"
	JKT      string        // cnf.jkt for a DPoP-bound token
	Extra    map[string]any
}

// UserToken signs a console user's access token.
func (f *IAM) UserToken(u User) string {
	now := time.Now()
	if u.Subject == "" {
		u.Subject = uuid.NewString()
	}
	if u.ACR == "" {
		u.ACR = "urn:iam:acr:mfa"
	}
	if u.AuthAge == 0 {
		u.AuthAge = time.Minute
	}
	if u.Audience == nil {
		u.Audience = "mailos"
	}
	if u.ClientID == "" {
		u.ClientID = "mailos-console"
	}
	claims := map[string]any{
		"iss": f.Issuer, "sub": u.Subject, "aud": u.Audience, "client_id": u.ClientID,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
		"auth_time": now.Add(-u.AuthAge).Unix(), "acr": u.ACR, "amr": []string{"pwd", "otp"},
		"sid": uuid.NewString(), "roles": u.Roles,
	}
	if u.Tenant != "" {
		claims["tid"] = u.Tenant
	}
	if u.Org != "" {
		claims["org_id"] = u.Org
	}
	if u.JKT != "" {
		claims["cnf"] = map[string]any{"jkt": u.JKT}
	}
	for k, v := range u.Extra {
		claims[k] = v
	}
	return f.Sign(f.Keys[0], "at+jwt", claims)
}

// ServiceToken signs a client-credentials token as IAM issues it for the
// mailos audience: sub "client:<id>", client_id, tid and org_id.
func (f *IAM) ServiceToken(clientID, tenant string) string {
	now := time.Now()
	claims := map[string]any{
		"iss": f.Issuer, "sub": "client:" + clientID, "client_id": clientID, "aud": "mailos",
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString(),
	}
	if tenant != "" {
		claims["tid"] = tenant
	}
	return f.Sign(f.Keys[1], "at+jwt", claims)
}

// MessageSignature signs the iam-msg-sig header for a pub/sub message
// (contract §2): typ mailos-msg+jwt, the topic and the SHA-256 of value.
func (f *IAM) MessageSignature(clientID, topic string, value []byte) string {
	now := time.Now()
	sum := sha256.Sum256(value)
	return f.Sign(f.Keys[0], "mailos-msg+jwt", map[string]any{
		"iss": f.Issuer, "aud": "mailos", "sub": clientID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": uuid.NewString(),
		"topic": topic, "body_sha256": base64.RawURLEncoding.EncodeToString(sum[:]),
	})
}
