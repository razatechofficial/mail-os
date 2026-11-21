//go:build e2e

package main

// OIDC provider mode (-oidc-client-id, -platform-oidc-client-id): enough of
// IAM's authorization server for the MailOS consoles' BFFs to sign in
// through it in their Playwright suites. It is deterministic: the user is
// the persona registered for the login_hint (POST /test/oidc/users, behind
// the mint token), with no login page. Authorization Code with PKCE (S256
// only), exact redirect URIs, one-time codes, rotating refresh tokens,
// userinfo, revocation, IAM's step-up route and an empty workspace list.
//
// Two kinds of client, as the IAM has (contract C1, C2):
//
//   - the tenant console's (-oidc-client-id): personas with a tid; access
//     tokens for aud "mailos" with tid, org_id and roles;
//   - the platform console's (-platform-oidc-client-id, kind platform_web):
//     only personas registered with "platform": true (no tid) sign in, a
//     workspace member gets error=access_denied; the authorization request
//     must name resource=mailos-platform (invalid_target otherwise, and the
//     tenant client may not name it); access tokens are platform tokens
//     (aud mailos-platform, no tid, org_id, act or roles), the id_token has
//     no tid, and refreshed tokens keep that shape.
//
//	GET  /oauth/authorize                       302 to redirect_uri?code&state&iss
//	POST /oauth/token                           authorization_code | refresh_token
//	GET  /oauth/userinfo                        the persona's profile
//	POST /oauth/revoke                          200 (RFC 7009)
//	GET  /oauth/logout                          302 to post_logout_redirect_uri
//	POST /api/v1/auth/step-up                   {"mfa_code":"000000"} -> {"access_token","expires_in"}
//	GET  /api/v1/oauth/clients/{id}/switchable-workspaces
//	POST /test/oidc/users                       {"login_hint","sub","tid","org_id","roles","acr","email","name","auth_age_seconds","platform"}

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

const (
	// StepUpCode is the authenticator code the step-up route accepts.
	stepUpCode   = "000000"
	codeLifetime = time.Minute
	tokenTTL     = 10 * time.Minute
)

type persona struct {
	LoginHint      string   `json:"login_hint"`
	Subject        string   `json:"sub"`
	Tenant         string   `json:"tid"`
	Org            string   `json:"org_id"`
	Roles          []string `json:"roles"`
	ACR            string   `json:"acr"`
	Email          string   `json:"email"`
	Name           string   `json:"name"`
	AuthAgeSeconds int64    `json:"auth_age_seconds"`
	// Platform marks a platform account (no tenant): the only persona the
	// platform console's client signs in.
	Platform bool `json:"platform"`
}

// client is one registered OIDC client.
type client struct {
	id         string
	secret     []byte
	redirects  []string
	logoutURIs []string
	// platform is a platform_web client (the platform console).
	platform bool
}

// platformOnlyDescription is the IAM's refusal of a workspace member at a
// platform application (contract C1).
const platformOnlyDescription = "only platform administrator accounts sign in to platform applications"

type grant struct {
	client      *client
	p           persona
	redirectURI string
	challenge   string
	nonce       string
	sid         string
	authTime    time.Time
	expires     time.Time
}

type provider struct {
	iam     *fakeiam.IAM
	clients map[string]*client

	mu       sync.Mutex
	personas map[string]persona
	codes    map[string]grant
	refresh  map[string]grant
}

func newProvider(iam *fakeiam.IAM) *provider {
	return &provider{iam: iam, clients: map[string]*client{}, personas: map[string]persona{}, codes: map[string]grant{}, refresh: map[string]grant{}}
}

// add registers a client.
func (o *provider) add(c *client) { o.clients[c.id] = c }

func (o *provider) mount(mux *http.ServeMux, m *minter) {
	mux.HandleFunc("GET /.well-known/openid-configuration", o.discovery)
	mux.HandleFunc("GET /oauth/authorize", o.authorize)
	mux.HandleFunc("GET /oauth/userinfo", o.userinfo)
	mux.HandleFunc("POST /oauth/revoke", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /oauth/logout", o.logout)
	mux.HandleFunc("POST /api/v1/auth/step-up", o.stepUp)
	mux.HandleFunc("GET /api/v1/oauth/clients/{id}/switchable-workspaces", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"workspaces": []any{}})
	})
	mux.HandleFunc("POST /test/oidc/users", m.guard(o.register))
}

func (o *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := o.iam.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": iss, "jwks_uri": iss + "/.well-known/jwks.json",
		"authorization_endpoint": iss + "/oauth/authorize", "token_endpoint": iss + "/oauth/token",
		"userinfo_endpoint": iss + "/oauth/userinfo", "revocation_endpoint": iss + "/oauth/revoke",
		"end_session_endpoint": iss + "/oauth/logout", "response_types_supported": []string{"code"},
		"code_challenge_methods_supported": []string{"S256"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (o *provider) register(w http.ResponseWriter, r *http.Request) {
	var p persona
	if !decode(w, r, &p) {
		return
	}
	switch {
	case p.LoginHint == "":
		writeError(w, http.StatusBadRequest, "login_hint is required")
		return
	case p.Platform && (p.Tenant != "" || p.Org != "" || len(p.Roles) > 0):
		writeError(w, http.StatusBadRequest, "a platform account has no tid, org_id or roles (ACS holds its roles)")
		return
	case !p.Platform && p.Tenant == "":
		writeError(w, http.StatusBadRequest, "tid is required (or platform: true)")
		return
	}
	if p.Subject == "" {
		p.Subject = uuid.NewString()
	}
	o.mu.Lock()
	o.personas[p.LoginHint] = p
	o.mu.Unlock()
	writeJSON(w, http.StatusOK, p)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// redirectError answers an authorization request with an OAuth error at
// the client's redirect URI (RFC 6749 §4.1.2.1).
func (o *provider) redirectError(w http.ResponseWriter, r *http.Request, redirect, state, code, desc string) {
	u, _ := url.Parse(redirect)
	rq := u.Query()
	rq.Set("error", code)
	rq.Set("error_description", desc)
	rq.Set("state", state)
	rq.Set("iss", o.iam.Issuer)
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (o *provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cl, ok := o.clients[q.Get("client_id")]
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	redirect := q.Get("redirect_uri")
	if !slices.Contains(cl.redirects, redirect) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered")
		return
	}
	if q.Get("response_type") != "code" || q.Get("state") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "response_type code, state and an S256 code_challenge are required")
		return
	}
	platformResource := slices.Contains(q["resource"], fakeiam.PlatformAudience)
	if cl.platform && (!platformResource || len(q["resource"]) != 1) {
		o.redirectError(w, r, redirect, q.Get("state"), "invalid_target", "a platform application requests resource=mailos-platform only")
		return
	}
	if !cl.platform && platformResource {
		o.redirectError(w, r, redirect, q.Get("state"), "invalid_target", "only a platform application may request a platform resource")
		return
	}
	o.mu.Lock()
	p, ok := o.personas[q.Get("login_hint")]
	o.mu.Unlock()
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_request", "no persona is registered for this login_hint")
		return
	}
	if cl.platform != p.Platform {
		desc := platformOnlyDescription
		if !cl.platform {
			desc = "a platform account has no workspace to sign in to"
		}
		o.redirectError(w, r, redirect, q.Get("state"), "access_denied", desc)
		return
	}
	auth := time.Now().Add(-time.Duration(p.AuthAgeSeconds) * time.Second)
	if q.Get("prompt") == "login" || q.Get("max_age") != "" {
		auth = time.Now()
	}
	code := randomToken()
	o.mu.Lock()
	o.codes[code] = grant{client: cl, p: p, redirectURI: redirect, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
		sid: uuid.NewString(), authTime: auth, expires: time.Now().Add(codeLifetime)}
	o.mu.Unlock()
	u, _ := url.Parse(redirect)
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	rq.Set("iss", o.iam.Issuer)
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// authenticated returns the client the request authenticates as.
func (o *provider) authenticated(r *http.Request) (*client, bool) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	cl, known := o.clients[id]
	if !known || subtle.ConstantTimeCompare([]byte(secret), cl.secret) != 1 {
		return nil, false
	}
	return cl, true
}

func (o *provider) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	cl, ok := o.authenticated(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	var g grant
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		o.mu.Lock()
		got, ok := o.codes[code]
		delete(o.codes, code) // one use, even when the exchange fails
		o.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case !ok || time.Now().After(got.expires) || got.client != cl:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired code")
			return
		case got.redirectURI != r.PostForm.Get("redirect_uri"):
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")
			return
		case base64.RawURLEncoding.EncodeToString(sum[:]) != got.challenge:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		g = got
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		o.mu.Lock()
		got, ok := o.refresh[rt]
		delete(o.refresh, rt) // rotation
		o.mu.Unlock()
		if !ok || got.client != cl {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
			return
		}
		g = got
		g.nonce = ""
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code or refresh_token")
		return
	}
	rt := randomToken()
	o.mu.Lock()
	o.refresh[rt] = g
	o.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": o.accessToken(g.client, g.p, g.authTime, g.sid), "id_token": o.idToken(g),
		"refresh_token": rt, "token_type": "Bearer", "expires_in": int(tokenTTL.Seconds()),
		"scope": "openid profile email offline_access",
	})
}

func (o *provider) accessToken(cl *client, p persona, authTime time.Time, sid string) string {
	if cl != nil && cl.platform {
		return o.iam.PlatformToken(fakeiam.PlatformUser{Subject: p.Subject, ACR: p.ACR, AuthAge: max(time.Since(authTime), time.Second),
			ClientID: cl.id, Email: p.Email, Extra: map[string]any{"sid": sid}})
	}
	return o.iam.UserToken(fakeiam.User{Subject: p.Subject, Tenant: p.Tenant, Org: p.Org, Roles: p.Roles, ACR: p.ACR,
		AuthAge: max(time.Since(authTime), time.Second), Extra: map[string]any{"sid": sid, "email": p.Email}})
}

func (o *provider) idToken(g grant) string {
	now := time.Now()
	acr := g.p.ACR
	if acr == "" {
		acr = "urn:iam:acr:mfa"
	}
	claims := map[string]any{
		"iss": o.iam.Issuer, "sub": g.p.Subject, "aud": g.client.id, "iat": now.Unix(), "exp": now.Add(tokenTTL).Unix(),
		"auth_time": g.authTime.Unix(), "acr": acr, "amr": []string{"pwd", "otp"}, "sid": g.sid,
		"email": g.p.Email, "email_verified": true, "name": g.p.Name,
	}
	if !g.p.Platform {
		claims["roles"], claims["tid"] = g.p.Roles, g.p.Tenant
	}
	if g.p.Org != "" {
		claims["org_id"] = g.p.Org
	}
	if g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	return o.iam.Sign(o.iam.Keys[0], "JWT", claims)
}

// bearer verifies a token this IAM signed and returns its claims.
func (o *provider) bearer(r *http.Request) (map[string]any, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, errors.New("no bearer token")
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.PS256, jose.ES256})
	if err != nil {
		return nil, err
	}
	for _, k := range o.iam.Keys {
		payload, err := jws.Verify(k.Signer.Public())
		if err != nil {
			continue
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			return nil, err
		}
		if exp, _ := claims["exp"].(float64); int64(exp) < time.Now().Unix() {
			return nil, errors.New("token expired")
		}
		return claims, nil
	}
	return nil, errors.New("signature does not verify")
}

func (o *provider) personaOf(claims map[string]any) (persona, bool) {
	sub, _ := claims["sub"].(string)
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, p := range o.personas {
		if p.Subject == sub {
			return p, true
		}
	}
	return persona{}, false
}

func (o *provider) userinfo(w http.ResponseWriter, r *http.Request) {
	claims, err := o.bearer(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	p, ok := o.personaOf(claims)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "unknown subject")
		return
	}
	given, family, _ := strings.Cut(p.Name, " ")
	info := map[string]any{"sub": p.Subject, "email": p.Email, "email_verified": true, "name": p.Name,
		"given_name": given, "family_name": family, "preferred_username": p.Email}
	if !p.Platform {
		info["tid"], info["org_id"] = p.Tenant, p.Org
	}
	writeJSON(w, http.StatusOK, info)
}

func (o *provider) logout(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("post_logout_redirect_uri")
	if !slices.ContainsFunc(o.clientList(), func(c *client) bool { return slices.Contains(c.logoutURIs, target) }) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "post_logout_redirect_uri is not registered")
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// stepUp is IAM's POST /api/v1/auth/step-up: a fresh access token for the
// bearer's user when the authenticator code is right.
func (o *provider) stepUp(w http.ResponseWriter, r *http.Request) {
	claims, err := o.bearer(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "UNAUTHORIZED", "message": err.Error()}})
		return
	}
	var body struct {
		Password string `json:"password"`
		MFACode  string `json:"mfa_code"`
	}
	if !decode(w, r, &body) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.MFACode), []byte(stepUpCode)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "INVALID_MFA_CODE", "message": "The code is not right"}})
		return
	}
	p, ok := o.personaOf(claims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "UNAUTHORIZED", "message": "unknown subject"}})
		return
	}
	sid, _ := claims["sid"].(string)
	clientID, _ := claims["client_id"].(string)
	writeJSON(w, http.StatusOK, map[string]any{"access_token": o.accessToken(o.clients[clientID], p, time.Now(), sid), "expires_in": int(tokenTTL.Seconds())})
}

func (o *provider) clientList() []*client {
	out := make([]*client, 0, len(o.clients))
	for _, c := range o.clients {
		out = append(out, c)
	}
	return out
}

func randomToken() string {
	return strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
}
