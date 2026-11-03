package mailer

import (
	"context"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is defined as the SHA-1 thumbprint (RFC 7515 §4.1.7)
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// Identity platforms, as pseudo-kinds: the Provider of their token errors
// and the BaseURLs keys that override their endpoints in tests.
const (
	oauthMicrosoft = "microsoft_entra"
	oauthGoogle    = "google_oauth"
)

// OAuth scopes MailOS asks for.
const (
	scopeGraph       = "/.default" // appended to the Graph host
	scopeOutlookSMTP = "https://outlook.office365.com/.default"
	scopeGmailSend   = "https://www.googleapis.com/auth/gmail.send"
	scopeGmailSMTP   = "https://mail.google.com/"
)

// tokenSource returns an OAuth 2.0 access token, cached until shortly
// before it expires.
type tokenSource struct {
	// platform is oauthMicrosoft or oauthGoogle; label names it in steps.
	platform string
	label    string
	fetch    func(ctx context.Context) (token string, ttl time.Duration, err error)

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Token returns a valid token, fetching one when needed.
func (t *tokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && time.Now().Before(t.expires) {
		return t.token, nil
	}
	tok, ttl, err := t.fetch(ctx)
	if err != nil {
		return "", err
	}
	// Refresh a minute early so a token never expires mid-send.
	t.token, t.expires = tok, time.Now().Add(max(ttl-time.Minute, 30*time.Second))
	return tok, nil
}

// Invalidate drops the cached token (the provider refused it).
func (t *tokenSource) Invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}

// step fetches a token as a probe step and warns when the token lacks the
// application permission sending needs (role "" skips the check).
func (t *tokenSource) step(ctx context.Context, p *Probe, role string) (string, error) {
	var tok string
	err := p.Step("token", "Get an access token from "+t.label, func() (string, error) {
		t.Invalidate() // a test always proves the credentials afresh
		var err error
		if tok, err = t.Token(ctx); err != nil {
			return "", err
		}
		return "token issued", nil
	})
	if err == nil && role != "" {
		if roles, ok := tokenRoles(tok); ok && !slices.Contains(roles, role) {
			p.Warn("The token has no " + role + " application permission. Add it to the app registration and grant admin consent, or sending will be refused.")
		}
	}
	return tok, err
}

// tokenRoles reads the roles claim of a JWT access token without
// verifying it (it is only advice to the administrator).
func tokenRoles(tok string) ([]string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var c struct {
		Roles []string `json:"roles"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return nil, false
	}
	return c.Roles, true
}

// tokenResponse is RFC 6749 §5.1, with Entra ID's error codes.
type tokenResponse struct {
	AccessToken      string          `json:"access_token"`
	ExpiresIn        json.RawMessage `json:"expires_in"`
	Error            string          `json:"error"`
	ErrorDescription string          `json:"error_description"`
	ErrorCodes       []int           `json:"error_codes"`
}

func (r tokenResponse) ttl() time.Duration {
	s := strings.Trim(string(r.ExpiresIn), `"`)
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(n) * time.Second
}

// requestToken posts a token request and classifies the OAuth error.
func requestToken(ctx context.Context, api *httpAPI, platform, tokenURL string, form url.Values) (string, time.Duration, error) {
	data, _, err := api.post(ctx, request{
		url: tokenURL, contentType: "application/x-www-form-urlencoded", body: []byte(form.Encode()),
		classify: func(e *message.SendError, body []byte, _ http.Header) { classifyOAuth(e, body) },
	})
	if err != nil {
		if se, ok := message.AsSendError(err); ok {
			se.Provider = platform
		}
		return "", 0, err
	}
	var r tokenResponse
	if json.Unmarshal(data, &r) != nil || r.AccessToken == "" {
		return "", 0, message.NewSendError(platform, message.ReasonUnavailable, http.StatusOK, "the token endpoint returned no access token")
	}
	return r.AccessToken, r.ttl(), nil
}

// Entra ID error codes that mean the tenant or application is wrong
// rather than the credential.
var entraConfigCodes = map[int]bool{
	90002:  true, // tenant not found
	900023: true, // tenant identifier is not valid
	700016: true, // application not found in the directory
	90014:  true, // a required field is missing
	70011:  true, // scope is not valid
	500011: true, // resource principal not found (Exchange Online not in tenant)
}

// classifyOAuth refines a token endpoint failure (RFC 6749 §5.2).
func classifyOAuth(e *message.SendError, body []byte) {
	var r tokenResponse
	if json.Unmarshal(body, &r) != nil || r.Error == "" {
		return
	}
	desc, _, _ := strings.Cut(r.ErrorDescription, "\r\n") // drop Entra's trace and correlation ids
	e.Detail = r.Error
	if desc != "" {
		e.Detail += ": " + truncate(desc, 240)
	}
	switch r.Error {
	case "invalid_client", "unauthorized_client", "invalid_grant", "access_denied":
		e.Reason = message.ReasonAuth
		if r.Error == "invalid_grant" && strings.Contains(r.ErrorDescription, "Invalid email or User ID") {
			e.Reason = message.ReasonConfig
		}
	case "invalid_scope", "invalid_resource":
		e.Reason = message.ReasonConfig
	case "invalid_request":
		e.Reason = message.ReasonAuth
	case "temporarily_unavailable", "server_error":
		e.Reason = message.ReasonUnavailable
	}
	for _, c := range r.ErrorCodes {
		if entraConfigCodes[c] {
			e.Reason = message.ReasonConfig
		}
	}
}

// microsoftTokens returns the client credentials flow of an Entra ID
// application, with a client secret or a certificate assertion
// (RFC 7523), for scope.
func microsoftTokens(kind provider.Kind, s provider.Settings, c provider.Credentials, scope string, opts Options) (*tokenSource, error) {
	invalid := func(d string) error { return message.NewSendError(string(kind), message.ReasonConfig, 0, d) }
	if s.TenantID == "" || s.ClientID == "" {
		return nil, invalid("the tenant ID and client ID are required")
	}
	loginHost, _ := s.MicrosoftEndpoints()
	base, err := opts.baseURL(oauthMicrosoft, loginHost)
	if err != nil {
		return nil, err
	}
	tokenURL := base + "/" + url.PathEscape(s.TenantID) + "/oauth2/v2.0/token"
	form := url.Values{"client_id": {s.ClientID}, "scope": {scope}, "grant_type": {"client_credentials"}}
	var assertion func() (string, error)
	switch s.AuthMethod {
	case provider.MicrosoftCertificate:
		certs, err := provider.ParseCertificates(s.ClientCertificate)
		if err != nil {
			return nil, invalid("the application certificate cannot be read")
		}
		key, err := provider.ParsePrivateKey(c.CertificateKey)
		rsaKey, ok := key.(*rsa.PrivateKey)
		if err != nil || !ok {
			return nil, invalid("the certificate's private key must be an RSA key")
		}
		assertion = microsoftAssertion(certs[0].Raw, rsaKey, s.ClientID, tokenURL)
	default:
		if c.ClientSecret == "" {
			return nil, invalid("the client secret is required")
		}
		form.Set("client_secret", c.ClientSecret)
	}
	api := newHTTPAPI(kind, opts)
	return &tokenSource{platform: oauthMicrosoft, label: "Microsoft Entra ID", fetch: func(ctx context.Context) (string, time.Duration, error) {
		f := url.Values{}
		for k, v := range form {
			f[k] = v
		}
		if assertion != nil {
			a, err := assertion()
			if err != nil {
				return "", 0, message.NewSendError(oauthMicrosoft, message.ReasonConfig, 0, "the certificate assertion cannot be signed")
			}
			f.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
			f.Set("client_assertion", a)
		}
		return requestToken(ctx, api, oauthMicrosoft, tokenURL, f)
	}}, nil
}

// microsoftAssertion signs a client assertion: RS256 with the
// certificate's thumbprints in x5t and x5t#S256.
func microsoftAssertion(certDER []byte, key *rsa.PrivateKey, clientID, aud string) func() (string, error) {
	sha1Sum := sha1.Sum(certDER) //nolint:gosec // thumbprint, not a security hash
	sha256Sum := sha256.Sum256(certDER)
	return func() (string, error) {
		so := (&jose.SignerOptions{}).WithType("JWT").
			WithHeader("x5t", base64.RawURLEncoding.EncodeToString(sha1Sum[:])).
			WithHeader("x5t#S256", base64.RawURLEncoding.EncodeToString(sha256Sum[:]))
		now := time.Now()
		return signJWT(key, so, map[string]any{
			"aud": aud, "iss": clientID, "sub": clientID, "jti": id.New(),
			"nbf": now.Unix(), "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		})
	}
}

func signJWT(key *rsa.PrivateKey, so *jose.SignerOptions, claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, so)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// googleTokens returns the JWT bearer flow (RFC 7523) of a service account
// acting as subject through domain-wide delegation, for scope.
func googleTokens(kind provider.Kind, keyFile, subject, scope string, opts Options) (*tokenSource, error) {
	invalid := func(d string) error { return message.NewSendError(string(kind), message.ReasonConfig, 0, d) }
	sa, problem := provider.ParseServiceAccount(keyFile)
	if problem != "" {
		return nil, invalid("the service account key file " + problem)
	}
	key, _ := provider.ParsePrivateKey(sa.PrivateKey)
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, invalid("the service account key must be an RSA key")
	}
	if subject == "" {
		return nil, invalid("the sending user is required")
	}
	base, err := opts.baseURL(oauthGoogle, "https://oauth2.googleapis.com")
	if err != nil {
		return nil, err
	}
	tokenURL := base + "/token"
	api := newHTTPAPI(kind, opts)
	return &tokenSource{platform: oauthGoogle, label: "Google (" + sa.ClientEmail + ")", fetch: func(ctx context.Context) (string, time.Duration, error) {
		now := time.Now()
		so := (&jose.SignerOptions{}).WithType("JWT")
		if sa.PrivateKeyID != "" {
			so = so.WithHeader("kid", sa.PrivateKeyID)
		}
		a, err := signJWT(rsaKey, so, map[string]any{
			"iss": sa.ClientEmail, "sub": subject, "scope": scope, "aud": provider.GoogleTokenURI,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		if err != nil {
			return "", 0, message.NewSendError(oauthGoogle, message.ReasonConfig, 0, "the service account assertion cannot be signed")
		}
		return requestToken(ctx, api, oauthGoogle, tokenURL, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {a},
		})
	}}, nil
}
