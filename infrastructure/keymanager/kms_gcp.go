package keymanager

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/config"
)

// Google Cloud KMS endpoints and the OAuth scope its calls need.
const (
	gcpKMSEndpoint      = "https://cloudkms.googleapis.com"
	gcpMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	gcpKMSScope         = "https://www.googleapis.com/auth/cloudkms"
)

// gcpKeyName is a CryptoKey (not a version: decrypt finds the version in
// the ciphertext, so the key's own rotation needs nothing from MailOS).
var gcpKeyName = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)

// GCPKMS is Google Cloud KMS as a RemoteKEKService. A data key is
// encrypted under a symmetric ENCRYPT_DECRYPT CryptoKey with its kid as
// additionalAuthenticatedData, so it opens for no other kid.
type GCPKMS struct {
	api      *remoteAPI
	endpoint string
}

var _ RemoteKEKService = (*GCPKMS)(nil)

// GCPKMSOptions builds a GCPKMS. Without CredentialsJSON the token comes
// from MetadataURL (the GCE/GKE metadata server).
type GCPKMSOptions struct {
	Endpoint        string
	CredentialsJSON []byte
	MetadataURL     string
	Client          *http.Client
}

// OpenGCPKMS reads the service-account key (KEY_MANAGER_GCP_KMS_CREDENTIALS_FILE,
// else GOOGLE_APPLICATION_CREDENTIALS) or falls back to the metadata server.
func OpenGCPKMS(_ context.Context, cfg config.KeyManagerGCPKMS) (*GCPKMS, error) {
	opts := GCPKMSOptions{Endpoint: cfg.Endpoint}
	file := cfg.CredentialsFile
	if file == "" {
		file = os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	}
	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("gcp kms: read credentials: %w", err)
		}
		opts.CredentialsJSON = raw
	}
	return NewGCPKMS(opts)
}

// NewGCPKMS returns the service.
func NewGCPKMS(o GCPKMSOptions) (*GCPKMS, error) {
	client := o.Client
	if client == nil {
		client = defaultRemoteClient()
	}
	endpoint := strings.TrimRight(o.Endpoint, "/")
	if endpoint == "" {
		endpoint = gcpKMSEndpoint
	}
	var fetch func(context.Context) (string, time.Duration, error)
	if len(o.CredentialsJSON) > 0 {
		sa, err := parseServiceAccount(o.CredentialsJSON)
		if err != nil {
			return nil, err
		}
		fetch = func(ctx context.Context) (string, time.Duration, error) { return sa.token(ctx, client) }
	} else {
		meta := o.MetadataURL
		if meta == "" {
			meta = gcpMetadataTokenURL
		}
		fetch = func(ctx context.Context) (string, time.Duration, error) {
			var tok oauthToken
			_, err := doJSON(ctx, client, "gcp metadata", http.MethodGet, meta,
				func(h http.Header) { h.Set("Metadata-Flavor", "Google") }, nil, &tok)
			return tok.AccessToken, tok.ttl(), err
		}
	}
	return &GCPKMS{
		endpoint: endpoint,
		api: &remoteAPI{service: "gcp kms", client: client, tokens: newTokenCache(fetch),
			auth: func(h http.Header, tok string) { h.Set("Authorization", "Bearer "+tok) }},
	}, nil
}

// gcpServiceAccount is the part of a service-account JSON key used.
type gcpServiceAccount struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
	key          *rsa.PrivateKey
}

func parseServiceAccount(raw []byte) (*gcpServiceAccount, error) {
	var sa gcpServiceAccount
	if err := json.Unmarshal(raw, &sa); err != nil {
		return nil, errors.New("gcp kms: credentials are not a service-account JSON key")
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("gcp kms: credentials are not a service-account key")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	if u, err := url.Parse(sa.TokenURI); err != nil || u.Scheme != "https" {
		return nil, errors.New("gcp kms: the service account's token_uri must be https")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("gcp kms: the service account's private key is not PEM")
	}
	var key any
	var err error
	if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	rk, ok := key.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("gcp kms: the service account's private key is not an RSA key")
	}
	sa.key = rk
	return &sa, nil
}

// token exchanges a signed JWT assertion for an access token (RFC 7523).
func (sa *gcpServiceAccount) token(ctx context.Context, client *http.Client) (string, time.Duration, error) {
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": sa.PrivateKeyID})
	claims, _ := json.Marshal(map[string]any{
		"iss": sa.ClientEmail, "scope": gcpKMSScope, "aud": sa.TokenURI,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	b64 := base64.RawURLEncoding.EncodeToString
	signing := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, sa.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", 0, fmt.Errorf("sign assertion: %w", err)
	}
	var tok oauthToken
	_, err = postForm(ctx, client, "gcp oauth", sa.TokenURI, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signing + "." + b64(sig)},
	}, &tok)
	return tok.AccessToken, tok.ttl(), err
}

func (g *GCPKMS) keyURL(name, verb string) (string, error) {
	if !gcpKeyName.MatchString(name) {
		return "", fmt.Errorf("gcp kms: %q is not a CryptoKey name (projects/…/locations/…/keyRings/…/cryptoKeys/…)", name)
	}
	return g.endpoint + "/v1/" + name + verb, nil
}

// Resolve checks the CryptoKey is for encryption and its primary version
// is enabled; the key's resource name is its stable name.
func (g *GCPKMS) Resolve(ctx context.Context, keyID string) (string, error) {
	u, err := g.keyURL(keyID, "")
	if err != nil {
		return "", err
	}
	var key struct {
		Name    string `json:"name"`
		Purpose string `json:"purpose"`
		Primary *struct {
			State string `json:"state"`
		} `json:"primary"`
	}
	if err := g.api.call(ctx, http.MethodGet, u, nil, &key); err != nil {
		return "", fmt.Errorf("gcp kms: key-encryption key %q: %w", keyID, err)
	}
	switch {
	case key.Purpose != "ENCRYPT_DECRYPT":
		return "", fmt.Errorf("gcp kms: key-encryption key %q is not a symmetric encryption key", keyID)
	case key.Primary == nil || key.Primary.State != "ENABLED":
		return "", fmt.Errorf("gcp kms: key-encryption key %q has no enabled primary version", keyID)
	}
	if key.Name != "" && key.Name != keyID {
		return "", fmt.Errorf("gcp kms: key-encryption key %q answered as %q", keyID, key.Name)
	}
	return keyID, nil
}

// Encrypt encrypts a data key under the CryptoKey's primary version.
func (g *GCPKMS) Encrypt(ctx context.Context, keyID string, plain, aad []byte) ([]byte, error) {
	u, err := g.keyURL(keyID, ":encrypt")
	if err != nil {
		return nil, err
	}
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	in := map[string]string{
		"plaintext":                   base64.StdEncoding.EncodeToString(plain),
		"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad),
	}
	if err := g.api.call(ctx, http.MethodPost, u, in, &out); err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(out.Ciphertext)
	if err != nil {
		return nil, errors.New("gcp kms: ciphertext is not base64")
	}
	return ct, nil
}

// Decrypt opens a data key; KMS refuses it under another key or aad.
func (g *GCPKMS) Decrypt(ctx context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	u, err := g.keyURL(keyID, ":decrypt")
	if err != nil {
		return nil, err
	}
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	in := map[string]string{
		"ciphertext":                  base64.StdEncoding.EncodeToString(ciphertext),
		"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad),
	}
	if err := g.api.call(ctx, http.MethodPost, u, in, &out); err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, errors.New("gcp kms: plaintext is not base64")
	}
	return pt, nil
}
