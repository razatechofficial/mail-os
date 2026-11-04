package keymanager

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/config"
)

// Azure Key Vault API version, the instance metadata token endpoint and
// the wrapping algorithm.
const (
	azureAPIVersion  = "7.4"
	azureIMDSToken   = "http://169.254.169.254/metadata/identity/oauth2/token"
	azureWrapAlg     = "RSA-OAEP-256"
	azureVaultScope  = "https://vault.azure.net"
	azureMHSMScope   = "https://managedhsm.azure.net"
	azureDefaultAuth = "https://login.microsoftonline.com"
)

var azureSegment = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)

// AzureKeyVault is Azure Key Vault (or Managed HSM) as a RemoteKEKService.
// A data key is wrapped with wrapKey RSA-OAEP-256 under an RSA key. Key
// wrapping takes no additional data, so the wrapped value is
// SHA-256(aad) || data key and unwrapping checks the hash: a data key
// opens for no other kid. The key version that wrapped it is stored with
// it ("<version>:<ciphertext>"), so a key rotated in the vault still
// opens older data keys and the KEK id (the versionless key URL) stays.
type AzureKeyVault struct {
	api   *remoteAPI
	vault string
}

var _ RemoteKEKService = (*AzureKeyVault)(nil)

// AzureKeyVaultOptions builds an AzureKeyVault. With ClientSecret the
// token is an Entra ID client-credentials token; otherwise it is the
// managed identity's, from IMDSURL.
type AzureKeyVaultOptions struct {
	VaultURL      string
	TenantID      string
	ClientID      string
	ClientSecret  string
	AuthorityHost string
	IMDSURL       string
	Client        *http.Client
}

// OpenAzureKeyVault reads the client secret (file) and builds the service.
func OpenAzureKeyVault(_ context.Context, cfg config.KeyManagerAzureKeyVault) (*AzureKeyVault, error) {
	secret, err := readSecret(cfg.ClientSecret, cfg.ClientSecretFile, "KEY_MANAGER_AZURE_CLIENT_SECRET_FILE")
	if err != nil {
		return nil, fmt.Errorf("azure key vault: %w", err)
	}
	return NewAzureKeyVault(AzureKeyVaultOptions{
		VaultURL: cfg.VaultURL, TenantID: cfg.TenantID, ClientID: cfg.ClientID,
		ClientSecret: secret, AuthorityHost: cfg.AuthorityHost,
	})
}

// NewAzureKeyVault returns the service.
func NewAzureKeyVault(o AzureKeyVaultOptions) (*AzureKeyVault, error) {
	vault := strings.TrimRight(strings.TrimSpace(o.VaultURL), "/")
	u, err := url.Parse(vault)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("azure key vault: the vault URL must be https://<name>.vault.azure.net")
	}
	client := o.Client
	if client == nil {
		client = defaultRemoteClient()
	}
	resource := azureVaultScope
	if strings.HasSuffix(u.Hostname(), ".managedhsm.azure.net") {
		resource = azureMHSMScope
	}
	var fetch func(context.Context) (string, time.Duration, error)
	if o.ClientSecret != "" {
		if o.TenantID == "" || o.ClientID == "" {
			return nil, errors.New("azure key vault: a client secret needs the tenant and client ids")
		}
		authority := strings.TrimRight(o.AuthorityHost, "/")
		if authority == "" {
			authority = azureDefaultAuth
		}
		tokenURL := authority + "/" + url.PathEscape(o.TenantID) + "/oauth2/v2.0/token"
		form := url.Values{
			"grant_type": {"client_credentials"}, "client_id": {o.ClientID},
			"client_secret": {o.ClientSecret}, "scope": {resource + "/.default"},
		}
		fetch = func(ctx context.Context) (string, time.Duration, error) {
			var tok oauthToken
			_, err := postForm(ctx, client, "azure entra id", tokenURL, form, &tok)
			return tok.AccessToken, tok.ttl(), err
		}
	} else {
		imds := o.IMDSURL
		if imds == "" {
			imds = azureIMDSToken
		}
		q := url.Values{"api-version": {"2018-02-01"}, "resource": {resource}}
		if o.ClientID != "" {
			q.Set("client_id", o.ClientID) // a user-assigned identity
		}
		tokenURL := imds + "?" + q.Encode()
		fetch = func(ctx context.Context) (string, time.Duration, error) {
			var tok oauthToken
			_, err := doJSON(ctx, client, "azure managed identity", http.MethodGet, tokenURL,
				func(h http.Header) { h.Set("Metadata", "true") }, nil, &tok)
			return tok.AccessToken, tok.ttl(), err
		}
	}
	return &AzureKeyVault{
		vault: vault,
		api: &remoteAPI{service: "azure key vault", client: client, tokens: newTokenCache(fetch),
			auth: func(h http.Header, tok string) { h.Set("Authorization", "Bearer "+tok) }},
	}, nil
}

// keyURL is the key's URL in this vault: keyID is "name", "name/version"
// or a key URL of this vault (what Resolve returns).
func (a *AzureKeyVault) keyURL(keyID string) (base, version string, err error) {
	ref := strings.TrimPrefix(keyID, a.vault+"/keys/")
	parts := strings.Split(ref, "/")
	if len(parts) > 2 || !azureSegment.MatchString(parts[0]) || (len(parts) == 2 && !azureSegment.MatchString(parts[1])) {
		return "", "", fmt.Errorf("azure key vault: %q is not a key of %s", keyID, a.vault)
	}
	if len(parts) == 2 {
		version = parts[1]
	}
	return a.vault + "/keys/" + parts[0], version, nil
}

func withAPIVersion(u string) string { return u + "?api-version=" + azureAPIVersion }

// Resolve checks the key is an enabled RSA key that may wrap and unwrap,
// and returns its URL: versionless unless keyID named a version.
func (a *AzureKeyVault) Resolve(ctx context.Context, keyID string) (string, error) {
	base, version, err := a.keyURL(keyID)
	if err != nil {
		return "", err
	}
	u := base
	if version != "" {
		u += "/" + version
	}
	var bundle struct {
		Key struct {
			Kid    string   `json:"kid"`
			Kty    string   `json:"kty"`
			KeyOps []string `json:"key_ops"`
		} `json:"key"`
		Attributes struct {
			Enabled bool `json:"enabled"`
		} `json:"attributes"`
	}
	if err := a.api.call(ctx, http.MethodGet, withAPIVersion(u), nil, &bundle); err != nil {
		return "", fmt.Errorf("azure key vault: key-encryption key %q: %w", keyID, err)
	}
	switch {
	case !bundle.Attributes.Enabled:
		return "", fmt.Errorf("azure key vault: key-encryption key %q is disabled", keyID)
	case bundle.Key.Kty != "RSA" && bundle.Key.Kty != "RSA-HSM":
		return "", fmt.Errorf("azure key vault: key-encryption key %q is not an RSA key", keyID)
	case !slices.Contains(bundle.Key.KeyOps, "wrapKey") || !slices.Contains(bundle.Key.KeyOps, "unwrapKey"):
		return "", fmt.Errorf("azure key vault: key-encryption key %q may not wrap and unwrap keys", keyID)
	case !strings.HasPrefix(bundle.Key.Kid, base+"/"):
		return "", fmt.Errorf("azure key vault: key-encryption key %q answered as another key", keyID)
	}
	return u, nil
}

// boundKey is what is wrapped: the kid's hash, then the data key.
func boundKey(plain, aad []byte) []byte {
	sum := sha256.Sum256(aad)
	return append(sum[:], plain...)
}

// Encrypt wraps a data key, prefixing the version that wrapped it.
func (a *AzureKeyVault) Encrypt(ctx context.Context, keyID string, plain, aad []byte) ([]byte, error) {
	base, version, err := a.keyURL(keyID)
	if err != nil {
		return nil, err
	}
	u := base
	if version != "" {
		u += "/" + version
	}
	in := map[string]string{"alg": azureWrapAlg, "value": base64.RawURLEncoding.EncodeToString(boundKey(plain, aad))}
	var out struct {
		Kid   string `json:"kid"`
		Value string `json:"value"`
	}
	if err := a.api.call(ctx, http.MethodPost, withAPIVersion(u+"/wrapkey"), in, &out); err != nil {
		return nil, err
	}
	used := strings.TrimPrefix(out.Kid, base+"/")
	if used == out.Kid || !azureSegment.MatchString(used) {
		return nil, errors.New("azure key vault: wrapKey did not name the key version it used")
	}
	ct, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(out.Value, "="))
	if err != nil || len(ct) == 0 {
		return nil, errors.New("azure key vault: wrapped key is not base64url")
	}
	return append([]byte(used+":"), ct...), nil
}

// Decrypt unwraps a data key with the version that wrapped it and checks
// it was wrapped for this aad.
func (a *AzureKeyVault) Decrypt(ctx context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	base, _, err := a.keyURL(keyID)
	if err != nil {
		return nil, err
	}
	version, ct, ok := strings.Cut(string(ciphertext), ":")
	if !ok || !azureSegment.MatchString(version) || ct == "" {
		return nil, errors.New("azure key vault: wrapped key has no key version")
	}
	in := map[string]string{"alg": azureWrapAlg, "value": base64.RawURLEncoding.EncodeToString([]byte(ct))}
	var out struct {
		Value string `json:"value"`
	}
	if err := a.api.call(ctx, http.MethodPost, withAPIVersion(base+"/"+version+"/unwrapkey"), in, &out); err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(out.Value, "="))
	if err != nil {
		return nil, errors.New("azure key vault: unwrapped key is not base64url")
	}
	sum := sha256.Sum256(aad)
	if len(raw) <= len(sum) || subtle.ConstantTimeCompare(raw[:len(sum)], sum[:]) != 1 {
		clear(raw)
		return nil, errors.New("azure key vault: data key was wrapped for another key id")
	}
	return raw[len(sum):], nil
}
