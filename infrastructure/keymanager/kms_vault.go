package keymanager

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/config"
)

var (
	vaultKeyName = regexp.MustCompile(`^[0-9A-Za-z_.-]{1,128}$`)
	vaultMount   = regexp.MustCompile(`^[0-9A-Za-z_.-]+(/[0-9A-Za-z_.-]+)*$`)
)

// VaultTransit is a HashiCorp Vault Transit engine as a RemoteKEKService.
// A data key is encrypted under an aes256-gcm96 or chacha20-poly1305 key
// with its kid as associated_data; the stored value is Vault's
// "vault:v<n>:…" ciphertext, so a key rotated in Vault still opens older
// data keys.
type VaultTransit struct {
	api   *remoteAPI
	addr  string
	mount string
}

var _ RemoteKEKService = (*VaultTransit)(nil)

// VaultTransitOptions builds a VaultTransit. Token (re-read through
// TokenFunc on refusal) or RoleID and SecretID (AppRole) authenticate.
type VaultTransitOptions struct {
	Address      string
	Namespace    string
	Mount        string
	TokenFunc    func() (string, error)
	RoleID       string
	SecretID     func() (string, error)
	AppRoleMount string
	Client       *http.Client
}

// OpenVaultTransit builds the service from configuration. A token file is
// re-read whenever Vault refuses the token (the agent renews it).
func OpenVaultTransit(_ context.Context, cfg config.KeyManagerVaultTransit) (*VaultTransit, error) {
	o := VaultTransitOptions{Address: cfg.Address, Namespace: cfg.Namespace, Mount: cfg.Mount,
		RoleID: cfg.RoleID, AppRoleMount: cfg.AppRoleMount}
	if cfg.RoleID != "" {
		o.SecretID = func() (string, error) {
			return readSecret(cfg.SecretID, cfg.SecretIDFile, "KEY_MANAGER_VAULT_SECRET_ID_FILE")
		}
	} else {
		o.TokenFunc = func() (string, error) {
			return readSecret(cfg.Token, cfg.TokenFile, "KEY_MANAGER_VAULT_TOKEN_FILE")
		}
	}
	return NewVaultTransit(o)
}

// NewVaultTransit returns the service.
func NewVaultTransit(o VaultTransitOptions) (*VaultTransit, error) {
	addr := strings.TrimRight(strings.TrimSpace(o.Address), "/")
	if u, err := url.Parse(addr); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("vault transit: the address must be an https URL")
	}
	mount := strings.Trim(o.Mount, "/ ")
	if mount == "" {
		mount = "transit"
	}
	if !vaultMount.MatchString(mount) {
		return nil, fmt.Errorf("vault transit: %q is not a mount path", mount)
	}
	client := o.Client
	if client == nil {
		client = defaultRemoteClient()
	}
	ns := strings.Trim(o.Namespace, "/ ")
	setNS := func(h http.Header) {
		if ns != "" {
			h.Set("X-Vault-Namespace", ns)
		}
	}
	var fetch func(context.Context) (string, time.Duration, error)
	switch {
	case o.RoleID != "" && o.SecretID != nil:
		approle := strings.Trim(o.AppRoleMount, "/ ")
		if approle == "" {
			approle = "approle"
		}
		if !vaultMount.MatchString(approle) {
			return nil, fmt.Errorf("vault transit: %q is not an auth mount path", approle)
		}
		loginURL := addr + "/v1/auth/" + approle + "/login"
		fetch = func(ctx context.Context) (string, time.Duration, error) {
			secret, err := o.SecretID()
			if err != nil {
				return "", 0, err
			}
			var out struct {
				Auth *struct {
					ClientToken   string `json:"client_token"`
					LeaseDuration int64  `json:"lease_duration"`
				} `json:"auth"`
			}
			if _, err := doJSON(ctx, client, "vault approle", http.MethodPost, loginURL, setNS,
				map[string]string{"role_id": o.RoleID, "secret_id": secret}, &out); err != nil {
				return "", 0, err
			}
			if out.Auth == nil {
				return "", 0, errors.New("vault approle: login returned no token")
			}
			return out.Auth.ClientToken, time.Duration(out.Auth.LeaseDuration) * time.Second, nil
		}
	case o.TokenFunc != nil:
		fetch = func(context.Context) (string, time.Duration, error) {
			tok, err := o.TokenFunc()
			// A static token is cached until Vault refuses it.
			return tok, 24 * time.Hour, err
		}
	default:
		return nil, errors.New("vault transit: a token or an AppRole is required")
	}
	return &VaultTransit{
		addr: addr, mount: mount,
		api: &remoteAPI{service: "vault transit", client: client, tokens: newTokenCache(fetch),
			auth: func(h http.Header, tok string) { h.Set("X-Vault-Token", tok); setNS(h) }},
	}, nil
}

// key splits "<mount>/<name>" (what Resolve returns) or a bare name.
func (v *VaultTransit) key(keyID string) (string, error) {
	name := strings.TrimPrefix(keyID, v.mount+"/")
	if !vaultKeyName.MatchString(name) {
		return "", fmt.Errorf("vault transit: %q is not a key of mount %s", keyID, v.mount)
	}
	return name, nil
}

func (v *VaultTransit) url(op, name string) string {
	return v.addr + "/v1/" + v.mount + "/" + op + "/" + name
}

// Resolve checks the Transit key is an AEAD key that encrypts and
// decrypts; its name is "<mount>/<key>".
func (v *VaultTransit) Resolve(ctx context.Context, keyID string) (string, error) {
	name, err := v.key(keyID)
	if err != nil {
		return "", err
	}
	var out struct {
		Data *struct {
			Type               string `json:"type"`
			SupportsEncryption bool   `json:"supports_encryption"`
			SupportsDecryption bool   `json:"supports_decryption"`
		} `json:"data"`
	}
	if err := v.api.call(ctx, http.MethodGet, v.url("keys", name), nil, &out); err != nil {
		return "", fmt.Errorf("vault transit: key-encryption key %q: %w", keyID, err)
	}
	switch {
	case out.Data == nil:
		return "", fmt.Errorf("vault transit: key-encryption key %q has no metadata", keyID)
	case out.Data.Type != "aes256-gcm96" && out.Data.Type != "chacha20-poly1305":
		return "", fmt.Errorf("vault transit: key-encryption key %q is %s, not aes256-gcm96 or chacha20-poly1305", keyID, out.Data.Type)
	case !out.Data.SupportsEncryption || !out.Data.SupportsDecryption:
		return "", fmt.Errorf("vault transit: key-encryption key %q cannot encrypt and decrypt", keyID)
	}
	return v.mount + "/" + name, nil
}

// Encrypt encrypts a data key bound to aad.
func (v *VaultTransit) Encrypt(ctx context.Context, keyID string, plain, aad []byte) ([]byte, error) {
	name, err := v.key(keyID)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data *struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	in := map[string]string{
		"plaintext":       base64.StdEncoding.EncodeToString(plain),
		"associated_data": base64.StdEncoding.EncodeToString(aad),
	}
	if err := v.api.call(ctx, http.MethodPost, v.url("encrypt", name), in, &out); err != nil {
		return nil, err
	}
	if out.Data == nil || !strings.HasPrefix(out.Data.Ciphertext, "vault:v") {
		return nil, errors.New("vault transit: encrypt returned no ciphertext")
	}
	return []byte(out.Data.Ciphertext), nil
}

// Decrypt opens a data key; Vault refuses it under another key or aad.
func (v *VaultTransit) Decrypt(ctx context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	name, err := v.key(keyID)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(ciphertext), "vault:v") {
		return nil, errors.New("vault transit: wrapped key is not a Vault ciphertext")
	}
	var out struct {
		Data *struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	in := map[string]string{"ciphertext": string(ciphertext), "associated_data": base64.StdEncoding.EncodeToString(aad)}
	if err := v.api.call(ctx, http.MethodPost, v.url("decrypt", name), in, &out); err != nil {
		return nil, err
	}
	if out.Data == nil {
		return nil, errors.New("vault transit: decrypt returned no plaintext")
	}
	pt, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, errors.New("vault transit: plaintext is not base64")
	}
	return pt, nil
}
