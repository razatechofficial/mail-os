package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Key manager providers (KEY_MANAGER_PROVIDER): where the key-encryption
// key (KEK) that wraps data keys lives.
const (
	KeyProviderSoftware = "software"
	KeyProviderPKCS11   = "pkcs11"
	KeyProviderKMS      = "kms"
	// KeyProviderGCPKMS is a symmetric Google Cloud KMS CryptoKey.
	KeyProviderGCPKMS = "gcp_kms"
	// KeyProviderAzureKeyVault is an RSA key in Azure Key Vault or Managed HSM.
	KeyProviderAzureKeyVault = "azure_key_vault"
	// KeyProviderVaultTransit is a HashiCorp Vault Transit key.
	KeyProviderVaultTransit = "vault_transit"
)

// keyProviders is the KEY_MANAGER_PROVIDER list, for error messages.
const keyProviders = "software, pkcs11, kms, gcp_kms, azure_key_vault or vault_transit"

// KeyManagerPKCS11 locates the KEK in an HSM through its PKCS#11 module.
type KeyManagerPKCS11 struct {
	ModulePath string `yaml:"module_path" env:"KEY_MANAGER_PKCS11_MODULE" env-default:""`
	TokenLabel string `yaml:"token_label" env:"KEY_MANAGER_PKCS11_TOKEN_LABEL" env-default:""`
	PIN        string `yaml:"pin" env:"KEY_MANAGER_PKCS11_PIN" env-default:""`
	// PINFile holds the user PIN, rendered from Vault by the Vault agent;
	// it wins over PIN.
	PINFile string `yaml:"pin_file" env:"KEY_MANAGER_PKCS11_PIN_FILE" env-default:""`
	// KEKLabel names the on-token AES-256 key that wraps data keys.
	KEKLabel string `yaml:"kek_label" env:"KEY_MANAGER_PKCS11_KEK_LABEL" env-default:"mailos-kek"`
	// NewKEKLabel names the on-token key a rotation moves data keys to.
	NewKEKLabel string `yaml:"new_kek_label" env:"KEY_MANAGER_PKCS11_NEW_KEK_LABEL" env-default:""`
}

// ResolvePIN returns the user PIN: the PIN file's content without its
// trailing newline when a file is set, else PIN.
func (p KeyManagerPKCS11) ResolvePIN() (string, error) {
	if p.PINFile == "" {
		if p.PIN == "" {
			return "", fmt.Errorf("KEY_MANAGER_PKCS11_PIN or KEY_MANAGER_PKCS11_PIN_FILE is required")
		}
		return p.PIN, nil
	}
	raw, err := os.ReadFile(p.PINFile)
	if err != nil {
		return "", fmt.Errorf("read KEY_MANAGER_PKCS11_PIN_FILE: %w", err)
	}
	pin := strings.TrimRight(string(raw), "\r\n")
	if pin == "" {
		return "", fmt.Errorf("KEY_MANAGER_PKCS11_PIN_FILE is empty")
	}
	return pin, nil
}

// Validate checks the HSM can be located and logged in to.
func (p KeyManagerPKCS11) Validate() error {
	if p.ModulePath == "" || p.TokenLabel == "" {
		return fmt.Errorf("KEY_MANAGER_PKCS11_MODULE and KEY_MANAGER_PKCS11_TOKEN_LABEL are required for the pkcs11 provider")
	}
	if !filepath.IsAbs(p.ModulePath) {
		return fmt.Errorf("KEY_MANAGER_PKCS11_MODULE must be an absolute path to the HSM's PKCS#11 library")
	}
	if p.PIN == "" && p.PINFile == "" {
		return fmt.Errorf("KEY_MANAGER_PKCS11_PIN or KEY_MANAGER_PKCS11_PIN_FILE is required for the pkcs11 provider")
	}
	return nil
}

// KeyManagerKMS locates the KEK in AWS KMS. Credentials come from the
// default AWS chain (IRSA, task or instance role), never from configuration.
type KeyManagerKMS struct {
	// Region is the KMS region; empty uses AWS_REGION.
	Region string `yaml:"region" env:"KEY_MANAGER_KMS_REGION" env-default:""`
	// KEKKeyID is the symmetric KMS key (ID, ARN or alias) that wraps data keys.
	KEKKeyID string `yaml:"kek_key_id" env:"KEY_MANAGER_KMS_KEK_KEY_ID" env-default:""`
	// NewKEKKeyID is the KMS key a rotation moves data keys to.
	NewKEKKeyID string `yaml:"new_kek_key_id" env:"KEY_MANAGER_KMS_NEW_KEK_KEY_ID" env-default:""`
	// Endpoint overrides the KMS endpoint (an https VPC endpoint).
	Endpoint string `yaml:"endpoint" env:"KEY_MANAGER_KMS_ENDPOINT" env-default:""`
}

func (k KeyManagerKMS) validate() error {
	if k.Endpoint != "" {
		u, err := url.Parse(k.Endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("KEY_MANAGER_KMS_ENDPOINT must be an https URL")
		}
	}
	return nil
}

// KeyManagerGCPKMS locates the KEK in Google Cloud KMS. Credentials are a
// service-account key file, else the metadata server's service account.
type KeyManagerGCPKMS struct {
	// KEKKey is the CryptoKey resource name:
	// projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>.
	KEKKey string `yaml:"kek_key" env:"KEY_MANAGER_GCP_KMS_KEK_KEY" env-default:""`
	// NewKEKKey is the CryptoKey a rotation moves data keys to.
	NewKEKKey string `yaml:"new_kek_key" env:"KEY_MANAGER_GCP_KMS_NEW_KEK_KEY" env-default:""`
	// CredentialsFile is a service-account JSON key (rendered by the Vault
	// agent); empty uses GOOGLE_APPLICATION_CREDENTIALS, then the metadata
	// server (GKE workload identity, GCE).
	CredentialsFile string `yaml:"credentials_file" env:"KEY_MANAGER_GCP_KMS_CREDENTIALS_FILE" env-default:""`
	// Endpoint overrides https://cloudkms.googleapis.com (Private Service Connect).
	Endpoint string `yaml:"endpoint" env:"KEY_MANAGER_GCP_KMS_ENDPOINT" env-default:""`
}

// KeyManagerAzureKeyVault locates the KEK in Azure Key Vault or Managed
// HSM. With a client id and secret MailOS signs in as that app
// registration; without, it uses the managed identity (IMDS).
type KeyManagerAzureKeyVault struct {
	// VaultURL is the vault, https://<name>.vault.azure.net (or a Managed HSM).
	VaultURL string `yaml:"vault_url" env:"KEY_MANAGER_AZURE_VAULT_URL" env-default:""`
	// KEKKey is the RSA key's name, optionally name/version.
	KEKKey string `yaml:"kek_key" env:"KEY_MANAGER_AZURE_KEK_KEY" env-default:""`
	// NewKEKKey is the key a rotation moves data keys to.
	NewKEKKey string `yaml:"new_kek_key" env:"KEY_MANAGER_AZURE_NEW_KEK_KEY" env-default:""`
	TenantID  string `yaml:"tenant_id" env:"KEY_MANAGER_AZURE_TENANT_ID" env-default:""`
	ClientID  string `yaml:"client_id" env:"KEY_MANAGER_AZURE_CLIENT_ID" env-default:""`
	// ClientSecret or ClientSecretFile (the file wins) authenticates ClientID.
	ClientSecret     string `yaml:"client_secret" env:"KEY_MANAGER_AZURE_CLIENT_SECRET" env-default:""`
	ClientSecretFile string `yaml:"client_secret_file" env:"KEY_MANAGER_AZURE_CLIENT_SECRET_FILE" env-default:""`
	// AuthorityHost is the Entra ID host (sovereign clouds).
	AuthorityHost string `yaml:"authority_host" env:"KEY_MANAGER_AZURE_AUTHORITY_HOST" env-default:"https://login.microsoftonline.com"`
}

// KeyManagerVaultTransit locates the KEK in a HashiCorp Vault Transit
// engine. MailOS authenticates with a token (file) or AppRole.
type KeyManagerVaultTransit struct {
	// Address is Vault's https address.
	Address   string `yaml:"address" env:"KEY_MANAGER_VAULT_ADDR" env-default:""`
	Namespace string `yaml:"namespace" env:"KEY_MANAGER_VAULT_NAMESPACE" env-default:""`
	// Mount is the Transit engine's path.
	Mount string `yaml:"mount" env:"KEY_MANAGER_VAULT_TRANSIT_MOUNT" env-default:"transit"`
	// KEKKey is the Transit key (aes256-gcm96 or chacha20-poly1305).
	KEKKey string `yaml:"kek_key" env:"KEY_MANAGER_VAULT_KEK_KEY" env-default:""`
	// NewKEKKey is the Transit key a rotation moves data keys to.
	NewKEKKey string `yaml:"new_kek_key" env:"KEY_MANAGER_VAULT_NEW_KEK_KEY" env-default:""`
	// Token or TokenFile (the Vault agent's sink; the file wins).
	Token     string `yaml:"token" env:"KEY_MANAGER_VAULT_TOKEN" env-default:""`
	TokenFile string `yaml:"token_file" env:"KEY_MANAGER_VAULT_TOKEN_FILE" env-default:""`
	// RoleID with SecretID or SecretIDFile signs in through AppRole.
	RoleID       string `yaml:"role_id" env:"KEY_MANAGER_VAULT_ROLE_ID" env-default:""`
	SecretID     string `yaml:"secret_id" env:"KEY_MANAGER_VAULT_SECRET_ID" env-default:""`
	SecretIDFile string `yaml:"secret_id_file" env:"KEY_MANAGER_VAULT_SECRET_ID_FILE" env-default:""`
	// AppRoleMount is the AppRole auth method's path.
	AppRoleMount string `yaml:"approle_mount" env:"KEY_MANAGER_VAULT_APPROLE_MOUNT" env-default:"approle"`
}

func httpsURL(name, v string, required bool) error {
	if strings.TrimSpace(v) == "" {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s must be an https URL", name)
	}
	return nil
}

func (g KeyManagerGCPKMS) validate() error {
	return httpsURL("KEY_MANAGER_GCP_KMS_ENDPOINT", g.Endpoint, false)
}

func (a KeyManagerAzureKeyVault) validate() error {
	if err := httpsURL("KEY_MANAGER_AZURE_VAULT_URL", a.VaultURL, true); err != nil {
		return err
	}
	if err := httpsURL("KEY_MANAGER_AZURE_AUTHORITY_HOST", a.AuthorityHost, false); err != nil {
		return err
	}
	secret := a.ClientSecret != "" || a.ClientSecretFile != ""
	if a.ClientID != "" && secret && a.TenantID == "" {
		return fmt.Errorf("KEY_MANAGER_AZURE_TENANT_ID is required with KEY_MANAGER_AZURE_CLIENT_SECRET")
	}
	if secret && a.ClientID == "" {
		return fmt.Errorf("KEY_MANAGER_AZURE_CLIENT_ID is required with KEY_MANAGER_AZURE_CLIENT_SECRET")
	}
	return nil
}

func (v KeyManagerVaultTransit) validate() error {
	if err := httpsURL("KEY_MANAGER_VAULT_ADDR", v.Address, true); err != nil {
		return err
	}
	if strings.Trim(v.Mount, "/ ") == "" {
		return fmt.Errorf("KEY_MANAGER_VAULT_TRANSIT_MOUNT is required")
	}
	token := v.Token != "" || v.TokenFile != ""
	approle := v.RoleID != "" || v.SecretID != "" || v.SecretIDFile != ""
	switch {
	case token && approle:
		return fmt.Errorf("set either KEY_MANAGER_VAULT_TOKEN(_FILE) or KEY_MANAGER_VAULT_ROLE_ID, not both")
	case approle && (v.RoleID == "" || (v.SecretID == "" && v.SecretIDFile == "")):
		return fmt.Errorf("KEY_MANAGER_VAULT_ROLE_ID needs KEY_MANAGER_VAULT_SECRET_ID or KEY_MANAGER_VAULT_SECRET_ID_FILE")
	case !token && !approle:
		return fmt.Errorf("KEY_MANAGER_VAULT_TOKEN, KEY_MANAGER_VAULT_TOKEN_FILE or KEY_MANAGER_VAULT_ROLE_ID is required for the vault_transit provider")
	}
	return nil
}

// KEKKey is the remote key a provider's current (or, isNew, new) KEK is
// in, for the providers whose KEK is a key in a remote service.
func (k KeyManager) KEKKey(provider string, isNew bool) string {
	pick := func(cur, next string) string {
		if isNew {
			return strings.TrimSpace(next)
		}
		return strings.TrimSpace(cur)
	}
	switch provider {
	case KeyProviderKMS:
		return pick(k.KMS.KEKKeyID, k.KMS.NewKEKKeyID)
	case KeyProviderGCPKMS:
		return pick(k.GCPKMS.KEKKey, k.GCPKMS.NewKEKKey)
	case KeyProviderAzureKeyVault:
		return pick(k.Azure.KEKKey, k.Azure.NewKEKKey)
	case KeyProviderVaultTransit:
		return pick(k.Vault.KEKKey, k.Vault.NewKEKKey)
	}
	return ""
}

// remoteSettings is each remote provider's key settings, for messages.
var remoteSettings = map[string][2]string{
	KeyProviderKMS:           {"KEY_MANAGER_KMS_KEK_KEY_ID", "KEY_MANAGER_KMS_NEW_KEK_KEY_ID"},
	KeyProviderGCPKMS:        {"KEY_MANAGER_GCP_KMS_KEK_KEY", "KEY_MANAGER_GCP_KMS_NEW_KEK_KEY"},
	KeyProviderAzureKeyVault: {"KEY_MANAGER_AZURE_KEK_KEY", "KEY_MANAGER_AZURE_NEW_KEK_KEY"},
	KeyProviderVaultTransit:  {"KEY_MANAGER_VAULT_KEK_KEY", "KEY_MANAGER_VAULT_NEW_KEK_KEY"},
}

// validateRemote checks a remote provider's connection settings.
func (k KeyManager) validateRemote(provider string) error {
	switch provider {
	case KeyProviderKMS:
		return k.KMS.validate()
	case KeyProviderGCPKMS:
		return k.GCPKMS.validate()
	case KeyProviderAzureKeyVault:
		return k.Azure.validate()
	case KeyProviderVaultTransit:
		return k.Vault.validate()
	}
	return nil
}

// NewKEKProvider is the provider of the KEK a rotation moves data keys to,
// "" when no new KEK is configured. It may differ from Provider, to move
// data keys from the master key into an HSM or KMS.
func (k KeyManager) NewKEKProvider() string {
	switch {
	case strings.TrimSpace(k.NewMasterKey) != "":
		return KeyProviderSoftware
	case strings.TrimSpace(k.PKCS11.NewKEKLabel) != "":
		return KeyProviderPKCS11
	case strings.TrimSpace(k.KMS.NewKEKKeyID) != "":
		return KeyProviderKMS
	case strings.TrimSpace(k.GCPKMS.NewKEKKey) != "":
		return KeyProviderGCPKMS
	case strings.TrimSpace(k.Azure.NewKEKKey) != "":
		return KeyProviderAzureKeyVault
	case strings.TrimSpace(k.Vault.NewKEKKey) != "":
		return KeyProviderVaultTransit
	}
	return ""
}

func validMasterKey(b64 string) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	return err == nil && len(key) == 32
}

// validate refuses a key manager that could not open what it sealed:
// provider and SMTP credentials, DKIM keys and webhook secrets are always
// sealed (contract §6), and there is no plaintext mode to fall back to.
func (k KeyManager) validate() error {
	switch k.Provider {
	case KeyProviderSoftware:
		if !validMasterKey(k.MasterKey) {
			return fmt.Errorf("KEY_MANAGER_MASTER_KEY must be a base64 32-byte key (openssl rand -base64 32), held in Vault")
		}
	case KeyProviderPKCS11:
		if err := k.PKCS11.Validate(); err != nil {
			return err
		}
		if strings.TrimSpace(k.PKCS11.KEKLabel) == "" {
			return fmt.Errorf("KEY_MANAGER_PKCS11_KEK_LABEL is required for the pkcs11 provider")
		}
	case KeyProviderKMS, KeyProviderGCPKMS, KeyProviderAzureKeyVault, KeyProviderVaultTransit:
		if k.KEKKey(k.Provider, false) == "" {
			return fmt.Errorf("%s is required for the %s provider", remoteSettings[k.Provider][0], k.Provider)
		}
		if err := k.validateRemote(k.Provider); err != nil {
			return err
		}
	default:
		return fmt.Errorf("KEY_MANAGER_PROVIDER must be %s", keyProviders)
	}
	if k.Provider != KeyProviderSoftware && k.MasterKey != "" {
		return fmt.Errorf("KEY_MANAGER_MASTER_KEY is only read by the software provider; remove it with KEY_MANAGER_PROVIDER=%s", k.Provider)
	}
	if err := k.validateNewKEK(); err != nil {
		return err
	}
	if k.EncryptionRotationPeriod != 0 && k.EncryptionRotationPeriod < 24*time.Hour {
		return fmt.Errorf("KEY_MANAGER_ENCRYPTION_ROTATION_PERIOD must be 0 (on request only) or at least 24h")
	}
	if k.ReencryptBatch < 1 || k.ReencryptBatch > 10000 {
		return fmt.Errorf("KEY_MANAGER_REENCRYPT_BATCH must be between 1 and 10000")
	}
	return nil
}

// validateNewKEK checks the KEK a rotation moves to: at most one, fully
// configured, and not the current one.
func (k KeyManager) validateNewKEK() error {
	set := 0
	for _, v := range []string{k.NewMasterKey, k.PKCS11.NewKEKLabel, k.KMS.NewKEKKeyID, k.GCPKMS.NewKEKKey, k.Azure.NewKEKKey, k.Vault.NewKEKKey} {
		if strings.TrimSpace(v) != "" {
			set++
		}
	}
	if set > 1 {
		return fmt.Errorf("set only one of KEY_MANAGER_NEW_MASTER_KEY, KEY_MANAGER_PKCS11_NEW_KEK_LABEL, KEY_MANAGER_KMS_NEW_KEK_KEY_ID, " +
			"KEY_MANAGER_GCP_KMS_NEW_KEK_KEY, KEY_MANAGER_AZURE_NEW_KEK_KEY and KEY_MANAGER_VAULT_NEW_KEK_KEY")
	}
	switch k.NewKEKProvider() {
	case KeyProviderSoftware:
		if !validMasterKey(k.NewMasterKey) {
			return fmt.Errorf("KEY_MANAGER_NEW_MASTER_KEY must be a base64 32-byte key")
		}
		if k.Provider == KeyProviderSoftware && strings.TrimSpace(k.NewMasterKey) == strings.TrimSpace(k.MasterKey) {
			return fmt.Errorf("KEY_MANAGER_NEW_MASTER_KEY must differ from KEY_MANAGER_MASTER_KEY")
		}
	case KeyProviderPKCS11:
		if err := k.PKCS11.Validate(); err != nil {
			return fmt.Errorf("KEY_MANAGER_PKCS11_NEW_KEK_LABEL: %w", err)
		}
		if k.Provider == KeyProviderPKCS11 && k.PKCS11.NewKEKLabel == k.PKCS11.KEKLabel {
			return fmt.Errorf("KEY_MANAGER_PKCS11_NEW_KEK_LABEL must differ from KEY_MANAGER_PKCS11_KEK_LABEL")
		}
	case KeyProviderKMS, KeyProviderGCPKMS, KeyProviderAzureKeyVault, KeyProviderVaultTransit:
		p := k.NewKEKProvider()
		if err := k.validateRemote(p); err != nil {
			return err
		}
		if k.Provider == p && k.KEKKey(p, true) == k.KEKKey(p, false) {
			return fmt.Errorf("%s must differ from %s", remoteSettings[p][1], remoteSettings[p][0])
		}
	}
	return nil
}
