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
)

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
	case KeyProviderKMS:
		if strings.TrimSpace(k.KMS.KEKKeyID) == "" {
			return fmt.Errorf("KEY_MANAGER_KMS_KEK_KEY_ID is required for the kms provider")
		}
		if err := k.KMS.validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("KEY_MANAGER_PROVIDER must be software, pkcs11 or kms")
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
	for _, v := range []string{k.NewMasterKey, k.PKCS11.NewKEKLabel, k.KMS.NewKEKKeyID} {
		if strings.TrimSpace(v) != "" {
			set++
		}
	}
	if set > 1 {
		return fmt.Errorf("set only one of KEY_MANAGER_NEW_MASTER_KEY, KEY_MANAGER_PKCS11_NEW_KEK_LABEL and KEY_MANAGER_KMS_NEW_KEK_KEY_ID")
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
	case KeyProviderKMS:
		if err := k.KMS.validate(); err != nil {
			return err
		}
		if k.Provider == KeyProviderKMS && k.KMS.NewKEKKeyID == k.KMS.KEKKeyID {
			return fmt.Errorf("KEY_MANAGER_KMS_NEW_KEK_KEY_ID must differ from KEY_MANAGER_KMS_KEK_KEY_ID")
		}
	}
	return nil
}
