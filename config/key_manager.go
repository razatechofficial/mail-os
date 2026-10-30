package config

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// validate requires the master key everywhere: provider and SMTP
// credentials, DKIM keys and webhook secrets are always sealed (contract
// §6), and there is no plaintext mode to fall back to.
func (k KeyManager) validate() error {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k.MasterKey))
	if err != nil || len(key) != 32 {
		return fmt.Errorf("KEY_MANAGER_MASTER_KEY must be a base64 32-byte key (openssl rand -base64 32), held in Vault")
	}
	if k.EncryptionRotationPeriod != 0 && k.EncryptionRotationPeriod < 24*time.Hour {
		return fmt.Errorf("KEY_MANAGER_ENCRYPTION_ROTATION_PERIOD must be 0 (on request only) or at least 24h")
	}
	if k.ReencryptBatch < 1 || k.ReencryptBatch > 10000 {
		return fmt.Errorf("KEY_MANAGER_REENCRYPT_BATCH must be between 1 and 10000")
	}
	return nil
}
