package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const otherMasterKey = "YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODk=" // 32 bytes

// hsmEnv is a valid production configuration with the KEK in an HSM.
func hsmEnv() map[string]string {
	env := productionEnv()
	env["KEY_MANAGER_MASTER_KEY"] = ""
	env["KEY_MANAGER_PROVIDER"] = "pkcs11"
	env["KEY_MANAGER_PKCS11_MODULE"] = "/usr/lib/softhsm/libsofthsm2.so"
	env["KEY_MANAGER_PKCS11_TOKEN_LABEL"] = "mailos"
	env["KEY_MANAGER_PKCS11_PIN_FILE"] = "/vault/secrets/hsm-pin"
	return env
}

func kmsEnv() map[string]string {
	env := productionEnv()
	env["KEY_MANAGER_MASTER_KEY"] = ""
	env["KEY_MANAGER_PROVIDER"] = "kms"
	env["KEY_MANAGER_KMS_KEK_KEY_ID"] = "alias/mailos-kek"
	return env
}

func gcpEnv() map[string]string {
	env := productionEnv()
	env["KEY_MANAGER_MASTER_KEY"] = ""
	env["KEY_MANAGER_PROVIDER"] = "gcp_kms"
	env["KEY_MANAGER_GCP_KMS_KEK_KEY"] = "projects/p/locations/global/keyRings/mailos/cryptoKeys/kek"
	return env
}

func azureEnv() map[string]string {
	env := productionEnv()
	env["KEY_MANAGER_MASTER_KEY"] = ""
	env["KEY_MANAGER_PROVIDER"] = "azure_key_vault"
	env["KEY_MANAGER_AZURE_VAULT_URL"] = "https://mailos.vault.azure.net"
	env["KEY_MANAGER_AZURE_KEK_KEY"] = "mailos-kek"
	env["KEY_MANAGER_AZURE_TENANT_ID"] = "t"
	env["KEY_MANAGER_AZURE_CLIENT_ID"] = "c"
	env["KEY_MANAGER_AZURE_CLIENT_SECRET_FILE"] = "/vault/secrets/azure"
	return env
}

func vaultEnv() map[string]string {
	env := productionEnv()
	env["KEY_MANAGER_MASTER_KEY"] = ""
	env["KEY_MANAGER_PROVIDER"] = "vault_transit"
	env["KEY_MANAGER_VAULT_ADDR"] = "https://vault.internal:8200"
	env["KEY_MANAGER_VAULT_KEK_KEY"] = "mailos-kek"
	env["KEY_MANAGER_VAULT_TOKEN_FILE"] = "/vault/secrets/token"
	return env
}

func TestKeyManagerRemoteProviders(t *testing.T) {
	for name, env := range map[string]func() map[string]string{"gcp_kms": gcpEnv, "azure_key_vault": azureEnv, "vault_transit": vaultEnv} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, env())
			if err != nil {
				t.Fatalf("%s refused: %v", name, err)
			}
			if cfg.KeyManager.Provider != name || cfg.KeyManager.KEKKey(name, false) == "" || cfg.KeyManager.NewKEKProvider() != "" {
				t.Fatalf("%+v", cfg.KeyManager)
			}
		})
	}
	t.Run("vault defaults", func(t *testing.T) {
		cfg, _ := load(t, vaultEnv())
		if cfg.KeyManager.Vault.Mount != "transit" || cfg.KeyManager.Vault.AppRoleMount != "approle" {
			t.Fatalf("%+v", cfg.KeyManager.Vault)
		}
	})
	t.Run("software into Vault", func(t *testing.T) {
		env := productionEnv()
		env["KEY_MANAGER_VAULT_ADDR"] = "https://vault.internal:8200"
		env["KEY_MANAGER_VAULT_ROLE_ID"] = "r"
		env["KEY_MANAGER_VAULT_SECRET_ID"] = "s"
		env["KEY_MANAGER_VAULT_NEW_KEK_KEY"] = "mailos-kek"
		cfg, err := load(t, env)
		if err != nil || cfg.KeyManager.NewKEKProvider() != KeyProviderVaultTransit || cfg.KeyManager.KEKKey(KeyProviderVaultTransit, true) != "mailos-kek" {
			t.Fatalf("%v", err)
		}
	})
}

func TestKeyManagerProviders(t *testing.T) {
	t.Run("pkcs11", func(t *testing.T) {
		cfg, err := load(t, hsmEnv())
		if err != nil {
			t.Fatalf("pkcs11 refused: %v", err)
		}
		if cfg.KeyManager.Provider != KeyProviderPKCS11 || cfg.KeyManager.PKCS11.KEKLabel != "mailos-kek" || cfg.KeyManager.NewKEKProvider() != "" {
			t.Fatalf("%+v", cfg.KeyManager)
		}
	})
	t.Run("kms", func(t *testing.T) {
		if _, err := load(t, kmsEnv()); err != nil {
			t.Fatalf("kms refused: %v", err)
		}
	})
	t.Run("software", func(t *testing.T) {
		cfg, err := load(t, productionEnv())
		if err != nil || cfg.KeyManager.Provider != KeyProviderSoftware {
			t.Fatalf("software is the default: %v", err)
		}
	})
}

// Moving data keys from the master key into the HSM: the software
// provider stays current while the HSM key is the new KEK.
func TestKeyManagerNewKEK(t *testing.T) {
	t.Run("into the HSM", func(t *testing.T) {
		env := productionEnv()
		env["KEY_MANAGER_PKCS11_MODULE"] = "/usr/lib/softhsm/libsofthsm2.so"
		env["KEY_MANAGER_PKCS11_TOKEN_LABEL"] = "mailos"
		env["KEY_MANAGER_PKCS11_PIN"] = "1234"
		env["KEY_MANAGER_PKCS11_NEW_KEK_LABEL"] = "mailos-kek-2026"
		cfg, err := load(t, env)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.KeyManager.NewKEKProvider() != KeyProviderPKCS11 {
			t.Fatalf("new KEK provider %q", cfg.KeyManager.NewKEKProvider())
		}
	})
	t.Run("new master key", func(t *testing.T) {
		env := productionEnv()
		env["KEY_MANAGER_NEW_MASTER_KEY"] = otherMasterKey
		if cfg, err := load(t, env); err != nil || cfg.KeyManager.NewKEKProvider() != KeyProviderSoftware {
			t.Fatalf("new master key: %v", err)
		}
	})
}

func TestKeyManagerRefusals(t *testing.T) {
	cases := []struct {
		name string
		base func() map[string]string
		set  map[string]string
		want string
	}{
		{"unknown provider", productionEnv, map[string]string{"KEY_MANAGER_PROVIDER": "vault"}, "KEY_MANAGER_PROVIDER"},
		{"software without master key", productionEnv, map[string]string{"KEY_MANAGER_MASTER_KEY": ""}, "KEY_MANAGER_MASTER_KEY"},
		{"pkcs11 without module", hsmEnv, map[string]string{"KEY_MANAGER_PKCS11_MODULE": ""}, "KEY_MANAGER_PKCS11_MODULE"},
		{"pkcs11 relative module", hsmEnv, map[string]string{"KEY_MANAGER_PKCS11_MODULE": "libsofthsm2.so"}, "absolute path"},
		{"pkcs11 without token", hsmEnv, map[string]string{"KEY_MANAGER_PKCS11_TOKEN_LABEL": ""}, "KEY_MANAGER_PKCS11_TOKEN_LABEL"},
		{"pkcs11 without PIN", hsmEnv, map[string]string{"KEY_MANAGER_PKCS11_PIN_FILE": ""}, "KEY_MANAGER_PKCS11_PIN"},
		{"pkcs11 without KEK label", hsmEnv, map[string]string{"KEY_MANAGER_PKCS11_KEK_LABEL": " "}, "KEY_MANAGER_PKCS11_KEK_LABEL"},
		{"pkcs11 beside a master key", hsmEnv, map[string]string{"KEY_MANAGER_MASTER_KEY": testMasterKey}, "only read by the software provider"},
		{"kms without key", kmsEnv, map[string]string{"KEY_MANAGER_KMS_KEK_KEY_ID": ""}, "KEY_MANAGER_KMS_KEK_KEY_ID"},
		{"kms over http", kmsEnv, map[string]string{"KEY_MANAGER_KMS_ENDPOINT": "http://kms.local"}, "KEY_MANAGER_KMS_ENDPOINT"},
		{"short new master key", productionEnv, map[string]string{"KEY_MANAGER_NEW_MASTER_KEY": "c2hvcnQ="}, "KEY_MANAGER_NEW_MASTER_KEY"},
		{"new master key is the current one", productionEnv, map[string]string{"KEY_MANAGER_NEW_MASTER_KEY": testMasterKey}, "must differ"},
		{"new HSM label is the current one", hsmEnv, map[string]string{"KEY_MANAGER_PKCS11_NEW_KEK_LABEL": "mailos-kek"}, "must differ"},
		{"new HSM key without the HSM", productionEnv, map[string]string{"KEY_MANAGER_PKCS11_NEW_KEK_LABEL": "mailos-kek-2"}, "KEY_MANAGER_PKCS11_MODULE"},
		{"new KMS key is the current one", kmsEnv, map[string]string{"KEY_MANAGER_KMS_NEW_KEK_KEY_ID": "alias/mailos-kek"}, "must differ"},
		{"two new KEKs", kmsEnv, map[string]string{"KEY_MANAGER_KMS_NEW_KEK_KEY_ID": "alias/b", "KEY_MANAGER_NEW_MASTER_KEY": otherMasterKey}, "set only one"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := c.base()
			for k, v := range c.set {
				env[k] = v
			}
			_, err := load(t, env)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestResolvePIN(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(file, []byte("4321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := KeyManagerPKCS11{PIN: "1234", PINFile: file}.ResolvePIN()
	if err != nil || pin != "4321" {
		t.Fatalf("the PIN file wins: %q %v", pin, err)
	}
	if pin, _ := (KeyManagerPKCS11{PIN: "1234"}).ResolvePIN(); pin != "1234" {
		t.Fatalf("PIN %q", pin)
	}
	if err := os.WriteFile(file, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (KeyManagerPKCS11{PINFile: file}).ResolvePIN(); err == nil {
		t.Fatal("empty PIN file accepted")
	}
	if _, err := (KeyManagerPKCS11{}).ResolvePIN(); err == nil {
		t.Fatal("no PIN accepted")
	}
}
