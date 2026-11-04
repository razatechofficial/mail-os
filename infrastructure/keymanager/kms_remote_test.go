package keymanager

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razatechofficial/mail-os/config"
	domain "github.com/razatechofficial/mail-os/domain/keymanager"
)

func mustKEK(t *testing.T, provider string, svc RemoteKEKService, keyID string) *ExternalKEK {
	t.Helper()
	k, err := NewExternalKEK(context.Background(), provider, svc, keyID)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func refuses(t *testing.T, provider string, svc RemoteKEKService, cases map[string]string) {
	t.Helper()
	for keyID, want := range cases {
		if _, err := NewExternalKEK(context.Background(), provider, svc, keyID); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", keyID, err, want)
		}
	}
}

func TestGCPKMSKEK(t *testing.T) {
	f := newFakeGCP(t)
	f.addKey(gcpTestKey, "ENCRYPT_DECRYPT", "ENABLED")
	f.addKey(gcpTestKey+"-2027", "ENCRYPT_DECRYPT", "ENABLED")
	svc, err := NewGCPKMS(GCPKMSOptions{Endpoint: f.srv.URL, CredentialsJSON: f.credentials(), Client: f.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	a := mustKEK(t, domain.ProviderGCPKMS, svc, gcpTestKey)
	b := mustKEK(t, domain.ProviderGCPKMS, svc, gcpTestKey+"-2027")
	assertKEK(t, a, b)
	if a.ID() != "gcp_kms:"+gcpTestKey {
		t.Fatalf("id %q", a.ID())
	}
	if f.tokens.issued != 1 {
		t.Fatalf("token fetched %d times, want once", f.tokens.issued)
	}
	// An expired token is replaced once and the call goes through.
	f.tokens.revoke()
	if _, err := a.Wrap(context.Background(), bytes.Repeat([]byte{1}, 32), []byte("mailos/key/kid-9")); err != nil {
		t.Fatalf("after revocation: %v", err)
	}

	f.addKey("projects/p/locations/global/keyRings/mailos/cryptoKeys/sign", "ASYMMETRIC_SIGN", "ENABLED")
	f.addKey("projects/p/locations/global/keyRings/mailos/cryptoKeys/off", "ENCRYPT_DECRYPT", "DISABLED")
	refuses(t, domain.ProviderGCPKMS, svc, map[string]string{
		"projects/p/locations/global/keyRings/mailos/cryptoKeys/sign":    "not a symmetric encryption key",
		"projects/p/locations/global/keyRings/mailos/cryptoKeys/off":     "no enabled primary version",
		"projects/p/locations/global/keyRings/mailos/cryptoKeys/missing": "not found",
		gcpTestKey + "/cryptoKeyVersions/1":                              "not a CryptoKey name",
	})
}

func TestGCPKMSMetadataServerAndFailures(t *testing.T) {
	ctx := context.Background()
	f := newFakeGCP(t)
	f.addKey(gcpTestKey, "ENCRYPT_DECRYPT", "ENABLED")
	svc, _ := NewGCPKMS(GCPKMSOptions{Endpoint: f.srv.URL, MetadataURL: f.srv.URL + "/meta", Client: f.srv.Client()})
	k := mustKEK(t, domain.ProviderGCPKMS, svc, gcpTestKey)
	assertKEK(t, k, nil)

	// A service account the token endpoint refuses: the error says why.
	other := newFakeGCP(t)
	other.addKey(gcpTestKey, "ENCRYPT_DECRYPT", "ENABLED")
	other.tokens.refuse = true
	bad, _ := NewGCPKMS(GCPKMSOptions{Endpoint: other.srv.URL, CredentialsJSON: other.credentials(), Client: other.srv.Client()})
	if _, err := NewExternalKEK(ctx, domain.ProviderGCPKMS, bad, gcpTestKey); err == nil ||
		!strings.Contains(err.Error(), "authenticate") || !strings.Contains(err.Error(), "Invalid JWT Signature") {
		t.Fatalf("refused credentials: %v", err)
	}
	// A malformed answer is an error, not a wrapped key.
	f.broken = true
	if _, err := k.Wrap(ctx, bytes.Repeat([]byte{1}, 32), []byte("a")); err == nil {
		t.Fatal("wrapped with a malformed answer")
	}
	for _, creds := range []string{`{}`, `{"type":"service_account","client_email":"x","private_key":"nope"}`, `not json`} {
		if _, err := NewGCPKMS(GCPKMSOptions{CredentialsJSON: []byte(creds)}); err == nil {
			t.Errorf("credentials %s accepted", creds)
		}
	}
}

func TestAzureKeyVaultKEK(t *testing.T) {
	ctx := context.Background()
	f := newFakeAzure(t)
	f.addVersion("mailos-kek", "RSA-HSM", true)
	f.addVersion("mailos-kek-2027", "RSA", true)
	svc, err := NewAzureKeyVault(AzureKeyVaultOptions{VaultURL: f.srv.URL, TenantID: "tenant-1", ClientID: "app",
		ClientSecret: "s3cret", AuthorityHost: f.srv.URL, Client: f.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	a := mustKEK(t, domain.ProviderAzureKeyVault, svc, "mailos-kek")
	b := mustKEK(t, domain.ProviderAzureKeyVault, svc, "mailos-kek-2027")
	assertKEK(t, a, b)
	// The KEK is the versionless key, so the vault's own rotation keeps it.
	if a.ID() != "azure_key_vault:"+f.srv.URL+"/keys/mailos-kek" {
		t.Fatalf("id %q", a.ID())
	}
	dek := bytes.Repeat([]byte{3}, 32)
	aad := []byte("mailos/key/kid-1")
	wrapped, err := a.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	f.addVersion("mailos-kek", "RSA-HSM", true) // rotated in the vault
	if got, err := a.Unwrap(ctx, wrapped, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("data key wrapped by the previous version: %v", err)
	}
	if again, _ := a.Wrap(ctx, dek, aad); bytes.HasPrefix(again, wrapped[:33]) {
		t.Fatal("new data keys are not wrapped by the new version")
	}
	// A refused token is replaced once.
	f.tokens.revoke()
	if _, err := a.Unwrap(ctx, wrapped, aad); err != nil {
		t.Fatalf("after revocation: %v", err)
	}

	f.addVersion("off", "RSA", false)
	f.addVersion("ec", "EC", true)
	f.addVersion("encrypt-only", "RSA", true, "encrypt", "decrypt")
	refuses(t, domain.ProviderAzureKeyVault, svc, map[string]string{
		"off":                         "disabled",
		"ec":                          "not an RSA key",
		"encrypt-only":                "may not wrap",
		"missing":                     "was not found",
		"../secrets/x":                "is not a key",
		"https://evil.example/keys/a": "is not a key",
	})
}

func TestAzureKeyVaultManagedIdentityAndFailures(t *testing.T) {
	ctx := context.Background()
	f := newFakeAzure(t)
	f.addVersion("mailos-kek", "RSA", true)
	svc, _ := NewAzureKeyVault(AzureKeyVaultOptions{VaultURL: f.srv.URL, IMDSURL: f.srv.URL + "/imds", Client: f.srv.Client()})
	assertKEK(t, mustKEK(t, domain.ProviderAzureKeyVault, svc, "mailos-kek"), nil)

	bad, _ := NewAzureKeyVault(AzureKeyVaultOptions{VaultURL: f.srv.URL, TenantID: "tenant-1", ClientID: "app",
		ClientSecret: "wrong", AuthorityHost: f.srv.URL, Client: f.srv.Client()})
	if _, err := NewExternalKEK(ctx, domain.ProviderAzureKeyVault, bad, "mailos-kek"); err == nil ||
		!strings.Contains(err.Error(), "Invalid client secret") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("refused secret: %v", err)
	}
	k := mustKEK(t, domain.ProviderAzureKeyVault, svc, "mailos-kek")
	for _, blob := range [][]byte{[]byte("no-version"), []byte("bad/version:xx"), []byte(":")} {
		if _, err := k.Unwrap(ctx, blob, []byte("a")); err == nil {
			t.Errorf("opened %q", blob)
		}
	}
	if _, err := NewAzureKeyVault(AzureKeyVaultOptions{VaultURL: "http://v.vault.azure.net"}); err == nil {
		t.Fatal("plain http vault accepted")
	}
}

func TestVaultTransitKEK(t *testing.T) {
	ctx := context.Background()
	f := newFakeVault(t)
	f.addKey("mailos-kek", "aes256-gcm96")
	f.addKey("mailos-kek-2027", "chacha20-poly1305")
	secret := "secret-1"
	svc, err := NewVaultTransit(VaultTransitOptions{Address: f.srv.URL, Namespace: "mailos", RoleID: "role-1",
		SecretID: func() (string, error) { return secret, nil }, Client: f.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	a := mustKEK(t, domain.ProviderVaultTransit, svc, "mailos-kek")
	b := mustKEK(t, domain.ProviderVaultTransit, svc, "mailos-kek-2027")
	assertKEK(t, a, b)
	if a.ID() != "vault_transit:transit/mailos-kek" {
		t.Fatalf("id %q", a.ID())
	}
	dek := bytes.Repeat([]byte{5}, 32)
	aad := []byte("mailos/key/kid-1")
	wrapped, _ := a.Wrap(ctx, dek, aad)
	f.rotate("mailos-kek")
	if got, err := a.Unwrap(ctx, wrapped, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("after a Vault key rotation: %v", err)
	}
	// An expired AppRole token: one new login, then the call succeeds.
	logins := f.logins
	f.tokens.revoke()
	if _, err := a.Unwrap(ctx, wrapped, aad); err != nil || f.logins != logins+1 {
		t.Fatalf("relogin: %v (%d logins)", err, f.logins-logins)
	}
	f.addKey("signing", "ed25519")
	refuses(t, domain.ProviderVaultTransit, svc, map[string]string{
		"signing":   "not aes256-gcm96",
		"missing":   "HTTP 404",
		"../sys/x":  "is not a key",
		"other/key": "is not a key",
	})
	// A refused AppRole login names Vault's reason.
	secret = "nope"
	f.tokens.revoke()
	if _, err := a.Unwrap(ctx, wrapped, aad); err == nil || !strings.Contains(err.Error(), "invalid role or secret ID") {
		t.Fatalf("refused login: %v", err)
	}
	if _, err := a.Unwrap(ctx, []byte("not-vault"), aad); err == nil {
		t.Fatal("opened a non-Vault ciphertext")
	}
}

func TestVaultTransitTokenFile(t *testing.T) {
	ctx := context.Background()
	f := newFakeVault(t)
	f.addKey("mailos-kek", "aes256-gcm96")
	file := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(file, []byte(f.tokens.issue()+"\n"), 0o600)
	svc, err := OpenVaultTransit(ctx, config.KeyManagerVaultTransit{Address: f.srv.URL, Namespace: "mailos", Mount: "transit", TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	svc.api.client = f.srv.Client()
	k := mustKEK(t, domain.ProviderVaultTransit, svc, "mailos-kek")
	assertKEK(t, k, nil)
	// The agent renewed the token: the file is read again after a refusal.
	_ = os.WriteFile(file, []byte(f.tokens.issue()), 0o600)
	if _, err := k.Wrap(ctx, bytes.Repeat([]byte{1}, 32), []byte("a")); err != nil {
		t.Fatalf("renewed token: %v", err)
	}
	f.tokens.revoke()
	if _, err := k.Wrap(ctx, bytes.Repeat([]byte{1}, 32), []byte("a")); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("revoked token: %v", err)
	}
	if _, err := NewVaultTransit(VaultTransitOptions{Address: "http://vault:8200", TokenFunc: func() (string, error) { return "t", nil }}); err == nil {
		t.Fatal("plain http Vault accepted")
	}
}

func TestOpenRemoteProviders(t *testing.T) {
	ctx := context.Background()
	g := newFakeGCP(t)
	g.addKey(gcpTestKey, "ENCRYPT_DECRYPT", "ENABLED")
	v := newFakeVault(t)
	v.addKey("mailos-kek", "aes256-gcm96")
	v.addKey("mailos-kek-2027", "aes256-gcm96")
	opened := map[string]int{}
	o := &Opener{OpenRemote: func(_ context.Context, provider string, cfg config.KeyManager) (RemoteKEKService, error) {
		opened[provider]++
		switch provider {
		case config.KeyProviderGCPKMS:
			return NewGCPKMS(GCPKMSOptions{Endpoint: g.srv.URL, CredentialsJSON: g.credentials(), Client: g.srv.Client()})
		default:
			return NewVaultTransit(VaultTransitOptions{Address: v.srv.URL, Namespace: "mailos", RoleID: "role-1",
				SecretID: func() (string, error) { return "secret-1", nil }, Client: v.srv.Client()})
		}
	}}
	cfg := config.KeyManager{Provider: "vault_transit",
		Vault:  config.KeyManagerVaultTransit{KEKKey: "mailos-kek", NewKEKKey: "mailos-kek-2027"},
		GCPKMS: config.KeyManagerGCPKMS{}}
	keks, closeKEKs, err := o.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeKEKs()
	if keks.Current().ID() != "vault_transit:transit/mailos-kek" || keks.Next().ID() != "vault_transit:transit/mailos-kek-2027" {
		t.Fatalf("%q %q", keks.Current().ID(), keks.Next().ID())
	}
	if opened["vault_transit"] != 1 {
		t.Fatalf("Vault opened %d times; one connection serves both KEKs", opened["vault_transit"])
	}
	// From Vault into Google Cloud KMS.
	cfg = config.KeyManager{Provider: "vault_transit", Vault: config.KeyManagerVaultTransit{KEKKey: "mailos-kek"},
		GCPKMS: config.KeyManagerGCPKMS{NewKEKKey: gcpTestKey}}
	keks, _, err = o.Open(ctx, cfg)
	if err != nil || keks.Next().ID() != "gcp_kms:"+gcpTestKey {
		t.Fatalf("into gcp: %v", err)
	}
	if _, _, err := o.Open(ctx, config.KeyManager{Provider: "vault_transit", Vault: config.KeyManagerVaultTransit{KEKKey: "missing"}}); err == nil {
		t.Fatal("opened a missing Vault key")
	}
}
