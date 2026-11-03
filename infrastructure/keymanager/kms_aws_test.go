package keymanager

import (
	"context"
	"strings"
	"testing"

	domain "github.com/razatechofficial/mail-os/domain/keymanager"
)

func kmsKEK(t *testing.T, f *fakeKMS, keyID string) *ExternalKEK {
	t.Helper()
	k, err := NewExternalKEK(context.Background(), domain.ProviderKMS, NewAWSKMS(f.client()), keyID)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAWSKMSKEK(t *testing.T) {
	f := newFakeKMS(t)
	arn := f.addKEK("mailos-kek")
	f.addKEK("mailos-kek-2027")
	a := kmsKEK(t, f, "alias/mailos-kek")
	b := kmsKEK(t, f, "alias/mailos-kek-2027")
	assertKEK(t, a, b)
	// The alias is resolved once: the KEK is named by its ARN.
	if a.ID() != "kms:"+arn {
		t.Fatalf("id %q", a.ID())
	}
	// Each data key is bound to its kid by the encryption context.
	enc := f.calls("Encrypt")
	if len(enc) == 0 || enc[0]["KeyId"] != arn {
		t.Fatalf("encrypt requests: %v", enc)
	}
	ec, _ := enc[0]["EncryptionContext"].(map[string]any)
	if ec["mailos"] != "mailos/key/kid-1" {
		t.Fatalf("encryption context %v", ec)
	}
	for _, d := range f.calls("Decrypt") {
		if d["KeyId"] == nil || d["EncryptionContext"] == nil {
			t.Fatalf("decrypt without key or context: %v", d)
		}
	}
}

// A KMS key that cannot wrap data keys stops the server at start.
func TestAWSKMSRefusesUnusableKeys(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS(t)
	disabled := f.addKEK("disabled")
	f.setState(disabled, "Disabled")
	f.addKey("signing", "ECC_NIST_P256", "SIGN_VERIFY")
	svc := NewAWSKMS(f.client())
	for keyID, want := range map[string]string{
		"alias/disabled": "is Disabled",
		"alias/signing":  "not a symmetric encryption key",
		"alias/missing":  "NotFoundException",
	} {
		if _, err := NewExternalKEK(ctx, domain.ProviderKMS, svc, keyID); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", keyID, err, want)
		}
	}
	if _, err := NewExternalKEK(ctx, domain.ProviderKMS, svc, ""); err == nil {
		t.Error("empty key id accepted")
	}
	// A key disabled after start stops unwrapping, with KMS's reason.
	k := kmsKEK(t, f, "alias/"+strings.TrimPrefix(f.addKEK("later"), fakeKMSAccount))
	wrapped, err := k.Wrap(ctx, make([]byte, 32), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	f.setState(fakeKMSAccount+"later", "Disabled")
	if _, err := k.Unwrap(ctx, wrapped, []byte("aad")); err == nil || !strings.Contains(err.Error(), "DisabledException") {
		t.Fatalf("disabled key: %v", err)
	}
}
