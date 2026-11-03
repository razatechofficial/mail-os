//go:build !pkcs11

package keymanager

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/razatechofficial/mail-os/config"
)

// Without -tags pkcs11 the HSM provider refuses to start, naming why,
// instead of falling back to the software KEK.
func TestPKCS11WithoutBinding(t *testing.T) {
	cfg := config.KeyManagerPKCS11{ModulePath: "/usr/lib/softhsm/libsofthsm2.so", TokenLabel: "mailos", PIN: "1234", KEKLabel: "mailos-kek"}
	if _, err := OpenPKCS11(cfg); !errors.Is(err, ErrNoPKCS11Binding) {
		t.Fatalf("err = %v", err)
	}
	cfg.TokenLabel = ""
	if _, err := OpenPKCS11(cfg); err == nil || !strings.Contains(err.Error(), "KEY_MANAGER_PKCS11_TOKEN_LABEL") {
		t.Fatalf("missing token: %v", err)
	}
	_, _, err := Open(context.Background(), config.KeyManager{Provider: config.KeyProviderPKCS11, PKCS11: config.KeyManagerPKCS11{
		ModulePath: "/usr/lib/softhsm/libsofthsm2.so", TokenLabel: "mailos", PIN: "1234", KEKLabel: "mailos-kek"}})
	if !errors.Is(err, ErrNoPKCS11Binding) {
		t.Fatalf("open: %v", err)
	}
}
