//go:build !pkcs11

package keymanager

import "github.com/razatechofficial/mail-os/config"

// OpenPKCS11 refuses: this build has no PKCS#11 binding (see
// ErrNoPKCS11Binding). The pkcs11 build tag links the real one.
func OpenPKCS11(cfg config.KeyManagerPKCS11) (Device, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return nil, ErrNoPKCS11Binding
}
