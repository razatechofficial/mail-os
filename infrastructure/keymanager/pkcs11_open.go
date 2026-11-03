//go:build pkcs11

package keymanager

import "github.com/razatechofficial/mail-os/config"

// OpenPKCS11 opens the HSM named in configuration through its PKCS#11
// module (built with -tags pkcs11 and cgo).
func OpenPKCS11(cfg config.KeyManagerPKCS11) (Device, error) {
	return openPKCS11Device(cfg)
}
