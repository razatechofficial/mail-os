package keymanager

import (
	"context"
	"errors"
	"fmt"

	app "github.com/razatechofficial/mail-os/application/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/keymanager"
)

// Device is a key store that never releases a key, such as an HSM reached
// through PKCS#11. AES-256 key-encryption keys live on it as sensitive,
// non-extractable token objects named by label (CKA_LABEL); data keys are
// wrapped with C_Encrypt/C_Decrypt and CKM_AES_GCM under them.
type Device interface {
	// EnsureKEK checks label names exactly one AES key on the token,
	// creating it (sensitive, non-extractable) when there is none.
	EnsureKEK(ctx context.Context, label string) error
	// Encrypt returns nonce || AES-256-GCM(plain, aad) under the key label.
	Encrypt(ctx context.Context, label string, plain, aad []byte) ([]byte, error)
	// Decrypt opens what Encrypt sealed under label with the same aad.
	Decrypt(ctx context.Context, label string, sealed, aad []byte) ([]byte, error)
	// Close logs out and unloads the module.
	Close()
}

// ErrNoPKCS11Binding: the default server is built with CGO_ENABLED=0, and
// the PKCS#11 binding (miekg/pkcs11) needs cgo. It is linked only into a
// build with -tags pkcs11; any other build refuses to start rather than fall
// back to the software KEK.
var ErrNoPKCS11Binding = errors.New("KEY_MANAGER_PROVIDER=pkcs11: this server was built without -tags pkcs11 (and cgo); build it with them or use the software provider")

// DeviceKEK is an AES-256 key on a Device, named by its label.
type DeviceKEK struct {
	dev   Device
	label string
}

var _ app.KEK = (*DeviceKEK)(nil)

// NewDeviceKEK returns the KEK labelled label on dev, checking it exists
// (or creating it, see Device.EnsureKEK).
func NewDeviceKEK(ctx context.Context, dev Device, label string) (*DeviceKEK, error) {
	if label == "" {
		return nil, errors.New("pkcs11: a key-encryption key label is required")
	}
	if err := dev.EnsureKEK(ctx, label); err != nil {
		return nil, err
	}
	return &DeviceKEK{dev: dev, label: label}, nil
}

// ID implements app.KEK: pkcs11:<label>.
func (k *DeviceKEK) ID() string { return domain.KEKID(domain.ProviderPKCS11, k.label) }

// Wrap encrypts a data key on the device.
func (k *DeviceKEK) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	return k.dev.Encrypt(ctx, k.label, dek, aad)
}

// Unwrap decrypts a data key on the device.
func (k *DeviceKEK) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	dek, err := k.dev.Decrypt(ctx, k.label, wrapped, aad)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: unwrap data key under %q: %w", k.label, err)
	}
	return dek, nil
}
