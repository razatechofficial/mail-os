// Package keymanager holds the key manager's key-encryption keys (KEKs):
// a master key from configuration (software), an AES-256 key in an HSM
// reached through PKCS#11, and a key in a remote key service (AWS KMS, with
// room for Google Cloud KMS, Azure Key Vault and Vault Transit behind the
// same interface). Each implements the application's KEK port; Open builds
// the ones configuration names.
package keymanager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	app "github.com/razatechofficial/mail-os/application/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/keymanager"
)

// SoftwareKEK wraps data keys with AES-256-GCM under a master key held in
// configuration (KEY_MANAGER_MASTER_KEY, from Vault; never stored).
type SoftwareKEK struct {
	id   string
	aead cipher.AEAD
}

var _ app.KEK = (*SoftwareKEK)(nil)

// MasterKeyID names a master key without revealing it: the first 8 bytes
// of HMAC-SHA256(key, "mailos/master-key-id"), hex.
func MasterKeyID(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("mailos/master-key-id"))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// NewSoftwareKEK parses a base64 32-byte master key; setting names it in
// errors (KEY_MANAGER_MASTER_KEY or KEY_MANAGER_NEW_MASTER_KEY).
func NewSoftwareKEK(setting, masterKeyB64 string) (*SoftwareKEK, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(masterKeyB64))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s must be a base64 32-byte key", setting)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SoftwareKEK{id: domain.KEKID(domain.ProviderSoftware, MasterKeyID(key)), aead: aead}, nil
}

// ID implements app.KEK: software:<master key id>.
func (k *SoftwareKEK) ID() string { return k.id }

// Wrap seals a data key, bound to aad (the kid): nonce || AES-256-GCM.
func (k *SoftwareKEK) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, dek, aad), nil
}

// Unwrap opens a wrapped key; a key swapped onto another kid, or another
// master key, fails.
func (k *SoftwareKEK) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(wrapped) <= ns {
		return nil, errors.New("wrapped key too short")
	}
	dek, err := k.aead.Open(nil, wrapped[:ns], wrapped[ns:], aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap data key under %s: %w", k.id, err)
	}
	return dek, nil
}
