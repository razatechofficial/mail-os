// Package keymanager holds the key manager's providers. The software
// provider wraps data keys with AES-256-GCM under KEY_MANAGER_MASTER_KEY
// (held in Vault, never stored); an HSM provider would implement the same
// application port.
package keymanager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	app "github.com/razatechofficial/mail-os/application/keymanager"
)

// SoftwareProvider wraps data keys under the master key.
type SoftwareProvider struct {
	aead cipher.AEAD
}

var _ app.Provider = (*SoftwareProvider)(nil)

// NewSoftwareProvider parses the base64 32-byte master key.
func NewSoftwareProvider(masterKeyB64 string) (*SoftwareProvider, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(masterKeyB64))
	if err != nil || len(key) != 32 {
		return nil, errors.New("KEY_MANAGER_MASTER_KEY must be a base64 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SoftwareProvider{aead: aead}, nil
}

// Name implements app.Provider.
func (p *SoftwareProvider) Name() string { return "software" }

// NewDataKey creates a random AES-256 key and wraps it, bound to aad (the kid).
func (p *SoftwareProvider) NewDataKey(_ context.Context, aad []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return p.aead.Seal(nonce, nonce, key, aad), nil
}

// UnwrapDataKey opens a wrapped key; a key swapped onto another kid, or a
// wrong master key, fails.
func (p *SoftwareProvider) UnwrapDataKey(_ context.Context, ref, aad []byte) ([]byte, error) {
	ns := p.aead.NonceSize()
	if len(ref) <= ns {
		return nil, errors.New("wrapped key too short")
	}
	key, err := p.aead.Open(nil, ref[:ns], ref[ns:], aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap data key: %w", err)
	}
	return key, nil
}
