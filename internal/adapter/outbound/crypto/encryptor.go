package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/razatechofficial/mail-os/internal/port"
)

type encryptor struct {
	gcm cipher.AEAD
}

func NewEncryptor(key []byte) (port.Encryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewEncryptor: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewEncryptor: %w", err)
	}
	return &encryptor{gcm: gcm}, nil
}

func (e *encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto.Encrypt: %w", err)
	}
	return e.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("crypto.Decrypt: ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto.Decrypt: %w", err)
	}
	return plaintext, nil
}

var _ port.Encryptor = (*encryptor)(nil)
