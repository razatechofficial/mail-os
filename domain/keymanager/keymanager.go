// Package keymanager holds the rules of MailOS's data-encryption keys,
// following IAM's key manager: one AES-256 key per purpose (PCI DSS 3.6.1),
// every sealed value naming the key that sealed it, and rotation that
// retires a key without breaking what it sealed.
package keymanager

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Purpose names what a key protects (contract §6).
type Purpose string

// Purposes of MailOS's sealed secrets.
const (
	// PurposeProvider seals provider API keys and SMTP passwords.
	PurposeProvider Purpose = "provider"
	// PurposeDKIM seals sending domains' DKIM private keys.
	PurposeDKIM Purpose = "dkim"
	// PurposeWebhook seals the signing secrets of outbound webhooks.
	PurposeWebhook Purpose = "webhook"
)

// Purposes lists every purpose.
var Purposes = []Purpose{PurposeProvider, PurposeDKIM, PurposeWebhook}

// Valid reports whether p is a known purpose.
func (p Purpose) Valid() bool {
	for _, q := range Purposes {
		if p == q {
			return true
		}
	}
	return false
}

// State is active (seals and opens) or retired (only opens, until nothing
// it sealed remains).
type State string

// Key states.
const (
	StateActive  State = "active"
	StateRetired State = "retired"
)

// EncryptionKey is one data-encryption key, wrapped by the provider.
type EncryptionKey struct {
	ID        uuid.UUID
	KID       string
	Purpose   Purpose
	State     State
	Provider  string
	KeyRef    []byte
	CreatedBy string
	CreatedAt time.Time
	RetiredAt *time.Time
}

// Due reports whether an active key has outlived its cryptoperiod.
func (k EncryptionKey) Due(now time.Time, period time.Duration) bool {
	return k.State == StateActive && period > 0 && now.Sub(k.CreatedAt) >= period
}

// NewKID returns a random key ID: 16 base64url characters (96 bits).
func NewKID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// CiphertextVersion prefixes every sealed value.
const CiphertextVersion = "km1"

// ErrCiphertextFormat is returned for a value not sealed by the key manager.
// There is no legacy format: such a value is refused, never guessed at.
var ErrCiphertextFormat = errors.New("ciphertext is not in the key manager format")

// FormatCiphertext is how a sealed value is stored: "km1.<kid>.<data>",
// data being base64url nonce || AES-GCM ciphertext.
func FormatCiphertext(kid string, sealed []byte) string {
	return CiphertextVersion + "." + kid + "." + base64.RawURLEncoding.EncodeToString(sealed)
}

// ParseCiphertext splits a stored value into its kid and sealed bytes.
func ParseCiphertext(s string) (kid string, sealed []byte, err error) {
	version, rest, ok := strings.Cut(s, ".")
	if !ok || version != CiphertextVersion {
		return "", nil, ErrCiphertextFormat
	}
	kid, data, ok := strings.Cut(rest, ".")
	if !ok || !validKID(kid) {
		return "", nil, ErrCiphertextFormat
	}
	sealed, err = base64.RawURLEncoding.DecodeString(data)
	if err != nil || len(sealed) == 0 {
		return "", nil, ErrCiphertextFormat
	}
	return kid, sealed, nil
}

// IsCiphertext reports whether s is a sealed value.
func IsCiphertext(s string) bool {
	_, _, err := ParseCiphertext(s)
	return err == nil
}

// AdditionalData binds a sealed value to its purpose and key: a value moved
// to another column, or relabelled with another kid, fails to open.
func AdditionalData(purpose Purpose, kid string) []byte {
	return []byte("mailos/" + string(purpose) + "/" + kid)
}

// WrapAdditionalData binds a wrapped data key to its kid.
func WrapAdditionalData(kid string) []byte {
	return []byte("mailos/key/" + kid)
}

func validKID(kid string) bool {
	if len(kid) < 8 || len(kid) > 64 {
		return false
	}
	for _, r := range kid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
