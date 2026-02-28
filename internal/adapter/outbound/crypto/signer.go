package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/razatechofficial/mail-os/internal/port"
)

type signer struct {
	secret []byte
}

func NewSigner(secret []byte) port.Signer {
	return &signer{secret: secret}
}

func (s *signer) Sign(payload []byte) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *signer) Verify(payload []byte, signature string) bool {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	expected := mac.Sum(nil)
	actual, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, actual)
}

var _ port.Signer = (*signer)(nil)
