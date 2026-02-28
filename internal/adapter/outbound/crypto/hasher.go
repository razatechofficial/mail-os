package crypto

import (
	"github.com/razatechofficial/mail-os/internal/port"
	"golang.org/x/crypto/bcrypt"
)

type hasher struct {
	cost int
}

func NewHasher() port.Hasher {
	return &hasher{cost: bcrypt.DefaultCost}
}

func (h *hasher) Hash(plaintext string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(plaintext), h.cost)
	return string(bytes), err
}

func (h *hasher) Compare(hash, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}

var _ port.Hasher = (*hasher)(nil)
