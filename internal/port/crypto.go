package port

type Hasher interface {
	Hash(plaintext string) (string, error)
	Compare(hash, plaintext string) error
}

type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type Signer interface {
	Sign(payload []byte) string
	Verify(payload []byte, signature string) bool
}
