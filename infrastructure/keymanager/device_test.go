package keymanager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeDevice stands in for an HSM: AES keys stay inside it, named by
// label, and are used only through Encrypt and Decrypt.
type fakeDevice struct {
	mu      sync.Mutex
	keys    map[string]cipher.AEAD
	created []string
	closed  bool
}

func newFakeDevice() *fakeDevice { return &fakeDevice{keys: map[string]cipher.AEAD{}} }

func (d *fakeDevice) EnsureKEK(_ context.Context, label string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.keys[label] != nil {
		return nil
	}
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, _ := aes.NewCipher(k)
	d.keys[label], _ = cipher.NewGCM(b)
	d.created = append(d.created, label)
	return nil
}

func (d *fakeDevice) aead(label string) (cipher.AEAD, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := d.keys[label]
	if a == nil {
		return nil, errors.New("pkcs11: no key labelled " + label)
	}
	return a, nil
}

func (d *fakeDevice) Encrypt(_ context.Context, label string, plain, aad []byte) ([]byte, error) {
	a, err := d.aead(label)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	return a.Seal(nonce, nonce, plain, aad), nil
}

func (d *fakeDevice) Decrypt(_ context.Context, label string, sealed, aad []byte) ([]byte, error) {
	a, err := d.aead(label)
	if err != nil {
		return nil, err
	}
	if len(sealed) < a.NonceSize() {
		return nil, errors.New("pkcs11: wrapped value too short")
	}
	return a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], aad)
}

func (d *fakeDevice) Close() { d.closed = true }

func TestDeviceKEK(t *testing.T) {
	ctx := context.Background()
	dev := newFakeDevice()
	a, err := NewDeviceKEK(ctx, dev, "mailos-kek")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewDeviceKEK(ctx, dev, "mailos-kek-2027")
	assertKEK(t, a, b)
	if a.ID() != "pkcs11:mailos-kek" || b.ID() != "pkcs11:mailos-kek-2027" {
		t.Fatalf("ids %q %q", a.ID(), b.ID())
	}
	if len(dev.created) != 2 {
		t.Fatalf("keys created on the device: %v", dev.created)
	}
	if _, err := NewDeviceKEK(ctx, dev, ""); err == nil {
		t.Fatal("empty label accepted")
	}
	// A key removed from the token stops unwrapping, with the label named.
	wrapped, _ := a.Wrap(ctx, make([]byte, 32), []byte("aad"))
	delete(dev.keys, "mailos-kek")
	if _, err := a.Unwrap(ctx, wrapped, []byte("aad")); err == nil || !strings.Contains(err.Error(), "mailos-kek") {
		t.Fatalf("missing key: %v", err)
	}
}
