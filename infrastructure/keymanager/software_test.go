package keymanager

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	app "github.com/razatechofficial/mail-os/application/keymanager"
)

func masterKeyB64(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// assertKEK checks the KEK contract: a wrapped data key opens only under
// the same KEK and additional data, and does not show the key.
func assertKEK(t *testing.T, kek, other app.KEK) {
	t.Helper()
	ctx := context.Background()
	dek := bytes.Repeat([]byte{7}, 32)
	aad := []byte("mailos/key/kid-1")
	wrapped, err := kek.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped key holds the data key")
	}
	got, err := kek.Unwrap(ctx, wrapped, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("round trip: %x %v", got, err)
	}
	if _, err := kek.Unwrap(ctx, wrapped, []byte("mailos/key/kid-2")); err == nil {
		t.Fatal("data key opened for another kid")
	}
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 1
	if _, err := kek.Unwrap(ctx, tampered, aad); err == nil {
		t.Fatal("tampered data key opened")
	}
	if other != nil {
		if _, err := other.Unwrap(ctx, wrapped, aad); err == nil {
			t.Fatal("data key opened under another KEK")
		}
	}
}

func TestSoftwareKEK(t *testing.T) {
	a, err := NewSoftwareKEK("KEY_MANAGER_MASTER_KEY", masterKeyB64(1))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSoftwareKEK("KEY_MANAGER_NEW_MASTER_KEY", masterKeyB64(2))
	assertKEK(t, a, b)
	if !strings.HasPrefix(a.ID(), "software:") || len(a.ID()) != len("software:")+16 || a.ID() == b.ID() {
		t.Fatalf("ids %q %q", a.ID(), b.ID())
	}
	again, _ := NewSoftwareKEK("KEY_MANAGER_MASTER_KEY", masterKeyB64(1))
	if again.ID() != a.ID() {
		t.Fatal("master key id is not stable")
	}
	if strings.Contains(a.ID(), masterKeyB64(1)[:8]) {
		t.Fatal("id shows the key")
	}
	if _, err := NewSoftwareKEK("KEY_MANAGER_NEW_MASTER_KEY", "c2hvcnQ="); err == nil || !strings.Contains(err.Error(), "KEY_MANAGER_NEW_MASTER_KEY") {
		t.Fatalf("short key: %v", err)
	}
}
