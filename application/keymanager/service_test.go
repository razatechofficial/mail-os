package keymanager_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	app "github.com/razatechofficial/mail-os/application/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/keymanager"
	infra "github.com/razatechofficial/mail-os/infrastructure/keymanager"
)

type memStore struct {
	mu   sync.Mutex
	keys []domain.EncryptionKey
}

func (m *memStore) ListKeys(context.Context) ([]domain.EncryptionKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]domain.EncryptionKey(nil), m.keys...), nil
}
func (m *memStore) InsertKey(_ context.Context, k domain.EncryptionKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.keys {
		if x.Purpose == k.Purpose && x.State == domain.StateActive {
			return errors.New("duplicate active key")
		}
	}
	m.keys = append(m.keys, k)
	return nil
}
func (m *memStore) RetireKey(_ context.Context, id uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.keys {
		if m.keys[i].ID == id {
			m.keys[i].State, m.keys[i].RetiredAt = domain.StateRetired, &at
		}
	}
	return nil
}
func (m *memStore) DeleteKey(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.keys {
		if m.keys[i].ID == id {
			m.keys = append(m.keys[:i], m.keys[i+1:]...)
			return nil
		}
	}
	return nil
}
func (m *memStore) WithLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

// column is one sealed column of provider credentials.
type column struct{ values []string }

func (c *column) Purpose() domain.Purpose { return domain.PurposeProvider }
func (c *column) Name() string            { return "providers.credentials" }
func (c *column) CountByKID(_ context.Context, kid string) (int, error) {
	n := 0
	for _, v := range c.values {
		if strings.HasPrefix(v, "km1."+kid+".") {
			n++
		}
	}
	return n, nil
}
func (c *column) Reencrypt(_ context.Context, kid string, limit int, rewrap func(string) (string, error)) (int, error) {
	n := 0
	for i, v := range c.values {
		if n < limit && strings.HasPrefix(v, "km1."+kid+".") {
			nv, err := rewrap(v)
			if err != nil {
				return n, err
			}
			c.values[i] = nv
			n++
		}
	}
	return n, nil
}

type auditLog struct{ actions []string }

func (a *auditLog) Append(_ context.Context, _, _, action string, _ map[string]any) error {
	a.actions = append(a.actions, action)
	return nil
}

func newService(t *testing.T, store *memStore, audit *auditLog) *app.Service {
	t.Helper()
	p, err := infra.NewSoftwareProvider(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s := app.New(p, store, audit, app.Config{ReencryptBatch: 1, DestroyGrace: time.Nanosecond})
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSealOpenRotateReencryptDestroy(t *testing.T) {
	ctx := context.Background()
	store, audit := &memStore{}, &auditLog{}
	s := newService(t, store, audit)
	if len(store.keys) != len(domain.Purposes) {
		t.Fatalf("bootstrap created %d keys", len(store.keys))
	}
	c := s.Cipher(domain.PurposeProvider)
	sealed, err := c.Seal(ctx, []byte("smtp-password"))
	if err != nil || !domain.IsCiphertext(sealed) || strings.Contains(sealed, "smtp-password") {
		t.Fatalf("seal: %q %v", sealed, err)
	}
	if _, err := s.Open(ctx, domain.PurposeDKIM, sealed); !errors.Is(err, app.ErrWrongPurpose) {
		t.Fatalf("value opened under another purpose: %v", err)
	}
	if _, err := c.Open(ctx, "plain-legacy-secret"); !errors.Is(err, domain.ErrCiphertextFormat) {
		t.Fatalf("legacy plaintext accepted: %v", err)
	}
	col := &column{values: []string{sealed}}
	second, _ := c.Seal(ctx, []byte("api-key"))
	col.values = append(col.values, second)
	s.Register(col)

	if _, err := s.Rotate(ctx, domain.PurposeProvider, "admin"); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Open(ctx, sealed); err != nil || string(got) != "smtp-password" {
		t.Fatalf("value sealed by the retired key: %q %v", got, err)
	}
	// Two ticks: the batch is 1, the retired key is destroyed once drained.
	for i := 0; i < 3; i++ {
		if err := s.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	oldKID, _, _ := domain.ParseCiphertext(sealed)
	for _, v := range col.values {
		if strings.HasPrefix(v, "km1."+oldKID+".") {
			t.Fatal("value not re-encrypted")
		}
	}
	for _, k := range store.keys {
		if k.KID == oldKID {
			t.Fatal("drained retired key not destroyed")
		}
	}
	if got, _ := c.Open(ctx, col.values[0]); string(got) != "smtp-password" {
		t.Fatal("re-encrypted value lost")
	}
	want := map[string]bool{"encryption_key.created": false, "encryption_key.rotated": false, "encryption_key.reencrypted": false, "encryption_key.destroyed": false}
	for _, a := range audit.actions {
		want[a] = true
	}
	for a, seen := range want {
		if !seen {
			t.Errorf("no %s audit event", a)
		}
	}
}

func TestTamperedValueRefused(t *testing.T) {
	ctx := context.Background()
	s := newService(t, &memStore{}, &auditLog{})
	sealed, _ := s.Seal(ctx, domain.PurposeWebhook, []byte("whsec"))
	kid, data, _ := domain.ParseCiphertext(sealed)
	data[len(data)-1] ^= 1
	if _, err := s.Open(ctx, domain.PurposeWebhook, domain.FormatCiphertext(kid, data)); err == nil {
		t.Fatal("tampered value opened")
	}
}

func TestWrongMasterKeyCannotLoad(t *testing.T) {
	store := &memStore{}
	newService(t, store, &auditLog{})
	other, _ := infra.NewSoftwareProvider(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))))
	if err := app.New(other, store, nil, app.Config{}).Bootstrap(context.Background()); err == nil {
		t.Fatal("keys unwrapped with another master key")
	}
}
