package keymanager_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
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
	mu        sync.Mutex
	keys      []domain.EncryptionKey
	rotations []domain.KEKRotation
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
func (m *memStore) ReplaceKeyRef(_ context.Context, id uuid.UUID, oldRef, newRef []byte, kekID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.keys {
		if m.keys[i].ID == id && bytes.Equal(m.keys[i].KeyRef, oldRef) {
			m.keys[i].KeyRef, m.keys[i].KEKID, m.keys[i].Provider = newRef, kekID, domain.KEKProvider(kekID)
			return true, nil
		}
	}
	return false, nil
}
func (m *memStore) WithLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}
func (m *memStore) LatestKEKRotation(context.Context) (*domain.KEKRotation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rotations) == 0 {
		return nil, nil
	}
	r := m.rotations[len(m.rotations)-1]
	return &r, nil
}
func (m *memStore) ListKEKRotations(_ context.Context, limit int) ([]domain.KEKRotation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]domain.KEKRotation(nil), m.rotations...)
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (m *memStore) InsertKEKRotation(_ context.Context, r domain.KEKRotation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.rotations {
		if x.State == domain.RotationRewrapping {
			return errors.New("duplicate running rotation")
		}
	}
	m.rotations = append(m.rotations, r)
	return nil
}
func (m *memStore) UpdateKEKRotation(_ context.Context, r domain.KEKRotation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rotations {
		if m.rotations[i].ID == r.ID {
			m.rotations[i] = r
		}
	}
	return nil
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

// masterKey is a software KEK of 32 copies of b.
func masterKey(t *testing.T, b byte) app.KEK {
	t.Helper()
	k, err := infra.NewSoftwareKEK("KEY_MANAGER_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keks(t *testing.T, current, next app.KEK) *app.KEKs {
	t.Helper()
	k, err := app.NewKEKs(current, next)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newService(t *testing.T, store *memStore, audit *auditLog) *app.Service {
	t.Helper()
	s := app.New(keks(t, masterKey(t, 0), nil), store, audit, app.Config{ReencryptBatch: 1, DestroyGrace: time.Nanosecond})
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
	if err := app.New(keks(t, masterKey(t, 'x'), nil), store, nil, app.Config{}).Bootstrap(context.Background()); err == nil {
		t.Fatal("keys unwrapped with another master key")
	}
}

// Evidence MACs: one active key for every input, verifiable by kid after a
// rotation, refused for any other purpose, and not reproducible without
// the key: neither a bare SHA-256 nor another deployment's key gives them.
func TestEvidenceMAC(t *testing.T) {
	ctx := context.Background()
	s := newService(t, &memStore{}, &auditLog{})
	kid, macs, err := s.MAC(ctx, domain.PurposeEvidence, []byte("subject"), []byte("Your code is 482913"))
	if err != nil || kid == "" || len(macs) != 2 || len(macs[1]) != sha256.Size {
		t.Fatalf("mac %q %d %v", kid, len(macs), err)
	}
	if ok, err := s.VerifyMAC(ctx, domain.PurposeEvidence, kid, []byte("Your code is 482913"), macs[1]); !ok || err != nil {
		t.Fatalf("verify %v %v", ok, err)
	}
	if ok, _ := s.VerifyMAC(ctx, domain.PurposeEvidence, kid, []byte("Your code is 482914"), macs[1]); ok {
		t.Fatal("another code verified")
	}
	bare := sha256.Sum256([]byte("Your code is 482913"))
	if bytes.Equal(bare[:], macs[1]) {
		t.Fatal("the MAC is a bare hash")
	}
	other := app.New(keks(t, masterKey(t, 'o'), nil), &memStore{}, nil, app.Config{})
	if err := other.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, theirs, _ := other.MAC(ctx, domain.PurposeEvidence, []byte("Your code is 482913")); bytes.Equal(theirs[0], macs[1]) {
		t.Fatal("another key reproduced the MAC")
	}
	if _, err := other.VerifyMAC(ctx, domain.PurposeEvidence, kid, []byte("Your code is 482913"), macs[1]); err == nil {
		t.Fatal("a deployment without the key verified")
	}
	if _, err := s.Rotate(ctx, domain.PurposeEvidence, "test"); err != nil {
		t.Fatal(err)
	}
	newKid, _, _ := s.MAC(ctx, domain.PurposeEvidence, []byte("x"))
	if newKid == kid {
		t.Fatal("rotation kept the key")
	}
	if ok, err := s.VerifyMAC(ctx, domain.PurposeEvidence, kid, []byte("Your code is 482913"), macs[1]); !ok || err != nil {
		t.Fatalf("a retired key no longer verifies: %v %v", ok, err)
	}
	if _, _, err := s.MAC(ctx, domain.PurposeProvider, []byte("x")); !errors.Is(err, app.ErrNotEvidence) {
		t.Fatalf("MAC under the provider purpose: %v", err)
	}
}
