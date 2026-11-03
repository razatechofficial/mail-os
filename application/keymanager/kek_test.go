package keymanager_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	app "github.com/razatechofficial/mail-os/application/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/keymanager"
	infra "github.com/razatechofficial/mail-os/infrastructure/keymanager"
)

// hsm stands in for a PKCS#11 token: AES keys stay inside it, by label.
type hsm struct {
	mu   sync.Mutex
	keys map[string]cipher.AEAD
}

func newAEAD() cipher.AEAD {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, _ := aes.NewCipher(k)
	a, _ := cipher.NewGCM(b)
	return a
}

func (h *hsm) EnsureKEK(_ context.Context, label string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.keys == nil {
		h.keys = map[string]cipher.AEAD{}
	}
	if h.keys[label] == nil {
		h.keys[label] = newAEAD()
	}
	return nil
}

func (h *hsm) key(label string) (cipher.AEAD, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if a := h.keys[label]; a != nil {
		return a, nil
	}
	return nil, errors.New("CKR_KEY_HANDLE_INVALID")
}

func (h *hsm) Encrypt(_ context.Context, label string, plain, aad []byte) ([]byte, error) {
	a, err := h.key(label)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	return a.Seal(nonce, nonce, plain, aad), nil
}

func (h *hsm) Decrypt(_ context.Context, label string, sealed, aad []byte) ([]byte, error) {
	a, err := h.key(label)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], aad)
}

func (h *hsm) Close() {}

func hsmKEK(t *testing.T, h *hsm, label string) app.KEK {
	t.Helper()
	k, err := infra.NewDeviceKEK(context.Background(), h, label)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// flaky fails Wrap while failing is set, as an HSM or KMS outage would.
type flaky struct {
	app.KEK
	mu      sync.Mutex
	failing bool
	wraps   int
}

func (f *flaky) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wraps++
	if f.failing && f.wraps%2 == 0 {
		return nil, errors.New("CKR_DEVICE_ERROR")
	}
	return f.KEK.Wrap(ctx, dek, aad)
}

func bootstrap(t *testing.T, k *app.KEKs, store *memStore, audit *auditLog) *app.Service {
	t.Helper()
	s := app.New(k, store, audit, app.Config{ReencryptBatch: 1, KEKSettle: time.Nanosecond})
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// sealAll seals one value per purpose and retires a key, so the store holds
// active and retired data keys.
func sealAll(t *testing.T, s *app.Service) map[domain.Purpose]string {
	t.Helper()
	ctx := context.Background()
	out := map[domain.Purpose]string{}
	for _, p := range domain.Purposes {
		v, err := s.Seal(ctx, p, []byte("secret of "+string(p)))
		if err != nil {
			t.Fatal(err)
		}
		out[p] = v
	}
	if _, err := s.Rotate(ctx, domain.PurposeDKIM, "test"); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertOpens(t *testing.T, s *app.Service, sealed map[domain.Purpose]string) {
	t.Helper()
	for p, v := range sealed {
		got, err := s.Open(context.Background(), p, v)
		if err != nil || string(got) != "secret of "+string(p) {
			t.Fatalf("%s: %q %v", p, got, err)
		}
	}
}

func kekIDs(store *memStore) map[string]int {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := map[string]int{}
	for _, k := range store.keys {
		out[k.KEKID]++
	}
	return out
}

// A KEK rotation re-wraps every data key under the new KEK without
// changing it: values sealed before keep opening, under the new KEK alone.
// It runs between providers too: from the master key into an HSM, from
// one HSM key to another, and into KMS.
func TestKEKRotationRewrapsEveryDataKey(t *testing.T) {
	token := &hsm{}
	remote := &remoteKMS{keys: map[string]cipher.AEAD{}}
	steps := []struct {
		name string
		to   func(t *testing.T) app.KEK
	}{
		{"new master key", func(t *testing.T) app.KEK { return masterKey(t, 1) }},
		{"master key into the HSM", func(t *testing.T) app.KEK { return hsmKEK(t, token, "mailos-kek") }},
		{"new HSM key", func(t *testing.T) app.KEK { return hsmKEK(t, token, "mailos-kek-2027") }},
		{"HSM into KMS", func(t *testing.T) app.KEK { return remote.kek(t, "alias/mailos-kek") }},
	}
	ctx := context.Background()
	store, audit := &memStore{}, &auditLog{}
	from := masterKey(t, 0)
	sealed := sealAll(t, bootstrap(t, keks(t, from, nil), store, audit))
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			to := step.to(t)
			// Every replica is redeployed with the new KEK beside the current one.
			s := bootstrap(t, keks(t, from, to), store, audit)
			r, err := s.StartKEKRotation(ctx, "admin", "annual rotation")
			if err != nil {
				t.Fatal(err)
			}
			if r.FromKEK != from.ID() || r.ToKEK != to.ID() || r.Total != len(store.keys) {
				t.Fatalf("rotation %+v", r)
			}
			// New data keys are wrapped under the new KEK at once.
			if _, err := s.Rotate(ctx, domain.PurposeWebhook, "admin"); err != nil {
				t.Fatal(err)
			}
			if err := s.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			if ids := kekIDs(store); len(ids) != 1 || ids[to.ID()] != len(store.keys) {
				t.Fatalf("data keys by KEK after the pass: %v", ids)
			}
			st, err := s.KEKStatus(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if st.Rotation != nil || st.History[0].State != domain.RotationCompleted || st.History[0].Rewrapped == 0 || st.WrappingKEK != to.ID() {
				t.Fatalf("status %+v", st)
			}
			// Promoted: the new KEK alone opens everything.
			promoted := bootstrap(t, keks(t, to, nil), store, audit)
			assertOpens(t, promoted, sealed)
			// The old KEK alone no longer opens anything.
			if err := app.New(keks(t, from, nil), store, nil, app.Config{}).Bootstrap(ctx); !errors.Is(err, domain.ErrKEKNotConfigured) {
				t.Fatalf("old KEK alone: %v", err)
			}
			from = to
		})
	}
	seen := map[string]bool{}
	for _, a := range audit.actions {
		seen[a] = true
	}
	for _, a := range []string{"kek.rotation_started", "kek.rewrapped", "kek.rotation_completed"} {
		if !seen[a] {
			t.Errorf("no %s audit event", a)
		}
	}
}

// A pass that fails part-way leaves the rotation running with what is
// left; the next pass, on any replica, finishes it.
func TestKEKRotationResumes(t *testing.T) {
	ctx := context.Background()
	store, audit := &memStore{}, &auditLog{}
	old, target := masterKey(t, 0), &flaky{KEK: masterKey(t, 1)}
	sealed := sealAll(t, bootstrap(t, keks(t, old, nil), store, audit))

	s := bootstrap(t, keks(t, old, target), store, audit)
	if _, err := s.StartKEKRotation(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	target.failing = true
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ := store.LatestKEKRotation(ctx)
	moved := kekIDs(store)[target.ID()]
	if r.State != domain.RotationRewrapping || r.Failed == 0 || r.LastError == "" || moved == 0 || r.Rewrapped != moved {
		t.Fatalf("after a failing pass: %+v (%d moved)", r, moved)
	}
	// Values open meanwhile, whichever KEK wraps their data key.
	assertOpens(t, bootstrap(t, keks(t, old, target), store, audit), sealed)

	// Another replica (or a restart) carries on from the store.
	target.failing = false
	other := bootstrap(t, keks(t, old, target), store, audit)
	if err := other.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ = store.LatestKEKRotation(ctx)
	if r.State != domain.RotationCompleted || r.Remaining != 0 || r.Failed != 0 || r.Rewrapped != len(store.keys) {
		t.Fatalf("after the resumed pass: %+v", r)
	}
	// Idempotent: another pass changes nothing.
	before := fmt.Sprint(store.keys)
	if err := other.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(store.keys) != before {
		t.Fatal("a pass over a completed rotation rewrote data keys")
	}
	assertOpens(t, bootstrap(t, keks(t, target, nil), store, audit), sealed)
}

func TestKEKRotationRefusals(t *testing.T) {
	ctx := context.Background()
	store := &memStore{}
	old, next := masterKey(t, 0), masterKey(t, 1)
	s := bootstrap(t, keks(t, old, nil), store, &auditLog{})
	if _, err := s.StartKEKRotation(ctx, "admin", ""); !errors.Is(err, app.ErrNoNewKEK) {
		t.Fatalf("without a new KEK: %v", err)
	}
	if _, err := app.NewKEKs(old, masterKey(t, 0)); err == nil {
		t.Fatal("the current KEK accepted as the new one")
	}
	s = app.New(keks(t, old, next), store, nil, app.Config{KEKSettle: time.Hour})
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartKEKRotation(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartKEKRotation(ctx, "admin", ""); !errors.Is(err, app.ErrKEKRotationActive) {
		t.Fatalf("second rotation: %v", err)
	}
	// The settle time keeps the drained rotation running.
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := store.LatestKEKRotation(ctx); r.State != domain.RotationRewrapping || r.Remaining != 0 {
		t.Fatalf("completed before the settle time: %+v", r)
	}
	store.rotations[0].StartedAt = time.Now().Add(-2 * time.Hour)
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartKEKRotation(ctx, "admin", ""); !errors.Is(err, app.ErrSameKEK) {
		t.Fatalf("rotation to the KEK already wrapping: %v", err)
	}
	// A replica without the rotation's KEK refuses to start.
	if err := app.New(keks(t, old, masterKey(t, 2)), store, nil, app.Config{}).Bootstrap(ctx); !errors.Is(err, domain.ErrKEKNotConfigured) {
		t.Fatalf("replica without the new KEK: %v", err)
	}
}

// Data keys wrapped before KEKs were recorded open under the configured
// KEK, and the schedule records it.
func TestUnrecordedKEKIsRecorded(t *testing.T) {
	ctx := context.Background()
	store := &memStore{}
	kek := masterKey(t, 0)
	sealed := sealAll(t, bootstrap(t, keks(t, kek, nil), store, &auditLog{}))
	for i := range store.keys {
		store.keys[i].KEKID = ""
	}
	s := bootstrap(t, keks(t, kek, nil), store, &auditLog{})
	assertOpens(t, s, sealed)
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if ids := kekIDs(store); ids[kek.ID()] != len(store.keys) {
		t.Fatalf("KEKs not recorded: %v", ids)
	}
	assertOpens(t, bootstrap(t, keks(t, kek, nil), store, &auditLog{}), sealed)
}

// remoteKMS stands in for a cloud key service: keys by ARN, aliases
// resolved to them.
type remoteKMS struct {
	mu   sync.Mutex
	keys map[string]cipher.AEAD
}

func (r *remoteKMS) kek(t *testing.T, alias string) app.KEK {
	t.Helper()
	r.mu.Lock()
	r.keys["arn:aws:kms:me-central-1:000000000000:key/"+alias[len("alias/"):]] = newAEAD()
	r.mu.Unlock()
	k, err := infra.NewExternalKEK(context.Background(), domain.ProviderKMS, r, alias)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (r *remoteKMS) Resolve(_ context.Context, keyID string) (string, error) {
	arn := "arn:aws:kms:me-central-1:000000000000:key/" + keyID[len("alias/"):]
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys[arn] == nil {
		return "", errors.New("NotFoundException")
	}
	return arn, nil
}

func (r *remoteKMS) Encrypt(_ context.Context, keyID string, plain, aad []byte) ([]byte, error) {
	r.mu.Lock()
	a := r.keys[keyID]
	r.mu.Unlock()
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	return a.Seal(nonce, nonce, plain, aad), nil
}

func (r *remoteKMS) Decrypt(_ context.Context, keyID string, ct, aad []byte) ([]byte, error) {
	r.mu.Lock()
	a := r.keys[keyID]
	r.mu.Unlock()
	return a.Open(nil, ct[:a.NonceSize()], ct[a.NonceSize():], aad)
}
