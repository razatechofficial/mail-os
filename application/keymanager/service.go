package keymanager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	domain "github.com/razatechofficial/mail-os/domain/keymanager"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Config tunes rotation.
type Config struct {
	// RotationPeriod is the data keys' cryptoperiod (0 = on request only).
	RotationPeriod time.Duration
	// ReencryptBatch is how many values per retired key one tick rewraps.
	ReencryptBatch int
	// DestroyGrace keeps a drained retired key a little longer, for values
	// read just before the swap.
	DestroyGrace time.Duration
}

type loaded struct {
	key  domain.EncryptionKey
	aead cipher.AEAD
}

// Service is the keyring and its schedule.
type Service struct {
	provider Provider
	store    Store
	audit    Auditor
	cfg      Config
	now      func() time.Time

	columns []SealedColumn

	mu         sync.RWMutex
	keys       map[string]loaded
	active     map[domain.Purpose]string
	lastReload time.Time
}

// New builds the service; call Bootstrap before serving.
func New(provider Provider, store Store, audit Auditor, cfg Config) *Service {
	if cfg.ReencryptBatch <= 0 {
		cfg.ReencryptBatch = 500
	}
	if cfg.DestroyGrace <= 0 {
		cfg.DestroyGrace = time.Hour
	}
	return &Service{provider: provider, store: store, audit: audit, cfg: cfg, now: time.Now,
		keys: map[string]loaded{}, active: map[domain.Purpose]string{}}
}

// Register adds the columns whose values the schedule re-encrypts.
func (s *Service) Register(cols ...SealedColumn) { s.columns = append(s.columns, cols...) }

// Errors.
var (
	ErrUnknownPurpose = errors.New("unknown key purpose")
	ErrNoActiveKey    = errors.New("no active key for the purpose")
	ErrWrongPurpose   = errors.New("the value was not sealed for this purpose")
)

// Bootstrap makes sure each purpose has an active key, then loads them.
func (s *Service) Bootstrap(ctx context.Context) error {
	if err := s.Reload(ctx); err != nil {
		return err
	}
	for _, p := range domain.Purposes {
		s.mu.RLock()
		_, ok := s.active[p]
		s.mu.RUnlock()
		if ok {
			continue
		}
		if _, err := s.createKey(ctx, p, "system"); err != nil {
			// Another replica created it first: load theirs.
			if rerr := s.Reload(ctx); rerr != nil {
				return rerr
			}
			s.mu.RLock()
			_, ok = s.active[p]
			s.mu.RUnlock()
			if !ok {
				return fmt.Errorf("create %s key: %w", p, err)
			}
		}
	}
	return s.Reload(ctx)
}

// Reload reads every key and unwraps it.
func (s *Service) Reload(ctx context.Context) error {
	list, err := s.store.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	keys := make(map[string]loaded, len(list))
	active := map[domain.Purpose]string{}
	for _, k := range list {
		raw, err := s.provider.UnwrapDataKey(ctx, k.KeyRef, domain.WrapAdditionalData(k.KID))
		if err != nil {
			return fmt.Errorf("unwrap key %s: %w", k.KID, err)
		}
		aead, err := newGCM(raw)
		if err != nil {
			return err
		}
		keys[k.KID] = loaded{key: k, aead: aead}
		if k.State == domain.StateActive {
			active[k.Purpose] = k.KID
		}
	}
	s.mu.Lock()
	s.keys, s.active, s.lastReload = keys, active, s.now()
	s.mu.Unlock()
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Cipher returns the sealer of one purpose.
func (s *Service) Cipher(p domain.Purpose) Cipher { return purposeCipher{s: s, p: p} }

type purposeCipher struct {
	s *Service
	p domain.Purpose
}

func (c purposeCipher) Seal(ctx context.Context, plaintext []byte) (string, error) {
	return c.s.Seal(ctx, c.p, plaintext)
}

func (c purposeCipher) Open(ctx context.Context, ciphertext string) ([]byte, error) {
	return c.s.Open(ctx, c.p, ciphertext)
}

// Seal encrypts plaintext with the purpose's active key.
func (s *Service) Seal(ctx context.Context, p domain.Purpose, plaintext []byte) (string, error) {
	if !p.Valid() {
		return "", ErrUnknownPurpose
	}
	s.mu.RLock()
	kid, ok := s.active[p]
	k := s.keys[kid]
	s.mu.RUnlock()
	if !ok {
		if err := s.Reload(ctx); err != nil {
			return "", err
		}
		s.mu.RLock()
		kid, ok = s.active[p]
		k = s.keys[kid]
		s.mu.RUnlock()
		if !ok {
			return "", ErrNoActiveKey
		}
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := k.aead.Seal(nonce, nonce, plaintext, domain.AdditionalData(p, kid))
	return domain.FormatCiphertext(kid, sealed), nil
}

// Open decrypts a value sealed for purpose p. A kid this replica has not
// loaded (another replica rotated) triggers one reload, at most every 5 s.
func (s *Service) Open(ctx context.Context, p domain.Purpose, ciphertext string) ([]byte, error) {
	kid, sealed, err := domain.ParseCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	k, ok := s.keys[kid]
	recent := s.now().Sub(s.lastReload) < 5*time.Second
	s.mu.RUnlock()
	if !ok && !recent {
		if err := s.Reload(ctx); err != nil {
			return nil, err
		}
		s.mu.RLock()
		k, ok = s.keys[kid]
		s.mu.RUnlock()
	}
	if !ok {
		return nil, fmt.Errorf("unknown encryption key %q", kid)
	}
	if k.key.Purpose != p {
		return nil, ErrWrongPurpose
	}
	ns := k.aead.NonceSize()
	if len(sealed) < ns {
		return nil, domain.ErrCiphertextFormat
	}
	out, err := k.aead.Open(nil, sealed[:ns], sealed[ns:], domain.AdditionalData(p, kid))
	if err != nil {
		return nil, fmt.Errorf("open %s value: %w", p, err)
	}
	return out, nil
}

func (s *Service) createKey(ctx context.Context, p domain.Purpose, by string) (domain.EncryptionKey, error) {
	kid, err := domain.NewKID()
	if err != nil {
		return domain.EncryptionKey{}, err
	}
	ref, err := s.provider.NewDataKey(ctx, domain.WrapAdditionalData(kid))
	if err != nil {
		return domain.EncryptionKey{}, fmt.Errorf("new data key: %w", err)
	}
	k := domain.EncryptionKey{ID: uuid.Must(uuid.NewV7()), KID: kid, Purpose: p, State: domain.StateActive,
		Provider: s.provider.Name(), KeyRef: ref, CreatedBy: by, CreatedAt: s.now().UTC()}
	if err := s.store.InsertKey(ctx, k); err != nil {
		return domain.EncryptionKey{}, err
	}
	s.record(ctx, k, "encryption_key.created", nil)
	return k, nil
}

// Rotate retires the purpose's active key and activates a new one. Values
// the old key sealed keep opening until the schedule re-encrypts them.
func (s *Service) Rotate(ctx context.Context, p domain.Purpose, by string) (domain.EncryptionKey, error) {
	if !p.Valid() {
		return domain.EncryptionKey{}, ErrUnknownPurpose
	}
	var created domain.EncryptionKey
	ran, err := s.store.WithLock(ctx, func(ctx context.Context) error {
		var err error
		created, err = s.rotateLocked(ctx, p, by)
		return err
	})
	if err != nil {
		return domain.EncryptionKey{}, err
	}
	if !ran {
		return domain.EncryptionKey{}, errors.New("another replica is rotating keys; try again")
	}
	return created, s.Reload(ctx)
}

func (s *Service) rotateLocked(ctx context.Context, p domain.Purpose, by string) (domain.EncryptionKey, error) {
	list, err := s.store.ListKeys(ctx)
	if err != nil {
		return domain.EncryptionKey{}, err
	}
	for _, k := range list {
		if k.Purpose == p && k.State == domain.StateActive {
			if err := s.store.RetireKey(ctx, k.ID, s.now().UTC()); err != nil {
				return domain.EncryptionKey{}, err
			}
			s.record(ctx, k, "encryption_key.rotated", map[string]any{"by": by})
		}
	}
	return s.createKey(ctx, p, by)
}

// Tick is the schedule (an asynq task every minute, one replica at a time):
// rotate keys past their cryptoperiod, re-encrypt a batch of what retired
// keys sealed, and destroy retired keys with nothing left after the grace.
func (s *Service) Tick(ctx context.Context) error {
	_, err := s.store.WithLock(ctx, func(ctx context.Context) error {
		list, err := s.store.ListKeys(ctx)
		if err != nil {
			return err
		}
		now := s.now()
		for _, k := range list {
			if k.Due(now, s.cfg.RotationPeriod) {
				if _, err := s.rotateLocked(ctx, k.Purpose, "schedule"); err != nil {
					return err
				}
			}
		}
		if err := s.Reload(ctx); err != nil {
			return err
		}
		for _, k := range list {
			if k.State != domain.StateRetired {
				continue
			}
			if err := s.drain(ctx, k); err != nil {
				s.record(ctx, k, "encryption_key.reencrypt_error", map[string]any{"error": err.Error()})
				logger.Error("re-encryption failed", logger.String("kid", k.KID), logger.Err(err))
			}
		}
		return nil
	})
	return err
}

func (s *Service) drain(ctx context.Context, k domain.EncryptionKey) error {
	remaining, moved := 0, 0
	for _, col := range s.columns {
		if col.Purpose() != k.Purpose {
			continue
		}
		n, err := col.Reencrypt(ctx, k.KID, s.cfg.ReencryptBatch, func(old string) (string, error) {
			plain, err := s.Open(ctx, k.Purpose, old)
			if err != nil {
				return "", err
			}
			return s.Seal(ctx, k.Purpose, plain)
		})
		if err != nil {
			return fmt.Errorf("%s: %w", col.Name(), err)
		}
		moved += n
		left, err := col.CountByKID(ctx, k.KID)
		if err != nil {
			return err
		}
		remaining += left
	}
	if moved > 0 {
		s.record(ctx, k, "encryption_key.reencrypted", map[string]any{"values": moved})
	}
	if remaining == 0 && k.RetiredAt != nil && s.now().Sub(*k.RetiredAt) >= s.cfg.DestroyGrace {
		if err := s.store.DeleteKey(ctx, k.ID); err != nil {
			return err
		}
		s.record(ctx, k, "encryption_key.destroyed", nil)
	}
	return nil
}

// PurposeStatus is what the admin API shows for one purpose.
type PurposeStatus struct {
	Purpose domain.Purpose `json:"purpose"`
	Keys    []KeyStatus    `json:"keys"`
}

// KeyStatus describes one key, never its material.
type KeyStatus struct {
	KID       string       `json:"kid"`
	State     domain.State `json:"state"`
	Provider  string       `json:"provider"`
	CreatedAt time.Time    `json:"created_at"`
	RetiredAt *time.Time   `json:"retired_at,omitempty"`
	Values    int          `json:"values"`
}

// Status lists keys per purpose with how many values each still seals.
func (s *Service) Status(ctx context.Context) ([]PurposeStatus, error) {
	list, err := s.store.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PurposeStatus, 0, len(domain.Purposes))
	for _, p := range domain.Purposes {
		ps := PurposeStatus{Purpose: p, Keys: []KeyStatus{}}
		for _, k := range list {
			if k.Purpose != p {
				continue
			}
			ks := KeyStatus{KID: k.KID, State: k.State, Provider: k.Provider, CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt}
			for _, col := range s.columns {
				if col.Purpose() == p {
					n, err := col.CountByKID(ctx, k.KID)
					if err != nil {
						return nil, err
					}
					ks.Values += n
				}
			}
			ps.Keys = append(ps.Keys, ks)
		}
		out = append(out, ps)
	}
	return out, nil
}

func (s *Service) record(ctx context.Context, k domain.EncryptionKey, action string, meta map[string]any) {
	if s.audit == nil {
		return
	}
	m := map[string]any{"purpose": string(k.Purpose), "kid": k.KID}
	for key, v := range meta {
		m[key] = v
	}
	if err := s.audit.Append(ctx, "encryption_key", k.KID, action, m); err != nil {
		logger.Error("audit key event", logger.String("action", action), logger.Err(err))
	}
}
