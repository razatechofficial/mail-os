package keymanager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	domain "github.com/razatechofficial/mail-os/domain/keymanager"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// KEKs are the key-encryption keys this replica holds: the current one
// (KEY_MANAGER_PROVIDER's) and, while data keys move, the new one. One of
// them wraps new data keys: the current KEK, or the new one once a KEK
// rotation names it.
type KEKs struct {
	current, next KEK

	mu   sync.RWMutex
	wrap KEK
}

// NewKEKs returns the ring; next is nil when no new KEK is configured.
func NewKEKs(current, next KEK) (*KEKs, error) {
	if current == nil {
		return nil, errors.New("key manager: no key-encryption key")
	}
	if next != nil && next.ID() == current.ID() {
		return nil, fmt.Errorf("key manager: the new key-encryption key is the current one (%s)", current.ID())
	}
	return &KEKs{current: current, next: next, wrap: current}, nil
}

// Current is KEY_MANAGER_PROVIDER's KEK.
func (k *KEKs) Current() KEK { return k.current }

// Next is the new KEK, nil when none is configured.
func (k *KEKs) Next() KEK { return k.next }

// Wrapping is the KEK new data keys are wrapped under.
func (k *KEKs) Wrapping() KEK {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.wrap
}

func (k *KEKs) get(id string) KEK {
	if k.current.ID() == id {
		return k.current
	}
	if k.next != nil && k.next.ID() == id {
		return k.next
	}
	return nil
}

func (k *KEKs) setWrapping(id string) error {
	kek := k.get(id)
	if kek == nil {
		return fmt.Errorf("%w: %s", domain.ErrKEKNotConfigured, id)
	}
	k.mu.Lock()
	k.wrap = kek
	k.mu.Unlock()
	return nil
}

// unwrap opens a data key with the KEK that wrapped it. A key wrapped
// before KEKs were recorded (kekID "") is tried under each configured KEK:
// AES-GCM and the HSM or KMS authenticate it, so a wrong KEK fails.
func (k *KEKs) unwrap(ctx context.Context, kekID string, ref, aad []byte) ([]byte, error) {
	var keks []KEK
	if kekID == "" {
		keks = []KEK{k.current}
		if k.next != nil {
			keks = append(keks, k.next)
		}
	} else if kek := k.get(kekID); kek != nil {
		keks = []KEK{kek}
	} else {
		return nil, fmt.Errorf("%w: %s", domain.ErrKEKNotConfigured, kekID)
	}
	var lastErr error
	for _, kek := range keks {
		raw, err := kek.Unwrap(ctx, ref, aad)
		if err == nil {
			if len(raw) != 32 {
				clear(raw)
				return nil, errors.New("data key is not 32 bytes")
			}
			return raw, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// KEK rotation errors the API maps to responses.
var (
	ErrNoNewKEK = apperrors.NewAppError(apperrors.KindConflict, "NO_NEW_KEK",
		domain.ErrNoNewKEK.Error()+"; set it beside the current one on every replica first")
	ErrSameKEK           = apperrors.NewAppError(apperrors.KindConflict, "KEK_ALREADY_CURRENT", domain.ErrSameKEK.Error())
	ErrKEKRotationActive = apperrors.NewAppError(apperrors.KindConflict, "KEK_ROTATION_RUNNING", domain.ErrKEKRotationActive.Error())
	ErrScheduleBusy      = apperrors.NewAppError(apperrors.KindConflict, "KEY_SCHEDULE_BUSY", "another replica is running the key schedule; try again")
)

// syncKEK makes this replica wrap under the KEK the latest rotation names,
// or the current KEK when none ran. A rotation to a KEK not configured here
// stops the replica: it could not open the data keys wrapped under it.
func (s *Service) syncKEK(ctx context.Context) error {
	r, err := s.store.LatestKEKRotation(ctx)
	if err != nil {
		return fmt.Errorf("latest KEK rotation: %w", err)
	}
	target := s.keks.Current().ID()
	if r != nil {
		target = r.ToKEK
	}
	if s.keks.Wrapping().ID() == target {
		return nil
	}
	if err := s.keks.setWrapping(target); err != nil {
		return fmt.Errorf("the latest KEK rotation wraps data keys under %s: configure it on this replica: %w", target, err)
	}
	logger.Info("key manager: wrapping new data keys under the rotation's KEK", logger.String("kek_id", target))
	return nil
}

// StartKEKRotation moves every data key to the new KEK. New data keys are
// wrapped under it at once; the schedule re-wraps the others. Configure the
// new KEK on every replica before starting.
func (s *Service) StartKEKRotation(ctx context.Context, by, reason string) (*domain.KEKRotation, error) {
	next := s.keks.Next()
	if next == nil {
		return nil, ErrNoNewKEK
	}
	var out domain.KEKRotation
	ran, err := s.store.WithLock(ctx, func(ctx context.Context) error {
		if err := s.syncKEK(ctx); err != nil {
			return err
		}
		latest, err := s.store.LatestKEKRotation(ctx)
		if err != nil {
			return err
		}
		if latest != nil && latest.State == domain.RotationRewrapping {
			return ErrKEKRotationActive
		}
		from := s.keks.Wrapping().ID()
		if from == next.ID() {
			return ErrSameKEK
		}
		keys, err := s.store.ListKeys(ctx)
		if err != nil {
			return err
		}
		out = domain.KEKRotation{ID: uuid.Must(uuid.NewV7()), FromKEK: from, ToKEK: next.ID(), State: domain.RotationRewrapping,
			Reason: reason, RequestedBy: by, StartedAt: s.now().UTC(), Total: len(keys), Remaining: len(keys)}
		if err := s.store.InsertKEKRotation(ctx, out); err != nil {
			return err
		}
		if err := s.keks.setWrapping(out.ToKEK); err != nil {
			return err
		}
		meta := map[string]any{"from_kek_id": out.FromKEK, "to_kek_id": out.ToKEK, "keys": out.Total, "by": by}
		if reason != "" {
			meta["reason"] = reason
		}
		s.recordKEK(ctx, out.ID, "kek.rotation_started", meta)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !ran {
		return nil, ErrScheduleBusy
	}
	return &out, nil
}

// rewrapKEKs is the schedule's KEK pass, under the key manager's lock: it
// re-wraps every data key not under the wrapping KEK (the latest rotation's
// target, or the current KEK) and completes a running rotation when none is
// left. A key is swapped only if its row is unchanged, so the pass can stop
// anywhere and the next one carries on. A completed rotation is checked too:
// a replica that wrapped a key under the old KEK just before the start is
// caught.
func (s *Service) rewrapKEKs(ctx context.Context) error {
	if err := s.syncKEK(ctx); err != nil {
		return err
	}
	target := s.keks.Wrapping()
	keys, err := s.store.ListKeys(ctx)
	if err != nil {
		return err
	}
	moved, remaining, failed, lastErr := 0, 0, 0, ""
	for _, k := range keys {
		if k.KEKID == target.ID() {
			continue
		}
		ok, err := s.rewrapKey(ctx, k, target)
		switch {
		case err != nil:
			failed++
			lastErr = k.KID + ": " + err.Error()
			logger.Error("data key not re-wrapped under the new KEK", logger.String("kid", k.KID), logger.String("kek_id", target.ID()), logger.Err(err))
		case ok:
			moved++
		default:
			// Changed or destroyed meanwhile: the next pass looks again.
			remaining++
		}
	}
	r, err := s.store.LatestKEKRotation(ctx)
	if err != nil || r == nil {
		return err
	}
	if r.State == domain.RotationCompleted && moved == 0 && failed == 0 {
		return nil
	}
	r.Total, r.Rewrapped, r.Remaining, r.Failed, r.LastError = len(keys), r.Rewrapped+moved, remaining+failed, failed, lastErr
	if moved > 0 {
		s.recordKEK(ctx, r.ID, "kek.rewrapped", map[string]any{"to_kek_id": r.ToKEK, "count": moved, "remaining": r.Remaining})
	}
	if failed > 0 {
		s.recordKEK(ctx, r.ID, "kek.rotation_error", map[string]any{"to_kek_id": r.ToKEK, "failed": failed, "error": lastErr})
	}
	if r.Done(s.now(), s.cfg.KEKSettle) {
		r.Complete(s.now().UTC())
		s.recordKEK(ctx, r.ID, "kek.rotation_completed", map[string]any{
			"from_kek_id": r.FromKEK, "to_kek_id": r.ToKEK, "keys": r.Total, "rewrapped": r.Rewrapped})
		logger.Info("KEK rotation completed; the old KEK can leave configuration once the new one is made current",
			logger.String("kek_id", r.ToKEK))
	}
	return s.store.UpdateKEKRotation(ctx, *r)
}

// rewrapKey unwraps a data key with its KEK and wraps it under target. The
// data key itself does not change.
func (s *Service) rewrapKey(ctx context.Context, k domain.EncryptionKey, target KEK) (bool, error) {
	aad := domain.WrapAdditionalData(k.KID)
	raw, err := s.keks.unwrap(ctx, k.KEKID, k.KeyRef, aad)
	if err != nil {
		return false, err
	}
	defer clear(raw)
	ref, err := target.Wrap(ctx, raw, aad)
	if err != nil {
		return false, fmt.Errorf("wrap under %s: %w", target.ID(), err)
	}
	return s.store.ReplaceKeyRef(ctx, k.ID, k.KeyRef, ref, target.ID())
}

// KEKStatus is what the admin API shows of the KEKs, never key material.
type KEKStatus struct {
	CurrentKEK  string `json:"current_kek_id"`
	NewKEK      string `json:"new_kek_id,omitempty"`
	WrappingKEK string `json:"wrapping_kek_id"`
	// WrappedBy counts data keys per KEK; "" counts keys wrapped before
	// KEKs were recorded, until the schedule re-wraps them.
	WrappedBy map[string]int      `json:"wrapped_by"`
	Rotation  *KEKRotationStatus  `json:"rotation,omitempty"`
	History   []KEKRotationStatus `json:"history"`
}

// KEKRotationStatus describes one KEK rotation.
type KEKRotationStatus struct {
	ID          uuid.UUID            `json:"id"`
	FromKEK     string               `json:"from_kek_id"`
	ToKEK       string               `json:"to_kek_id"`
	State       domain.RotationState `json:"state"`
	Reason      string               `json:"reason,omitempty"`
	RequestedBy string               `json:"requested_by"`
	StartedAt   time.Time            `json:"started_at"`
	CompletedAt *time.Time           `json:"completed_at,omitempty"`
	Total       int                  `json:"total"`
	Rewrapped   int                  `json:"rewrapped"`
	Remaining   int                  `json:"remaining"`
	Failed      int                  `json:"failed"`
	LastError   string               `json:"last_error,omitempty"`
}

// RotationStatus is the view of r.
func RotationStatus(r domain.KEKRotation) KEKRotationStatus {
	return KEKRotationStatus{ID: r.ID, FromKEK: r.FromKEK, ToKEK: r.ToKEK, State: r.State, Reason: r.Reason,
		RequestedBy: r.RequestedBy, StartedAt: r.StartedAt, CompletedAt: r.CompletedAt, Total: r.Total,
		Rewrapped: r.Rewrapped, Remaining: r.Remaining, Failed: r.Failed, LastError: r.LastError}
}

// KEKStatus reads the KEKs, how many data keys each wraps, and the
// rotations.
func (s *Service) KEKStatus(ctx context.Context) (*KEKStatus, error) {
	out := &KEKStatus{CurrentKEK: s.keks.Current().ID(), WrappingKEK: s.keks.Wrapping().ID(), WrappedBy: map[string]int{},
		History: []KEKRotationStatus{}}
	if n := s.keks.Next(); n != nil {
		out.NewKEK = n.ID()
	}
	keys, err := s.store.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		out.WrappedBy[k.KEKID]++
	}
	list, err := s.store.ListKEKRotations(ctx, 10)
	if err != nil {
		return nil, err
	}
	for _, r := range list {
		out.History = append(out.History, RotationStatus(r))
	}
	if len(out.History) > 0 && out.History[0].State == domain.RotationRewrapping {
		cur := out.History[0]
		out.Rotation = &cur
	}
	return out, nil
}

func (s *Service) recordKEK(ctx context.Context, id uuid.UUID, action string, meta map[string]any) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Append(ctx, "kek_rotation", id.String(), action, meta); err != nil {
		logger.Error("audit KEK event", logger.String("action", action), logger.Err(err))
	}
}
