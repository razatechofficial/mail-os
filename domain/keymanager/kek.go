package keymanager

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// KEK providers: where the key-encryption key that wraps data keys lives.
const (
	// ProviderSoftware: a master key held in configuration (Vault).
	ProviderSoftware = "software"
	// ProviderPKCS11: a non-extractable AES-256 key in an HSM.
	ProviderPKCS11 = "pkcs11"
	// ProviderKMS: a symmetric key in AWS KMS.
	ProviderKMS = "kms"
)

// KEKID names a key-encryption key, never revealing it:
// "<provider>:<reference>", such as software:<fingerprint>,
// pkcs11:<HSM key label> or kms:<key ARN>. It is stored beside every data
// key the KEK wraps.
func KEKID(provider, ref string) string { return provider + ":" + ref }

// KEKProvider returns the provider part of a KEK id.
func KEKProvider(id string) string {
	p, _, _ := strings.Cut(id, ":")
	return p
}

// RotationState is where a KEK rotation is.
type RotationState string

// KEK rotation states.
const (
	// RotationRewrapping: new data keys are wrapped under the new KEK and
	// the schedule re-wraps the others.
	RotationRewrapping RotationState = "rewrapping"
	// RotationCompleted: every data key is wrapped under the new KEK; the
	// old one can leave configuration.
	RotationCompleted RotationState = "completed"
)

// KEKRotation moves every data key from one KEK to another. Data keys keep
// their kid and material, so nothing sealed has to be re-encrypted.
type KEKRotation struct {
	ID          uuid.UUID
	FromKEK     string
	ToKEK       string
	State       RotationState
	Reason      string
	RequestedBy string
	StartedAt   time.Time
	CompletedAt *time.Time
	// Total is how many data keys exist; Rewrapped how many the schedule
	// has moved; Remaining how many are not yet under ToKEK.
	Total     int
	Rewrapped int
	Remaining int
	Failed    int
	LastError string
}

// Errors of KEK rotation.
var (
	ErrNoNewKEK          = errors.New("no new key-encryption key is configured")
	ErrSameKEK           = errors.New("the new key-encryption key already wraps new data keys")
	ErrKEKRotationActive = errors.New("a key-encryption key rotation is already running")
	ErrKEKNotConfigured  = errors.New("key-encryption key is not configured on this replica")
)

// Complete marks the rotation finished.
func (r *KEKRotation) Complete(now time.Time) {
	r.State, r.CompletedAt, r.Remaining = RotationCompleted, &now, 0
}

// Done reports whether the rotation can complete: nothing left, no
// failures, and settle has passed since it started, so a replica that
// wrapped a data key under the old KEK just before the start is caught.
func (r KEKRotation) Done(now time.Time, settle time.Duration) bool {
	return r.State == RotationRewrapping && r.Remaining == 0 && r.Failed == 0 && !now.Before(r.StartedAt.Add(settle))
}
