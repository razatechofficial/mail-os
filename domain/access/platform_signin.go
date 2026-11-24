package access

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// PlatformACR is the sign-in a platform token must carry (ADR 0001 D2,
// contract C2): the IAM's phishing-resistant level, a passkey or security
// key. It is a floor, not a setting.
const PlatformACR = ACRPhishingResistant

// DefaultPlatformMaxAge is the platform session's total length (ADR 0001
// §3.4): a platform token whose sign-in is older is refused.
const DefaultPlatformMaxAge = 8 * time.Hour

// PlatformSignIn is the platform plane's sign-in rule, checked on every
// /api/platform/v1 request after the token itself verifies:
//
//   - azp names one of ClientIDs, the platform console's OAuth clients, so
//     a token another platform_web application obtained for
//     mailos-platform is refused;
//   - acr is at least PlatformACR;
//   - auth_time is no older than MaxAge.
type PlatformSignIn struct {
	ClientIDs []string
	MaxAge    time.Duration
}

// Platform sign-in refusals. ErrPlatformClient is a token for another
// client (a new sign-in through the same client cannot fix it); the other
// two are RFC 9470 step-up: the console signs in again and retries.
var (
	ErrPlatformClient = errors.New("the token was not issued to the platform console")
	ErrPlatformWeak   = errors.New("the platform sign-in did not use a passkey or security key")
	ErrPlatformStale  = errors.New("the platform sign-in is older than the platform session allows")
)

// MaxAgeOrDefault is MaxAge, or DefaultPlatformMaxAge when unset.
func (s PlatformSignIn) MaxAgeOrDefault() time.Duration {
	if s.MaxAge <= 0 {
		return DefaultPlatformMaxAge
	}
	return s.MaxAge
}

// Check applies the rule to a verified platform principal at now. With no
// ClientIDs every token is refused: the platform plane fails closed.
func (s PlatformSignIn) Check(p Principal, now time.Time) error {
	if p.ClientID == "" || !slices.ContainsFunc(s.ClientIDs, func(id string) bool {
		return strings.EqualFold(strings.TrimSpace(id), p.ClientID)
	}) {
		return ErrPlatformClient
	}
	if !ACRSatisfies(p.ACR, PlatformACR) {
		return ErrPlatformWeak
	}
	if p.AuthTime.IsZero() || now.Sub(p.AuthTime) > s.MaxAgeOrDefault() {
		return ErrPlatformStale
	}
	return nil
}
