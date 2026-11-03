// Package smtpcredential is an application's SMTP username and password:
// the one secret MailOS itself issues.
//
// Everywhere else MailOS issues no secret (mailos-applications.md §1): an
// application is bound to its IAM OAuth client and proves it with an IAM
// access token. A bank's legacy software often cannot fetch a token; it
// can only be given a host, a port, a username and a password, as it is
// for the SMTP interfaces of AWS SES, SendGrid and Postmark. For those
// applications, and only when an administrator opts the application in
// (smtp_password_auth), MailOS generates credentials:
//
//   - the username is generated (never chosen), so it names nothing;
//   - the password is 256 random bits, shown once, and stored only as an
//     Argon2id hash (RFC 9106; OWASP parameters m=19 MiB, t=2, p=1);
//   - at most MaxActive are active per application, so a password is
//     rotated without downtime (create a second, switch, revoke the first),
//     or in place (Rotate: a new password for the same username);
//   - revoked credentials stay for the audit trail; last use is recorded.
package smtpcredential

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Credential is one SMTP username of an application.
type Credential struct {
	ID            string
	TenantID      string
	ApplicationID string
	Username      string
	// PasswordHash is the Argon2id PHC string; the password is never kept.
	PasswordHash string
	Description  string
	CreatedBy    string
	CreatedAt    time.Time
	RotatedAt    *time.Time
	RotatedBy    string
	LastUsedAt   *time.Time
	LastUsedIP   string
	RevokedAt    *time.Time
	RevokedBy    string
}

// Active reports whether the credential may authenticate.
func (c Credential) Active() bool { return c.RevokedAt == nil }

// Limits.
const (
	// MaxActive is how many credentials an application may hold at once:
	// two, for a rotation without downtime.
	MaxActive      = 2
	MaxDescription = 200
	// UsernamePrefix marks a MailOS SMTP username.
	UsernamePrefix = "smtp_"
	// PasswordPrefix marks a MailOS SMTP password, so secret scanners can
	// find one that leaked into a repository or a ticket.
	PasswordPrefix = "mosmtp_"
)

var usernameRE = regexp.MustCompile(`^smtp_[a-z2-7]{24}$`)

// ValidUsername reports whether s has the shape of a generated username.
// Anything else is not looked up (and not written to the audit trail: it
// may be a password typed into the wrong field).
func ValidUsername(s string) bool { return usernameRE.MatchString(s) }

var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewUsername returns a fresh username: the prefix and 120 random bits.
func NewUsername() (string, error) {
	var b [15]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return UsernamePrefix + lowerBase32.EncodeToString(b[:]), nil
}

// NewPassword returns a fresh password: the prefix and 256 random bits.
func NewPassword() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return PasswordPrefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Argon2id parameters (OWASP Password Storage Cheat Sheet: m=19 MiB, t=2,
// p=1).
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// Hash returns the Argon2id PHC string of password.
func Hash(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// ErrMalformedHash is a stored hash that is not an Argon2id PHC string.
var ErrMalformedHash = errors.New("smtp credential: malformed password hash")

// Verify reports whether password matches the PHC string, in constant
// time. The parameters are read from the hash, so stronger ones can be
// introduced without invalidating stored credentials.
func Verify(hash, password string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrMalformedHash
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil ||
		memory == 0 || memory > 256*1024 || iterations == 0 || iterations > 10 || threads == 0 {
		return false, ErrMalformedHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrMalformedHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, ErrMalformedHash
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
