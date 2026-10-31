package message

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Reason classifies a send failure. It decides whether the message is
// retried and whether the router tries the tenant's next provider.
type Reason string

// Send failure reasons.
const (
	// ReasonInvalidRecipient: the recipient does not exist or its address
	// is refused (SMTP 550/553, a provider's invalid-email error). The
	// message bounces; another provider would fail the same way.
	ReasonInvalidRecipient Reason = "invalid_recipient"
	// ReasonRejected: the message itself was refused (content, sender
	// policy, size). Permanent.
	ReasonRejected Reason = "rejected"
	// ReasonInvalid: the message cannot be built (bad header, no body).
	// Permanent.
	ReasonInvalid Reason = "invalid"
	// ReasonAuth: the provider refused the credentials. Permanent for the
	// provider; the router tries the next one.
	ReasonAuth Reason = "auth"
	// ReasonConfig: the provider is misconfigured (unknown domain,
	// untrusted TLS certificate, no STARTTLS, disallowed address).
	// Permanent for the provider; the router tries the next one.
	ReasonConfig Reason = "config"
	// ReasonRateLimited: the provider asked to slow down (HTTP 429, SMTP
	// 421/450/451/452 for rate). Transient; RetryAfter may be set.
	ReasonRateLimited Reason = "rate_limited"
	// ReasonUnavailable: the provider failed (HTTP 5xx, SMTP 4xx).
	// Transient.
	ReasonUnavailable Reason = "unavailable"
	// ReasonNetwork: the provider could not be reached or did not answer
	// in time. Transient. A timeout after the message was written may mean
	// it was accepted: a retry can deliver it twice.
	ReasonNetwork Reason = "network"
)

// Permanent reports whether retrying the same provider fails the same way.
func (r Reason) Permanent() bool {
	switch r {
	case ReasonInvalidRecipient, ReasonRejected, ReasonInvalid, ReasonAuth, ReasonConfig:
		return true
	}
	return false
}

// ProviderFault reports whether the failure is the provider's, not the
// message's, so another provider may succeed.
func (r Reason) ProviderFault() bool {
	switch r {
	case ReasonAuth, ReasonConfig, ReasonRateLimited, ReasonUnavailable, ReasonNetwork:
		return true
	}
	return false
}

// SendError is a classified send failure. Detail is safe to store and
// show: it never holds credentials, bodies or the provider's raw response.
type SendError struct {
	Reason Reason
	// Provider is the provider kind that failed ("smtp", "ses", …).
	Provider string
	// Status is the HTTP status or SMTP reply code, 0 when there was none.
	Status int
	// RetryAfter is the provider's requested wait, if any.
	RetryAfter time.Duration
	Detail     string
	// Err is the underlying error, for logs (may hold addresses).
	Err error
}

// NewSendError returns a send error.
func NewSendError(provider string, reason Reason, status int, detail string) *SendError {
	return &SendError{Provider: provider, Reason: reason, Status: status, Detail: detail}
}

func (e *SendError) Error() string {
	s := string(e.Reason)
	if e.Provider != "" {
		s = e.Provider + ": " + s
	}
	if e.Status != 0 {
		s += fmt.Sprintf(" (%d)", e.Status)
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func (e *SendError) Unwrap() error { return e.Err }

// Permanent reports whether the error is permanent.
func (e *SendError) Permanent() bool { return e.Reason.Permanent() }

// AsSendError returns err's SendError, if any.
func AsSendError(err error) (*SendError, bool) {
	var se *SendError
	ok := errors.As(err, &se)
	return se, ok
}

// IsPermanent reports whether err will fail again on retry. Errors that
// are not classified are treated as transient, so nothing is dropped on an
// unexpected failure; attempts still bound the retries.
func IsPermanent(err error) bool {
	if se, ok := AsSendError(err); ok {
		return se.Permanent()
	}
	return false
}

// RetryAfterOf returns the provider's requested wait, or 0.
func RetryAfterOf(err error) time.Duration {
	if se, ok := AsSendError(err); ok {
		return se.RetryAfter
	}
	return 0
}

// SafeDetail describes err for storage and the console: the SendError
// text, or a generic line for anything unclassified (driver errors may
// hold addresses or hosts).
func SafeDetail(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "the send was interrupted"
	}
	if se, ok := AsSendError(err); ok {
		return se.Error()
	}
	return "the send failed"
}
