package application

import "errors"

// Refusals. Each has a stable reason (Reason) that the refusal's audit
// record carries; the API answers 403, or 429 for the limits.
var (
	// Who is calling.
	ErrUnknownClient   = errors.New("the IAM client is not a MailOS application")
	ErrSuspended       = errors.New("the application is suspended")
	ErrTenantMismatch  = errors.New("the token or event names another tenant than the application's")
	ErrKindMismatch    = errors.New("the application kind does not allow this kind of token")
	ErrNotService      = errors.New("only an application's service client may do this")
	ErrScopeMissing    = errors.New("the browser token lacks the mailos.send.self scope")
	ErrNoVerifiedEmail = errors.New("the browser token carries no verified email address")
	ErrOrigin          = errors.New("the request origin is not one of the application's")

	// What it sends.
	ErrTypeNotAllowed     = errors.New("the application may not send this message type")
	ErrRawNotAllowed      = errors.New("the application may send only published templates")
	ErrNotBrowserTemplate = errors.New("the template is not allowed from a browser")
	ErrSenderNotAllowed   = errors.New("the sender is not one of the application's senders")
	ErrSenderUnverified   = errors.New("the sender is not on a verified sending domain")
	ErrSenderRequired     = errors.New("the application has no default sender; name one of its senders")
	ErrStreamMismatch     = errors.New("marketing mail goes out on a broadcast application")

	// How much.
	ErrRateLimited     = errors.New("the application's per-minute limit is reached")
	ErrQuotaExceeded   = errors.New("the application's daily quota is used up")
	ErrUserRateLimited = errors.New("this user's hourly self-send limit is reached")
)

var reasons = map[error]string{
	ErrUnknownClient:      "unknown_client",
	ErrSuspended:          "application_suspended",
	ErrTenantMismatch:     "tenant_mismatch",
	ErrKindMismatch:       "kind_mismatch",
	ErrNotService:         "not_service_caller",
	ErrScopeMissing:       "scope_missing",
	ErrNoVerifiedEmail:    "no_verified_email",
	ErrOrigin:             "origin_not_allowed",
	ErrTypeNotAllowed:     "message_type_not_allowed",
	ErrRawNotAllowed:      "raw_content_not_allowed",
	ErrNotBrowserTemplate: "template_not_browser_allowed",
	ErrSenderNotAllowed:   "sender_not_allowed",
	ErrSenderUnverified:   "sender_domain_unverified",
	ErrSenderRequired:     "sender_required",
	ErrStreamMismatch:     "stream_mismatch",
	ErrRateLimited:        "rate_limited",
	ErrQuotaExceeded:      "quota_exceeded",
	ErrUserRateLimited:    "user_rate_limited",
}

// Reason is the stable machine-readable name of a refusal, "" for any
// other error.
func Reason(err error) string {
	for e, r := range reasons {
		if errors.Is(err, e) {
			return r
		}
	}
	return ""
}

// IsLimit reports whether err is a rate limit or quota refusal (429).
func IsLimit(err error) bool {
	return errors.Is(err, ErrRateLimited) || errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrUserRateLimited)
}

// Identity reports whether err refuses who is calling rather than what
// it sends: its message is not returned to the caller.
func Identity(err error) bool {
	for _, e := range []error{ErrUnknownClient, ErrSuspended, ErrTenantMismatch, ErrKindMismatch, ErrNotService} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
