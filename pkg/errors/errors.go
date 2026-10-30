// Package errors provides application-level error types and utilities.
// Protocol-agnostic: sentinel errors, AppError with ErrorKind, and KindOf().
// Transport layers (HTTP, gRPC) map ErrorKind to status codes.
package errors

import (
	"errors"
	"fmt"
)

// ErrorKind is the protocol-agnostic classification of an error.
// HTTP and gRPC layers map Kind to their status codes.
type ErrorKind int

const (
	KindUnknown ErrorKind = iota
	KindNotFound
	KindAlreadyExists
	KindConflict
	KindUnauthorized
	KindForbidden
	KindStepUpRequired
	KindInactive
	KindInvalidInput
	KindBadRequest
	KindTokenInvalid
	KindRateLimited
	KindInternal
	KindUnavailable
)

// Machine-readable codes the transports return. The console reads these
// (docs/mailos-template-api.md, "Errors").
const (
	CodeBadRequest       = "BAD_REQUEST"
	CodeUnauthorized     = "UNAUTHORIZED"
	CodeForbidden        = "FORBIDDEN"
	CodeStepUpRequired   = "STEP_UP_REQUIRED"
	CodeFourEyesRequired = "FOUR_EYES_REQUIRED"
	CodeNotFound         = "NOT_FOUND"
	CodeConflict         = "CONFLICT"
	CodeValidation       = "VALIDATION"
	CodeRateLimited      = "RATE_LIMITED"
	CodeInternal         = "INTERNAL_SERVER_ERROR"
	CodeUnavailable      = "SERVICE_UNAVAILABLE"
)

// ── sentinel errors ───────────────────────────────────────────────────────
// Services return these; transport layers use KindOf(err) to map to status codes.

var (
	ErrNotFound      = errors.New("resource not found")
	ErrAlreadyExists = errors.New("resource already exists")
	ErrConflict      = errors.New("resource was changed by someone else")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")
	ErrInactive      = errors.New("resource is inactive")
	ErrInvalidInput  = errors.New("invalid input")
	ErrTokenInvalid  = errors.New("token invalid")
	ErrRateLimited   = errors.New("rate limited")
)

// FieldError is one field's validation failure. Code is machine-readable
// ("required", "too_long", "unknown_variable"); Message is for people.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ── app error type ────────────────────────────────────────────────────────

// AppError is a structured error with Kind, machine-readable code, and message.
// Use when you need richer context beyond sentinels.
type AppError struct {
	Kind              ErrorKind
	Code              string // machine-readable: "NOT_FOUND", "CONFLICT"
	Message           string
	Err               error
	Details           []FieldError // for KindInvalidInput
	RetryAfterSeconds int          // for KindRateLimited; maps to HTTP Retry-After and error.retry_after_seconds
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// NewAppError creates a new AppError with the given kind and code.
func NewAppError(kind ErrorKind, code, message string) *AppError {
	return &AppError{Kind: kind, Code: code, Message: message}
}

// Wrap wraps an existing error with AppError context.
func Wrap(err error, kind ErrorKind, code, message string) *AppError {
	return &AppError{Kind: kind, Code: code, Message: message, Err: err}
}

// NotFound is a 404 with a message naming what was not found.
func NotFound(message string) *AppError {
	return NewAppError(KindNotFound, CodeNotFound, message)
}

// Conflict is a 409, such as a draft saved over a newer revision.
func Conflict(message string) *AppError {
	return NewAppError(KindConflict, CodeConflict, message)
}

// Forbidden is a 403 for a caller whose roles do not allow the action.
func Forbidden(message string) *AppError {
	return NewAppError(KindForbidden, CodeForbidden, message)
}

// BadRequest is a 400 for a request that cannot be parsed.
func BadRequest(message string) *AppError {
	return NewAppError(KindBadRequest, CodeBadRequest, message)
}

// Unavailable is a 503 for a dependency the request needs (Redis for the
// replay guard, the IAM JWKS) that cannot answer. Callers never map it to
// an authentication failure: the credential was never checked.
func Unavailable(message string) *AppError {
	return NewAppError(KindUnavailable, CodeUnavailable, message)
}

// Validation is a 422 carrying one entry per failing field.
func Validation(details ...FieldError) *AppError {
	return &AppError{Kind: KindInvalidInput, Code: CodeValidation, Message: "validation failed", Details: details}
}

// Invalid is a 422 for one field.
func Invalid(field, code, message string) *AppError {
	return Validation(FieldError{Field: field, Code: code, Message: message})
}

// NewRateLimitedError returns a rate-limit error with a suggested retry delay in seconds (HTTP 429 / Retry-After).
func NewRateLimitedError(message string, retryAfterSeconds int) *AppError {
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	return &AppError{
		Kind:              KindRateLimited,
		Code:              CodeRateLimited,
		Message:           message,
		RetryAfterSeconds: retryAfterSeconds,
	}
}

// ── utility functions ─────────────────────────────────────────────────────

// IsNotFound reports whether err is or wraps ErrNotFound or a NotFound AppError.
func IsNotFound(err error) bool {
	return KindOf(err) == KindNotFound
}

// KindOf returns the ErrorKind for err.
// Used by transport layers to map to HTTP status or gRPC codes.
func KindOf(err error) ErrorKind {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Kind
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return KindNotFound
	case errors.Is(err, ErrAlreadyExists):
		return KindAlreadyExists
	case errors.Is(err, ErrConflict):
		return KindConflict
	case errors.Is(err, ErrUnauthorized):
		return KindUnauthorized
	case errors.Is(err, ErrForbidden):
		return KindForbidden
	case errors.Is(err, ErrInactive):
		return KindInactive
	case errors.Is(err, ErrInvalidInput):
		return KindInvalidInput
	case errors.Is(err, ErrTokenInvalid):
		return KindTokenInvalid
	case errors.Is(err, ErrRateLimited):
		return KindRateLimited
	default:
		return KindInternal
	}
}

const unexpectedErrorMessage = "an unexpected error occurred"

// UserMessage returns a client-safe message.
// Authored AppError and sentinel messages are returned as-is.
// Unclassified errors (driver, SQL, network) never leak to the client.
func UserMessage(err error) string {
	if err == nil {
		return ""
	}
	var appErr *AppError
	if errors.As(err, &appErr) && appErr.Message != "" {
		return appErr.Message
	}
	switch KindOf(err) {
	case KindInternal, KindUnknown:
		return unexpectedErrorMessage
	default:
		return err.Error()
	}
}

// Code returns the machine-readable error code for err.
// Returns "INTERNAL_SERVER_ERROR" when not an AppError or known sentinel.
func Code(err error) string {
	var appErr *AppError
	if errors.As(err, &appErr) && appErr.Code != "" {
		return appErr.Code
	}
	switch KindOf(err) {
	case KindNotFound:
		return CodeNotFound
	case KindAlreadyExists, KindConflict:
		return CodeConflict
	case KindUnauthorized, KindTokenInvalid:
		return CodeUnauthorized
	case KindForbidden, KindInactive:
		return CodeForbidden
	case KindStepUpRequired:
		return CodeStepUpRequired
	case KindInvalidInput:
		return CodeValidation
	case KindBadRequest:
		return CodeBadRequest
	case KindRateLimited:
		return CodeRateLimited
	case KindUnavailable:
		return CodeUnavailable
	default:
		return CodeInternal
	}
}

// DetailsOf returns the field errors carried by err, if any.
func DetailsOf(err error) []FieldError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Details
	}
	return nil
}
