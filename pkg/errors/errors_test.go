package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestKindAndCode(t *testing.T) {
	cases := []struct {
		err  error
		kind ErrorKind
		code string
	}{
		{ErrNotFound, KindNotFound, CodeNotFound},
		{fmt.Errorf("wrapped: %w", ErrConflict), KindConflict, CodeConflict},
		{ErrForbidden, KindForbidden, CodeForbidden},
		{Validation(FieldError{Field: "subject", Code: "required"}), KindInvalidInput, CodeValidation},
		{NewAppError(KindForbidden, CodeFourEyesRequired, "x"), KindForbidden, CodeFourEyesRequired},
		{errors.New("pq: relation does not exist"), KindInternal, CodeInternal},
		{Unavailable("redis down"), KindUnavailable, CodeUnavailable},
	}
	for _, c := range cases {
		if got := KindOf(c.err); got != c.kind {
			t.Errorf("KindOf(%v) = %v, want %v", c.err, got, c.kind)
		}
		if got := Code(c.err); got != c.code {
			t.Errorf("Code(%v) = %q, want %q", c.err, got, c.code)
		}
	}
}

func TestUserMessageNeverLeaksInternalErrors(t *testing.T) {
	if got := UserMessage(errors.New("dial tcp 10.0.0.5:5432: connection refused")); got != unexpectedErrorMessage {
		t.Fatalf("internal error leaked: %q", got)
	}
	if got := UserMessage(NotFound("template not found")); got != "template not found" {
		t.Fatalf("authored message lost: %q", got)
	}
}

func TestDetailsAndRateLimit(t *testing.T) {
	err := fmt.Errorf("save: %w", Invalid("locale", "invalid", "locale must be en or ur"))
	d := DetailsOf(err)
	if len(d) != 1 || d[0].Field != "locale" || d[0].Code != "invalid" {
		t.Fatalf("details = %+v", d)
	}
	rl := NewRateLimitedError("slow down", 0)
	if rl.RetryAfterSeconds != 1 || Code(rl) != CodeRateLimited {
		t.Fatalf("rate limit = %+v", rl)
	}
}
