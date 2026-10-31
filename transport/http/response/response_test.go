package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func run(err error) (*httptest.ResponseRecorder, Response) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
	c.Set("request_id", "req-1")
	FromError(c, err)
	var body Response
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

func TestFromError(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{apperrors.Validation(apperrors.FieldError{Field: "subject", Code: "required", Message: "x"}), 422, "VALIDATION"},
		{apperrors.Conflict("revision"), 409, "CONFLICT"},
		{apperrors.NewAppError(apperrors.KindForbidden, apperrors.CodeFourEyesRequired, "four eyes"), 403, "FOUR_EYES_REQUIRED"},
		{apperrors.ErrNotFound, 404, "NOT_FOUND"},
		{apperrors.NewRateLimitedError("slow", 30), 429, "RATE_LIMITED"},
		{errors.New("pq: secret driver detail"), 500, "INTERNAL_SERVER_ERROR"},
	}
	for _, c := range cases {
		w, body := run(c.err)
		if w.Code != c.status || body.Error == nil || body.Error.Code != c.code || body.Success || body.RequestID != "req-1" {
			t.Errorf("%v: %d %+v", c.err, w.Code, body)
		}
	}
	_, body := run(errors.New("pq: secret driver detail"))
	if body.Error.Message != "an unexpected error occurred" {
		t.Fatalf("internal error leaked: %q", body.Error.Message)
	}
	w, body := run(apperrors.Validation(apperrors.FieldError{Field: "locale", Code: "invalid", Message: "en or ur"}))
	if len(body.Error.Details) != 1 || body.Error.Details[0].Field != "locale" || w.Header().Get("Retry-After") != "" {
		t.Fatalf("details %+v", body.Error)
	}
	w, _ = run(apperrors.NewRateLimitedError("slow", 30))
	if w.Header().Get("Retry-After") != "30" {
		t.Fatal("no Retry-After")
	}
}
