package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/domain/access"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// IdempotencyHeader is the request header (IETF draft
// httpapi-idempotency-key-header, as Stripe and Postmark use it).
const IdempotencyHeader = "Idempotency-Key"

// ReplayedHeader marks a response replayed from an earlier request.
const ReplayedHeader = "Idempotent-Replayed"

// MaxIdempotencyKey bounds a key.
const MaxIdempotencyKey = 255

// IdempotencyRecord is a stored key. Status 0 means the first request is
// still running.
type IdempotencyRecord struct {
	RequestSHA256 string
	Status        int
	Body          []byte
}

// IdempotencyStore keeps the first response for a (scope, key) until it
// expires (Postgres idempotency_keys).
type IdempotencyStore interface {
	// Claim records the key for a request with hash unless an unexpired
	// record exists; then it returns that record and false.
	Claim(ctx context.Context, scope, key, hash string, expires time.Time) (IdempotencyRecord, bool, error)
	// Complete stores the response of a claimed key.
	Complete(ctx context.Context, scope, key string, status int, body []byte) error
	// Release forgets a claimed key, so the request can be tried again.
	Release(ctx context.Context, scope, key string) error
}

// Idempotency makes a POST safe to retry with an Idempotency-Key: the
// first response for the key is stored for ttl, per application (or per
// tenant for a console user), and replayed for the same request; the same
// key with another request body is 409, and while the first request is
// still running a retry is 409 too. 5xx and 429 responses are not stored:
// the request did not take effect and may be retried with the same key.
// Without the header the request runs as it is.
func Idempotency(store IdempotencyStore, ttl time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader(IdempotencyHeader)
		if key == "" || store == nil {
			c.Next()
			return
		}
		if !validIdempotencyKey(key) {
			response.FromError(c, apperrors.Invalid(IdempotencyHeader, "invalid", "Idempotency-Key must be 1 to 255 printable ASCII characters"))
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			response.Abort(c, http.StatusRequestEntityTooLarge, &response.Error{Code: "PAYLOAD_TOO_LARGE", Message: "request body too large"})
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		sum := sha256.New()
		sum.Write([]byte(c.Request.Method + " " + c.FullPath() + "\n"))
		sum.Write(body)
		hash := hex.EncodeToString(sum.Sum(nil))

		ctx := c.Request.Context()
		scope := idempotencyScope(PrincipalFrom(c))
		rec, fresh, err := store.Claim(ctx, scope, key, hash, time.Now().Add(ttl))
		if err != nil {
			logger.FromContext(ctx).Warn("idempotency store unavailable", logger.Err(err))
			response.FromError(c, apperrors.Unavailable("the request cannot be made idempotent right now; try again shortly"))
			return
		}
		if !fresh {
			switch {
			case rec.RequestSHA256 != hash:
				response.FromError(c, apperrors.Conflict("this Idempotency-Key was already used for a different request"))
			case rec.Status == 0:
				response.FromError(c, apperrors.Conflict("a request with this Idempotency-Key is still being processed"))
			default:
				c.Header(ReplayedHeader, "true")
				c.Data(rec.Status, "application/json; charset=utf-8", rec.Body)
				c.Abort()
			}
			return
		}

		w := &captureWriter{ResponseWriter: c.Writer}
		c.Writer = w
		c.Next()
		done := context.WithoutCancel(ctx)
		status := w.Status()
		if status >= 500 || status == http.StatusTooManyRequests {
			if err := store.Release(done, scope, key); err != nil {
				logger.FromContext(ctx).Warn("release idempotency key", logger.Err(err))
			}
			return
		}
		if err := store.Complete(done, scope, key, status, w.buf.Bytes()); err != nil {
			logger.FromContext(ctx).Warn("store idempotent response", logger.Err(err))
		}
	}
}

// idempotencyScope keeps keys apart per application, else per tenant.
func idempotencyScope(p access.Principal) string {
	if p.ApplicationID != "" {
		return p.ApplicationID
	}
	return "tenant:" + p.TenantID
}

func validIdempotencyKey(k string) bool {
	if len(k) == 0 || len(k) > MaxIdempotencyKey {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// captureWriter keeps a copy of the response body.
type captureWriter struct {
	gin.ResponseWriter
	buf bytes.Buffer
}

func (w *captureWriter) Write(b []byte) (int, error) {
	w.buf.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *captureWriter) WriteString(s string) (int, error) {
	w.buf.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}
