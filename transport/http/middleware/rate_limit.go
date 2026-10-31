package middleware

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/domain/access"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// WindowCounter counts requests in fixed windows (Redis INCR).
type WindowCounter interface {
	CountWindow(ctx context.Context, key string, window time.Duration) (int64, error)
}

// Scope picks what a limit is counted per.
type Scope int

// Limit scopes.
const (
	PerTenant Scope = iota // the caller's tenant (the API as a whole)
	PerUser                // one person (previews, test sends)
)

// RateLimit allows limit requests per window per scope and answers 429
// RATE_LIMITED with Retry-After beyond it. A counter that cannot answer
// lets the request through and logs it: limits protect capacity, while
// authorization never depends on them.
func RateLimit(counter WindowCounter, name string, scope Scope, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if counter == nil || limit <= 0 {
			c.Next()
			return
		}
		p, _ := access.FromContext(c.Request.Context())
		key := "mailos:rl:" + name + ":" + p.TenantID
		if scope == PerUser {
			key += ":" + p.Actor()
		}
		n, err := counter.CountWindow(c.Request.Context(), key, window)
		if err != nil {
			logger.Warn("rate limit counter unavailable", logger.String("limit", name), logger.Err(err))
			c.Next()
			return
		}
		if n > int64(limit) {
			response.FromError(c, apperrors.NewRateLimitedError("Too many requests; try again later", int(window.Seconds())))
			return
		}
		c.Next()
	}
}
