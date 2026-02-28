package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/httputil"
)

const rateLimitKeyPrefix = "rate_limit:org:"
const rateLimitWindow = 60 * time.Second

func RateLimit(cache port.Cache, defaultLimit int) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := httputil.OrgIDFromContext(c)
		if orgID == "" {
			c.Next()
			return
		}
		key := rateLimitKeyPrefix + orgID
		ctx := c.Request.Context()
		raw, err := cache.Get(ctx, key)
		count := 0
		if err == nil && len(raw) > 0 {
			count, _ = strconv.Atoi(string(raw))
		}
		if count >= defaultLimit {
			httputil.FromError(c, errors.ErrRateLimited)
			c.Abort()
			return
		}
		count++
		_ = cache.Set(ctx, key, []byte(strconv.Itoa(count)), rateLimitWindow)
		c.Next()
	}
}
