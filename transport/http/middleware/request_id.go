// Package middleware holds the Gin middleware of the REST API: request IDs,
// structured logging with masking, metrics, recovery, security headers,
// body limits, IAM token authentication with DPoP, role permissions,
// step-up and rate limits.
package middleware

import (
	"regexp"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// RequestIDHeader carries the request ID in and out.
const RequestIDHeader = "X-Request-ID"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// RequestID keeps a well-formed incoming X-Request-ID (the console's BFF
// sends one) or creates one, and puts it on the response, the log context
// and the audit context.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader(RequestIDHeader)
		if !requestIDPattern.MatchString(rid) {
			rid = id.New()
		}
		c.Set("request_id", rid)
		c.Header(RequestIDHeader, rid)
		ctx := logger.WithRequestIDContext(c.Request.Context(), rid)
		ctx = audit.WithRequestMeta(ctx, audit.RequestMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent(), RequestID: rid})
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
