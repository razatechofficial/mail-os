package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/metrics"
)

// Logger logs one line per request and records its metrics. It logs the
// route template, never the query string or bodies, so no address, token
// or one-time code reaches the log.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		d := time.Since(start)
		status := c.Writer.Status()
		metrics.ObserveHTTP(route, c.Request.Method, strconv.Itoa(status), d)
		fields := []logger.Field{
			logger.String("method", c.Request.Method), logger.String("route", route),
			logger.Int("status", status), logger.Duration("duration", d), logger.String("client_ip", c.ClientIP()),
		}
		l := logger.FromContext(c.Request.Context())
		switch {
		case status >= 500:
			l.Error("http request", fields...)
		case status >= 400:
			l.Warn("http request", fields...)
		default:
			l.Info("http request", fields...)
		}
	}
}
