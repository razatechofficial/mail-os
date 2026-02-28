package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

func Logging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		clientIP := c.ClientIP()
		method := c.Request.Method
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()
		logger.Info("request",
			logger.String("method", method),
			logger.String("path", path),
			logger.String("client_ip", clientIP),
			logger.Int("status", status),
			logger.Any("latency_ms", latency.Milliseconds()),
		)
	}
}
