package middleware

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders sets the API's response headers (OWASP ASVS V3.4): no
// caching of responses that may carry message bodies, no sniffing, no
// framing, HSTS when serving TLS.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if c.Request.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		c.Next()
	}
}

// BodyLimit caps request bodies; a larger body fails to read with 413.
func BodyLimit(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > limit {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"success": false,
				"error": gin.H{"code": "PAYLOAD_TOO_LARGE", "message": "request body too large"}})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

// CORS allows only the configured origins; the console calls through its
// BFF, so production normally configures none.
func CORS(origins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" || !slices.Contains(origins, origin) {
			if c.Request.Method == http.MethodOptions && origin != "" {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Next()
			return
		}
		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Add("Vary", "Origin")
		h.Set("Access-Control-Allow-Headers", "Authorization, DPoP, Content-Type, X-Request-ID")
		h.Set("Access-Control-Allow-Methods", strings.Join([]string{"GET", "POST", "PUT", "DELETE"}, ", "))
		h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, X-Request-ID, Retry-After")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
