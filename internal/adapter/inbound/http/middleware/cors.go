package middleware

import (
	"github.com/gin-gonic/gin"
)

func CORS(origins []string) gin.HandlerFunc {
	originSet := make(map[string]bool)
	for _, o := range origins {
		originSet[o] = true
	}
	return func(c *gin.Context) {
		allow := "*"
		if len(originSet) > 0 {
			reqOrigin := c.GetHeader("Origin")
			if originSet[reqOrigin] {
				allow = reqOrigin
			} else {
				allow = origins[0]
			}
		}
		c.Header("Access-Control-Allow-Origin", allow)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-API-Key, X-Request-ID")
		c.Header("Access-Control-Max-Age", "86400")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
