package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/core/apikey"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/httputil"
)

const orgIDKey = "org_id"

func Auth(svc apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/ready" {
			c.Next()
			return
		}
		token := extractAPIKey(c)
		if token == "" {
			httputil.FromError(c, errors.ErrUnauthorized)
			c.Abort()
			return
		}
		key, err := svc.ValidateKey(c.Request.Context(), token)
		if err != nil {
			httputil.FromError(c, err)
			c.Abort()
			return
		}
		c.Set(orgIDKey, string(key.OrgID))
		c.Next()
	}
}

func extractAPIKey(c *gin.Context) string {
	if auth := c.GetHeader("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	if k := c.GetHeader("X-API-Key"); k != "" {
		return k
	}
	return ""
}
