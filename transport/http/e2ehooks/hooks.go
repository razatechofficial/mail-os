// Package e2ehooks serves the test-only hook routes (MAILOS_E2E_HOOKS):
// the mail the platform sink captured, read by the black-box suite as a
// person reads their inbox. config.Load refuses the hooks outside test
// environments, and every route needs the hook token.
package e2ehooks

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/infrastructure/mailer"
)

// Mailbox lists captured mail.
type Mailbox interface {
	List(ctx context.Context, addr string) ([]mailer.CapturedMail, error)
}

// Mount adds GET /e2e/v1/messages?to=.
func Mount(r *gin.Engine, token string, box Mailbox) {
	g := r.Group("/e2e/v1", func(c *gin.Context) {
		got := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "hook token required"}})
			return
		}
		c.Next()
	})
	g.GET("/messages", func(c *gin.Context) {
		list, err := box.List(c.Request.Context(), c.Query("to"))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"success": false})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": list})
	})
}
