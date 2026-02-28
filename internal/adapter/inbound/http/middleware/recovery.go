package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/errors"
)

func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("panic recovered", logger.Any("panic", err))
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error":   errors.ErrInternal.Error(),
				})
			}
		}()
		c.Next()
	}
}
