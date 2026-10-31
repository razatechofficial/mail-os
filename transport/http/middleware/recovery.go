package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// Recovery turns a panic into a 500 envelope and logs it with the request ID.
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				logger.FromContext(c.Request.Context()).Error("panic", logger.Any("panic", r), logger.String("route", c.FullPath()))
				response.Abort(c, http.StatusInternalServerError, &response.Error{Code: "INTERNAL_SERVER_ERROR", Message: "an unexpected error occurred"})
			}
		}()
		c.Next()
	}
}
