package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/domain"
)

func OrgFromContext(c *gin.Context) domain.OrganizationID {
	val, exists := c.Get(orgIDKey)
	if !exists {
		return ""
	}
	if s, ok := val.(string); ok {
		return domain.OrganizationID(s)
	}
	return ""
}
