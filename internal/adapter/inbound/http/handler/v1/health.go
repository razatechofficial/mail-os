package v1

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/pkg/httputil"
)

type HealthChecker interface {
	Health(ctx context.Context) error
}

type HealthHandler struct {
	dbHealth HealthChecker
}

func NewHealthHandler(dbHealth HealthChecker) *HealthHandler {
	return &HealthHandler{dbHealth: dbHealth}
}

func (h *HealthHandler) Health(c *gin.Context) {
	httputil.OK(c, dto.HealthResponse{Status: "ok"})
}

func (h *HealthHandler) Ready(c *gin.Context) {
	if h.dbHealth != nil {
		if err := h.dbHealth.Health(c.Request.Context()); err != nil {
			c.AbortWithStatusJSON(503, gin.H{"success": false, "error": "service unavailable"})
			return
		}
	}
	httputil.OK(c, dto.HealthResponse{Status: "ok"})
}
