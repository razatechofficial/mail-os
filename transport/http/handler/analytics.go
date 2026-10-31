package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/analytics"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// AnalyticsHandler serves the sending statistics.
type AnalyticsHandler struct {
	svc *analytics.Service
}

// NewAnalyticsHandler builds the handler.
func NewAnalyticsHandler(svc *analytics.Service) *AnalyticsHandler {
	return &AnalyticsHandler{svc: svc}
}

// Mount registers the routes.
func (h *AnalyticsHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/analytics/stats", g.Require(access.PermAnalyticsRead), h.Stats)
}

// Stats is GET /analytics/stats?period_type=daily|monthly&from&to.
func (h *AnalyticsHandler) Stats(c *gin.Context) {
	from, err := timeQuery(c, "from")
	if err != nil {
		response.FromError(c, err)
		return
	}
	to, err := timeQuery(c, "to")
	if err != nil {
		response.FromError(c, err)
		return
	}
	rows, err := h.svc.Stats(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Query("period_type"), from, to)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, rows)
}
