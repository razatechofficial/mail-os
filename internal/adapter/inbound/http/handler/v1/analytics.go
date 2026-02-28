package v1

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/analytics"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type AnalyticsHandler struct {
	svc analytics.Service
}

func NewAnalyticsHandler(svc analytics.Service) *AnalyticsHandler {
	return &AnalyticsHandler{svc: svc}
}

func (h *AnalyticsHandler) GetStats(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	periodType := domain.PeriodType(c.DefaultQuery("period_type", "daily"))
	fromStr := c.Query("from")
	toStr := c.Query("to")
	if fromStr == "" || toStr == "" {
		httputil.FromError(c, errors.NewBadRequest("from and to are required"))
		return
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		from, err = time.Parse("2006-01-02", fromStr)
	}
	if err != nil {
		httputil.FromError(c, errors.NewBadRequest("invalid from date"))
		return
	}
	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		to, err = time.Parse("2006-01-02", toStr)
	}
	if err != nil {
		httputil.FromError(c, errors.NewBadRequest("invalid to date"))
		return
	}
	params := analytics.StatsParams{PeriodType: periodType, From: from, To: to}
	stats, err := h.svc.GetStats(c.Request.Context(), orgID, params)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.StatsResponse, len(stats))
	for i, s := range stats {
		items[i] = dto.SendingStatsToResponse(s)
	}
	httputil.OK(c, items)
}

func (h *AnalyticsHandler) GetAuditLogs(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	auditParams := analytics.AuditLogParams{Resource: c.Query("resource")}
	auditParams.Params = params
	logs, total, err := h.svc.GetAuditLogs(c.Request.Context(), orgID, auditParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.AuditLogResponse, len(logs))
	for i, a := range logs {
		items[i] = dto.AuditLogToResponse(a)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}
