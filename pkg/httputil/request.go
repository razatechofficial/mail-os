package httputil

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

func PaginationFromContext(ctx *gin.Context) pagination.Params {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(ctx.DefaultQuery("limit", "20"))
	sortBy := ctx.Query("sort_by")
	sortOrder := ctx.DefaultQuery("sort_order", "asc")
	return pagination.NewParams(page, limit, sortBy, sortOrder)
}

func OrgIDFromContext(ctx *gin.Context) string {
	orgID, _ := ctx.Get("org_id")
	if s, ok := orgID.(string); ok {
		return s
	}
	return ""
}
