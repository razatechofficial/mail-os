// Package handler holds the REST handlers. Each handler type mounts its own
// routes with the permission each needs (Mount), so the router stays
// wiring only.
package handler

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// bind decodes a JSON body; a malformed body is 400 BAD_REQUEST, an
// oversized one 413.
func bind(c *gin.Context, v any) bool {
	if err := c.ShouldBindJSON(v); err != nil {
		if err.Error() == "http: request body too large" {
			response.Abort(c, 413, &response.Error{Code: "PAYLOAD_TOO_LARGE", Message: "request body too large"})
			return false
		}
		response.BadRequest(c, "malformed JSON body")
		return false
	}
	return true
}

// page reads page and limit.
func page(c *gin.Context) pagination.Params {
	return pagination.NewParams(pagination.ParsePage(c.Query("page")), pagination.ParseLimit(c.Query("limit")), c.Query("sort_by"), c.Query("sort_order"))
}

// timeQuery reads an RFC 3339 (or date-only) query parameter.
func timeQuery(c *gin.Context, name string) (*time.Time, error) {
	v := c.Query(name)
	if v == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return &t, nil
		}
	}
	return nil, apperrors.Invalid(name, "invalid_datetime", name+" must be RFC 3339 or YYYY-MM-DD")
}

// intQuery reads an optional integer query parameter.
func intQuery(c *gin.Context, name string, def int) int {
	if n, err := strconv.Atoi(c.Query(name)); err == nil {
		return n
	}
	return def
}
