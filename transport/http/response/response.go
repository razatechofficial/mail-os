// Package response provides HTTP response helpers for the Gin transport.
// Maps pkg/errors.ErrorKind to HTTP status codes and writes the standard
// envelope { success, data, meta, error, request_id }.
package response

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

// Response is the standard envelope for all API responses.
type Response struct {
	Success   bool   `json:"success"`
	Data      any    `json:"data,omitempty"`
	Meta      any    `json:"meta,omitempty"`
	Error     *Error `json:"error,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Error is the standard error shape in responses.
type Error struct {
	Code              string                 `json:"code"`
	Message           string                 `json:"message"`
	Details           []apperrors.FieldError `json:"details,omitempty"`
	RetryAfterSeconds int                    `json:"retry_after_seconds,omitempty"`
	// Step-up hints (RFC 9470) repeated from WWW-Authenticate for the console.
	ACRValues string `json:"acr_values,omitempty"`
	MaxAge    int64  `json:"max_age,omitempty"`
}

// HTTPStatusFromKind maps protocol-agnostic ErrorKind to HTTP status code.
func HTTPStatusFromKind(k apperrors.ErrorKind) int {
	switch k {
	case apperrors.KindNotFound:
		return http.StatusNotFound
	case apperrors.KindAlreadyExists, apperrors.KindConflict:
		return http.StatusConflict
	case apperrors.KindUnauthorized, apperrors.KindTokenInvalid:
		return http.StatusUnauthorized
	case apperrors.KindForbidden, apperrors.KindInactive, apperrors.KindStepUpRequired:
		return http.StatusForbidden
	case apperrors.KindInvalidInput:
		return http.StatusUnprocessableEntity
	case apperrors.KindBadRequest:
		return http.StatusBadRequest
	case apperrors.KindRateLimited:
		return http.StatusTooManyRequests
	case apperrors.KindUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// ── success ───────────────────────────────────────────────────────────────

func OK(c *gin.Context, data any) { c.JSON(http.StatusOK, Response{Success: true, Data: data}) }

func Created(c *gin.Context, data any) { c.JSON(http.StatusCreated, Response{Success: true, Data: data}) }

func Accepted(c *gin.Context, data any) { c.JSON(http.StatusAccepted, Response{Success: true, Data: data}) }

func NoContent(c *gin.Context) { c.Status(http.StatusNoContent) }

// List sends a paginated list.
func List(c *gin.Context, data any, meta *pagination.Meta) {
	c.JSON(http.StatusOK, Response{Success: true, Data: data, Meta: meta})
}

// ── error ─────────────────────────────────────────────────────────────────

// BadRequest is a malformed body or query.
func BadRequest(c *gin.Context, message string) {
	Abort(c, http.StatusBadRequest, &Error{Code: apperrors.CodeBadRequest, Message: message})
}

// FromError maps any error to the envelope. Server-side errors are logged
// with the request ID and their text never reaches the client.
func FromError(c *gin.Context, err error) {
	kind := apperrors.KindOf(err)
	status := HTTPStatusFromKind(kind)
	e := &Error{Code: apperrors.Code(err), Message: apperrors.UserMessage(err), Details: apperrors.DetailsOf(err)}
	var appErr *apperrors.AppError
	if errors.As(err, &appErr) && appErr.RetryAfterSeconds > 0 {
		e.RetryAfterSeconds = appErr.RetryAfterSeconds
		c.Header("Retry-After", strconv.Itoa(appErr.RetryAfterSeconds))
	}
	if status >= 500 {
		logger.FromContext(c.Request.Context()).Error("internal error",
			logger.String("route", c.FullPath()), logger.String("method", c.Request.Method),
			logger.Int("status", status), logger.Err(err))
		if kind != apperrors.KindUnavailable {
			e.Message = "an unexpected error occurred"
		}
	}
	Abort(c, status, e)
}

// Abort writes an error envelope and stops the handler chain.
func Abort(c *gin.Context, status int, e *Error) {
	c.AbortWithStatusJSON(status, Response{Success: false, Error: e, RequestID: c.GetString("request_id")})
}
