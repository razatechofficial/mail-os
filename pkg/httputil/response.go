package httputil

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type Response struct {
	Success bool `json:"success"`
	Data    any  `json:"data,omitempty"`
	Meta    any  `json:"meta,omitempty"`
	Error   any  `json:"error,omitempty"`
}

func OK(ctx *gin.Context, data any) {
	ctx.JSON(http.StatusOK, Response{Success: true, Data: data})
}

func Created(ctx *gin.Context, data any) {
	ctx.JSON(http.StatusCreated, Response{Success: true, Data: data})
}

func NoContent(ctx *gin.Context) {
	ctx.Status(http.StatusNoContent)
}

func List(ctx *gin.Context, data any, meta pagination.Meta) {
	ctx.JSON(http.StatusOK, Response{Success: true, Data: data, Meta: meta})
}

func FromError(ctx *gin.Context, err error) {
	status := errors.HTTPStatusFromError(err)
	ctx.JSON(status, Response{Success: false, Error: err.Error()})
}
