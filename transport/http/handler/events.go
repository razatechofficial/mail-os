package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/domain/event"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// EventHandler accepts events services publish over HTTP (contract §2): the
// body is IAM's eventbus.Event JSON, the caller a service token.
type EventHandler struct {
	svc *inbound.Service
}

// NewEventHandler builds the handler.
func NewEventHandler(svc *inbound.Service) *EventHandler { return &EventHandler{svc: svc} }

// Mount registers the routes.
func (h *EventHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.POST("/events", g.Require(access.PermEventsDispatch), h.Dispatch)
}

// eventAccepted is the 202 body.
type eventAccepted struct {
	Accepted   bool   `json:"accepted"`
	DeliveryID string `json:"delivery_id"`
	EventID    string `json:"event_id"`
	Duplicate  bool   `json:"duplicate"`
}

// Dispatch is POST /events. A body that is not JSON is 400, an invalid
// envelope or data 422, a refused sender or tenant 403 (audited), a
// redelivered event 202 with duplicate true.
func (h *EventHandler) Dispatch(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, event.MaxSize+1))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			response.Abort(c, http.StatusRequestEntityTooLarge, &response.Error{Code: "PAYLOAD_TOO_LARGE", Message: "request body too large"})
			return
		}
		response.BadRequest(c, "the request body cannot be read")
		return
	}
	if len(body) > event.MaxSize {
		response.Abort(c, http.StatusRequestEntityTooLarge, &response.Error{Code: "PAYLOAD_TOO_LARGE", Message: "the event is over 256 KiB"})
		return
	}
	if !json.Valid(body) {
		response.BadRequest(c, "malformed JSON body")
		return
	}
	ev, err := event.Parse(body)
	if err != nil {
		var r *event.Rejection
		msg := "the event envelope is invalid"
		if errors.As(err, &r) && r.Err != nil {
			msg = r.Err.Error()
		}
		response.FromError(c, apperrors.Invalid("event", "invalid_event", msg))
		return
	}
	res, err := h.svc.Dispatch(c.Request.Context(), inbound.In{Transport: inbound.TransportHTTP, Event: ev})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Accepted(c, eventAccepted{Accepted: res.Accepted, DeliveryID: res.DeliveryID, EventID: res.EventID, Duplicate: res.Duplicate})
}
