package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

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
	svc    *inbound.Service
	status *inbound.StatusService
}

// NewEventHandler builds the handler.
func NewEventHandler(svc *inbound.Service) *EventHandler { return &EventHandler{svc: svc} }

// WithStatus adds the delivery status reads.
func (h *EventHandler) WithStatus(st *inbound.StatusService) *EventHandler {
	h.status = st
	return h
}

// Mount registers the routes.
func (h *EventHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.POST("/events", g.Require(access.PermEventsDispatch), h.Dispatch)
	api.GET("/events/deliveries/:delivery_id", g.Require(access.PermEventsDispatch), h.DeliveryStatus)
	api.GET("/events/:event_id/delivery", g.Require(access.PermEventsDispatch), h.EventDelivery)
}

// deliveryStepView is one step of a delivery.
type deliveryStepView struct {
	Type       string    `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
}

// deliveryStatusView is the status API's body.
type deliveryStatusView struct {
	DeliveryID string             `json:"delivery_id"`
	EventID    string             `json:"event_id,omitempty"`
	Status     string             `json:"status"`
	CreatedAt  time.Time          `json:"created_at"`
	UpdatedAt  time.Time          `json:"updated_at"`
	LastError  string             `json:"last_error,omitempty"`
	Events     []deliveryStepView `json:"events"`
}

func deliveryStatusOf(st inbound.DeliveryStatus) deliveryStatusView {
	steps := make([]deliveryStepView, len(st.Events))
	for i, e := range st.Events {
		steps[i] = deliveryStepView{Type: e.Type, OccurredAt: e.OccurredAt}
	}
	return deliveryStatusView{DeliveryID: st.DeliveryID, EventID: st.EventID, Status: st.Status, CreatedAt: st.CreatedAt,
		UpdatedAt: st.UpdatedAt, LastError: st.LastError, Events: steps}
}

func (h *EventHandler) answerStatus(c *gin.Context, read func() (inbound.DeliveryStatus, error)) {
	if h.status == nil {
		response.FromError(c, apperrors.NewAppError(apperrors.KindUnavailable, "UNAVAILABLE", "delivery status is not available"))
		return
	}
	st, err := read()
	if err != nil {
		response.FromError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.OK(c, deliveryStatusOf(st))
}

// DeliveryStatus is GET /events/deliveries/:delivery_id: where the
// message POST /events returned is (queued, sent, delivered, bounced…),
// for the application that sent it only; 404 otherwise.
func (h *EventHandler) DeliveryStatus(c *gin.Context) {
	h.answerStatus(c, func() (inbound.DeliveryStatus, error) {
		return h.status.ByDelivery(c.Request.Context(), c.Param("delivery_id"))
	})
}

// EventDelivery is GET /events/:event_id/delivery: the same, by the
// sender's own event id.
func (h *EventHandler) EventDelivery(c *gin.Context) {
	h.answerStatus(c, func() (inbound.DeliveryStatus, error) {
		return h.status.ByEvent(c.Request.Context(), c.Param("event_id"))
	})
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
