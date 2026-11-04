package handler

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/providerevents"
	"github.com/razatechofficial/mail-os/infrastructure/providerhooks"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// ProviderEventsPath is where a tenant's provider posts its delivery
// events: /webhooks/providers/{tenant id}/{provider id}.
const ProviderEventsPath = "/webhooks/providers/:tenant_id/:provider_id"

// maxProviderWebhook bounds one webhook body (SendGrid and SparkPost batch
// events).
const maxProviderWebhook = 4 << 20

// retryAfter is the Retry-After of an event for a message still being
// sent.
const retryAfter = 60

// ProviderEventHandler receives the sending APIs' delivery event webhooks.
// The route is public: each request is authenticated by the provider's
// signature or the event URL's password (application/providerevents).
type ProviderEventHandler struct {
	svc *providerevents.Service
}

// NewProviderEventHandler builds the handler.
func NewProviderEventHandler(svc *providerevents.Service) *ProviderEventHandler {
	return &ProviderEventHandler{svc: svc}
}

// MountPublic registers the unauthenticated route.
func (h *ProviderEventHandler) MountPublic(r gin.IRouter) {
	r.POST(ProviderEventsPath, h.Receive)
}

// refuse answers 401 with a basic-auth challenge: SNS sends the event
// URL's credentials only after one.
func refuse(c *gin.Context) {
	c.Header("WWW-Authenticate", `Basic realm="mailos-provider-events"`)
	response.FromError(c, providerevents.ErrRefused)
}

// Receive is POST /webhooks/providers/:tenant_id/:provider_id: 200 with
// what was recorded, 401 when the webhook is not authenticated, 400 when
// its payload cannot be read, 503 (Retry-After) when a message is still
// being sent.
func (h *ProviderEventHandler) Receive(c *gin.Context) {
	tenant, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		refuse(c)
		return
	}
	if _, err := uuid.Parse(c.Param("provider_id")); err != nil {
		refuse(c)
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxProviderWebhook+1))
	if err != nil || len(body) > maxProviderWebhook {
		response.Abort(c, http.StatusRequestEntityTooLarge, &response.Error{Code: "PAYLOAD_TOO_LARGE", Message: "the webhook body is too large"})
		return
	}
	sum, err := h.svc.Receive(c.Request.Context(), tenant.String(), c.Param("provider_id"),
		providerhooks.Request{Header: c.Request.Header, Body: body})
	switch {
	case errors.Is(err, providerevents.ErrRefused):
		refuse(c)
	case errors.Is(err, providerevents.ErrRetry):
		c.Header("Retry-After", strconv.Itoa(retryAfter))
		response.FromError(c, err)
	case err != nil:
		response.FromError(c, err)
	default:
		response.OK(c, sum)
	}
}
