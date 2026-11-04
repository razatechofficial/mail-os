package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/domain/access"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

func (s *evStore) Record(_ context.Context, tenantID, eventID string) (inbound.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[tenantID+eventID]
	if !ok {
		return inbound.Record{}, apperrors.NotFound("event not found")
	}
	return r, nil
}

// statusDeliveries holds every message the dispatcher created, as the
// application that sent it.
type statusDeliveries struct {
	appID string
	at    time.Time
}

func (d statusDeliveries) Delivery(_ context.Context, tenantID, id string) (domainmsg.Message, []domainmsg.DeliveryEvent, error) {
	if tenantID != evTenant || id == "msg-unknown" {
		return domainmsg.Message{}, nil, apperrors.NotFound("message not found")
	}
	sent := d.at.Add(time.Second)
	m := domainmsg.Message{ID: id, OrgID: tenantID, ApplicationID: d.appID, Status: domainmsg.StatusBounced,
		LastError: "550 unknown", CreatedAt: d.at, UpdatedAt: d.at, SentAt: &sent}
	return m, []domainmsg.DeliveryEvent{{Type: domainmsg.EventBounced, OccurredAt: d.at.Add(time.Minute)}}, nil
}

func TestDeliveryStatusRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	log := &evAudit{}
	app := appstest.Server("iam", evTenant, "iam.*")
	apps := appstest.New(app, appstest.Server("crm", evTenant, "iam.*"))
	store := &evStore{rows: map[string]inbound.Record{}}
	svc := inbound.NewService(apps, evTenants{}, store, evTx{}, &evDispatcher{}, log)
	status := inbound.NewStatusService(apps, statusDeliveries{appID: app.ID, at: time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)}, store)
	auth := &middleware.Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}), Tenants: evTenants{},
		Apps: apps, Audit: log}
	g := middleware.Guard{StepUp: access.StepUpPolicy{MaxAge: 5 * time.Minute, ACR: access.ACRMFA}, Audit: log}
	r := gin.New()
	NewEventHandler(svc).WithStatus(status).Mount(r.Group("/api/v1", auth.Required()), g)

	token := iam.ServiceToken("iam", evTenant)
	const eventID = "0193a000-0000-7000-8000-0000000000cd"
	if w := postEvent(r, token, iamEvent(eventID, "iam.auth.password_reset_requested", evTenant)); w.Code != http.StatusAccepted {
		t.Fatalf("dispatch %d %s", w.Code, w.Body)
	}
	get := func(path, token string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r.ServeHTTP(w, req)
		return w
	}
	for _, path := range []string{"/api/v1/events/deliveries/msg-" + eventID, "/api/v1/events/" + eventID + "/delivery"} {
		w := get(path, token)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		var body struct {
			Data struct {
				DeliveryID string `json:"delivery_id"`
				EventID    string `json:"event_id"`
				Status     string `json:"status"`
				LastError  string `json:"last_error"`
				Events     []struct {
					Type       string    `json:"type"`
					OccurredAt time.Time `json:"occurred_at"`
				} `json:"events"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		d := body.Data
		if d.DeliveryID != "msg-"+eventID || d.Status != "bounced" || d.LastError != "550 unknown" || len(d.Events) != 3 ||
			d.Events[2].Type != "bounced" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %s", path, w.Body)
		}
		if path != "/api/v1/events/deliveries/msg-"+eventID && d.EventID != eventID {
			t.Fatalf("event id missing: %s", w.Body)
		}
	}
	// Another application of the tenant sees nothing; a user may not ask.
	if w := get("/api/v1/events/"+eventID+"/delivery", iam.ServiceToken("crm", evTenant)); w.Code != http.StatusNotFound {
		t.Fatalf("other application: %d %s", w.Code, w.Body)
	}
	if w := get("/api/v1/events/deliveries/msg-unknown", token); w.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", w.Code)
	}
	user := iam.UserToken(fakeiam.User{Tenant: evTenant, Roles: []string{"mailos_admin"}})
	if w := get("/api/v1/events/deliveries/msg-"+eventID, user); w.Code != http.StatusForbidden {
		t.Fatalf("user: %d %s", w.Code, w.Body)
	}
}
