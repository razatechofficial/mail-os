package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

const (
	evTenant      = "8d3b1f7a-2c4e-4f6a-9b1d-3e5f7a9c1b2d"
	evOtherTenant = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
)

type evAudit struct {
	mu      sync.Mutex
	entries []map[string]any
}

func (a *evAudit) Append(_ context.Context, _, _, action string, meta map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := map[string]any{"action": action}
	for k, v := range meta {
		m[k] = v
	}
	a.entries = append(a.entries, m)
	return nil
}

func (a *evAudit) last() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) == 0 {
		return nil
	}
	return a.entries[len(a.entries)-1]
}

type evStore struct {
	mu   sync.Mutex
	rows map[string]inbound.Record
}

func (s *evStore) Claim(_ context.Context, r inbound.Record) (inbound.Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.rows[r.TenantID+r.EventID]; ok {
		return p, false, nil
	}
	s.rows[r.TenantID+r.EventID] = r
	return inbound.Record{}, true, nil
}

func (s *evStore) Complete(_ context.Context, tenant, id, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[tenant+id]
	r.MessageID = msg
	s.rows[tenant+id] = r
	return nil
}

type evTx struct{}

func (evTx) InTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

type evTenants struct{}

func (evTenants) Ensure(context.Context, string) error { return nil }

type evDispatcher struct {
	mu   sync.Mutex
	sent []inbound.Delivery
}

func (d *evDispatcher) Dispatch(_ context.Context, del inbound.Delivery) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = append(d.sent, del)
	return "msg-" + del.EventID, nil
}

func eventsRouter(t *testing.T) (*fakeiam.IAM, *gin.Engine, *evAudit, *evDispatcher) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	log, disp := &evAudit{}, &evDispatcher{}
	grants := access.NewServiceGrants([]access.ServiceGrant{{ClientID: "iam", TopicPatterns: []string{"iam.*"}}})
	svc := inbound.NewService(grants, evTenants{}, &evStore{rows: map[string]inbound.Record{}}, evTx{}, disp, log)
	auth := &middleware.Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}), Tenants: evTenants{}, Audit: log}
	g := middleware.Guard{StepUp: access.StepUpPolicy{MaxAge: 5 * time.Minute, ACR: access.ACRMFA}, Audit: log}
	r := gin.New()
	NewEventHandler(svc).Mount(r.Group("/api/v1", auth.Required()), g)
	return iam, r, log, disp
}

func postEvent(r *gin.Engine, token, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/events", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func iamEvent(id, typ, tenant string) string {
	b, _ := json.Marshal(map[string]any{
		"id": id, "type": typ, "source": "iam", "timestamp": "2026-10-31T10:00:00Z", "tenant_uuid": tenant,
		"data": map[string]any{"email": "amna@example.com", "reset_link": "https://iam.example.com/reset/x"},
	})
	return string(b)
}

func TestPostEventAcceptedOnce(t *testing.T) {
	iam, r, log, disp := eventsRouter(t)
	token := iam.ServiceToken("iam", evTenant)
	body := iamEvent("e1", "iam.auth.password_reset_requested", evTenant)
	w := postEvent(r, token, body)
	if w.Code != 202 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	var got struct {
		Data eventAccepted `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Data.Accepted || got.Data.DeliveryID != "msg-e1" || got.Data.Duplicate {
		t.Fatalf("body %s", w.Body)
	}
	if len(disp.sent) != 1 || disp.sent[0].TenantID != evTenant || disp.sent[0].ClientID != "iam" {
		t.Fatalf("dispatched %+v", disp.sent)
	}
	if a := log.last(); a["action"] != inbound.AuditAccepted || a["message_id"] != "msg-e1" {
		t.Fatalf("audit %+v", a)
	}

	w = postEvent(r, token, body)
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 202 || !got.Data.Duplicate || got.Data.DeliveryID != "msg-e1" || len(disp.sent) != 1 {
		t.Fatalf("duplicate: %d %s", w.Code, w.Body)
	}
}

func TestPostEventRefusals(t *testing.T) {
	iam, r, log, disp := eventsRouter(t)
	reset := "iam.auth.password_reset_requested"
	cases := []struct {
		name, token, body, action, reason string
	}{
		{"unknown client", iam.ServiceToken("crm", evTenant), iamEvent("e1", reset, evTenant), inbound.AuditRefused, "unknown_client"},
		{"foreign tenant", iam.ServiceToken("iam", evTenant), iamEvent("e2", reset, evOtherTenant), inbound.AuditRefused, "tenant_mismatch"},
		{"wrong topic", iam.ServiceToken("iam", evTenant), iamEvent("e3", "mailos.campaign", evTenant), inbound.AuditRefused, "topic_not_allowed"},
		{"user token", iam.UserToken(fakeiam.User{Tenant: evTenant, Roles: []string{"mailos_admin"}}), iamEvent("e4", reset, evTenant), "access_denied", "permission"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postEvent(r, tc.token, tc.body)
			if w.Code != 403 {
				t.Fatalf("status %d %s", w.Code, w.Body)
			}
			if a := log.last(); a["action"] != tc.action || a["reason"] != tc.reason {
				t.Fatalf("audit %+v, want %s %s", a, tc.action, tc.reason)
			}
		})
	}
	if len(disp.sent) != 0 {
		t.Fatalf("a refused event was dispatched: %+v", disp.sent)
	}
}

func TestPostEventInvalid(t *testing.T) {
	iam, r, _, disp := eventsRouter(t)
	token := iam.ServiceToken("iam", evTenant)
	if w := postEvent(r, token, `{"type":`); w.Code != 400 {
		t.Fatalf("malformed JSON: %d", w.Code)
	}
	if w := postEvent(r, token, `{"type":"iam.auth.password_reset_requested","data":[]}`); w.Code != 422 {
		t.Fatalf("data not an object: %d %s", w.Code, w.Body)
	}
	noEmail := `{"id":"e9","type":"iam.auth.password_reset_requested","data":{"reset_link":"https://iam.example.com/r"}}`
	if w := postEvent(r, token, noEmail); w.Code != 422 || !strings.Contains(w.Body.String(), "data.email") {
		t.Fatalf("no recipient: %d %s", w.Code, w.Body)
	}
	if w := postEvent(r, token, `{"type":"iam.auth.login","data":{"x":"`+strings.Repeat("a", 300<<10)+`"}}`); w.Code != 413 {
		t.Fatalf("oversized: %d", w.Code)
	}
	if w := postEvent(r, "", iamEvent("e1", "iam.auth.password_reset_requested", evTenant)); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	if len(disp.sent) != 0 {
		t.Fatal("an invalid event was dispatched")
	}
}
