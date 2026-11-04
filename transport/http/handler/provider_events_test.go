package handler

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/application/providerevents"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/infrastructure/providerhooks"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

const (
	pwTenant   = "8d3b1f7a-2c4e-4f6a-9b1d-3e5f7a9c1b2d"
	pwProvider = "0193a000-0000-7000-8000-0000000000aa"
)

type pwSecrets struct{}

func (pwSecrets) WebhookSecret(_ context.Context, tenantID, id string) (provider.Kind, string, error) {
	if tenantID != pwTenant || id != pwProvider {
		return "", "", apperrors.NotFound("provider not found")
	}
	return provider.KindPostmark, "hook-password", nil
}

type pwRecorder struct {
	got []domainmsg.ProviderEvent
	err error
}

func (r *pwRecorder) RecordProviderEvent(_ context.Context, _, _ string, e domainmsg.ProviderEvent) (appmessage.EventOutcome, error) {
	r.got = append(r.got, e)
	if r.err != nil {
		return "", r.err
	}
	return appmessage.OutcomeRecorded, nil
}

func TestProviderEventWebhook(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := &pwRecorder{}
	log := &evAudit{}
	svc := providerevents.NewService(pwSecrets{}, &providerhooks.Verifier{}, nil, rec, log)
	r := gin.New()
	NewProviderEventHandler(svc).MountPublic(r)

	body := `{"RecordType":"Delivery","MessageID":"pm-1","Recipient":"a@x.example","DeliveredAt":"2026-11-20T10:00:00Z"}`
	post := func(path, password string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		if password != "" {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("mailos:"+password)))
		}
		r.ServeHTTP(w, req)
		return w
	}
	path := "/webhooks/providers/" + pwTenant + "/" + pwProvider
	w := post(path, "hook-password")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"recorded":1`) || len(rec.got) != 1 ||
		rec.got[0].Type != domainmsg.EventDelivered || rec.got[0].ProviderMessageID != "pm-1" {
		t.Fatalf("%d %s %+v", w.Code, w.Body, rec.got)
	}
	for name, p := range map[string]struct{ path, password string }{
		"no password":      {path, ""},
		"wrong password":   {path, "nope"},
		"unknown provider": {"/webhooks/providers/" + pwTenant + "/0193a000-0000-7000-8000-0000000000bb", "hook-password"},
		"bad ids":          {"/webhooks/providers/x/y", "hook-password"},
	} {
		w := post(p.path, p.password)
		if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic") {
			t.Errorf("%s: %d %v", name, w.Code, w.Header())
		}
	}
	if len(rec.got) != 1 {
		t.Fatal("a refused webhook recorded events")
	}
	if log.last()["action"] != providerevents.AuditRefused {
		t.Fatalf("refusal not audited: %v", log.entries)
	}

	rec.err = appmessage.ErrStillSending
	if w := post(path, "hook-password"); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("still sending: %d %v", w.Code, w.Header())
	}
}
