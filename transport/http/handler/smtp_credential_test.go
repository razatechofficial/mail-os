package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/application/smtpcred"
	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	"github.com/razatechofficial/mail-os/domain/smtpcredential"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type oneApp struct{ a domainapp.Application }

func (o oneApp) Get(_ context.Context, tenantID, id string) (domainapp.Application, error) {
	if id != o.a.ID || tenantID != o.a.TenantID {
		return domainapp.Application{}, apperrors.NotFound("application not found")
	}
	return o.a, nil
}

type credRepo struct{ creds []smtpcredential.Credential }

func (r *credRepo) Create(_ context.Context, c smtpcredential.Credential) error {
	r.creds = append(r.creds, c)
	return nil
}

func (r *credRepo) Get(_ context.Context, _, id string) (smtpcredential.Credential, error) {
	for _, c := range r.creds {
		if c.ID == id {
			return c, nil
		}
	}
	return smtpcredential.Credential{}, apperrors.NotFound("smtp credential not found")
}

func (r *credRepo) ByUsername(context.Context, string) (smtpcredential.Credential, error) {
	return smtpcredential.Credential{}, smtpcred.ErrNotFound
}

func (r *credRepo) List(context.Context, string, string) ([]smtpcredential.Credential, error) {
	return r.creds, nil
}

func (r *credRepo) SetPassword(context.Context, smtpcredential.Credential) error { return nil }

func (r *credRepo) Revoke(_ context.Context, _, id string, at time.Time, by string) error {
	for i := range r.creds {
		if r.creds[i].ID == id {
			r.creds[i].RevokedAt, r.creds[i].RevokedBy = &at, by
		}
	}
	return nil
}

func (r *credRepo) Touch(context.Context, string, time.Time, string) error { return nil }

func TestSMTPCredentialRoutes(t *testing.T) {
	app := domainapp.Application{ID: "app-1", TenantID: testTenant, Kind: domainapp.KindServer, Status: domainapp.StatusActive,
		SMTPPasswordAuth: true}
	repo := &credRepo{}
	audit := &recAudit{}
	h := NewSMTPCredentialHandler(smtpcred.NewService(repo, oneApp{app}, audit, smtpcred.Config{}),
		SMTPEndpoint{Enabled: true, Host: "smtp.mailos.bank.example", Port: 587, ImplicitTLSPort: 465, PasswordAuth: true})
	admin := engine(t, h, []access.Role{access.RoleAdmin}, time.Minute, access.ACRMFA)

	w := httptest.NewRecorder()
	admin.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/applications/app-1/smtp-credentials",
		strings.NewReader(`{"description":"core batch host"}`)))
	if w.Code != http.StatusCreated || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var created struct {
		Data struct {
			ID, Username, Password string
			SMTP                   SMTPEndpoint
		}
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if !smtpcredential.ValidUsername(created.Data.Username) || !strings.HasPrefix(created.Data.Password, smtpcredential.PasswordPrefix) ||
		created.Data.SMTP.Host != "smtp.mailos.bank.example" {
		t.Fatalf("created %+v", created.Data)
	}

	w = httptest.NewRecorder()
	admin.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/applications/app-1/smtp-credentials", nil))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), created.Data.Password) || strings.Contains(w.Body.String(), "argon2") ||
		!strings.Contains(w.Body.String(), created.Data.Username) {
		t.Fatalf("list never shows a password or hash: %d %s", w.Code, w.Body)
	}

	// Changing credentials needs a fresh sign-in, and the admin role.
	stale := engine(t, h, []access.Role{access.RoleAdmin}, time.Hour, access.ACRMFA)
	w = httptest.NewRecorder()
	stale.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/applications/app-1/smtp-credentials/"+created.Data.ID+"/rotate", nil))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("rotate without step-up: %d %s", w.Code, w.Body)
	}
	viewer := engine(t, h, []access.Role{access.RoleViewer}, time.Minute, access.ACRMFA)
	w = httptest.NewRecorder()
	viewer.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/applications/app-1/smtp-credentials/"+created.Data.ID, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a viewer revokes: %d", w.Code)
	}

	w = httptest.NewRecorder()
	admin.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/applications/app-1/smtp-credentials/"+created.Data.ID+"/rotate", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"password":"mosmtp_`) {
		t.Fatalf("rotate: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	admin.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/applications/app-1/smtp-credentials/"+created.Data.ID, nil))
	if w.Code != http.StatusNoContent || repo.creds[0].Active() {
		t.Fatalf("revoke: %d", w.Code)
	}
	want := []string{smtpcred.AuditCreated, smtpcred.AuditRotated, smtpcred.AuditRevoked}
	if strings.Join(audit.actions, ",") != strings.Join(want, ",") {
		t.Fatalf("audit %v", audit.actions)
	}
}
