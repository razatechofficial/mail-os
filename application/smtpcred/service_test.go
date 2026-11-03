package smtpcred

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	domainapp "github.com/razatechofficial/mail-os/domain/application"
	domain "github.com/razatechofficial/mail-os/domain/smtpcredential"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

const tenant = "0a1b2c3d-0000-4000-8000-000000000001"

type memRepo struct {
	mu    sync.Mutex
	creds map[string]domain.Credential
}

func (r *memRepo) Create(_ context.Context, c domain.Credential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.creds[c.ID] = c
	return nil
}

func (r *memRepo) Get(_ context.Context, tenantID, id string) (domain.Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.creds[id]
	if !ok || c.TenantID != tenantID {
		return domain.Credential{}, apperrors.NotFound("smtp credential not found")
	}
	return c, nil
}

func (r *memRepo) ByUsername(_ context.Context, username string) (domain.Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.creds {
		if c.Username == username {
			return c, nil
		}
	}
	return domain.Credential{}, ErrNotFound
}

func (r *memRepo) List(_ context.Context, tenantID, applicationID string) ([]domain.Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.Credential
	for _, c := range r.creds {
		if c.TenantID == tenantID && c.ApplicationID == applicationID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func (r *memRepo) SetPassword(_ context.Context, c domain.Credential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.creds[c.ID] = c
	return nil
}

func (r *memRepo) Revoke(_ context.Context, _, id string, at time.Time, by string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.creds[id]
	c.RevokedAt, c.RevokedBy = &at, by
	r.creds[id] = c
	return nil
}

func (r *memRepo) Touch(_ context.Context, id string, at time.Time, ip string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.creds[id]
	c.LastUsedAt, c.LastUsedIP = &at, ip
	r.creds[id] = c
	return nil
}

type memApps struct {
	apps map[string]domainapp.Application
}

func (m *memApps) Get(_ context.Context, tenantID, id string) (domainapp.Application, error) {
	a, ok := m.apps[id]
	if !ok || a.TenantID != tenantID {
		return domainapp.Application{}, apperrors.NotFound("application not found")
	}
	return a, nil
}

type memAudit struct{ actions []string }

func (a *memAudit) Change(_ context.Context, _, _, action string, before, after any, extra map[string]any) error {
	for _, v := range []any{before, after, extra} {
		if r, ok := v.(record); ok && r.Username == "" {
			return errors.New("record without username")
		}
	}
	a.actions = append(a.actions, action)
	return nil
}

func newEnv(a domainapp.Application) (*Service, *memRepo, *memApps, *memAudit) {
	repo := &memRepo{creds: map[string]domain.Credential{}}
	apps := &memApps{apps: map[string]domainapp.Application{a.ID: a}}
	audit := &memAudit{}
	return NewService(repo, apps, audit, Config{}), repo, apps, audit
}

func legacyApp() domainapp.Application {
	return domainapp.Application{ID: "app-1", TenantID: tenant, Kind: domainapp.KindServer, ClientID: "core-banking",
		Status: domainapp.StatusActive, SMTPPasswordAuth: true}
}

func reason(err error) string {
	var ae *AuthError
	if errors.As(err, &ae) {
		return ae.Reason
	}
	return ""
}

func TestCreateAuthenticateRotateRevoke(t *testing.T) {
	svc, repo, _, audit := newEnv(legacyApp())
	ctx := context.Background()
	c, password, err := svc.Create(ctx, tenant, "app-1", "core banking batch host", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !domain.ValidUsername(c.Username) || password == "" || c.PasswordHash == "" || c.PasswordHash == password {
		t.Fatalf("credential %+v", c)
	}
	got, a, err := svc.Authenticate(ctx, " "+c.Username+" ", password, "10.0.0.7")
	if err != nil || got.ID != c.ID || a.ID != "app-1" {
		t.Fatalf("authenticate: %v", err)
	}
	if stored := repo.creds[c.ID]; stored.LastUsedAt == nil || stored.LastUsedIP != "10.0.0.7" {
		t.Fatalf("last use not recorded: %+v", stored)
	}
	if _, _, err := svc.Authenticate(ctx, c.Username, password+"x", ""); reason(err) != ReasonBadPassword {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, err := svc.Authenticate(ctx, "smtp_aaaaaaaaaaaaaaaaaaaaaaaa", password, ""); reason(err) != ReasonUnknownUsername {
		t.Fatalf("unknown username: %v", err)
	}
	if _, _, err := svc.Authenticate(ctx, password, c.Username, ""); reason(err) != ReasonUnknownUsername {
		t.Fatalf("swapped fields: %v", err)
	}

	_, newPassword, err := svc.Rotate(ctx, tenant, "app-1", c.ID, "admin")
	if err != nil || newPassword == password {
		t.Fatalf("rotate: %v", err)
	}
	if _, _, err := svc.Authenticate(ctx, c.Username, password, ""); reason(err) != ReasonBadPassword {
		t.Fatalf("the old password after rotation: %v", err)
	}
	if _, _, err := svc.Authenticate(ctx, c.Username, newPassword, ""); err != nil {
		t.Fatalf("the new password: %v", err)
	}

	if err := svc.Revoke(ctx, tenant, "app-1", c.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, tenant, "app-1", c.ID, "admin"); err != nil {
		t.Fatalf("revoking twice: %v", err)
	}
	if _, _, err := svc.Authenticate(ctx, c.Username, newPassword, ""); reason(err) != ReasonRevoked {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := svc.Check(ctx, c); reason(err) != ReasonRevoked {
		t.Fatalf("an open session of a revoked credential: %v", err)
	}
	want := []string{AuditCreated, AuditRotated, AuditRevoked}
	if len(audit.actions) != len(want) {
		t.Fatalf("audit %v", audit.actions)
	}
	for i := range want {
		if audit.actions[i] != want[i] {
			t.Fatalf("audit %v", audit.actions)
		}
	}
}

func TestCreateNeedsAnOptedInServerApplication(t *testing.T) {
	ctx := context.Background()
	off := legacyApp()
	off.SMTPPasswordAuth = false
	svc, _, _, _ := newEnv(off)
	if _, _, err := svc.Create(ctx, tenant, "app-1", "", "admin"); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("not opted in: %v", err)
	}
	spa := legacyApp()
	spa.Kind = domainapp.KindSPA
	svc, _, _, _ = newEnv(spa)
	if _, _, err := svc.Create(ctx, tenant, "app-1", "", "admin"); apperrors.KindOf(err) != apperrors.KindForbidden {
		t.Fatalf("spa: %v", err)
	}
	svc, _, _, _ = newEnv(legacyApp())
	if _, _, err := svc.Create(ctx, "other-tenant", "app-1", "", "admin"); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant's application: %v", err)
	}
	for i := 0; i < domain.MaxActive; i++ {
		if _, _, err := svc.Create(ctx, tenant, "app-1", "", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := svc.Create(ctx, tenant, "app-1", "", "admin"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("a third active credential: %v", err)
	}
}

func TestAuthenticateFollowsTheApplication(t *testing.T) {
	ctx := context.Background()
	svc, _, apps, _ := newEnv(legacyApp())
	c, password, err := svc.Create(ctx, tenant, "app-1", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	a := apps.apps["app-1"]
	a.Status = domainapp.StatusSuspended
	apps.apps["app-1"] = a
	if _, _, err := svc.Authenticate(ctx, c.Username, password, ""); reason(err) != ReasonApplication {
		t.Fatalf("suspended application: %v", err)
	}
	a.Status, a.SMTPPasswordAuth = domainapp.StatusActive, false
	apps.apps["app-1"] = a
	if _, _, err := svc.Authenticate(ctx, c.Username, password, ""); reason(err) != ReasonNotEnabled {
		t.Fatalf("opt-in turned off: %v", err)
	}
	if _, err := svc.Check(ctx, c); reason(err) != ReasonNotEnabled {
		t.Fatalf("an open session after the opt-in is turned off: %v", err)
	}
}
