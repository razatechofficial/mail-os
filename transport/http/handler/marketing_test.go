package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/campaign"
	"github.com/razatechofficial/mail-os/application/contact"
	"github.com/razatechofficial/mail-os/domain/access"
	domaincampaign "github.com/razatechofficial/mail-os/domain/campaign"
	domaincontact "github.com/razatechofficial/mail-os/domain/contact"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

const (
	tenantA = "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"
	tenantB = "0b6c0a51-1d6e-4a6b-b0f4-6b8f8c1d2e3f"
)

// memory is just enough storage for the routes: contacts, lists and
// campaigns by id, tenant-scoped like the Postgres repositories.
type memory struct {
	contacts  map[string]domaincontact.Contact
	lists     map[string]domaincontact.List
	campaigns map[string]domaincampaign.Campaign
}

func (m *memory) Get(_ context.Context, t, id string) (domaincontact.Contact, error) {
	if c, ok := m.contacts[id]; ok && c.OrgID == t {
		return c, nil
	}
	return domaincontact.Contact{}, domaincontact.ErrNotFound
}
func (m *memory) List(_ context.Context, t string, _ contact.Filter) ([]domaincontact.Contact, int, error) {
	var out []domaincontact.Contact
	for _, c := range m.contacts {
		if c.OrgID == t {
			out = append(out, c)
		}
	}
	return out, len(out), nil
}
func (m *memory) Create(_ context.Context, c domaincontact.Contact) error { m.contacts[c.ID] = c; return nil }
func (m *memory) CreateMany(_ context.Context, cs []domaincontact.Contact) (int, error) {
	for _, c := range cs {
		m.contacts[c.ID] = c
	}
	return len(cs), nil
}
func (m *memory) Update(_ context.Context, c domaincontact.Contact) error { m.contacts[c.ID] = c; return nil }
func (m *memory) Delete(_ context.Context, _, id string) error           { delete(m.contacts, id); return nil }

func (m *memory) GetList(_ context.Context, t, id string) (domaincontact.List, error) {
	if l, ok := m.lists[id]; ok && l.OrgID == t {
		return l, nil
	}
	return domaincontact.List{}, domaincontact.ErrListNotFound
}
func (m *memory) Lists(context.Context, string, int, int) ([]domaincontact.List, int, error) {
	return nil, 0, nil
}
func (m *memory) CreateList(_ context.Context, l domaincontact.List) error { m.lists[l.ID] = l; return nil }
func (m *memory) UpdateList(_ context.Context, l domaincontact.List) error { m.lists[l.ID] = l; return nil }
func (m *memory) DeleteList(_ context.Context, _, id string) error         { delete(m.lists, id); return nil }
func (m *memory) InUse(context.Context, string, string) (bool, error)      { return false, nil }
func (m *memory) MissingContacts(ctx context.Context, t string, ids []string) ([]string, error) {
	var out []string
	for _, id := range ids {
		if _, err := m.Get(ctx, t, id); err != nil {
			out = append(out, id)
		}
	}
	return out, nil
}
func (m *memory) AddMembers(_ context.Context, _, _ string, ids []string) (int, error) {
	return len(ids), nil
}
func (m *memory) RemoveMembers(context.Context, string, string, []string) (int, error) { return 0, nil }
func (m *memory) Members(context.Context, string, string, contact.Filter) ([]domaincontact.Contact, int, error) {
	return nil, 0, nil
}

// campaigns is the campaign side of memory (method names overlap).
type campaigns struct{ *memory }

func (m campaigns) Get(_ context.Context, t, id string) (domaincampaign.Campaign, error) {
	if c, ok := m.campaigns[id]; ok && c.OrgID == t {
		return c, nil
	}
	return domaincampaign.Campaign{}, domaincampaign.ErrNotFound
}
func (m campaigns) Lock(ctx context.Context, t, id string) (domaincampaign.Campaign, error) {
	return m.Get(ctx, t, id)
}
func (m campaigns) List(context.Context, string, campaign.Filter) ([]domaincampaign.Campaign, int, error) {
	return nil, 0, nil
}
func (m campaigns) Create(_ context.Context, c domaincampaign.Campaign) error {
	m.campaigns[c.ID] = c
	return nil
}
func (m campaigns) Update(_ context.Context, c domaincampaign.Campaign) error {
	m.campaigns[c.ID] = c
	return nil
}
func (m campaigns) Delete(_ context.Context, _, id string) error { delete(m.campaigns, id); return nil }
func (m campaigns) Due(context.Context, time.Time, int) ([]domaincampaign.Campaign, error) {
	return nil, nil
}
func (m campaigns) Stalled(context.Context, time.Time, int) ([]domaincampaign.Campaign, error) {
	return nil, nil
}
func (m campaigns) SetTotal(context.Context, string, int) error       { return nil }
func (m campaigns) AddCounts(context.Context, string, int, int) error { return nil }
func (m campaigns) TemplateExists(_ context.Context, t, id string) (bool, error) {
	return id == "tpl-1" && t == tenantA, nil
}
func (m campaigns) ListExists(ctx context.Context, t, id string) (bool, error) {
	_, err := m.GetList(ctx, t, id)
	return err == nil, nil
}
func (m campaigns) EnqueueFanout(context.Context, string, string) error { return nil }

type noAudit struct{}

func (noAudit) Append(context.Context, string, string, string, map[string]any) error { return nil }
func (noAudit) Change(context.Context, string, string, string, any, any, map[string]any) error {
	return nil
}

type noTx struct{}

func (noTx) InTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

type okSender struct{}

func (okSender) SendCampaignMessage(context.Context, campaign.CampaignMessage) (string, error) {
	return "m1", nil
}

type ensureAll struct{}

func (ensureAll) Ensure(context.Context, string) error { return nil }

// marketingRouter mounts the three handlers behind real authentication.
func marketingRouter(t *testing.T, sender campaign.CampaignSender) (*fakeiam.IAM, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	m := &memory{contacts: map[string]domaincontact.Contact{}, lists: map[string]domaincontact.List{}, campaigns: map[string]domaincampaign.Campaign{}}
	cs := contact.NewService(m, m, noTx{}, noAudit{})
	cm := campaigns{m}
	ps := campaign.NewService(campaign.Deps{Campaigns: cm, Targets: cm, Queue: cm, Sender: sender, Tx: noTx{}, Audit: noAudit{}}, campaign.Config{})
	auth := &middleware.Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}), Tenants: ensureAll{}}
	g := middleware.Guard{StepUp: access.StepUpPolicy{MaxAge: 5 * time.Minute, ACR: access.ACRMFA}}
	r := gin.New()
	api := r.Group("/api/v1", middleware.RequestID(), auth.Required())
	for _, h := range []interface {
		Mount(*gin.RouterGroup, middleware.Guard)
	}{NewContactHandler(cs), NewContactListHandler(cs), NewCampaignHandler(ps)} {
		h.Mount(api, g)
	}
	return iam, r
}

type reply struct {
	status int
	Data   map[string]any `json:"data"`
	Error  struct {
		Code    string `json:"code"`
		Details []struct{ Field, Code string }
	} `json:"error"`
}

func do(r *gin.Engine, method, path, token string, body any) reply {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out reply
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	out.status = w.Code
	return out
}

func token(iam *fakeiam.IAM, tenant string, role access.Role) string {
	return iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{string(role)}})
}

// Every role reads; only mailos_admin and mailos_operator change contacts
// and campaigns. Another tenant's rows are 404.
func TestMarketingRoles(t *testing.T) {
	iam, r := marketingRouter(t, okSender{})
	viewer, operator := token(iam, tenantA, access.RoleViewer), token(iam, tenantA, access.RoleOperator)
	admin, editor := token(iam, tenantA, access.RoleAdmin), token(iam, tenantA, access.RoleTemplateEditor)
	foreign := token(iam, tenantB, access.RoleAdmin)

	for _, tok := range []string{viewer, editor, operator} {
		for _, p := range []string{"/api/v1/contacts", "/api/v1/contact-lists", "/api/v1/campaigns"} {
			if got := do(r, "GET", p, tok, nil); got.status != 200 {
				t.Fatalf("GET %s: %d", p, got.status)
			}
		}
	}
	contactBody := map[string]any{"email": "Amna@Example.com", "first_name": "Amna"}
	for _, tok := range []string{viewer, editor} {
		if got := do(r, "POST", "/api/v1/contacts", tok, contactBody); got.status != 403 || got.Error.Code != "FORBIDDEN" {
			t.Fatalf("read-only role created a contact: %d", got.status)
		}
		if got := do(r, "POST", "/api/v1/campaigns", tok, map[string]any{}); got.status != 403 {
			t.Fatalf("read-only role created a campaign: %d", got.status)
		}
	}
	created := do(r, "POST", "/api/v1/contacts", operator, contactBody)
	if created.status != 201 || created.Data["email"] != "amna@example.com" || created.Data["status"] != "active" {
		t.Fatalf("operator create: %d %v", created.status, created.Data)
	}
	id, _ := created.Data["id"].(string)
	if got := do(r, "GET", "/api/v1/contacts/"+id, viewer, nil); got.status != 200 {
		t.Fatalf("viewer get: %d", got.status)
	}
	if got := do(r, "GET", "/api/v1/contacts/"+id, foreign, nil); got.status != 404 {
		t.Fatalf("other tenant reads the contact: %d", got.status)
	}
	if got := do(r, "DELETE", "/api/v1/contacts/"+id, foreign, nil); got.status != 404 {
		t.Fatalf("other tenant deletes the contact: %d", got.status)
	}
	if got := do(r, "POST", "/api/v1/contacts", admin, map[string]any{"email": "nope"}); got.status != 422 ||
		len(got.Error.Details) != 1 || got.Error.Details[0].Field != "email" {
		t.Fatalf("invalid contact: %d %+v", got.status, got.Error)
	}
	if got := do(r, "POST", "/api/v1/contacts/batch", admin, map[string]any{"contacts": []any{map[string]any{"email": "b@example.com"}}}); got.status != 201 || got.Data["created_count"] != float64(1) {
		t.Fatalf("import: %d %v", got.status, got.Data)
	}

	list := do(r, "POST", "/api/v1/contact-lists", operator, map[string]any{"name": "VIP"})
	if list.status != 201 || list.Data["type"] != "static" {
		t.Fatalf("list: %d %v", list.status, list.Data)
	}
	listID, _ := list.Data["id"].(string)
	if got := do(r, "POST", "/api/v1/contact-lists/"+listID+"/members", viewer, map[string]any{"contact_ids": []string{id}}); got.status != 403 {
		t.Fatalf("viewer added members: %d", got.status)
	}
	if got := do(r, "POST", "/api/v1/contact-lists/"+listID+"/members", operator, map[string]any{"contact_ids": []string{id}}); got.status != 204 {
		t.Fatalf("add members: %d", got.status)
	}
	if got := do(r, "POST", "/api/v1/contact-lists/"+listID+"/members", operator, map[string]any{"contact_ids": []string{"missing"}}); got.status != 422 {
		t.Fatalf("unknown member: %d", got.status)
	}
	if got := do(r, "GET", "/api/v1/contact-lists/"+listID+"/members", foreign, nil); got.status != 404 {
		t.Fatalf("other tenant reads members: %d", got.status)
	}

	cmp := do(r, "POST", "/api/v1/campaigns", operator, map[string]any{"name": "Autumn", "subject": "News", "from_name": "Averox",
		"from_email": "news@example.com", "template_id": "tpl-1", "contact_list_id": listID})
	if cmp.status != 201 || cmp.Data["status"] != "draft" {
		t.Fatalf("campaign: %d %v %+v", cmp.status, cmp.Data, cmp.Error)
	}
	cid, _ := cmp.Data["id"].(string)
	if got := do(r, "POST", "/api/v1/campaigns/"+cid+"/launch", viewer, nil); got.status != 403 {
		t.Fatalf("viewer launched: %d", got.status)
	}
	if got := do(r, "POST", "/api/v1/campaigns/"+cid+"/launch", foreign, nil); got.status != 404 {
		t.Fatalf("other tenant launched: %d", got.status)
	}
	if got := do(r, "POST", "/api/v1/campaigns/"+cid+"/launch", operator, nil); got.status != 200 || got.Data["status"] != "sending" {
		t.Fatalf("launch: %d %v", got.status, got.Data)
	}
	if got := do(r, "POST", "/api/v1/campaigns/"+cid+"/resume", operator, nil); got.status != 409 || got.Error.Code != "CONFLICT" {
		t.Fatalf("resume while sending: %d %s", got.status, got.Error.Code)
	}
	if got := do(r, "POST", "/api/v1/campaigns/"+cid+"/pause", admin, nil); got.status != 200 || got.Data["status"] != "paused" {
		t.Fatalf("pause: %d %v", got.status, got.Data)
	}
	if got := do(r, "DELETE", "/api/v1/campaigns/"+cid, operator, nil); got.status != 204 {
		t.Fatalf("delete paused: %d", got.status)
	}
}

// Without a sender a launch is 503 SERVICE_UNAVAILABLE.
func TestLaunchUnavailableWithoutSender(t *testing.T) {
	iam, r := marketingRouter(t, nil)
	operator := token(iam, tenantA, access.RoleOperator)
	list := do(r, "POST", "/api/v1/contact-lists", operator, map[string]any{"name": "VIP"})
	cmp := do(r, "POST", "/api/v1/campaigns", operator, map[string]any{"name": "Autumn", "subject": "News", "from_name": "Averox",
		"from_email": "news@example.com", "template_id": "tpl-1", "contact_list_id": list.Data["id"]})
	cid, _ := cmp.Data["id"].(string)
	if got := do(r, "POST", "/api/v1/campaigns/"+cid+"/launch", operator, nil); got.status != 503 || got.Error.Code != "SERVICE_UNAVAILABLE" {
		t.Fatalf("launch without sender: %d %s", got.status, got.Error.Code)
	}
}
