//go:build e2e

// Package campaigns sends a campaign to a static list end to end: each
// active contact gets the published template rendered with their fields,
// unsubscribed contacts get nothing, and a finished campaign cannot be
// launched again.
package campaigns

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "campaigns", &fx) }

func draft(t *testing.T, c *harness.Client, id string, rev any, subject, html string) map[string]any {
	t.Helper()
	return c.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/templates/"+id+"/draft", map[string]any{
		"locale": "en", "revision": rev, "subject": subject, "html_body": html, "text_body": subject}).Data()
}

func TestCampaignSkipsUnsubscribedContacts(t *testing.T) {
	op, _ := fx.NewUser(t, harness.RoleOperator)
	admin := fx.Admin(t)
	tpl := harness.Str(admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", map[string]any{
		"name": "Promo", "slug": "promo-" + harness.Unique(), "category": "marketing"}).Data(), "id")
	d := draft(t, admin, tpl, 0, "November offer", "<p>Dear {{contact.first_name}}</p>")
	admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+tpl+"/publish", map[string]any{"locale": "en", "revision": d["revision"]})

	in, out := fx.Env.NewMailbox("in"), fx.Env.NewMailbox("out")
	op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/contacts/batch", map[string]any{"contacts": []map[string]any{
		{"email": in.Address, "first_name": "Ina"}, {"email": out.Address, "first_name": "Otto"}}})
	contacts := op.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/contacts?limit=100", nil).Items()
	var ids []string
	for _, c := range contacts {
		if c["email"] == in.Address || c["email"] == out.Address {
			ids = append(ids, harness.Str(c, "id"))
		}
		if c["email"] == out.Address {
			op.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/contacts/"+harness.Str(c, "id"), map[string]any{"status": "unsubscribed"})
		}
	}
	if len(ids) != 2 {
		t.Fatalf("imported contacts: %v", contacts)
	}
	list := harness.Str(op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/contact-lists", map[string]any{"name": "Nov", "type": "static"}).Data(), "id")
	op.Expect(t, http.StatusNoContent, http.MethodPost, "/api/v1/contact-lists/"+list+"/members", map[string]any{"contact_ids": ids})
	camp := harness.Str(op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/campaigns", map[string]any{
		"name": "Nov", "subject": "November offer", "from_name": "MMBL", "from_email": "offers@example.com",
		"template_id": tpl, "contact_list_id": list, "type": "regular"}).Data(), "id")
	op.Expect(t, http.StatusOK, http.MethodPost, "/api/v1/campaigns/"+camp+"/launch", nil)
	if mail := in.Wait(t, nil); !strings.Contains(mail.HTML+mail.Text, "Ina") {
		t.Fatalf("campaign mail: %s", mail.JSON())
	}
	out.Empty(t, 3*time.Second)
	op.ExpectError(t, http.StatusConflict, "", http.MethodPost, "/api/v1/campaigns/"+camp+"/launch", nil)
	op.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPost, "/api/v1/contact-lists", map[string]any{"name": "Dyn", "type": "dynamic", "query": "x"})
}
