//go:build integration

package integration

import (
	"testing"

	"github.com/google/uuid"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/infrastructure/mailer"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// Templates list with their publication state and are found by part of
// the name or slug; LIKE wildcards in the search are literal.
func TestTemplateListPublicationAndSearchOnPostgres(t *testing.T) {
	e := newTemplateEnv(t)
	tpl, err := e.svc.Create(e.ctx, e.tenant, apptemplate.CreateInput{Name: "One-time code OTP_1", Slug: "otp-code"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Create(e.ctx, e.tenant, apptemplate.CreateInput{Name: "Welcome OTPx1", Slug: "welcome"}); err != nil {
		t.Fatal(err)
	}
	one := func(search string) apptemplate.Listed {
		t.Helper()
		list, total, err := e.svc.List(e.ctx, e.tenant, apptemplate.ListQuery{Search: search, Limit: 10})
		if err != nil || total != 1 || len(list) != 1 {
			t.Fatalf("search %q: %d %+v %v", search, total, list, err)
		}
		return list[0]
	}
	if l := one("otp_"); l.ID != tpl.ID || l.Publication() != apptemplate.PublicationDraft {
		t.Fatalf("draft: %+v", l)
	}
	by := uuid.NewString()
	e.save(t, tpl.ID, "en", 0, "Your code", by)
	if _, err := e.svc.Publish(e.ctx, e.tenant, tpl.ID, "en", 1, by); err != nil {
		t.Fatal(err)
	}
	if l := one("one-TIME"); l.Publication() != apptemplate.PublicationPublished || l.PublishedVersion != 1 {
		t.Fatalf("published: %+v", l)
	}
	e.save(t, tpl.ID, "en", 1, "Your new code", by)
	if l := one("otp_"); l.Publication() != apptemplate.PublicationChanged || l.PublishedVersion != 1 {
		t.Fatalf("changed: %+v", l)
	}
}

// Messages are found by part of the recipient and sorted on request.
func TestMessageListSearchAndSortOnPostgres(t *testing.T) {
	e := newMsgEnv(t)
	svc := messageService(e, mailer.NewE2ESink(connectRedis(t).Client, platformFrom))
	ctx := e.userCtx()
	for _, to := range []string{"ana@bank.example", "bob@bank.example", "an_a@other.example"} {
		if _, err := svc.Send(ctx, appmessage.SendInput{TenantID: e.tenant, FromEmail: "noreply@bank.example", ToEmail: to,
			Subject: "Hi", Text: "hello"}); err != nil {
			t.Fatal(err)
		}
	}
	repo := postgres.NewMessageRepository(e.db)
	list, total, err := repo.List(ctx, appmessage.Filter{TenantID: e.tenant, Search: "AN_", Limit: 10})
	if err != nil || total != 1 || list[0].ToEmail != "an_a@other.example" {
		t.Fatalf("search with a literal underscore: %d %v", total, err)
	}
	list, total, err = repo.List(ctx, appmessage.Filter{TenantID: e.tenant, Search: "bank.example", SortBy: "to_email", SortOrder: "asc", Limit: 10})
	if err != nil || total != 2 || list[0].ToEmail != "ana@bank.example" || list[1].ToEmail != "bob@bank.example" {
		t.Fatalf("sorted: %d %v", total, err)
	}
	list, _, _ = repo.List(ctx, appmessage.Filter{TenantID: e.tenant, Search: "bank.example", SortBy: "to_email", SortOrder: "desc", Limit: 10})
	if list[0].ToEmail != "bob@bank.example" {
		t.Fatal("descending sort ignored")
	}
}
