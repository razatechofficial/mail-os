//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"

	"github.com/razatechofficial/mail-os/application/campaign"
	"github.com/razatechofficial/mail-os/application/contact"
	"github.com/razatechofficial/mail-os/application/tenant"
	"github.com/razatechofficial/mail-os/domain/access"
	domaincampaign "github.com/razatechofficial/mail-os/domain/campaign"
	domaincontact "github.com/razatechofficial/mail-os/domain/contact"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// recordingSender is the messaging slice's stand-in.
type recordingSender struct {
	mu   sync.Mutex
	sent []campaign.CampaignMessage
	fail string
}

func (s *recordingSender) SendCampaignMessage(_ context.Context, m campaign.CampaignMessage) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.To == s.fail {
		return "", apperrors.Invalid("to", "refused", "recipient refused")
	}
	s.sent = append(s.sent, m)
	return "msg-" + uuid.NewString(), nil
}

// noQueue drops fan-out tasks: the test runs Fanout itself.
type noQueue struct{}

func (noQueue) EnqueueFanout(context.Context, string, string) error { return nil }

type marketing struct {
	db        *postgres.Pool
	auditRepo *postgres.AuditRepository
	contacts  *contact.Service
	campaigns *campaign.Service
	sender    *recordingSender
}

func newMarketing(t *testing.T) marketing {
	t.Helper()
	db := connectPostgres(t)
	auditRepo := postgres.NewAuditRepository(db)
	w := audit.NewWriter(auditRepo, false)
	snd := &recordingSender{}
	repo := postgres.NewCampaignRepository(db)
	return marketing{
		db: db, auditRepo: auditRepo, sender: snd,
		contacts: contact.NewService(postgres.NewContactRepository(db), postgres.NewContactListRepository(db), db, w),
		campaigns: campaign.NewService(campaign.Deps{Campaigns: repo, Targets: repo, Recipients: postgres.NewCampaignRecipientRepository(db),
			Queue: noQueue{}, Sender: snd, Tx: db, Audit: w, ScopeTenant: audit.WithTenant}, campaign.Config{PageSize: 3, PagesPerTask: 50}),
	}
}

// newTenant provisions a tenant with one template and returns a context
// acting as one of its users.
func newTenant(t *testing.T, m marketing) (context.Context, string, string) {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	if err := tenant.NewService(postgres.NewTenantRepository(m.db), nil, time.Minute).Ensure(ctx, id); err != nil {
		t.Fatal(err)
	}
	tpl := uuid.NewString()
	if _, err := m.db.Exec(ctx, `INSERT INTO templates (id, org_id, name, slug) VALUES ($1, $2, 'Campaign', $1)`, tpl, id); err != nil {
		t.Fatal(err)
	}
	return access.WithPrincipal(ctx, access.Principal{Kind: access.KindUser, Subject: uuid.NewString(), TenantID: id}), id, tpl
}

func TestContactsAndLists(t *testing.T) {
	m := newMarketing(t)
	ctx, tid, _ := newTenant(t, m)
	_, other, _ := newTenant(t, m)

	c, err := m.contacts.Create(ctx, tid, domaincontact.Contact{Email: " Amna@Example.com ", FirstName: "Amna", Metadata: map[string]any{"tier": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.contacts.Create(ctx, tid, domaincontact.Contact{Email: "AMNA@example.com"}); apperrors.KindOf(err) != apperrors.KindAlreadyExists {
		t.Fatalf("duplicate address: %v", err)
	}
	if _, err := m.contacts.Get(ctx, other, c.ID); !apperrors.IsNotFound(err) {
		t.Fatalf("other tenant reads the contact: %v", err)
	}
	got, err := m.contacts.Get(ctx, tid, c.ID)
	if err != nil || got.Email != "amna@example.com" || got.Metadata["tier"] != "gold" {
		t.Fatalf("get %+v %v", got, err)
	}
	res, err := m.contacts.Import(ctx, tid, []domaincontact.Contact{{Email: "amna@example.com"}, {Email: "b@example.com", LastName: "B"}, {Email: "c@example.com"}})
	if err != nil || res.Created != 2 || res.Skipped != 1 {
		t.Fatalf("import %+v %v", res, err)
	}
	page, total, err := m.contacts.List(ctx, tid, contact.Filter{Search: "B@EX", Limit: 10})
	if err != nil || total != 1 || len(page) != 1 || page[0].LastName != "B" {
		t.Fatalf("search %d %v %v", total, page, err)
	}
	if _, total, _ := m.contacts.List(ctx, tid, contact.Filter{Search: "%", Limit: 10}); total != 0 {
		t.Fatalf("a %% search matched %d contacts", total)
	}
	all, total, err := m.contacts.List(ctx, tid, contact.Filter{SortBy: "email", SortOrder: "asc", Limit: 2})
	if err != nil || total != 3 || len(all) != 2 || all[0].Email != "amna@example.com" {
		t.Fatalf("sorted page %d %v %v", total, all, err)
	}

	l, err := m.contacts.CreateList(ctx, tid, domaincontact.List{Name: "VIP", Description: "best"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := m.contacts.Create(ctx, other, domaincontact.Contact{Email: "f@example.com"})
	if _, err := m.contacts.AddMembers(ctx, tid, l.ID, []string{c.ID, foreign.ID}); apperrors.KindOf(err) != apperrors.KindInvalidInput ||
		!strings.Contains(apperrors.UserMessage(err)+fmt.Sprint(apperrors.DetailsOf(err)), foreign.ID) {
		t.Fatalf("other tenant's contact added: %v", err)
	}
	ids := []string{c.ID}
	for _, x := range all {
		ids = append(ids, x.ID)
	}
	if n, err := m.contacts.AddMembers(ctx, tid, l.ID, ids); err != nil || n != 2 {
		t.Fatalf("add %d %v", n, err)
	}
	members, total, err := m.contacts.Members(ctx, tid, l.ID, contact.Filter{Limit: 10})
	if err != nil || total != 2 || len(members) != 2 {
		t.Fatalf("members %d %v", total, err)
	}
	if _, _, err := m.contacts.Members(ctx, other, l.ID, contact.Filter{Limit: 10}); !apperrors.IsNotFound(err) {
		t.Fatal("other tenant reads the members")
	}
	if n, err := m.contacts.RemoveMembers(ctx, tid, l.ID, []string{c.ID}); err != nil || n != 1 {
		t.Fatalf("remove %d %v", n, err)
	}
	if err := m.contacts.Delete(ctx, tid, all[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := m.contacts.Members(ctx, tid, l.ID, contact.Filter{Limit: 10}); total != 0 {
		t.Fatalf("deleted contact still a member (%d)", total)
	}
	if err := m.contacts.DeleteList(ctx, tid, l.ID); err != nil {
		t.Fatal(err)
	}
	events, _, err := m.auditRepo.List(ctx, postgres.AuditFilter{TenantUUID: uuid.MustParse(tid), Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, ev := range events {
		actions[ev.Action] = true
		if strings.Contains(fmt.Sprint(ev.Metadata), "amna@example.com") {
			t.Fatalf("address in the audit log: %s %v", ev.Action, ev.Metadata)
		}
	}
	for _, a := range []string{"contact.created", "contact.imported", "contact.deleted", "contact_list.created", "contact_list.members_added",
		"contact_list.members_removed", "contact_list.deleted"} {
		if !actions[a] {
			t.Fatalf("%s not audited: %v", a, actions)
		}
	}
}

// A campaign reaches the list's active, unsuppressed members once each,
// across pages, a pause and a duplicate fan-out, then completes.
func TestCampaignFanout(t *testing.T) {
	m := newMarketing(t)
	ctx, tid, tpl := newTenant(t, m)
	_, other, otherTpl := newTenant(t, m)

	var batch []domaincontact.Contact
	for i := range 8 {
		batch = append(batch, domaincontact.Contact{Email: fmt.Sprintf("p%d@example.com", i), FirstName: "P", LastName: fmt.Sprint(i)})
	}
	if _, err := m.contacts.Import(ctx, tid, batch); err != nil {
		t.Fatal(err)
	}
	cs, _, _ := m.contacts.List(ctx, tid, contact.Filter{Limit: 100})
	l, _ := m.contacts.CreateList(ctx, tid, domaincontact.List{Name: "All"})
	var ids []string
	for _, c := range cs {
		ids = append(ids, c.ID)
	}
	if _, err := m.contacts.AddMembers(ctx, tid, l.ID, ids); err != nil {
		t.Fatal(err)
	}
	unsub := domaincontact.StatusUnsubscribed
	byEmail := map[string]domaincontact.Contact{}
	for _, c := range cs {
		byEmail[c.Email] = c
	}
	if _, err := m.contacts.Update(ctx, tid, byEmail["p1@example.com"].ID, contact.Update{Status: &unsub}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.db.Exec(ctx, `INSERT INTO suppressions (id, org_id, email, type) VALUES ($1, $2, 'p2@example.com', 'bounce')`, uuid.NewString(), tid); err != nil {
		t.Fatal(err)
	}
	m.sender.fail = "p3@example.com"

	in := domaincampaign.Campaign{Name: "Autumn", Subject: "News", FromName: "Averox", FromEmail: "news@example.com", TemplateID: otherTpl, ContactListID: l.ID}
	if _, err := m.campaigns.Create(ctx, tid, in); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("other tenant's template accepted: %v", err)
	}
	in.TemplateID = tpl
	cmp, err := m.campaigns.Create(ctx, tid, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.campaigns.Launch(ctx, other, cmp.ID); !apperrors.IsNotFound(err) {
		t.Fatalf("other tenant launched: %v", err)
	}
	if cmp, err = m.campaigns.Launch(ctx, tid, cmp.ID); err != nil || cmp.Status != domaincampaign.StatusSending {
		t.Fatalf("launch %+v %v", cmp, err)
	}
	if err := m.contacts.DeleteList(ctx, tid, l.ID); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("deleted the list of a sending campaign: %v", err)
	}

	// Two fan-outs at once send nobody twice.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = m.campaigns.Fanout(context.Background(), tid, cmp.ID) }()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, _ := m.campaigns.Get(ctx, tid, cmp.ID)
	if got.Status != domaincampaign.StatusCompleted || got.SentCount != 5 || got.FailedCount != 1 || got.TotalRecipients != 6 {
		t.Fatalf("after fan-out %+v", got)
	}
	seen := map[string]bool{}
	for _, msg := range m.sender.sent {
		if seen[msg.To] || msg.To == "p1@example.com" || msg.To == "p2@example.com" {
			t.Fatalf("%s sent wrongly (seen=%v)", msg.To, seen[msg.To])
		}
		seen[msg.To] = true
		if contact, _ := msg.Data["contact"].(map[string]any); contact["email"] != msg.To || msg.TenantID != tid || msg.TemplateID != tpl {
			t.Fatalf("message %+v", msg)
		}
	}
	var sent, failed int
	_ = m.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'sent' AND message_id IS NOT NULL), count(*) FILTER (WHERE status = 'failed')
		FROM campaign_recipients WHERE campaign_id = $1`, cmp.ID).Scan(&sent, &failed)
	if sent != 5 || failed != 1 {
		t.Fatalf("ledger sent %d failed %d", sent, failed)
	}
	events, _, _ := m.auditRepo.List(ctx, postgres.AuditFilter{TenantUUID: uuid.MustParse(tid), ResourceType: "campaign", Limit: 20})
	actions := map[string]bool{}
	for _, ev := range events {
		actions[ev.Action] = true
	}
	if !actions["campaign.created"] || !actions["campaign.launched"] || !actions["campaign.completed"] {
		t.Fatalf("campaign audit %v", actions)
	}
}

// Pause stops the fan-out between pages; resume finishes it. A scheduled
// campaign is released once due.
func TestCampaignPauseAndSchedule(t *testing.T) {
	m := newMarketing(t)
	ctx, tid, tpl := newTenant(t, m)
	var batch []domaincontact.Contact
	for i := range 7 {
		batch = append(batch, domaincontact.Contact{Email: fmt.Sprintf("q%d@example.com", i)})
	}
	_, _ = m.contacts.Import(ctx, tid, batch)
	cs, _, _ := m.contacts.List(ctx, tid, contact.Filter{Limit: 100})
	l, _ := m.contacts.CreateList(ctx, tid, domaincontact.List{Name: "All"})
	var ids []string
	for _, c := range cs {
		ids = append(ids, c.ID)
	}
	_, _ = m.contacts.AddMembers(ctx, tid, l.ID, ids)

	in := domaincampaign.Campaign{Name: "Paused", Subject: "S", FromName: "A", FromEmail: "a@example.com", TemplateID: tpl, ContactListID: l.ID}
	cmp, _ := m.campaigns.Create(ctx, tid, in)
	if _, err := m.campaigns.Launch(ctx, tid, cmp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.campaigns.Pause(ctx, tid, cmp.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.campaigns.Fanout(ctx, tid, cmp.ID); err != nil || len(m.sender.sent) != 0 {
		t.Fatalf("paused campaign sent %d (%v)", len(m.sender.sent), err)
	}
	if _, err := m.campaigns.Resume(ctx, tid, cmp.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.campaigns.Fanout(ctx, tid, cmp.ID); err != nil || len(m.sender.sent) != 7 {
		t.Fatalf("resumed campaign sent %d (%v)", len(m.sender.sent), err)
	}

	at := time.Now().Add(time.Hour)
	in.Name, in.ScheduledAt = "Later", &at
	later, _ := m.campaigns.Create(ctx, tid, in)
	if later, err := m.campaigns.Launch(ctx, tid, later.ID); err != nil || later.Status != domaincampaign.StatusScheduled {
		t.Fatalf("scheduled launch %+v %v", later, err)
	}
	if err := m.campaigns.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.campaigns.Get(ctx, tid, later.ID); got.Status != domaincampaign.StatusScheduled {
		t.Fatalf("released early: %s", got.Status)
	}
	if _, err := m.db.Exec(ctx, `UPDATE campaigns SET scheduled_at = now() - interval '1 minute' WHERE id = $1`, later.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.campaigns.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.campaigns.Get(ctx, tid, later.ID); got.Status != domaincampaign.StatusSending || got.StartedAt == nil {
		t.Fatalf("not released: %+v", got)
	}
	events, _, _ := m.auditRepo.List(ctx, postgres.AuditFilter{TenantUUID: uuid.MustParse(tid), ResourceID: later.ID, Action: "campaign.released", Limit: 5})
	if len(events) != 1 || events[0].ActorType != audit.ActorSystem {
		t.Fatalf("release audit %+v", events)
	}
	if err := m.campaigns.Delete(ctx, tid, later.ID); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("deleted while sending: %v", err)
	}
	if _, err := m.campaigns.Cancel(ctx, tid, later.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.campaigns.Delete(ctx, tid, later.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.campaigns.Get(ctx, tid, later.ID); !apperrors.IsNotFound(err) {
		t.Fatal("deleted campaign still readable")
	}
}

// The fan-out task lands on the low queue.
func TestCampaignQueue(t *testing.T) {
	connectRedis(t)
	opt, err := worker.RedisOpt(testConfig().Redis)
	if err != nil {
		t.Fatal(err)
	}
	e := worker.NewEnqueuer(opt)
	defer e.Close()
	id := uuid.NewString()
	if err := (worker.CampaignQueue{Enqueuer: e}).EnqueueFanout(context.Background(), "t1", id); err != nil {
		t.Fatal(err)
	}
	ins := asynq.NewInspector(opt)
	defer ins.Close()
	tasks, err := ins.ListPendingTasks(worker.QueueLow, asynq.PageSize(1000))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, task := range tasks {
		if task.Type == worker.TypeCampaignFanout && strings.Contains(string(task.Payload), id) {
			found = true
			_ = ins.DeleteTask(worker.QueueLow, task.ID)
		}
	}
	if !found {
		t.Fatal("fan-out task not on the low queue")
	}
}
