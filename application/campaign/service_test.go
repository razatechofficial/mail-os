package campaign

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/campaign"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

const tenant, other = "tenant-a", "tenant-b"

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// fake is an in-memory Repository, Targets, Recipients and Queue.
type fake struct {
	campaigns map[string]domain.Campaign
	templates map[string]string // id -> tenant
	lists     map[string]string
	members   map[string][]Recipient // list id -> members
	rows      map[string]map[string]string
	queued    []string
	// pauseAfter pauses the campaign during that Pending call, as a
	// console pause arriving while the page sends.
	pauseAfter int
	pending    int
}

func newFake() *fake {
	return &fake{campaigns: map[string]domain.Campaign{}, templates: map[string]string{"t1": tenant}, lists: map[string]string{"l1": tenant},
		members: map[string][]Recipient{}, rows: map[string]map[string]string{}}
}

func (f *fake) Get(_ context.Context, t, id string) (domain.Campaign, error) {
	c, ok := f.campaigns[id]
	if !ok || c.OrgID != t {
		return domain.Campaign{}, apperrors.NotFound("campaign not found")
	}
	return c, nil
}
func (f *fake) Lock(ctx context.Context, t, id string) (domain.Campaign, error) { return f.Get(ctx, t, id) }
func (f *fake) List(context.Context, string, Filter) ([]domain.Campaign, int, error) {
	return nil, 0, nil
}
func (f *fake) Create(_ context.Context, c domain.Campaign) error { f.campaigns[c.ID] = c; return nil }
func (f *fake) Update(_ context.Context, c domain.Campaign) error {
	old := f.campaigns[c.ID]
	c.SentCount, c.FailedCount, c.TotalRecipients = old.SentCount, old.FailedCount, old.TotalRecipients
	f.campaigns[c.ID] = c
	return nil
}
func (f *fake) Delete(_ context.Context, _, id string) error { delete(f.campaigns, id); return nil }
func (f *fake) Due(_ context.Context, at time.Time, _ int) ([]domain.Campaign, error) {
	var out []domain.Campaign
	for _, c := range f.campaigns {
		if c.Status == domain.StatusScheduled && !c.ScheduledAt.After(at) {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *fake) Stalled(_ context.Context, before time.Time, _ int) ([]domain.Campaign, error) {
	var out []domain.Campaign
	for _, c := range f.campaigns {
		if c.Status == domain.StatusSending && c.UpdatedAt.Before(before) {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *fake) SetTotal(_ context.Context, id string, total int) error {
	c := f.campaigns[id]
	c.TotalRecipients = total
	f.campaigns[id] = c
	return nil
}
func (f *fake) AddCounts(_ context.Context, id string, sent, failed int) error {
	c := f.campaigns[id]
	c.SentCount += sent
	c.FailedCount += failed
	f.campaigns[id] = c
	return nil
}

func (f *fake) TemplateExists(_ context.Context, t, id string) (bool, error) { return f.templates[id] == t, nil }
func (f *fake) ListExists(_ context.Context, t, id string) (bool, error)     { return f.lists[id] == t, nil }

func (f *fake) Pending(_ context.Context, _, campaignID, listID string, limit int) ([]Recipient, error) {
	f.pending++
	if f.pauseAfter > 0 && f.pending >= f.pauseAfter {
		c := f.campaigns[campaignID]
		c.Status = domain.StatusPaused
		f.campaigns[campaignID] = c
	}
	var out []Recipient
	for _, r := range f.members[listID] {
		if _, done := f.rows[campaignID][r.ContactID]; !done && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fake) Count(_ context.Context, _, campaignID, listID string) (int, int, error) {
	recorded := len(f.rows[campaignID])
	return recorded, len(f.members[listID]) - recorded, nil
}
func (f *fake) Claim(_ context.Context, campaignID, contactID string) (bool, error) {
	if f.rows[campaignID] == nil {
		f.rows[campaignID] = map[string]string{}
	}
	if _, ok := f.rows[campaignID][contactID]; ok {
		return false, nil
	}
	f.rows[campaignID][contactID] = domain.RecipientQueued
	return true, nil
}
func (f *fake) Release(_ context.Context, campaignID, contactID string) error {
	delete(f.rows[campaignID], contactID)
	return nil
}
func (f *fake) MarkSent(_ context.Context, campaignID, contactID, _ string, _ time.Time) error {
	f.rows[campaignID][contactID] = domain.RecipientSent
	return nil
}
func (f *fake) MarkFailed(_ context.Context, campaignID, contactID, _ string, _ time.Time) error {
	f.rows[campaignID][contactID] = domain.RecipientFailed
	return nil
}
func (f *fake) EnqueueFanout(_ context.Context, t, id string) error {
	f.queued = append(f.queued, t+"/"+id)
	return nil
}

type sender struct {
	sent []CampaignMessage
	// fail maps an address to the error its send returns.
	fail map[string]error
}

func (s *sender) SendCampaignMessage(_ context.Context, m CampaignMessage) (string, error) {
	if err := s.fail[m.To]; err != nil {
		return "", err
	}
	s.sent = append(s.sent, m)
	return "msg-" + m.To, nil
}

type auditLog struct{ actions []string }

func (a *auditLog) Append(_ context.Context, _, _, action string, _ map[string]any) error {
	a.actions = append(a.actions, action)
	return nil
}
func (a *auditLog) Change(ctx context.Context, rt, id, action string, _, _ any, _ map[string]any) error {
	return a.Append(ctx, rt, id, action, nil)
}

type tx struct{}

func (tx) InTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

func setup(withSender bool) (*Service, *fake, *sender, *auditLog) {
	f, snd, log := newFake(), &sender{fail: map[string]error{}}, &auditLog{}
	d := Deps{Campaigns: f, Targets: f, Recipients: f, Queue: f, Tx: tx{}, Audit: log}
	if withSender {
		d.Sender = snd
	}
	svc := NewService(d, Config{PageSize: 2, PagesPerTask: 3})
	svc.now = func() time.Time { return now }
	return svc, f, snd, log
}

func draft() domain.Campaign {
	return domain.Campaign{Name: "Autumn", Subject: "News", FromName: "Averox", FromEmail: "news@example.com", TemplateID: "t1", ContactListID: "l1"}
}

func members(n int) []Recipient {
	out := make([]Recipient, n)
	for i := range out {
		out[i] = Recipient{ContactID: fmt.Sprintf("c%02d", i), Email: fmt.Sprintf("p%02d@example.com", i), FirstName: "P", LastName: fmt.Sprint(i)}
	}
	return out
}

func TestCreateChecksTargets(t *testing.T) {
	svc, f, _, log := setup(true)
	ctx := context.Background()
	c, err := svc.Create(ctx, tenant, draft())
	if err != nil || c.Status != domain.StatusDraft || c.ID == "" {
		t.Fatalf("create %+v %v", c, err)
	}
	f.templates["t2"], f.lists["l2"] = other, other
	bad := draft()
	bad.TemplateID, bad.ContactListID = "t2", "l2"
	err = func() error { _, err := svc.Create(ctx, tenant, bad); return err }()
	var fields []string
	for _, d := range apperrors.DetailsOf(err) {
		fields = append(fields, d.Field+":"+d.Code)
	}
	if strings.Join(fields, ",") != "template_id:not_found,contact_list_id:not_found" {
		t.Fatalf("another tenant's template and list: %v", fields)
	}
	if _, err := svc.Get(ctx, other, c.ID); !apperrors.IsNotFound(err) {
		t.Fatal("other tenant reads the campaign")
	}
	subject := "Fresh news"
	if u, err := svc.Update(ctx, tenant, c.ID, Update{Subject: &subject}); err != nil || u.Subject != subject {
		t.Fatalf("update %+v %v", u, err)
	}
	if strings.Join(log.actions, ",") != "campaign.created,campaign.updated" {
		t.Fatalf("audit %v", log.actions)
	}
}

func TestLaunchWithoutSenderIsUnavailable(t *testing.T) {
	svc, f, _, _ := setup(false)
	ctx := context.Background()
	c, _ := svc.Create(ctx, tenant, draft())
	if _, err := svc.Launch(ctx, tenant, c.ID); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("launch without sender: %v", err)
	}
	if f.campaigns[c.ID].Status != domain.StatusDraft {
		t.Fatal("status changed")
	}
	if err := svc.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFanoutSendsSkipsAndCompletes(t *testing.T) {
	svc, f, snd, log := setup(true)
	ctx := context.Background()
	f.members["l1"] = members(5)
	snd.fail["p03@example.com"] = apperrors.Invalid("to", "invalid", "refused")
	c, _ := svc.Create(ctx, tenant, draft())
	c, err := svc.Launch(ctx, tenant, c.ID)
	if err != nil || c.Status != domain.StatusSending || len(f.queued) != 1 {
		t.Fatalf("launch %+v %v queued %v", c, err, f.queued)
	}
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	got := f.campaigns[c.ID]
	if got.Status != domain.StatusCompleted || got.SentCount != 4 || got.FailedCount != 1 || got.TotalRecipients != 5 {
		t.Fatalf("after fan-out %+v", got)
	}
	m := snd.sent[0]
	contact, _ := m.Data["contact"].(map[string]any)
	if m.TenantID != tenant || m.TemplateID != "t1" || m.FromEmail != "news@example.com" || m.ToName != "P 0" || contact["email"] != m.To {
		t.Fatalf("message %+v", m)
	}
	if !slices.Contains(log.actions, "campaign.completed") {
		t.Fatalf("audit %v", log.actions)
	}
	// A second run (a duplicate task) sends nobody again.
	before := len(snd.sent)
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil || len(snd.sent) != before {
		t.Fatalf("duplicate fan-out sent %d more (%v)", len(snd.sent)-before, err)
	}
}

func TestFanoutContinuesInANewTask(t *testing.T) {
	svc, f, snd, _ := setup(true)
	ctx := context.Background()
	f.members["l1"] = members(9) // 2 per page, 3 pages per task
	c, _ := svc.Create(ctx, tenant, draft())
	_, _ = svc.Launch(ctx, tenant, c.ID)
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if len(snd.sent) != 6 || len(f.queued) != 2 || f.campaigns[c.ID].Status != domain.StatusSending {
		t.Fatalf("sent %d queued %v status %s", len(snd.sent), f.queued, f.campaigns[c.ID].Status)
	}
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if len(snd.sent) != 9 || f.campaigns[c.ID].Status != domain.StatusCompleted {
		t.Fatalf("sent %d status %s", len(snd.sent), f.campaigns[c.ID].Status)
	}
}

func TestPauseStopsBetweenPagesAndResumeContinues(t *testing.T) {
	svc, f, snd, log := setup(true)
	ctx := context.Background()
	f.members["l1"] = members(6)
	c, _ := svc.Create(ctx, tenant, draft())
	_, _ = svc.Launch(ctx, tenant, c.ID)
	f.pauseAfter = 1 // paused while the first page sends
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if len(snd.sent) != 2 || f.campaigns[c.ID].Status != domain.StatusPaused {
		t.Fatalf("sent %d status %s", len(snd.sent), f.campaigns[c.ID].Status)
	}
	f.pauseAfter = 0
	if _, err := svc.Resume(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if len(snd.sent) != 6 || f.campaigns[c.ID].Status != domain.StatusCompleted {
		t.Fatalf("after resume sent %d status %s", len(snd.sent), f.campaigns[c.ID].Status)
	}
	seen := map[string]bool{}
	for _, m := range snd.sent {
		if seen[m.To] {
			t.Fatalf("%s sent twice", m.To)
		}
		seen[m.To] = true
	}
	if !slices.Contains(log.actions, "campaign.resumed") {
		t.Fatalf("audit %v", log.actions)
	}
}

func TestCancelledFanoutSendsNothing(t *testing.T) {
	svc, f, snd, _ := setup(true)
	ctx := context.Background()
	f.members["l1"] = members(3)
	c, _ := svc.Create(ctx, tenant, draft())
	_, _ = svc.Launch(ctx, tenant, c.ID)
	if _, err := svc.Cancel(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil || len(snd.sent) != 0 {
		t.Fatalf("cancelled campaign sent %d (%v)", len(snd.sent), err)
	}
	if _, err := svc.Resume(ctx, tenant, c.ID); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("resumed a cancelled campaign: %v", err)
	}
}

func TestUnavailableSenderReleasesTheRecipient(t *testing.T) {
	svc, f, snd, _ := setup(true)
	ctx := context.Background()
	f.members["l1"] = members(2)
	snd.fail["p01@example.com"] = apperrors.Unavailable("queue down")
	c, _ := svc.Create(ctx, tenant, draft())
	_, _ = svc.Launch(ctx, tenant, c.ID)
	if err := svc.Fanout(ctx, tenant, c.ID); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("temporary failure not returned for retry: %v", err)
	}
	if _, claimed := f.rows[c.ID]["c01"]; claimed || f.campaigns[c.ID].SentCount != 1 {
		t.Fatalf("rows %v counts %+v", f.rows[c.ID], f.campaigns[c.ID])
	}
	delete(snd.fail, "p01@example.com")
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil || f.campaigns[c.ID].Status != domain.StatusCompleted || len(snd.sent) != 2 {
		t.Fatalf("retry: %v %+v", err, f.campaigns[c.ID])
	}
}

func TestScheduledReleaseAndStalledRestart(t *testing.T) {
	svc, f, _, log := setup(true)
	ctx := context.Background()
	at := now.Add(time.Hour)
	in := draft()
	in.ScheduledAt = &at
	c, _ := svc.Create(ctx, tenant, in)
	if c, err := svc.Launch(ctx, tenant, c.ID); err != nil || c.Status != domain.StatusScheduled || len(f.queued) != 0 {
		t.Fatalf("scheduled launch %+v %v", c, err)
	}
	if err := svc.Release(ctx); err != nil || f.campaigns[c.ID].Status != domain.StatusScheduled {
		t.Fatal("released before its time")
	}
	svc.now = func() time.Time { return at }
	if err := svc.Release(ctx); err != nil || f.campaigns[c.ID].Status != domain.StatusSending || len(f.queued) != 1 {
		t.Fatalf("release: %v %s %v", err, f.campaigns[c.ID].Status, f.queued)
	}
	if !slices.Contains(log.actions, "campaign.released") {
		t.Fatalf("audit %v", log.actions)
	}
	svc.now = func() time.Time { return at.Add(10 * time.Minute) }
	if err := svc.Release(ctx); err != nil || len(f.queued) != 2 {
		t.Fatalf("stalled fan-out not restarted: %v", f.queued)
	}
}

func TestDeleteRefusedWhileSending(t *testing.T) {
	svc, f, _, _ := setup(true)
	ctx := context.Background()
	f.members["l1"] = members(1)
	c, _ := svc.Create(ctx, tenant, draft())
	_, _ = svc.Launch(ctx, tenant, c.ID)
	if err := svc.Delete(ctx, tenant, c.ID); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("deleted while sending: %v", err)
	}
	name := "x"
	if _, err := svc.Update(ctx, tenant, c.ID, Update{Name: &name}); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("edited while sending: %v", err)
	}
	_, _ = svc.Pause(ctx, tenant, c.ID)
	if err := svc.Delete(ctx, other, c.ID); !apperrors.IsNotFound(err) {
		t.Fatal("other tenant deletes the campaign")
	}
	if err := svc.Delete(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil {
		t.Fatalf("fan-out of a deleted campaign: %v", err)
	}
}

func TestEnqueueFailureDoesNotFailLaunch(t *testing.T) {
	svc, f, _, _ := setup(true)
	svc.d.Queue = failingQueue{}
	c, _ := svc.Create(context.Background(), tenant, draft())
	if c, err := svc.Launch(context.Background(), tenant, c.ID); err != nil || c.Status != domain.StatusSending {
		t.Fatalf("launch %v", err)
	}
	// The release task restarts it once it is stalled.
	svc.d.Queue = f
	svc.now = func() time.Time { return now.Add(time.Hour) }
	if err := svc.Release(context.Background()); err != nil || len(f.queued) != 1 {
		t.Fatalf("not restarted: %v %v", err, f.queued)
	}
}

type failingQueue struct{}

func (failingQueue) EnqueueFanout(context.Context, string, string) error { return errors.New("redis down") }
