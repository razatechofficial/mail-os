package suppression

import (
	"context"
	"testing"

	"github.com/razatechofficial/mail-os/domain/message"
	domain "github.com/razatechofficial/mail-os/domain/suppression"
)

type memRepo struct{ rows []domain.Suppression }

func (r *memRepo) Upsert(_ context.Context, s domain.Suppression) (domain.Suppression, error) {
	for _, o := range r.rows {
		if o.OrgID == s.OrgID && o.Email == s.Email && o.ApplicationID == s.ApplicationID {
			return o, nil
		}
	}
	r.rows = append(r.rows, s)
	return s, nil
}

func (r *memRepo) Delete(_ context.Context, tenantID, appID, email string) (bool, error) {
	for i, o := range r.rows {
		if o.OrgID == tenantID && o.Email == email && o.ApplicationID == appID {
			r.rows = append(r.rows[:i], r.rows[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func (r *memRepo) Find(_ context.Context, tenantID, appID, email string) ([]domain.Suppression, error) {
	var out []domain.Suppression
	for _, o := range r.rows {
		if o.OrgID == tenantID && o.Email == email && (o.ApplicationID == "" || (appID != "" && o.ApplicationID == appID)) {
			out = append(out, o)
		}
	}
	return out, nil
}

func (r *memRepo) List(context.Context, Filter) ([]domain.Suppression, int, error) {
	return r.rows, len(r.rows), nil
}

type nopAudit struct{}

func (nopAudit) Append(context.Context, string, string, string, map[string]any) error { return nil }

// A tenant-wide entry stops everyone's mail; an application's entry stops
// only that application's, and an unsubscribe only marketing.
func TestBlocksByScope(t *testing.T) {
	svc := NewService(&memRepo{}, nopAudit{})
	ctx := context.Background()
	if _, err := svc.Add(ctx, domain.Suppression{OrgID: "t", ApplicationID: "app-1", Email: "A@example.com", Type: domain.TypeManual}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Add(ctx, domain.Suppression{OrgID: "t", Email: "b@example.com", Type: domain.TypeUnsubscribe}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		app, email string
		mt         message.Type
		blocked    bool
	}{
		{"app-1", "a@example.com", message.TypeTransactional, true},
		{"app-2", "a@example.com", message.TypeTransactional, false},
		{"", "a@example.com", message.TypeTransactional, false},
		{"app-2", "b@example.com", message.TypeMarketing, true},
		{"app-2", "b@example.com", message.TypeTransactional, false},
		{"", "b@example.com", message.TypeMarketing, true},
	} {
		sup, err := svc.Blocks(ctx, "t", c.app, c.email, c.mt)
		if err != nil || (sup != nil) != c.blocked {
			t.Errorf("%+v: %v %v", c, sup, err)
		}
	}
	if err := svc.Remove(ctx, "t", "", "a@example.com"); err != nil {
		t.Fatal(err)
	}
	if sup, _ := svc.Blocks(ctx, "t", "app-1", "a@example.com", message.TypeTransactional); sup == nil {
		t.Fatal("removing the tenant-wide entry lifted the application's")
	}
	if err := svc.Remove(ctx, "t", "app-1", "a@example.com"); err != nil {
		t.Fatal(err)
	}
	if sup, _ := svc.Blocks(ctx, "t", "app-1", "a@example.com", message.TypeTransactional); sup != nil {
		t.Fatal("the application's entry is still there")
	}
}

// A provider's hard bounce or complaint suppresses the address
// tenant-wide, from the webhook source, for every kind of mail.
func TestRecordFeedback(t *testing.T) {
	repo := &memRepo{}
	svc := NewService(repo, nopAudit{})
	ctx := context.Background()
	if err := svc.RecordFeedback(ctx, "t", " Gone@Example.com ", domain.TypeComplaint, "abuse report"); err != nil {
		t.Fatal(err)
	}
	if len(repo.rows) != 1 || repo.rows[0].Source != domain.SourceWebhook || repo.rows[0].ApplicationID != "" ||
		repo.rows[0].Email != "gone@example.com" {
		t.Fatalf("rows %+v", repo.rows)
	}
	sup, err := svc.Blocks(ctx, "t", "app-1", "gone@example.com", message.TypeTransactional)
	if err != nil || sup == nil {
		t.Fatalf("complaint must block transactional mail: %v %v", sup, err)
	}
	if err := svc.RecordFeedback(ctx, "t", "x", domain.TypeBounce, ""); err == nil {
		t.Fatal("an invalid address is refused")
	}
}
