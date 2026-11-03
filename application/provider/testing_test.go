package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domain "github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// fakeTester records what it was asked to test and answers d.
type fakeTester struct {
	d     domain.Diagnosis
	got   domain.Provider
	creds domain.Credentials
	out   domainmsg.Outgoing
}

func (f *fakeTester) Test(_ context.Context, p domain.Provider, c domain.Credentials) domain.Diagnosis {
	f.got, f.creds = p, c
	d := f.d
	d.Kind = domain.TestConnection
	return d
}

func (f *fakeTester) Send(_ context.Context, p domain.Provider, c domain.Credentials, out domainmsg.Outgoing) domain.Diagnosis {
	f.got, f.creds, f.out = p, c, out
	d := f.d
	d.Kind = domain.TestSend
	return d
}

type fakeRecorder struct{ got []TestMessage }

func (r *fakeRecorder) RecordProviderTest(_ context.Context, m TestMessage) error {
	r.got = append(r.got, m)
	return nil
}

func newTestingSvc(d domain.Diagnosis) (*Service, *memRepo, *fakeTester, *fakeRecorder, *[]audit.Event) {
	svc, repo, events := newSvc()
	ft, fr := &fakeTester{d: d}, &fakeRecorder{}
	svc.SetTesting(ft, fr)
	return svc, repo, ft, fr, events
}

func sendGrid(t *testing.T, svc *Service, from string) domain.Provider {
	t.Helper()
	p, err := svc.Create(context.Background(), tenant, Input{Name: "SendGrid", Kind: domain.KindSendGrid,
		Settings: domain.Settings{FromEmail: from}, Credentials: domain.Credentials{APIKey: "SG.super-secret-key-1234"}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTestConnectionKeepsTheOutcome(t *testing.T) {
	failed := domain.Diagnosis{OK: false, Step: "auth", ErrorClass: "auth", Detail: "The provided authorization grant is invalid", Hint: "check the key"}
	svc, repo, ft, _, _ := newTestingSvc(failed)
	p := sendGrid(t, svc, "")
	d, err := svc.TestConnection(context.Background(), tenant, p.ID, "admin")
	if err != nil || d.OK || ft.creds.APIKey != "SG.super-secret-key-1234" {
		t.Fatalf("%+v %v", d, err)
	}
	lt := repo.rows[p.ID].Provider.LastTest
	if lt == nil || lt.OK || lt.Kind != domain.TestConnection || lt.ErrorClass != "auth" || lt.Hint != "check the key" {
		t.Fatalf("last test %+v", lt)
	}
	if _, err := svc.TestConnection(context.Background(), "other-tenant", p.ID, "admin"); apperrors.KindOf(err) != apperrors.KindNotFound {
		t.Fatal("another tenant tested the provider")
	}
}

func TestTestDraftUsesStoredSecretsOnlyForTheSameKind(t *testing.T) {
	svc, repo, ft, _, _ := newTestingSvc(domain.Diagnosis{OK: true})
	p := sendGrid(t, svc, "")
	d, err := svc.TestDraft(context.Background(), tenant, Draft{ID: p.ID, Kind: domain.KindSendGrid,
		Settings: domain.Settings{Region: "eu"}}, "admin")
	if err != nil || !d.OK || ft.creds.APIKey != "SG.super-secret-key-1234" || ft.got.Settings.Region != "eu" {
		t.Fatalf("%+v %v %+v", d, err, ft.got)
	}
	if repo.rows[p.ID].Provider.LastTest != nil {
		t.Fatal("a draft test was kept on the provider")
	}
	// Another kind never receives the stored key.
	_, err = svc.TestDraft(context.Background(), tenant, Draft{ID: p.ID, Kind: domain.KindResend}, "admin")
	if got := apperrors.DetailsOf(err); len(got) == 0 || got[0].Field != "credentials.api_key" {
		t.Fatalf("%v", got)
	}
	// Invalid values are refused before anything is reached.
	ft.got = domain.Provider{}
	_, err = svc.TestDraft(context.Background(), tenant, Draft{Kind: domain.KindSMTP, Settings: domain.Settings{Host: "bad host"}}, "admin")
	if apperrors.KindOf(err) != apperrors.KindInvalidInput || ft.got.Kind != "" {
		t.Fatalf("invalid draft tested: %v", err)
	}
}

func TestSendTestRecordsAMessageAndTheOutcome(t *testing.T) {
	svc, repo, ft, fr, _ := newTestingSvc(domain.Diagnosis{OK: true, ProviderMessageID: "sg-1"})
	p := sendGrid(t, svc, "noreply@bank.example")
	d, err := svc.SendTest(context.Background(), tenant, p.ID, " ops@bank.example ", "admin")
	if err != nil || !d.OK || d.MessageID == "" {
		t.Fatalf("%+v %v", d, err)
	}
	if ft.out.To.Email != "ops@bank.example" || ft.out.From.Email != "noreply@bank.example" || ft.out.MessageID != d.MessageID ||
		!strings.Contains(ft.out.Subject, "SendGrid") || ft.out.Text == "" || ft.out.HTML == "" {
		t.Fatalf("outgoing %+v", ft.out)
	}
	if len(fr.got) != 1 || !fr.got[0].Sent || fr.got[0].ID != d.MessageID || fr.got[0].ProviderMessageID != "sg-1" || fr.got[0].ProviderID != p.ID {
		t.Fatalf("recorded %+v", fr.got)
	}
	lt := repo.rows[p.ID].Provider.LastTest
	if lt == nil || !lt.OK || lt.Kind != domain.TestSend || lt.ToEmail != "ops@bank.example" || lt.MessageID != d.MessageID {
		t.Fatalf("last test %+v", lt)
	}
}

func TestSendTestRefusesBadInput(t *testing.T) {
	svc, _, _, fr, _ := newTestingSvc(domain.Diagnosis{OK: true})
	p := sendGrid(t, svc, "")
	if _, err := svc.SendTest(context.Background(), tenant, p.ID, "not an address", "admin"); apperrors.DetailsOf(err)[0].Field != "to_email" {
		t.Fatal(err)
	}
	if _, err := svc.SendTest(context.Background(), tenant, p.ID, "ops@bank.example", "admin"); apperrors.DetailsOf(err)[0].Field != "from_email" {
		t.Fatal(err)
	}
	if len(fr.got) != 0 {
		t.Fatal("a refused test was recorded")
	}
}

func TestTestsAuditWithoutSecretsOrProviderDetail(t *testing.T) {
	svc, _, _, _, events := newTestingSvc(domain.Diagnosis{OK: false, Step: "auth", ErrorClass: "auth", Detail: "key SG.super-secret-key-1234 refused"})
	p := sendGrid(t, svc, "noreply@bank.example")
	if _, err := svc.SendTest(context.Background(), tenant, p.ID, "ops@bank.example", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TestConnection(context.Background(), tenant, p.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, ev := range *events {
		actions[ev.Action] = true
	}
	raw, _ := json.Marshal(*events)
	if !actions["provider.test_sent"] || !actions["provider.tested"] || strings.Contains(string(raw), "super-secret") ||
		strings.Contains(string(raw), "ops@bank.example") {
		t.Fatalf("audit %s", raw)
	}
}

func TestUpdateRefusesAnotherKindAndPrunesUnusedSecrets(t *testing.T) {
	svc, repo, _ := newSvc()
	p, err := svc.Create(context.Background(), tenant, Input{Name: "Relay", Kind: domain.KindSMTP,
		Settings:    domain.Settings{Host: "smtp.office365.com", Port: 587, TLSMode: domain.TLSStartTLS, AuthMechanism: domain.AuthLogin, Username: "mailer@bank.example", FromEmail: "mailer@bank.example"},
		Credentials: domain.Credentials{Password: "pw-123"}}, "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(context.Background(), tenant, p.ID, Patch{Kind: domain.KindSendGrid}, "a"); apperrors.DetailsOf(err)[0].Field != "type" {
		t.Fatal("kind changed", err)
	}
	s := repo.rows[p.ID].Provider.Settings
	s.AuthMechanism = domain.AuthNone
	s.Username = ""
	if _, err := svc.Update(context.Background(), tenant, p.ID, Patch{Settings: &s}, "a"); err != nil {
		t.Fatal(err)
	}
	c, _ := svc.open(context.Background(), repo.rows[p.ID].Sealed)
	raw, _ := json.Marshal(c.Map())
	if c.Password != "" || repo.rows[p.ID].Provider.HasCredentials {
		t.Fatalf("unused password kept: %s", raw)
	}
}
