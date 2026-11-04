package provider

import (
	"context"
	"html"
	"strings"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domain "github.com/razatechofficial/mail-os/domain/provider"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Tester reaches a provider: Test connects and authenticates without
// sending mail; Send delivers one message. Both report a diagnosis and
// never return the credentials.
type Tester interface {
	Test(ctx context.Context, p domain.Provider, c domain.Credentials) domain.Diagnosis
	Send(ctx context.Context, p domain.Provider, c domain.Credentials, out domainmsg.Outgoing) domain.Diagnosis
}

// TestMessage is a test send already made through one provider, for the
// message log.
type TestMessage struct {
	ID                string
	TenantID          string
	ProviderID        string
	From              domainmsg.Address
	ToEmail           string
	Subject           string
	HTML              string
	Text              string
	Sent              bool
	ProviderMessageID string
	Error             string
}

// TestRecorder keeps a test send in the message log, tagged as a test.
type TestRecorder interface {
	RecordProviderTest(ctx context.Context, m TestMessage) error
}

// SetTesting wires connection tests and test sends.
func (s *Service) SetTesting(t Tester, r TestRecorder) {
	s.tester, s.recorder = t, r
}

// Schema is the provider types' form schema.
func (s *Service) Schema() domain.Catalog { return domain.Schema(s.cfg.AllowPlaintext) }

var errNoTesting = apperrors.Unavailable("provider tests are not configured")

func (s *Service) opened(ctx context.Context, tenantID, providerID string) (domain.Provider, domain.Credentials, error) {
	st, err := s.repo.Get(ctx, tenantID, providerID)
	if err != nil {
		return domain.Provider{}, domain.Credentials{}, err
	}
	c, err := s.open(ctx, st.Sealed)
	return st.Provider, c, err
}

// testAudit is what the audit log keeps of a test: the outcome, never the
// detail a provider echoed back.
func testAudit(d domain.Diagnosis, extra map[string]any) map[string]any {
	out := map[string]any{"ok": d.OK, "kind": d.Kind}
	if !d.OK {
		out["step"], out["error_class"] = d.Step, d.ErrorClass
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// TestConnection tests a stored provider without sending mail, keeps the
// outcome as its last test and audits it.
func (s *Service) TestConnection(ctx context.Context, tenantID, providerID, actor string) (domain.Diagnosis, error) {
	if s.tester == nil {
		return domain.Diagnosis{}, errNoTesting
	}
	p, c, err := s.opened(ctx, tenantID, providerID)
	if err != nil {
		return domain.Diagnosis{}, err
	}
	d := s.tester.Test(ctx, p, c)
	if err := s.repo.SetLastTest(ctx, tenantID, providerID, d.Summary("")); err != nil {
		return domain.Diagnosis{}, err
	}
	err = s.audit.Change(ctx, "provider", providerID, "provider.tested", nil, nil,
		testAudit(d, map[string]any{"by": actor, "provider_kind": string(p.Kind)}))
	return d, err
}

// Draft is a provider form not yet saved. With ID, the stored provider's
// secrets fill the blank ones (when the kind is unchanged).
type Draft struct {
	ID          string
	Kind        domain.Kind
	Settings    domain.Settings
	Credentials domain.Credentials
}

// TestDraft tests a provider form's values without saving them. It is
// guarded like a save (it can point stored secrets at a new host) and
// audited; the outcome is not kept on a provider.
func (s *Service) TestDraft(ctx context.Context, tenantID string, in Draft, actor string) (domain.Diagnosis, error) {
	if s.tester == nil {
		return domain.Diagnosis{}, errNoTesting
	}
	p := domain.Provider{OrgID: tenantID, Name: "draft", Kind: in.Kind, Settings: in.Settings, Weight: domain.DefaultWeight, Active: true}
	creds := in.Credentials
	if in.ID != "" {
		stored, c, err := s.opened(ctx, tenantID, in.ID)
		if err != nil {
			return domain.Diagnosis{}, err
		}
		if stored.Kind == in.Kind {
			creds = c.Merge(in.Credentials)
		}
		p.ID, p.Name = stored.ID, stored.Name
	}
	creds, err := s.validate(&p, creds)
	if err != nil {
		return domain.Diagnosis{}, err
	}
	d := s.tester.Test(ctx, p, creds)
	extra := map[string]any{"by": actor, "provider_kind": string(p.Kind), "draft": true}
	if in.ID != "" {
		extra["provider_id"] = in.ID
	}
	err = s.audit.Change(ctx, "provider", in.ID, "provider.draft_tested", nil, nil, testAudit(d, extra))
	return d, err
}

// Test send content: fixed, so a test proves the provider and nothing
// else.
const (
	testSubject = "MailOS test message"
	testText    = "This is a test message from MailOS.\n\n" +
		"It was sent through the mail provider \"%s\" to check that the provider accepts mail from MailOS. " +
		"No action is needed.\n"
)

func testContent(providerName string) (subject, text, htmlBody string) {
	text = strings.Replace(testText, "%s", providerName, 1)
	htmlBody = "<!doctype html><html><body style=\"font-family:sans-serif\"><h1 style=\"font-size:18px\">MailOS test message</h1>" +
		"<p>This is a test message from MailOS.</p><p>It was sent through the mail provider <strong>" + html.EscapeString(providerName) +
		"</strong> to check that the provider accepts mail from MailOS. No action is needed.</p></body></html>"
	return testSubject + ": " + providerName, text, htmlBody
}

// SendTest sends the fixed test message to toEmail through one stored
// provider (not the router), keeps it in the message log tagged "test",
// keeps the outcome as the provider's last test and audits it.
func (s *Service) SendTest(ctx context.Context, tenantID, providerID, toEmail, actor string) (domain.Diagnosis, error) {
	if s.tester == nil || s.recorder == nil {
		return domain.Diagnosis{}, errNoTesting
	}
	toEmail = strings.TrimSpace(toEmail)
	if !domain.ValidEmail(toEmail) {
		return domain.Diagnosis{}, apperrors.Invalid("to_email", "invalid", "enter one email address")
	}
	p, c, err := s.opened(ctx, tenantID, providerID)
	if err != nil {
		return domain.Diagnosis{}, err
	}
	name, from := p.Settings.DefaultFrom()
	if from == "" {
		return domain.Diagnosis{}, apperrors.Invalid("from_email", "required",
			"set this provider's default sender (From address) before sending a test")
	}
	if name == "" {
		name = "MailOS"
	}
	subject, text, htmlBody := testContent(p.Name)
	out := domainmsg.Outgoing{
		TenantID: tenantID, MessageID: id.New(), From: domainmsg.Address{Name: name, Email: from},
		To: domainmsg.Address{Email: toEmail}, Subject: subject, HTML: htmlBody, Text: text, Tags: []string{"test", "provider-test"},
	}
	d := s.tester.Send(ctx, p, c, out)
	d.MessageID = out.MessageID
	if err := s.recorder.RecordProviderTest(ctx, TestMessage{
		ID: out.MessageID, TenantID: tenantID, ProviderID: providerID, From: out.From, ToEmail: toEmail,
		Subject: subject, HTML: htmlBody, Text: text, Sent: d.OK, ProviderMessageID: d.ProviderMessageID, Error: d.Detail,
	}); err != nil {
		return domain.Diagnosis{}, err
	}
	if err := s.repo.SetLastTest(ctx, tenantID, providerID, d.Summary(toEmail)); err != nil {
		return domain.Diagnosis{}, err
	}
	err = s.audit.Change(ctx, "provider", providerID, "provider.test_sent", nil, nil,
		testAudit(d, map[string]any{"by": actor, "provider_kind": string(p.Kind), "to": logger.MaskEmail(toEmail), "message_id": out.MessageID}))
	return d, err
}

// RecordDelivery keeps a live send's outcome through the provider as its
// last test (mailer.FailureRecorder): a failed delivery marks it failing in
// the console until a send through it succeeds.
func (s *Service) RecordDelivery(ctx context.Context, tenantID, providerID string, t domain.LastTest) error {
	return s.repo.SetLastTest(ctx, tenantID, providerID, t)
}
