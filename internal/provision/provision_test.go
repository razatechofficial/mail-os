package provision

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	appsendingdomain "github.com/razatechofficial/mail-os/application/sendingdomain"
	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/application/template/templatetest"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domaindomain "github.com/razatechofficial/mail-os/domain/sendingdomain"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/render"
)

const tenant = "0190f5e2-7c1a-7b3e-9f00-0000000000aa"

func iamTopics() []domaintemplate.Topic {
	var out []domaintemplate.Topic
	for _, t := range domaintemplate.Topics() {
		if t.Source == domaintemplate.SourceIAM {
			out = append(out, t)
		}
	}
	return out
}

func newTemplates(fourEyes bool) *apptemplate.Service {
	return apptemplate.New(apptemplate.Deps{Repo: templatetest.NewRepository(), Settings: &templatetest.Settings{FourEyes: fourEyes},
		Audit: &templatetest.Audit{}})
}

// Every IAM topic has its own wording, and the wording uses only the
// topic's variables (a typo would render as an empty string).
func TestEveryIAMTopicHasContent(t *testing.T) {
	common := map[string]bool{"user.name": true, "user.email": true, "brand.company_name": true}
	topics := iamTopics()
	if len(topics) < 18 {
		t.Fatalf("only %d IAM topics in the catalogue", len(topics))
	}
	for _, topic := range topics {
		c, ok := iamContent[topic.Key]
		if !ok {
			t.Errorf("%s has no default content", topic.Key)
			continue
		}
		_, _, vars := compile(c)
		for _, v := range vars {
			if _, ok := topic.Variable(v); !ok && !common[v] {
				t.Errorf("%s uses %q, which the topic does not carry", topic.Key, v)
			}
		}
	}
}

func TestSeedTemplatesPublishesOnceAndKeepsAdministratorsWork(t *testing.T) {
	ctx := context.Background()
	svc := newTemplates(false)

	// An administrator already published the invitation.
	inv, err := svc.Create(ctx, tenant, apptemplate.CreateInput{Name: "Our invitation", Slug: "our-invitation",
		Category: domaintemplate.CategoryTransactional, Topic: domaintemplate.TopicInvite, DefaultLocale: domaintemplate.LocaleEnglish})
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := svc.SaveDraft(ctx, tenant, inv.ID, apptemplate.DraftInput{Locale: "en", Subject: "Join {{org_name}}",
		HTMLBody: `<p><a href="{{link}}">Join</a></p>`, TextBody: "Join: {{link}}", Variables: []string{"org_name", "link"}}, apptemplate.Editor{ID: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Publish(ctx, tenant, inv.ID, "en", d.Revision, "admin"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rep, err := SeedTemplates(ctx, svc, tenant, &out)
	if err != nil {
		t.Fatalf("seed: %v\n%s", err, out.String())
	}
	n := len(iamTopics())
	if rep.Published != n-1 || rep.Kept != 1 || rep.Failed != 0 {
		t.Fatalf("report %+v, want %d published and 1 kept\n%s", rep, n-1, out.String())
	}
	if v, err := svc.ActiveVersion(ctx, tenant, inv.ID, ""); err != nil || v.Subject != "Join {{org_name}}" {
		t.Fatalf("the administrator's invitation was replaced: %+v %v", v, err)
	}

	// Every topic now resolves to a published version that renders.
	for _, topic := range iamTopics() {
		tpl, v, err := svc.ResolvePublished(ctx, tenant, apptemplate.Ref{Topic: topic.Key}, "en")
		if err != nil {
			t.Fatalf("%s: %v", topic.Key, err)
		}
		if tpl.Slug != slugOf(topic.Key) && topic.Key != domaintemplate.TopicInvite {
			t.Errorf("%s: slug %q", topic.Key, tpl.Slug)
		}
		c, err := render.Render(render.Content{Subject: v.Subject, HTML: v.HTMLBody, Text: v.TextBody},
			domaintemplate.SampleData(topic.Key), render.Options{})
		if err != nil {
			t.Fatalf("%s: render: %v", topic.Key, err)
		}
		if strings.Contains(c.HTML, "{{") || strings.Contains(c.Text, "{{") {
			t.Errorf("%s: placeholder left after rendering", topic.Key)
		}
		if bv := iamContent[topic.Key].ButtonVar; bv != "" && topic.Key != domaintemplate.TopicInvite {
			sample, _ := topic.Variable(bv)
			if !strings.Contains(c.HTML, `href="`+sample.Sample+`"`) {
				t.Errorf("%s: the button does not link to %s", topic.Key, bv)
			}
		}
	}

	// A second run changes nothing.
	out.Reset()
	rep, err = SeedTemplates(ctx, svc, tenant, &out)
	if err != nil || rep.Published != 0 || rep.Kept != n || rep.Failed != 0 {
		t.Fatalf("second run: %+v %v\n%s", rep, err, out.String())
	}
}

// Under four-eyes the bootstrap cannot publish its own drafts: it reports
// each topic and leaves publishing to a second person.
func TestSeedTemplatesUnderFourEyesReportsAndContinues(t *testing.T) {
	var out bytes.Buffer
	rep, err := SeedTemplates(context.Background(), newTemplates(true), tenant, &out)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Published != 0 || rep.Failed != len(iamTopics()) {
		t.Fatalf("report %+v", rep)
	}
	if !strings.Contains(out.String(), "publish it in the console") {
		t.Fatalf("output: %s", out.String())
	}
}

func TestEnsureBranding(t *testing.T) {
	ctx := context.Background()
	svc := newTemplates(false)
	if err := EnsureBranding(ctx, svc, tenant, "MMBL UAT", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	b, _ := svc.Branding(ctx, tenant)
	if b.CompanyName != "MMBL UAT" {
		t.Fatalf("company name %q", b.CompanyName)
	}
	if err := EnsureBranding(ctx, svc, tenant, "Something else", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if b, _ = svc.Branding(ctx, tenant); b.CompanyName != "MMBL UAT" {
		t.Fatalf("an administrator's branding was replaced: %q", b.CompanyName)
	}
}

type fakeDomains struct {
	list     []domaindomain.Domain
	created  int
	verified int
	verify   func(domaindomain.Domain) (domaindomain.Domain, error)
}

func (f *fakeDomains) List(context.Context, string, int, int) ([]domaindomain.Domain, int, error) {
	return f.list, len(f.list), nil
}

func (f *fakeDomains) Create(_ context.Context, tenantID string, in appsendingdomain.Input, _ string) (domaindomain.Domain, error) {
	d, _, err := domaindomain.New(tenantID, in.Name, domaindomain.Options{Selector: in.Selector, DMARCReportTo: in.DMARCReportTo,
		SPFIncludes: []string{"amazonses.com"}}, time.Now())
	if err != nil {
		return domaindomain.Domain{}, err
	}
	d.ID = "dom-1"
	f.created++
	f.list = append(f.list, *d)
	return *d, nil
}

func (f *fakeDomains) Verify(_ context.Context, _, id string) (domaindomain.Domain, error) {
	f.verified++
	for _, d := range f.list {
		if d.ID == id {
			return f.verify(d)
		}
	}
	return domaindomain.Domain{}, errors.New("not found")
}

func TestEnsureDomainCreatesPrintsRecordsThenVerifies(t *testing.T) {
	ctx := context.Background()
	f := &fakeDomains{verify: func(d domaindomain.Domain) (domaindomain.Domain, error) {
		d.Status = domaindomain.StatusVerified
		return d, nil
	}}
	spec := DomainSpec{Name: "Mail.Bank.Example", Selector: "mailos1", DMARCReportTo: "dmarc@bank.example", FromEmail: "no-reply@mail.bank.example"}
	var out bytes.Buffer
	d, err := EnsureDomain(ctx, f, tenant, spec, &out)
	if err != nil {
		t.Fatal(err)
	}
	if f.created != 1 || d.Name != "mail.bank.example" {
		t.Fatalf("created %d, domain %+v", f.created, d)
	}
	for _, want := range []string{"mailos1._domainkey.mail.bank.example", "v=DKIM1; k=rsa; p=", "v=spf1 include:amazonses.com ~all",
		"_dmarc.mail.bank.example", "v=DMARC1; p=none; adkim=r; aspf=r; rua=mailto:dmarc@bank.example"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "WARNING") {
		t.Fatalf("aligned sender warned:\n%s", out.String())
	}

	out.Reset()
	if d, err = EnsureDomain(ctx, f, tenant, spec, &out); err != nil || f.created != 1 || f.verified != 1 || d.Status != domaindomain.StatusVerified {
		t.Fatalf("second run: created %d verified %d status %s err %v", f.created, f.verified, d.Status, err)
	}

	out.Reset()
	spec.FromEmail = "no-reply@elsewhere.example"
	if _, err := EnsureDomain(ctx, f, tenant, spec, &out); err != nil || !strings.Contains(out.String(), "WARNING") {
		t.Fatalf("misaligned sender not reported: %v\n%s", err, out.String())
	}
}

type fakeMessages struct {
	sent   appmessage.TemplatedSend
	status []domainmsg.Status
	calls  int
}

func (f *fakeMessages) SendTemplated(_ context.Context, in appmessage.TemplatedSend) (domainmsg.Message, error) {
	f.sent = in
	return domainmsg.Message{ID: "msg-1", Status: domainmsg.StatusQueued}, nil
}

func (f *fakeMessages) Get(context.Context, string, string) (appmessage.View, error) {
	s := f.status[min(f.calls, len(f.status)-1)]
	f.calls++
	m := domainmsg.Message{ID: "msg-1", Status: s, ProviderID: "platform"}
	if s == domainmsg.StatusFailed {
		m.LastError = "the server does not offer STARTTLS"
	}
	return appmessage.View{Message: m}, nil
}

func TestTestSend(t *testing.T) {
	ctx := context.Background()
	f := &fakeMessages{status: []domainmsg.Status{domainmsg.StatusSent}}
	if err := TestSend(ctx, f, tenant, "ops@bank.example", "no-reply@mail.bank.example", time.Second, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if f.sent.Topic != domaintemplate.TopicLifecycleEmail || f.sent.To != "ops@bank.example" || f.sent.TenantID != tenant {
		t.Fatalf("sent %+v", f.sent)
	}
	if errs := domaintemplate.ValidateData(f.sent.Topic, f.sent.Data); len(errs) > 0 {
		t.Fatalf("the test data does not satisfy the topic: %+v", errs)
	}

	f = &fakeMessages{status: []domainmsg.Status{domainmsg.StatusFailed}}
	err := TestSend(ctx, f, tenant, "ops@bank.example", "", time.Second, &bytes.Buffer{})
	if !errors.Is(err, ErrTestFailed) || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("failed send: %v", err)
	}

	var out bytes.Buffer
	if err := TestSend(ctx, &fakeMessages{}, tenant, " ", "", time.Second, &out); err != nil || !strings.Contains(out.String(), "skipped") {
		t.Fatalf("empty recipient: %v %s", err, out.String())
	}
}

// Every default template renders from its topic's samples with nothing
// left unfilled, and IAM's awkward cases read well: a platform approval
// has no scope name, and a security notice names its kind in words.
func TestDefaultContentRenders(t *testing.T) {
	for _, topic := range iamTopics() {
		htmlBody, textBody, _ := compile(contentFor(topic))
		c := iamContent[topic.Key]
		data := domaintemplate.SampleData(topic.Key)
		out, err := render.Render(render.Content{Subject: c.Subject, HTML: htmlBody, Text: textBody}, data, render.Options{})
		if err != nil {
			t.Errorf("%s: %v", topic.Key, err)
			continue
		}
		if strings.Contains(out.Subject+out.HTML+out.Text, "{{") || strings.TrimSpace(out.Subject) == "" {
			t.Errorf("%s renders unfilled: %q", topic.Key, out.Subject)
		}
	}
	approval := iamContent[domaintemplate.TopicApprovalRequested]
	_, textBody, _ := compile(approval)
	data := domaintemplate.WithDerived(domaintemplate.TopicApprovalRequested, map[string]any{"tenant_id": "platform", "scope_name": "",
		"operation_label": "Cancel a tenant", "user": map[string]any{"name": "Owner"}})
	out, _ := render.Render(render.Content{Text: textBody}, data, render.Options{})
	if !strings.Contains(out.Text, "An administrator asked to Cancel a tenant in the platform.") {
		t.Errorf("platform approval: %q", out.Text)
	}
	notice := iamContent[domaintemplate.TopicSecurityNotice]
	data = domaintemplate.WithDerived(domaintemplate.TopicSecurityNotice, map[string]any{"kind": "temporary_access_pass_issued"})
	out, _ = render.Render(render.Content{Subject: notice.Subject}, data, render.Options{})
	if out.Subject != "Security notice: A temporary access pass was issued for your account" {
		t.Errorf("notice subject: %q", out.Subject)
	}
}
