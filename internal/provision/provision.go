// Package provision prepares a new deployment's tenant for IAM's mail
// without a console user: a published default template for every IAM
// topic, the tenant's template branding, its sending domain with the DNS
// records to publish, and a test send through the configured provider. It
// is what cmd/bootstrap runs; every step is idempotent and never replaces
// what an administrator changed.
//
// It exists because the first console user cannot be invited before IAM
// can mail, and IAM cannot mail before its templates are published.
package provision

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	appsendingdomain "github.com/razatechofficial/mail-os/application/sendingdomain"
	apptemplate "github.com/razatechofficial/mail-os/application/template"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domaindomain "github.com/razatechofficial/mail-os/domain/sendingdomain"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Actor is who the audit records name for the bootstrap's changes.
const Actor = "mailos-bootstrap"

// Templates is the template use case (apptemplate.Service).
type Templates interface {
	List(ctx context.Context, tenantID string, limit, offset int) ([]domaintemplate.Template, int, error)
	Create(ctx context.Context, tenantID string, in apptemplate.CreateInput) (domaintemplate.Template, error)
	ActiveVersion(ctx context.Context, tenantID, templateID, loc string) (domaintemplate.Version, error)
	Draft(ctx context.Context, tenantID, templateID, loc string) (domaintemplate.Draft, error)
	SaveDraft(ctx context.Context, tenantID, templateID string, in apptemplate.DraftInput, by apptemplate.Editor) (domaintemplate.Draft, []apperrors.FieldError, error)
	Publish(ctx context.Context, tenantID, templateID, loc string, revision int, publisher string) (domaintemplate.Version, error)
	Branding(ctx context.Context, tenantID string) (domaintemplate.Branding, error)
	UpdateBranding(ctx context.Context, tenantID string, next domaintemplate.Branding, by string) (domaintemplate.Branding, error)
}

// Domains is the sending domain use case (appsendingdomain.Service).
type Domains interface {
	List(ctx context.Context, tenantID string, limit, offset int) ([]domaindomain.Domain, int, error)
	Create(ctx context.Context, tenantID string, in appsendingdomain.Input, actor string) (domaindomain.Domain, error)
	Verify(ctx context.Context, tenantID, id string) (domaindomain.Domain, error)
}

// Messages is the message use case (appmessage.Service).
type Messages interface {
	SendTemplated(ctx context.Context, in appmessage.TemplatedSend) (domainmsg.Message, error)
	Get(ctx context.Context, tenantID, id string) (appmessage.View, error)
}

// TemplateReport counts what SeedTemplates did.
type TemplateReport struct {
	Published int // topics that got their default template
	Kept      int // topics that already had a published template
	Failed    int // topics left for the console (the error is printed)
}

const pageSize = 100

// existingByTopic lists the tenant's templates by topic.
func existingByTopic(ctx context.Context, t Templates, tenantID string) (map[string]domaintemplate.Template, error) {
	out := map[string]domaintemplate.Template{}
	for offset := 0; ; offset += pageSize {
		list, total, err := t.List(ctx, tenantID, pageSize, offset)
		if err != nil {
			return nil, err
		}
		for _, tpl := range list {
			if tpl.Topic != "" {
				out[tpl.Topic] = tpl
			}
		}
		if len(list) == 0 || offset+len(list) >= total {
			return out, nil
		}
	}
}

// SeedTemplates publishes a default template for every IAM topic of the
// catalogue that has no published version in the tenant yet. A topic whose
// template an administrator created or published is kept as it is; a
// template without a published version gets the default as its first
// version. A topic that cannot be published (four-eyes on, for example) is
// reported and the others continue.
func SeedTemplates(ctx context.Context, t Templates, tenantID string, out io.Writer) (TemplateReport, error) {
	var rep TemplateReport
	existing, err := existingByTopic(ctx, t, tenantID)
	if err != nil {
		return rep, fmt.Errorf("list templates: %w", err)
	}
	en := string(domaintemplate.LocaleEnglish)
	for _, topic := range domaintemplate.Topics() {
		if topic.Source != domaintemplate.SourceIAM {
			continue
		}
		tpl, ok := existing[topic.Key]
		if ok {
			if _, err := t.ActiveVersion(ctx, tenantID, tpl.ID, ""); err == nil {
				rep.Kept++
				continue
			} else if !apperrors.IsNotFound(err) {
				return rep, fmt.Errorf("%s: %w", topic.Key, err)
			}
		}
		if err := publishDefault(ctx, t, tenantID, topic, tpl, ok, en); err != nil {
			rep.Failed++
			fmt.Fprintf(out, "  ! %s: %v (publish it in the console)\n", topic.Key, err)
			continue
		}
		rep.Published++
		fmt.Fprintf(out, "  + %s published\n", topic.Key)
	}
	return rep, nil
}

func publishDefault(ctx context.Context, t Templates, tenantID string, topic domaintemplate.Topic, tpl domaintemplate.Template, exists bool, loc string) error {
	c := contentFor(topic)
	if !exists {
		var err error
		tpl, err = t.Create(ctx, tenantID, apptemplate.CreateInput{Name: c.Name, Slug: slugOf(topic.Key), Description: topic.Description,
			Category: domaintemplate.CategoryTransactional, Topic: topic.Key, DefaultLocale: domaintemplate.LocaleEnglish})
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		loc = string(tpl.DefaultLocale)
	} else if tpl.DefaultLocale != "" {
		loc = string(tpl.DefaultLocale)
	}
	draft, err := t.Draft(ctx, tenantID, tpl.ID, loc)
	if err != nil {
		return fmt.Errorf("read draft: %w", err)
	}
	htmlBody, textBody, vars := compile(c)
	saved, _, err := t.SaveDraft(ctx, tenantID, tpl.ID, apptemplate.DraftInput{Locale: loc, Revision: draft.Revision,
		Subject: c.Subject, Preheader: c.Preheader, HTMLBody: htmlBody, TextBody: textBody, Variables: vars},
		apptemplate.Editor{ID: Actor})
	if err != nil {
		return fmt.Errorf("save draft: %w", err)
	}
	if _, err := t.Publish(ctx, tenantID, tpl.ID, loc, saved.Revision, Actor); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}

// EnsureBranding sets the company name templates show in their header and
// footer, only while the tenant still has the default branding.
func EnsureBranding(ctx context.Context, t Templates, tenantID, companyName string, out io.Writer) error {
	companyName = strings.TrimSpace(companyName)
	if companyName == "" {
		return nil
	}
	b, err := t.Branding(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("read branding: %w", err)
	}
	if !b.UpdatedAt.IsZero() || b.CompanyName != "" {
		fmt.Fprintf(out, "branding kept (company name %q)\n", b.CompanyName)
		return nil
	}
	b.CompanyName = companyName
	if _, err := t.UpdateBranding(ctx, tenantID, b, Actor); err != nil {
		return fmt.Errorf("set branding: %w", err)
	}
	fmt.Fprintf(out, "branding: company name %q\n", companyName)
	return nil
}

// DomainSpec is the tenant's sending domain.
type DomainSpec struct {
	Name          string
	Selector      string
	DMARCReportTo string
	// FromEmail is the address IAM's mail goes out from (SMTP_FROM_ADDR);
	// it must be on Name for DKIM and SPF to align with DMARC.
	FromEmail string
}

// EnsureDomain creates the tenant's sending domain with a new DKIM key, or
// checks the DNS of the one it has, and prints the records to publish.
// A domain whose records are not published yet is not an error: the
// bootstrap is run again once they are.
func EnsureDomain(ctx context.Context, d Domains, tenantID string, spec DomainSpec, out io.Writer) (domaindomain.Domain, error) {
	name := domaindomain.NormalizeName(spec.Name)
	if name == "" {
		fmt.Fprintln(out, "sending domain: none configured (MAILOS_SENDING_DOMAIN); mail is not DKIM-signed")
		return domaindomain.Domain{}, nil
	}
	if from := domaindomain.FromDomain(spec.FromEmail); from != "" && from != name && !strings.HasSuffix(from, "."+name) {
		fmt.Fprintf(out, "WARNING: the sender %s is not on %s; DMARC will not align until it is\n", spec.FromEmail, name)
	}
	var found *domaindomain.Domain
	for offset := 0; found == nil; offset += pageSize {
		list, total, err := d.List(ctx, tenantID, pageSize, offset)
		if err != nil {
			return domaindomain.Domain{}, fmt.Errorf("list sending domains: %w", err)
		}
		for i := range list {
			if list[i].Name == name {
				found = &list[i]
				break
			}
		}
		if len(list) == 0 || offset+len(list) >= total {
			break
		}
	}
	var dom domaindomain.Domain
	if found == nil {
		created, err := d.Create(ctx, tenantID, appsendingdomain.Input{Name: name, Selector: spec.Selector, DMARCReportTo: spec.DMARCReportTo}, Actor)
		if err != nil {
			return domaindomain.Domain{}, fmt.Errorf("create sending domain %s: %w", name, err)
		}
		dom = created
		fmt.Fprintf(out, "sending domain %s created (DKIM selector %s); publish these records, then run the bootstrap again:\n", name, dom.DKIMSelector)
	} else {
		dom = *found
		checked, err := d.Verify(ctx, tenantID, dom.ID)
		switch {
		case err == nil:
			dom = checked
		case apperrors.KindOf(err) == apperrors.KindUnavailable:
			fmt.Fprintf(out, "sending domain %s: the DNS lookup failed (%v); status stays %s\n", name, err, dom.Status)
		default:
			return dom, fmt.Errorf("verify sending domain %s: %w", name, err)
		}
		if dom.Status == domaindomain.StatusVerified {
			fmt.Fprintf(out, "sending domain %s verified: mail from it is DKIM-signed (selector %s)\n", name, dom.DKIMSelector)
		} else {
			fmt.Fprintf(out, "sending domain %s is %s: %s\nPublish these records, then run the bootstrap again:\n", name, dom.Status, dom.FailureReason)
		}
	}
	for _, r := range dom.Records() {
		fmt.Fprintf(out, "  %-5s %s  TXT  %q\n", strings.ToUpper(r.Purpose), r.Name, r.Value)
	}
	return dom, nil
}

// ErrTestFailed is a test send the provider did not accept.
var ErrTestFailed = errors.New("the test message was not sent")

// TestSend queues one message to to through the tenant's providers (or the
// platform relay) and waits for the worker's outcome. It uses the
// iam.lifecycle.email topic, whose template takes a subject and body.
func TestSend(ctx context.Context, m Messages, tenantID, to, from string, timeout time.Duration, out io.Writer) error {
	to = strings.TrimSpace(to)
	if to == "" {
		fmt.Fprintln(out, "test send: skipped (MAILOS_TEST_RECIPIENT is empty)")
		return nil
	}
	now := time.Now().UTC()
	msg, err := m.SendTemplated(ctx, appmessage.TemplatedSend{
		TenantID: tenantID, Topic: domaintemplate.TopicLifecycleEmail, To: to, FromEmail: strings.TrimSpace(from),
		Source: Actor, Tags: []string{"provider-test"},
		Data: map[string]any{
			"email": to, "user_uuid": "00000000-0000-0000-0000-000000000000", "tenant_uuid": tenantID,
			"subject": "MailOS provider test", "occurred_at": now.Format(time.RFC3339),
			"body": "This message tests the MailOS provider configured for this deployment. No action is needed.",
		},
	})
	if err != nil {
		return fmt.Errorf("queue the test message: %w", err)
	}
	fmt.Fprintf(out, "test send: message %s queued to %s\n", msg.ID, to)
	deadline := time.Now().Add(timeout)
	for {
		v, err := m.Get(ctx, tenantID, msg.ID)
		if err != nil {
			return fmt.Errorf("read the test message: %w", err)
		}
		switch v.Status {
		case domainmsg.StatusSent, domainmsg.StatusDelivered:
			fmt.Fprintf(out, "test send: %s by provider %s (id %s)\n", v.Status, v.ProviderID, v.ProviderMessageID)
			return nil
		case domainmsg.StatusFailed, domainmsg.StatusBounced, domainmsg.StatusSuppressed, domainmsg.StatusCancelled:
			return fmt.Errorf("%w: %s: %s", ErrTestFailed, v.Status, v.LastError)
		}
		if time.Now().After(deadline) {
			last := v.LastError
			if last == "" {
				last = "is the worker running?"
			}
			return fmt.Errorf("%w: still %s after %s: %s", ErrTestFailed, v.Status, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
