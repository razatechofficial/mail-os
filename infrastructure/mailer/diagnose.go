package mailer

import (
	"context"
	"errors"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Checker is a sender that can test its connection and credentials
// without sending mail: SMTP connects, negotiates TLS and authenticates;
// an API makes a harmless authenticated call.
type Checker interface {
	Check(ctx context.Context, p *Probe) error
}

// Probe records a test's steps. A nil Probe records nothing, so a sender
// runs the same code when it sends.
type Probe struct {
	steps    []provider.Step
	warnings []string
}

// Step runs one stage of a test and records it; fn returns a detail for
// the administrator (never a secret).
func (p *Probe) Step(name, label string, fn func() (string, error)) error {
	if p == nil {
		_, err := fn()
		return err
	}
	start := time.Now()
	detail, err := fn()
	st := provider.Step{Name: name, Label: label, OK: err == nil, Detail: detail, DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		st.Detail = errorDetail(err)
	}
	p.steps = append(p.steps, st)
	return err
}

// Warn records something that does not fail the test but needs attention.
func (p *Probe) Warn(s string) {
	if p != nil {
		p.warnings = append(p.warnings, s)
	}
}

func errorDetail(err error) string {
	if se, ok := message.AsSendError(err); ok && se.Detail != "" {
		return se.Detail
	}
	return message.SafeDetail(err)
}

func now() time.Time { return time.Now().UTC() }

// Test runs s's connection test.
func Test(ctx context.Context, kind provider.Kind, s Sender) provider.Diagnosis {
	d := provider.Diagnosis{Kind: provider.TestConnection, At: now()}
	p := &Probe{}
	c, ok := s.(Checker)
	if !ok {
		return p.finish(ctx, d, kind, message.NewSendError(string(kind), message.ReasonConfig, 0, "this provider cannot be tested without sending"))
	}
	return p.finish(ctx, d, kind, c.Check(ctx, p))
}

// TestSend sends out through s and reports it as a diagnosis.
func TestSend(ctx context.Context, kind provider.Kind, s Sender, out message.Outgoing) provider.Diagnosis {
	d := provider.Diagnosis{Kind: provider.TestSend, At: now()}
	p := &Probe{}
	var res Result
	err := p.Step("send", "Send the test message to "+out.To.Email, func() (string, error) {
		var err error
		res, err = s.Send(ctx, out)
		if err != nil {
			return "", err
		}
		return "accepted as " + res.ProviderMessageID, nil
	})
	d.ProviderMessageID = res.ProviderMessageID
	return p.finish(ctx, d, kind, err)
}

func (p *Probe) finish(ctx context.Context, d provider.Diagnosis, kind provider.Kind, err error) provider.Diagnosis {
	d.Steps, d.Warnings = p.steps, p.warnings
	if d.Steps == nil {
		d.Steps = []provider.Step{}
	}
	if err == nil {
		d.OK = true
		return d
	}
	se, ok := message.AsSendError(err)
	if !ok {
		se = classifyNetwork(ctx, kind, err)
	}
	if n := len(d.Steps); n > 0 && !d.Steps[n-1].OK {
		d.Step = d.Steps[n-1].Name
	}
	d.ErrorClass = string(se.Reason)
	d.Detail = errorDetail(se)
	d.Hint = Hint(kind, d.Step, se)
	return d
}

// Hint says what an administrator should check after a failure at step.
func Hint(kind provider.Kind, step string, se *message.SendError) string {
	if se == nil {
		return ""
	}
	if h := kindHint(kind, step, se); h != "" {
		return h
	}
	switch se.Reason {
	case message.ReasonNetwork:
		if errors.Is(se.Err, context.DeadlineExceeded) || isTimeout(se.Err) {
			return "The provider did not answer in time. Check that the firewall allows MailOS's egress addresses to reach it, and the host and port."
		}
		return "Check the host and port, that the name resolves, and that the firewall allows MailOS's egress addresses to reach it."
	case message.ReasonAuth:
		return "The provider refused the credentials. Check they were copied completely, are not expired or revoked, and allow sending."
	case message.ReasonRateLimited:
		return "The provider is rate limiting this account. Try again later, or lower this provider's weight or daily limit."
	case message.ReasonUnavailable:
		return "The provider reported a temporary failure. Try again; meanwhile MailOS fails over to your other providers."
	case message.ReasonInvalidRecipient:
		return "The provider refused the recipient address. Check it, and that it is not on the provider's suppression list."
	case message.ReasonRejected:
		return "The provider refused the message. Usually the sender address or its domain is not verified with the provider."
	case message.ReasonInvalid:
		return "The message could not be built. Set a valid default sender on the provider."
	}
	if step == "tls" || step == "connect" && se.Detail == tlsDetail {
		return "The relay's certificate is not trusted or does not match the host. For an internal CA, add it under TLS and certificates; make sure the host is the name in the certificate."
	}
	return "Check the provider's settings: region, domain, sending mailbox and sender identity."
}

func kindHint(kind provider.Kind, step string, se *message.SendError) string {
	switch {
	case step == "token" && se.Reason == message.ReasonAuth && kind == provider.KindGmail,
		step == "token" && se.Reason == message.ReasonAuth && se.Provider == oauthGoogle:
		return "Google refused the service account. In the Google Admin console, give its client ID domain-wide delegation for the scope MailOS asks for, check the sending user exists, and that the key was not deleted."
	case step == "token" && se.Reason == message.ReasonConfig && (kind == provider.KindGmail || se.Provider == oauthGoogle):
		return "Google does not know the sending user. Check the address of the user the service account acts as."
	case step == "token" && se.Reason == message.ReasonAuth:
		return "Microsoft Entra ID refused the application's credentials. Check the client secret's value (not its ID) and expiry, or that the certificate is the one uploaded to the app registration."
	case step == "token" && se.Reason == message.ReasonConfig:
		return "Microsoft Entra ID does not know the tenant or application. Check the directory (tenant) ID and the application (client) ID."
	case kind == provider.KindMSGraph && se.Reason == message.ReasonAuth:
		return "Graph refused to send as the mailbox. Grant the Mail.Send application permission with admin consent, and include the mailbox in any application access policy."
	case kind == provider.KindMSGraph && se.Reason == message.ReasonConfig:
		return "Graph does not know the mailbox, or it cannot send. Check the sending mailbox exists and is licensed for Exchange Online."
	case kind == provider.KindSMTP && step == "auth" && se.Reason == message.ReasonAuth:
		return "The relay refused the credentials. Check the username and password. For Microsoft 365, SMTP AUTH must be enabled for the mailbox and the app needs SMTP.SendAsApp; for Google, use an app password or XOAUTH2."
	case kind == provider.KindSMTP && step == "auth" && se.Reason == message.ReasonConfig:
		return "The relay does not offer this authentication mechanism, or would receive the password without TLS. Pick one of the mechanisms it lists."
	case kind == provider.KindSMTP && (step == "tls" || se.Detail == tlsDetail):
		return "The relay's certificate is not trusted or does not match the host. For an internal CA, add it under TLS and certificates; make sure the host is the name in the certificate."
	case kind == provider.KindSMTP && se.Reason == message.ReasonConfig && se.Detail == noSTARTTLS:
		return "The relay does not offer STARTTLS. Enable TLS on the relay, or use implicit TLS on port 465 if it supports it. MailOS never sends credentials or mail in plaintext."
	case kind == provider.KindSMTP && se.Reason == message.ReasonConfig && se.Detail == addressRefused:
		return "Tenant providers cannot reach private or loopback addresses. Use the relay's public name, or ask the operator to run it as the platform relay."
	case kind == provider.KindACS && se.Reason == message.ReasonAuth:
		return "Azure refused the access key. Copy the resource's primary or secondary key again from Keys in the Azure portal."
	case kind == provider.KindACS && se.Reason == message.ReasonConfig:
		return "Check the endpoint and that the sender address belongs to a domain connected to the Communication Services resource."
	case kind == provider.KindBrevo && se.Reason == message.ReasonAuth:
		return "Brevo refused the key. Check it is a v3 API key, and that MailOS's egress addresses are in Brevo's authorised IPs if that restriction is on."
	case kind == provider.KindSES && se.Reason == message.ReasonConfig:
		return "SES refused the sender: verify the From address or its domain in this region, and request production access to send to unverified recipients."
	}
	return ""
}
