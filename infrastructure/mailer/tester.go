package mailer

import (
	"context"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Tester runs provider tests with a sender built for each test, so a test
// never reuses or disturbs the router's cached senders.
type Tester struct {
	Options Options
}

// build returns the provider's sender, or the failed diagnosis of why it
// cannot be built (missing or malformed settings and credentials).
func (t Tester) build(ctx context.Context, kind string, p provider.Provider, c provider.Credentials) (Sender, *provider.Diagnosis) {
	snd, err := New(p, c, t.Options)
	if err == nil {
		return snd, nil
	}
	pr := &Probe{}
	_ = pr.Step("configure", "Read the provider's settings", func() (string, error) { return "", err })
	d := pr.finish(ctx, provider.Diagnosis{Kind: kind, At: now()}, p.Kind, err)
	return nil, &d
}

func release(s Sender) {
	if c, ok := s.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// Test connects to the provider and checks its credentials, sending no
// mail.
func (t Tester) Test(ctx context.Context, p provider.Provider, c provider.Credentials) provider.Diagnosis {
	snd, failed := t.build(ctx, provider.TestConnection, p, c)
	if failed != nil {
		return *failed
	}
	defer release(snd)
	return Test(ctx, p.Kind, snd)
}

// Send sends out through the provider.
func (t Tester) Send(ctx context.Context, p provider.Provider, c provider.Credentials, out message.Outgoing) provider.Diagnosis {
	snd, failed := t.build(ctx, provider.TestSend, p, c)
	if failed != nil {
		return *failed
	}
	defer release(snd)
	return TestSend(ctx, p.Kind, snd, out)
}
