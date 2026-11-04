package providerevents

import (
	"context"
	"errors"
	"testing"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/infrastructure/providerhooks"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type fakeSecrets map[string]string

func (f fakeSecrets) WebhookSecret(_ context.Context, tenantID, id string) (provider.Kind, string, error) {
	s, ok := f[tenantID+"/"+id]
	if !ok {
		return "", "", apperrors.NotFound("provider not found")
	}
	return provider.KindPostmark, s, nil
}

type fakeParser struct {
	res providerhooks.Result
	err error
	got string
}

func (p *fakeParser) Parse(_ context.Context, _ provider.Kind, secret string, _ providerhooks.Request) (providerhooks.Result, error) {
	p.got = secret
	return p.res, p.err
}

type fakeRecorder struct{ outcomes []any }

func (r *fakeRecorder) RecordProviderEvent(_ context.Context, _, _ string, _ domainmsg.ProviderEvent) (appmessage.EventOutcome, error) {
	next := r.outcomes[0]
	r.outcomes = r.outcomes[1:]
	if err, ok := next.(error); ok {
		return "", err
	}
	return next.(appmessage.EventOutcome), nil
}

type fakeConfirmer struct{ urls []string }

func (c *fakeConfirmer) Confirm(_ context.Context, u string) error {
	c.urls = append(c.urls, u)
	return nil
}

type fakeAudit struct{ actions []string }

func (a *fakeAudit) Append(_ context.Context, _, _, action string, _ map[string]any) error {
	a.actions = append(a.actions, action)
	return nil
}

func events(n int) []domainmsg.ProviderEvent {
	return make([]domainmsg.ProviderEvent, n)
}

func TestReceiveRecordsEvents(t *testing.T) {
	parser := &fakeParser{res: providerhooks.Result{Events: events(3)}}
	rec := &fakeRecorder{outcomes: []any{appmessage.OutcomeRecorded, appmessage.OutcomeDuplicate, appmessage.OutcomeUnknownMessage}}
	svc := NewService(fakeSecrets{"t/p1": "pw"}, parser, nil, rec, &fakeAudit{})
	sum, err := svc.Receive(context.Background(), "t", "p1", providerhooks.Request{})
	if err != nil || sum != (Summary{Recorded: 1, Duplicates: 1, Unknown: 1}) || parser.got != "pw" {
		t.Fatalf("%+v %v %q", sum, err, parser.got)
	}
}

func TestReceiveRefusesAndAudits(t *testing.T) {
	a := &fakeAudit{}
	parser := &fakeParser{err: providerhooks.ErrUnauthenticated}
	svc := NewService(fakeSecrets{"t/p1": "pw"}, parser, nil, &fakeRecorder{}, a)
	if _, err := svc.Receive(context.Background(), "t", "p1", providerhooks.Request{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v", err)
	}
	if len(a.actions) != 1 || a.actions[0] != AuditRefused {
		t.Fatalf("audit %v", a.actions)
	}
	// An unknown provider is refused the same way, without parsing.
	parser.got = ""
	if _, err := svc.Receive(context.Background(), "t", "nope", providerhooks.Request{}); !errors.Is(err, ErrRefused) || parser.got != "" {
		t.Fatalf("err = %v", err)
	}
	parser.err = providerhooks.ErrMalformed
	if _, err := svc.Receive(context.Background(), "t", "p1", providerhooks.Request{}); apperrors.KindOf(err) != apperrors.KindBadRequest {
		t.Fatalf("malformed: %v", err)
	}
}

func TestReceiveConfirmsSNSAndAsksForRetry(t *testing.T) {
	c, a := &fakeConfirmer{}, &fakeAudit{}
	parser := &fakeParser{res: providerhooks.Result{SubscribeURL: "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription"}}
	svc := NewService(fakeSecrets{"t/p1": "pw"}, parser, c, &fakeRecorder{}, a)
	sum, err := svc.Receive(context.Background(), "t", "p1", providerhooks.Request{})
	if err != nil || !sum.Confirmed || len(c.urls) != 1 || a.actions[0] != AuditConfirmed {
		t.Fatalf("%+v %v %v", sum, err, c.urls)
	}

	parser.res = providerhooks.Result{Events: events(2)}
	svc.recorder = &fakeRecorder{outcomes: []any{appmessage.OutcomeRecorded, appmessage.ErrStillSending}}
	sum, err = svc.Receive(context.Background(), "t", "p1", providerhooks.Request{})
	if !errors.Is(err, ErrRetry) || sum.Recorded != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
}
