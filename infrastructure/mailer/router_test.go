package mailer

import (
	"context"
	"errors"
	"net/textproto"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

type fakeSource struct {
	list []Configured
	err  error
}

func (f *fakeSource) ActiveProviders(context.Context, string) ([]Configured, error) {
	return f.list, f.err
}

// fakeSender answers with err (nil for success) and counts calls.
type fakeSender struct {
	id    string
	err   error
	mu    sync.Mutex
	calls int
}

func (f *fakeSender) Send(context.Context, message.Outgoing) (Result, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return Result{}, f.err
	}
	return Result{ProviderMessageID: f.id + "-msg"}, nil
}

func configured(id string, priority, weight int) Configured {
	return Configured{Provider: provider.Provider{ID: id, Kind: provider.KindPostmark, Priority: priority, Weight: weight, Active: true}}
}

// routerWith builds a router over fake senders keyed by provider id.
func routerWith(list []Configured, senders map[string]*fakeSender, platform Sender) (*Router, *int) {
	builds := 0
	return NewRouterWithBuilder(&fakeSource{list: list}, platform, func(p provider.Provider, _ provider.Credentials) (Sender, error) {
		builds++
		return senders[p.ID], nil
	}), &builds
}

func TestRouterPriorityThenFailover(t *testing.T) {
	senders := map[string]*fakeSender{
		"high": {id: "high", err: message.NewSendError("postmark", message.ReasonAuth, 401, "bad token")},
		"low":  {id: "low"},
	}
	r, _ := routerWith([]Configured{configured("low", 1, 100), configured("high", 10, 100)}, senders, nil)
	res, err := r.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderID != "low" || res.ProviderMessageID != "low-msg" || res.Kind != provider.KindPostmark {
		t.Fatalf("%+v %v", res, err)
	}
	if senders["high"].calls != 1 {
		t.Fatal("higher priority not tried first")
	}
}

func TestRouterStopsOnMessageFault(t *testing.T) {
	senders := map[string]*fakeSender{
		"a": {err: message.NewSendError("ses", message.ReasonInvalidRecipient, 400, "bad address")},
		"b": {id: "b"},
	}
	r, _ := routerWith([]Configured{configured("a", 10, 1), configured("b", 1, 1)}, senders, nil)
	_, err := r.Send(context.Background(), sampleOutgoing())
	if se, _ := message.AsSendError(err); se == nil || se.Reason != message.ReasonInvalidRecipient || senders["b"].calls != 0 {
		t.Fatalf("%v, b called %d", err, senders["b"].calls)
	}
}

func TestRouterPrefersTransientWhenAllFail(t *testing.T) {
	senders := map[string]*fakeSender{
		"a": {err: message.NewSendError("smtp", message.ReasonConfig, 0, "no STARTTLS")},
		"b": {err: message.NewSendError("ses", message.ReasonUnavailable, 503, "down")},
	}
	r, _ := routerWith([]Configured{configured("a", 10, 1), configured("b", 1, 1)}, senders, nil)
	_, err := r.Send(context.Background(), sampleOutgoing())
	if message.IsPermanent(err) {
		t.Fatalf("permanent error returned while one provider was only down: %v", err)
	}
	senders["b"].err = message.NewSendError("ses", message.ReasonAuth, 403, "bad keys")
	_, err = r.Send(context.Background(), sampleOutgoing())
	if !message.IsPermanent(err) {
		t.Fatalf("%v", err)
	}
}

func TestRouterWeightsAndStandby(t *testing.T) {
	senders := map[string]*fakeSender{"heavy": {id: "heavy"}, "light": {id: "light"}, "standby": {id: "standby"}}
	list := []Configured{configured("heavy", 5, 300), configured("light", 5, 100), configured("standby", 5, 0)}
	r, _ := routerWith(list, senders, nil)
	for range 2000 {
		if _, err := r.Send(context.Background(), sampleOutgoing()); err != nil {
			t.Fatal(err)
		}
	}
	heavy, light := senders["heavy"].calls, senders["light"].calls
	if senders["standby"].calls != 0 || heavy < 2*light || light < 200 {
		t.Fatalf("heavy %d light %d standby %d", heavy, light, senders["standby"].calls)
	}
	// The standby goes last.
	got := order(list)
	if got[2].Provider.ID != "standby" {
		t.Fatalf("order %v", got)
	}
}

func TestRouterSkipsInactiveAndCachesSenders(t *testing.T) {
	inactive := configured("off", 10, 100)
	inactive.Provider.Active = false
	senders := map[string]*fakeSender{"on": {id: "on"}, "off": {id: "off"}}
	list := []Configured{inactive, configured("on", 1, 100)}
	r, builds := routerWith(list, senders, nil)
	for range 3 {
		if res, err := r.Send(context.Background(), sampleOutgoing()); err != nil || res.ProviderID != "on" {
			t.Fatal(res, err)
		}
	}
	if *builds != 1 {
		t.Fatalf("built %d times", *builds)
	}
	list[1].Provider.UpdatedAt = time.Now()
	_, _ = r.Send(context.Background(), sampleOutgoing())
	if *builds != 2 {
		t.Fatal("a changed provider was not rebuilt")
	}
}

func TestRouterPlatformFallback(t *testing.T) {
	platform := &fakeSender{id: "relay"}
	r, _ := routerWith(nil, nil, platform)
	res, err := r.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderID != "" || res.Kind != provider.KindSMTP || platform.calls != 1 {
		t.Fatalf("%+v %v", res, err)
	}

	var disabled *SMTP // NewPlatformSMTP returns nil when the relay is off
	r, _ = routerWith(nil, nil, disabled)
	_, err = r.Send(context.Background(), sampleOutgoing())
	if se, _ := message.AsSendError(err); se == nil || se.Reason != message.ReasonConfig {
		t.Fatalf("%v", err)
	}

	// A source failure is transient and never falls back to the relay.
	r = NewRouterWithBuilder(&fakeSource{err: errors.New("db down")}, platform, nil)
	_, err = r.Send(context.Background(), sampleOutgoing())
	if message.IsPermanent(err) || platform.calls != 1 {
		t.Fatalf("%v", err)
	}
}

func TestNewBuildsEachKind(t *testing.T) {
	opts := Options{AllowLoopback: true}
	cases := []Configured{
		{provider.Provider{Kind: provider.KindSMTP, Settings: provider.Settings{Host: "smtp.example.com", Port: 587}}, provider.Credentials{}},
		{provider.Provider{Kind: provider.KindSES, Settings: provider.Settings{Region: "eu-west-1"}}, provider.Credentials{AccessKeyID: "a", SecretAccessKey: "b"}},
		{provider.Provider{Kind: provider.KindSendGrid}, provider.Credentials{APIKey: "k"}},
		{provider.Provider{Kind: provider.KindMailgun, Settings: provider.Settings{Domain: "mg.example.com"}}, provider.Credentials{APIKey: "k"}},
		{provider.Provider{Kind: provider.KindPostmark}, provider.Credentials{ServerToken: "t"}},
	}
	for _, c := range cases {
		if s, err := New(c.Provider, c.Credentials, opts); err != nil || s == nil {
			t.Errorf("%s: %v", c.Provider.Kind, err)
		}
	}
	if _, err := New(provider.Provider{Kind: provider.KindSES, Settings: provider.Settings{Region: "eu-west-1"}}, provider.Credentials{}, opts); err == nil {
		t.Fatal("SES without keys built")
	}
}

type recordedOutcome struct {
	tenant, provider string
	test             provider.LastTest
}

type memOutcomes struct{ got []recordedOutcome }

func (m *memOutcomes) RecordDelivery(_ context.Context, tenantID, providerID string, t provider.LastTest) error {
	m.got = append(m.got, recordedOutcome{tenantID, providerID, t})
	return nil
}

// A provider that refuses a live send for its configuration (the relay
// refuses the sender) is marked failing, the router fails over, and the
// next success through it clears the mark. A refused recipient marks
// nothing: it is the message's fault.
func TestRouterMarksProviderFailingOnConfigurationRefusal(t *testing.T) {
	senderRefused := classifySMTP(context.Background(), stageRcpt,
		&textproto.Error{Code: 550, Msg: "5.7.60 SMTP; Client does not have permissions to send as this sender"})
	senders := map[string]*fakeSender{"relay": {err: senderRefused}, "backup": {id: "backup"}}
	r, _ := routerWith([]Configured{configured("relay", 10, 1), configured("backup", 1, 1)}, senders, nil)
	rec := &memOutcomes{}
	r.SetFailureRecorder(rec)
	out := sampleOutgoing()
	out.TenantID = "tenant-1"
	res, err := r.Send(context.Background(), out)
	if err != nil || res.ProviderID != "backup" {
		t.Fatalf("failover = %+v, %v", res, err)
	}
	if len(rec.got) != 1 {
		t.Fatalf("recorded %+v", rec.got)
	}
	got := rec.got[0]
	if got.tenant != "tenant-1" || got.provider != "relay" || got.test.OK || got.test.Kind != provider.TestDelivery ||
		got.test.ErrorClass != string(message.ReasonConfig) || got.test.Hint == "" {
		t.Fatalf("outcome = %+v", got)
	}

	// The relay is fixed: the next send through it clears the mark once.
	failed := got.test
	list := []Configured{configured("relay", 10, 1)}
	list[0].Provider.LastTest = &failed
	senders["relay"].err = nil
	r2, _ := routerWith(list, senders, nil)
	r2.SetFailureRecorder(rec)
	if _, err := r2.Send(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	if n := len(rec.got); n != 2 || !rec.got[1].test.OK {
		t.Fatalf("recovery = %+v", rec.got)
	}
	list[0].Provider.LastTest = &rec.got[1].test
	r3, _ := routerWith(list, senders, nil)
	r3.SetFailureRecorder(rec)
	_, _ = r3.Send(context.Background(), out)
	if len(rec.got) != 2 {
		t.Fatal("a healthy provider was recorded on every send")
	}

	senders["relay"].err = message.NewSendError("smtp", message.ReasonInvalidRecipient, 550, "no such user")
	_, _ = r3.Send(context.Background(), out)
	if len(rec.got) != 2 {
		t.Fatal("a refused recipient marked the provider failing")
	}
}

// sendsCounted reads mailos_sends_total for a provider kind and result.
func sendsCounted(t *testing.T, kind, result string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "mailos_sends_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["provider"] == kind && labels["result"] == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// Each provider attempt is counted by kind and outcome, so a failing
// provider shows on the dashboard even when failover delivers the mail.
func TestRouterCountsSendAttempts(t *testing.T) {
	kind := string(provider.KindPostmark)
	sent, auth := sendsCounted(t, kind, "sent"), sendsCounted(t, kind, string(message.ReasonAuth))
	senders := map[string]*fakeSender{
		"high": {id: "high", err: message.NewSendError("postmark", message.ReasonAuth, 401, "bad token")},
		"low":  {id: "low"},
	}
	r, _ := routerWith([]Configured{configured("low", 1, 100), configured("high", 10, 100)}, senders, nil)
	if _, err := r.Send(context.Background(), sampleOutgoing()); err != nil {
		t.Fatal(err)
	}
	if got := sendsCounted(t, kind, "sent"); got != sent+1 {
		t.Errorf("sent = %v, want %v", got, sent+1)
	}
	if got := sendsCounted(t, kind, string(message.ReasonAuth)); got != auth+1 {
		t.Errorf("auth failures = %v, want %v", got, auth+1)
	}
}

// Authentication mail (NoTracking) goes only through providers that can
// turn click and open tracking off for the message; the others are
// skipped, and a tenant with none of them gets a configuration error.
func TestRouterNoTracking(t *testing.T) {
	brevo := configured("brevo", 10, 1)
	brevo.Provider.Kind = provider.KindBrevo
	resend := configured("resend", 10, 1)
	resend.Provider.Kind = provider.KindResend
	sendgrid := configured("sendgrid", 1, 1)
	sendgrid.Provider.Kind = provider.KindSendGrid
	senders := map[string]*fakeSender{"brevo": {id: "brevo"}, "resend": {id: "resend"}, "sendgrid": {id: "sendgrid"}}
	r, _ := routerWith([]Configured{brevo, resend, sendgrid}, senders, nil)
	out := message.Outgoing{TenantID: "t", NoTracking: true}
	res, err := r.Send(context.Background(), out)
	if err != nil || res.ProviderID != "sendgrid" || senders["brevo"].calls+senders["resend"].calls != 0 {
		t.Fatalf("untracked send went to %q (%v), brevo %d resend %d", res.ProviderID, err, senders["brevo"].calls, senders["resend"].calls)
	}
	// Ordinary mail still prefers the higher priority.
	if res, err := r.Send(context.Background(), message.Outgoing{TenantID: "t"}); err != nil || res.ProviderID == "sendgrid" {
		t.Fatalf("tracked send %q %v", res.ProviderID, err)
	}

	only := map[string]*fakeSender{"brevo": {id: "brevo"}}
	r, _ = routerWith([]Configured{brevo}, only, &fakeSender{id: "platform"})
	_, err = r.Send(context.Background(), out)
	if !errors.Is(err, ErrNoUntrackedProvider) || only["brevo"].calls != 0 {
		t.Fatalf("brevo-only tenant: %v, calls %d", err, only["brevo"].calls)
	}
	if se, ok := message.AsSendError(err); !ok || !se.Permanent() {
		t.Fatalf("not a permanent send error: %v", err)
	}

	// A tenant without providers uses the platform relay (SMTP never tracks).
	platform := &fakeSender{id: "platform"}
	r, _ = routerWith(nil, nil, platform)
	if _, err := r.Send(context.Background(), out); err != nil || platform.calls != 1 {
		t.Fatalf("platform relay %v %d", err, platform.calls)
	}
	for _, k := range []provider.Kind{provider.KindBrevo, provider.KindResend} {
		if TracksOff(k) {
			t.Errorf("%s claims to turn tracking off", k)
		}
	}
	for _, k := range []provider.Kind{provider.KindSMTP, provider.KindACS, provider.KindSES, provider.KindSendGrid, provider.KindMailgun,
		provider.KindPostmark, provider.KindSparkPost, provider.KindMandrill, provider.KindMailjet, provider.KindMSGraph, provider.KindGmail} {
		if !TracksOff(k) {
			t.Errorf("%s cannot send untracked", k)
		}
	}
}
