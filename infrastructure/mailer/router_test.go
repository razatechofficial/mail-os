package mailer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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
