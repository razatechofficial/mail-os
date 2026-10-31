package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/webhook"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type fakeCipher struct{}

func (fakeCipher) Seal(_ context.Context, p []byte) (string, error) {
	return "km1.testkid0.x" + string(p), nil
}
func (fakeCipher) Open(_ context.Context, c string) ([]byte, error) {
	return []byte(strings.TrimPrefix(c, "km1.testkid0.x")), nil
}

type memRepo struct {
	hooks      map[string]Stored
	deliveries map[string]domain.Delivery
}

func (r *memRepo) Create(_ context.Context, s Stored) error { r.hooks[s.Webhook.ID] = s; return nil }
func (r *memRepo) Update(_ context.Context, w domain.Webhook, sealed *string) error {
	s := r.hooks[w.ID]
	s.Webhook = w
	if sealed != nil {
		s.Sealed = *sealed
	}
	r.hooks[w.ID] = s
	return nil
}
func (r *memRepo) Delete(_ context.Context, _, id string, _ time.Time) error {
	delete(r.hooks, id)
	return nil
}
func (r *memRepo) Get(_ context.Context, t, id string) (Stored, error) {
	s, ok := r.hooks[id]
	if !ok || s.Webhook.OrgID != t {
		return Stored{}, apperrors.NotFound("webhook not found")
	}
	return s, nil
}
func (r *memRepo) List(context.Context, string, int, int) ([]domain.Webhook, int, error) {
	return nil, 0, nil
}
func (r *memRepo) Subscribed(_ context.Context, t, app, event string) ([]domain.Webhook, error) {
	var out []domain.Webhook
	for _, s := range r.hooks {
		scope := s.Webhook.ApplicationID == "" || (app != "" && s.Webhook.ApplicationID == app)
		if s.Webhook.OrgID == t && scope && s.Webhook.Subscribes(event) {
			out = append(out, s.Webhook)
		}
	}
	return out, nil
}
func (r *memRepo) CreateDelivery(_ context.Context, d domain.Delivery) error {
	r.deliveries[d.ID] = d
	return nil
}
func (r *memRepo) Delivery(_ context.Context, id string) (domain.Delivery, Stored, error) {
	d := r.deliveries[id]
	return d, r.hooks[d.WebhookID], nil
}
func (r *memRepo) UpdateDelivery(_ context.Context, d domain.Delivery) error {
	r.deliveries[d.ID] = d
	return nil
}
func (r *memRepo) Legacy(context.Context) ([]LegacyRow, error)         { return nil, nil }
func (r *memRepo) ReplaceLegacy(context.Context, string, string) error { return nil }
func (r *memRepo) WithLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

type memQueue struct{ ids []string }

func (q *memQueue) EnqueueWebhook(_ context.Context, id string) error {
	q.ids = append(q.ids, id)
	return nil
}

type poster struct {
	status  int
	err     error
	headers map[string]string
	body    []byte
}

func (p *poster) Post(_ context.Context, _ string, h map[string]string, b []byte) (int, error) {
	p.headers, p.body = h, b
	return p.status, p.err
}

type nopAudit struct{}

func (nopAudit) Change(context.Context, string, string, string, any, any, map[string]any) error {
	return nil
}

func TestNotifyAndDeliverSigned(t *testing.T) {
	repo := &memRepo{hooks: map[string]Stored{}, deliveries: map[string]domain.Delivery{}}
	q, p := &memQueue{}, &poster{status: 204}
	svc := NewService(repo, fakeCipher{}, q, p, nopAudit{}, Config{})
	w, secret, err := svc.Create(context.Background(), "t1", Input{URL: "https://hooks.bank.example/m", Events: []string{domain.EventSent}}, "a")
	if err != nil || !strings.HasPrefix(secret, "whsec_") || !strings.HasPrefix(repo.hooks[w.ID].Sealed, "km1.") {
		t.Fatal(w, err)
	}
	if err := svc.Notify(context.Background(), "t1", "", domain.EventFailed, "m1", nil); err != nil || len(q.ids) != 0 {
		t.Fatal("unsubscribed event queued")
	}
	if err := svc.Notify(context.Background(), "t1", "", domain.EventSent, "m1", map[string]any{"message_id": "m1"}); err != nil || len(q.ids) != 1 {
		t.Fatal(err)
	}
	if err := svc.Deliver(context.Background(), q.ids[0], false); err != nil {
		t.Fatal(err)
	}
	if !domain.Verify(secret, p.headers[domain.IDHeader], p.headers[domain.TimestampHeader], p.headers[domain.SignatureHeader],
		p.body, time.Now(), time.Minute) || p.headers[domain.IDHeader] != q.ids[0] {
		t.Fatal("signature does not verify with the secret")
	}
	var body struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(p.body, &body); err != nil || body.Type != domain.EventSent || body.Data["message_id"] != "m1" {
		t.Fatalf("payload %s", p.body)
	}
	if d := repo.deliveries[q.ids[0]]; d.Status != domain.DeliveryDelivered || d.Attempts != 1 {
		t.Fatalf("%+v", d)
	}
}

// An application's endpoint gets that application's events only; a
// tenant-wide endpoint gets every application's.
func TestNotifyApplicationScope(t *testing.T) {
	repo := &memRepo{hooks: map[string]Stored{}, deliveries: map[string]domain.Delivery{}}
	q := &memQueue{}
	svc := NewService(repo, fakeCipher{}, q, &poster{status: 204}, nopAudit{}, Config{})
	scoped, _, err := svc.Create(context.Background(), "t1", Input{ApplicationID: "app-1", URL: "https://hooks.bank.example/a",
		Events: []string{domain.EventSent}}, "a")
	if err != nil || scoped.ApplicationID != "app-1" {
		t.Fatal(scoped, err)
	}
	if _, _, err := svc.Create(context.Background(), "t1", Input{URL: "https://hooks.bank.example/all", Events: []string{domain.EventSent}}, "a"); err != nil {
		t.Fatal(err)
	}
	for app, want := range map[string]int{"app-1": 2, "app-2": 1, "": 1} {
		before := len(q.ids)
		if err := svc.Notify(context.Background(), "t1", app, domain.EventSent, "m", nil); err != nil {
			t.Fatal(err)
		}
		if got := len(q.ids) - before; got != want {
			t.Errorf("application %q: %d deliveries, want %d", app, got, want)
		}
	}
}

func TestDeliverRetriesAndGivesUp(t *testing.T) {
	repo := &memRepo{hooks: map[string]Stored{}, deliveries: map[string]domain.Delivery{}}
	q, p := &memQueue{}, &poster{status: 503}
	svc := NewService(repo, fakeCipher{}, q, p, nopAudit{}, Config{})
	_, _, _ = svc.Create(context.Background(), "t1", Input{URL: "https://hooks.bank.example/m", Secret: "a-chosen-secret-0123", Events: []string{domain.EventSent}}, "a")
	_ = svc.Notify(context.Background(), "t1", "", domain.EventSent, "m1", nil)
	var de *DeliveryError
	if err := svc.Deliver(context.Background(), q.ids[0], false); !errors.As(err, &de) || de.Status != 503 {
		t.Fatal(err)
	}
	if err := svc.Deliver(context.Background(), q.ids[0], true); err != nil || repo.deliveries[q.ids[0]].Status != domain.DeliveryFailed {
		t.Fatal("final attempt not failed", err)
	}
	// A 4xx refusal is final at once.
	p.status = 410
	_ = svc.Notify(context.Background(), "t1", "", domain.EventSent, "m2", nil)
	if err := svc.Deliver(context.Background(), q.ids[1], false); err != nil || repo.deliveries[q.ids[1]].Status != domain.DeliveryFailed {
		t.Fatal(err)
	}
}

func TestCreateRefusesPlainHTTP(t *testing.T) {
	svc := NewService(&memRepo{hooks: map[string]Stored{}}, fakeCipher{}, &memQueue{}, &poster{}, nopAudit{}, Config{})
	if _, _, err := svc.Create(context.Background(), "t1", Input{URL: "http://hooks.bank.example", Events: []string{domain.EventSent}}, "a"); err == nil {
		t.Fatal("http accepted")
	}
}
