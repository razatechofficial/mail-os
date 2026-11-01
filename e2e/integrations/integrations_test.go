//go:build e2e

// Package integrations covers what other systems see of MailOS: signed
// webhook deliveries with retries, and the inbound event API's topic
// allow-list and envelope rules.
package integrations

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "integrations", &fx) }

// receiverAddr is the e2e port the webhook receiver listens on (the
// deployment refuses loopback; APP_ENV=e2e allows it).
const receiverAddr = "127.0.0.1:19884"

type delivery struct {
	header http.Header
	body   []byte
}

type receiver struct {
	mu    sync.Mutex
	got   []delivery
	codes []int // answered in turn; 200 after
}

func listen(t *testing.T, codes ...int) *receiver {
	t.Helper()
	rcv := &receiver{codes: codes}
	ln, err := net.Listen("tcp", receiverAddr)
	if err != nil {
		t.Fatalf("listen %s: %v", receiverAddr, err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rcv.mu.Lock()
		rcv.got = append(rcv.got, delivery{header: r.Header.Clone(), body: body})
		code := http.StatusOK
		if len(rcv.codes) > 0 {
			code, rcv.codes = rcv.codes[0], rcv.codes[1:]
		}
		rcv.mu.Unlock()
		w.WriteHeader(code)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return rcv
}

func (r *receiver) deliveries() []delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]delivery(nil), r.got...)
}

// verify checks "t=<unix>,v1=<hex HMAC-SHA256(secret, t.body)>".
func verify(secret string, d delivery) bool {
	var ts, sig string
	for _, part := range strings.Split(d.header.Get("X-MailOS-Signature"), ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(n, 0)).Abs() > 5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(d.body)
	want, _ := hex.DecodeString(sig)
	return hmac.Equal(mac.Sum(nil), want)
}

func TestWebhookIsSignedRetriedAndSecretShownOnce(t *testing.T) {
	rcv := listen(t, http.StatusServiceUnavailable)
	admin := fx.Admin(t)
	created := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/webhooks", map[string]any{
		"url": "http://" + receiverAddr + "/hook", "events": []string{"message.sent"}})
	secret, id := harness.Str(created.Data(), "secret"), harness.Str(created.Data(), "id")
	if !strings.HasPrefix(secret, "whsec_") || created.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %s (Cache-Control %q)", created, created.Header.Get("Cache-Control"))
	}
	for _, r := range []*harness.Response{admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/webhooks/"+id, nil),
		admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/webhooks", nil)} {
		if strings.Contains(r.String(), secret) {
			t.Fatalf("the secret is shown again: %s", r)
		}
	}

	box := fx.Env.NewMailbox("hooked")
	msg := harness.Str(admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send",
		map[string]any{"to_email": box.Address, "subject": "Hooked", "text_body": "x"}).Data(), "message_id")
	harness.Eventually(t, "a retried webhook delivery", 60*time.Second, func() bool { return len(rcv.deliveries()) >= 2 })
	ds := rcv.deliveries()
	for _, d := range ds {
		if !verify(secret, d) {
			t.Fatalf("signature does not verify: %q", d.header.Get("X-MailOS-Signature"))
		}
		if verify("whsec_wrong", d) {
			t.Fatal("a wrong secret verifies")
		}
		if d.header.Get("X-MailOS-Event") != "message.sent" || !strings.Contains(string(d.body), msg) {
			t.Fatalf("delivery: %v %s", d.header, d.body)
		}
	}
	if ds[0].header.Get("X-MailOS-Delivery") != ds[1].header.Get("X-MailOS-Delivery") {
		t.Fatal("the retry is a different delivery")
	}

	// A paused webhook receives nothing more.
	admin.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/webhooks/"+id, map[string]any{"is_active": false})
	admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", map[string]any{"to_email": box.Address, "subject": "Quiet", "text_body": "x"})
	box.WaitSubject(t, "Quiet")
	time.Sleep(2 * time.Second)
	if n := len(rcv.deliveries()); n != len(ds) {
		t.Fatalf("a paused webhook got %d more deliveries", n-len(ds))
	}
}

func TestWebhookValidation(t *testing.T) {
	admin := fx.Admin(t)
	for _, body := range []map[string]any{
		{"url": "ftp://hooks.example.com/x", "events": []string{"message.sent"}},
		{"url": "https://user:pass@hooks.example.com/x", "events": []string{"message.sent"}},
		{"url": "/relative", "events": []string{"message.sent"}},
		{"url": "https://hooks.example.com/x", "events": []string{}},
		{"url": "https://hooks.example.com/x", "events": []string{"message.everything"}},
		{"url": "https://hooks.example.com/x", "events": []string{"message.sent"}, "secret": "short"},
	} {
		admin.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPost, "/api/v1/webhooks", body)
	}
}

const otpTopic = "iam.auth.mfa_email_code_requested"

func otpEvent(email string) map[string]any {
	return map[string]any{"id": harness.NewID(), "type": otpTopic, "source": "iam",
		"data": map[string]any{"email": email, "code": "551177", "purpose": "sign_in", "expires_in_minutes": 5}}
}

var publishOnce sync.Map

// publish gives the tenant a published template for topic, once.
func publish(t *testing.T, topic string) {
	t.Helper()
	if _, done := publishOnce.LoadOrStore(topic, true); done {
		return
	}
	admin := fx.Admin(t)
	id := harness.Str(admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", map[string]any{
		"name": topic, "slug": "t-" + harness.Unique(), "topic": topic, "default_locale": "en"}).Data(), "id")
	d := admin.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/templates/"+id+"/draft", map[string]any{
		"locale": "en", "revision": 0, "subject": "Notice", "html_body": "<p>Notice</p>", "text_body": "Notice"}).Data()
	admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+id+"/publish", map[string]any{"locale": "en", "revision": d["revision"]})
}

func TestTopicAllowList(t *testing.T) {
	publish(t, otpTopic)
	publish(t, "iam.auth.magic_link_requested")
	narrow := fx.Service(t, "e2e-narrow")
	narrow.Expect(t, http.StatusAccepted, http.MethodPost, "/api/v1/events", otpEvent(harness.NewEmail("narrow")))
	other := otpEvent(harness.NewEmail("narrow"))
	other["type"] = "iam.auth.magic_link_requested"
	other["data"] = map[string]any{"email": harness.NewEmail("narrow"), "link": "https://iam.example.com/m/x"}
	narrow.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/events", other)
	harness.Eventually(t, "the refused topic in the audit log", 10*time.Second, func() bool {
		return strings.Contains(fx.Admin(t).Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/audit-logs?limit=100", nil).String(), "topic_not_allowed")
	})
}

func TestEventEnvelopeRules(t *testing.T) {
	publish(t, otpTopic)
	svc := fx.Service(t, "mailos-iam")
	svc.ExpectError(t, http.StatusBadRequest, "", http.MethodPost, "/api/v1/events", []byte("{not json"))
	noEmail := otpEvent("")
	svc.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPost, "/api/v1/events", noEmail)
	unknown := otpEvent(harness.NewEmail("u"))
	unknown["type"] = "iam.no.such.topic"
	if r := svc.Do(t, http.MethodPost, "/api/v1/events", unknown); r.Status == http.StatusAccepted || r.Status >= 500 {
		t.Fatalf("unknown topic = %s", r)
	}
	big := otpEvent(harness.NewEmail("big"))
	big["data"].(map[string]any)["padding"] = strings.Repeat("x", 300<<10)
	svc.Expect(t, http.StatusRequestEntityTooLarge, http.MethodPost, "/api/v1/events", big)

	ev := otpEvent(harness.NewEmail("reuse"))
	svc.Expect(t, http.StatusAccepted, http.MethodPost, "/api/v1/events", ev)
	ev["data"] = map[string]any{"email": harness.NewEmail("reuse"), "code": "999999", "purpose": "sign_in", "expires_in_minutes": 5}
	svc.ExpectError(t, http.StatusConflict, "", http.MethodPost, "/api/v1/events", ev)
}

// A topic the tenant has published no template for is refused (404), so
// IAM sees the failure; nothing is queued and nothing is sent.
func TestEventWithoutPublishedTemplateIsRefused(t *testing.T) {
	box := fx.Env.NewMailbox("notemplate")
	ev := map[string]any{"id": harness.NewID(), "type": "iam.auth.password_reset_requested", "source": "iam",
		"data": map[string]any{"email": box.Address, "reset_link": "https://iam.example.com/r/x", "expires_in_minutes": 30}}
	fx.Service(t, "mailos-iam").ExpectError(t, http.StatusNotFound, "NOT_FOUND", http.MethodPost, "/api/v1/events", ev)
	box.Empty(t, 2*time.Second)
}
