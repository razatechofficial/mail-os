package providerhooks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SNS SignatureVersion 1
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

const msgID = "0193a000-0000-7000-8000-000000000001"

func verifier(certs Certificates) *Verifier {
	return &Verifier{Certs: certs, Now: func() time.Time { return now }}
}

func basic(password string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("mailos:"+password)))
	return h
}

func mustUnauthenticated(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

// one returns the only event of a parse.
func one(t *testing.T) func(Result, error) message.ProviderEvent {
	return func(res Result, err error) message.ProviderEvent {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Events) != 1 {
			t.Fatalf("events = %+v, want one", res.Events)
		}
		return res.Events[0]
	}
}

// --- SES through SNS ---

type fakeCerts struct {
	pem  []byte
	urls []string
}

func (f *fakeCerts) Certificate(_ context.Context, u string) ([]byte, error) {
	f.urls = append(f.urls, u)
	return f.pem, nil
}

func snsKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sns.amazonaws.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func signSNS(t *testing.T, key *rsa.PrivateKey, m snsMessage) []byte {
	t.Helper()
	var sig []byte
	var err error
	if m.SignatureVersion == "1" {
		d := sha1.Sum([]byte(m.stringToSign())) //nolint:gosec // SNS SignatureVersion 1
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, d[:])
	} else {
		d := sha256.Sum256([]byte(m.stringToSign()))
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	raw, _ := json.Marshal(m)
	return raw
}

func sesNotification(event string, version string, at time.Time) snsMessage {
	return snsMessage{Type: snsNotification, MessageID: "sns-1", TopicArn: "arn:aws:sns:eu-west-1:123:ses", Message: event,
		Timestamp: at.Format(time.RFC3339Nano), SignatureVersion: version,
		SigningCertURL: "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-abc.pem"}
}

const sesBounce = `{"eventType":"Bounce","mail":{"messageId":"ses-mid","tags":{"mailos_message_id":["` + msgID + `"]}},
"bounce":{"bounceType":"Permanent","bounceSubType":"General","timestamp":"2026-11-20T11:59:00Z",
"bouncedRecipients":[{"emailAddress":"Gone@Example.com","diagnosticCode":"smtp; 550 5.1.1 user unknown"}]}}`

func TestSESThroughSNS(t *testing.T) {
	key, certPEM := snsKey(t)
	certs := &fakeCerts{pem: certPEM}
	v := verifier(certs)
	for _, version := range []string{"1", "2"} {
		body := signSNS(t, key, sesNotification(sesBounce, version, now))
		ev := one(t)(v.ses(context.Background(), "pw", Request{Header: basic("pw"), Body: body}))
		if ev.Type != message.EventBounced || ev.MessageID != msgID || ev.ProviderMessageID != "ses-mid" ||
			ev.Recipient != "Gone@Example.com" || ev.ProviderEventID == "" {
			t.Fatalf("v%s: %+v", version, ev)
		}
	}
	if certs.urls[0] != "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-abc.pem" {
		t.Fatalf("fetched %v", certs.urls)
	}

	good := sesNotification(sesBounce, "2", now)
	body := signSNS(t, key, good)
	// Wrong password.
	_, err := v.Parse(context.Background(), provider.KindSES, "pw", Request{Header: basic("nope"), Body: body})
	mustUnauthenticated(t, err)
	// Tampered message.
	var tampered snsMessage
	_ = json.Unmarshal(body, &tampered)
	tampered.Message = `{"eventType":"Delivery"}`
	raw, _ := json.Marshal(tampered)
	_, err = v.Parse(context.Background(), provider.KindSES, "pw", Request{Header: basic("pw"), Body: raw})
	mustUnauthenticated(t, err)
	// Stale.
	_, err = v.Parse(context.Background(), provider.KindSES, "pw",
		Request{Header: basic("pw"), Body: signSNS(t, key, sesNotification(sesBounce, "2", now.Add(-2*time.Hour)))})
	mustUnauthenticated(t, err)
	// A certificate off SNS's hosts is never fetched.
	evil := good
	evil.SigningCertURL = "https://sns.eu-west-1.amazonaws.com.evil.example/cert.pem"
	n := len(certs.urls)
	_, err = v.Parse(context.Background(), provider.KindSES, "pw", Request{Header: basic("pw"), Body: signSNS(t, key, evil)})
	mustUnauthenticated(t, err)
	if len(certs.urls) != n {
		t.Fatal("fetched a certificate from a non-SNS host")
	}
	// Signed by another key.
	other, _ := snsKey(t)
	_, err = v.Parse(context.Background(), provider.KindSES, "pw", Request{Header: basic("pw"), Body: signSNS(t, other, good)})
	mustUnauthenticated(t, err)
}

func TestSNSSubscriptionConfirmation(t *testing.T) {
	key, certPEM := snsKey(t)
	v := verifier(&fakeCerts{pem: certPEM})
	m := snsMessage{Type: snsSubscription, MessageID: "m", Token: "tok", TopicArn: "arn:aws:sns:eu-west-1:1:t", Message: "confirm",
		SubscribeURL: "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription&Token=tok",
		Timestamp:    now.Format(time.RFC3339), SignatureVersion: "2",
		SigningCertURL: "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-abc.pem"}
	res, err := v.Parse(context.Background(), provider.KindSES, "pw", Request{Header: basic("pw"), Body: signSNS(t, key, m)})
	if err != nil || res.SubscribeURL != m.SubscribeURL || len(res.Events) != 0 {
		t.Fatalf("res %+v err %v", res, err)
	}
	m.SubscribeURL = "https://attacker.example/confirm"
	_, err = v.Parse(context.Background(), provider.KindSES, "pw", Request{Header: basic("pw"), Body: signSNS(t, key, m)})
	mustUnauthenticated(t, err)
}

func TestSESEventMapping(t *testing.T) {
	cases := map[string]message.EventType{
		`{"eventType":"Delivery","mail":{"messageId":"x"},"delivery":{"timestamp":"2026-11-20T11:00:00Z","recipients":["a@x.example"]}}`:           message.EventDelivered,
		`{"notificationType":"Complaint","mail":{"messageId":"x"},"complaint":{"complainedRecipients":[{"emailAddress":"a@x.example"}]}}`:          message.EventComplained,
		`{"eventType":"Bounce","mail":{"messageId":"x"},"bounce":{"bounceType":"Transient","bouncedRecipients":[{"emailAddress":"a@x.example"}]}}`: message.EventSoftBounced,
		`{"eventType":"DeliveryDelay","mail":{"messageId":"x"},"deliveryDelay":{"delayedRecipients":[{"emailAddress":"a@x.example"}]}}`:            message.EventDeferred,
	}
	for raw, want := range cases {
		got, err := sesEvents([]byte(raw))
		if err != nil || len(got) != 1 || got[0].Type != want {
			t.Fatalf("%s: %+v %v", raw, got, err)
		}
	}
	if got, _ := sesEvents([]byte(`{"eventType":"Open","mail":{"messageId":"x"}}`)); len(got) != 0 {
		t.Fatal("opens are ignored")
	}
}

func TestSNSURLAllowed(t *testing.T) {
	for u, ok := range map[string]bool{
		"https://sns.us-east-1.amazonaws.com/x.pem":        true,
		"https://sns.cn-north-1.amazonaws.com.cn/x.pem":    true,
		"http://sns.us-east-1.amazonaws.com/x.pem":         false,
		"https://sns.us-east-1.amazonaws.com:8443/x":       false,
		"https://evil.example/sns.us-east-1.amazonaws.com": false,
		"https://user@sns.us-east-1.amazonaws.com/x.pem":   false,
	} {
		if SNSURLAllowed(u) != ok {
			t.Errorf("%s: want %v", u, ok)
		}
	}
}

// --- SendGrid ---

func sendGridSigned(t *testing.T, key *ecdsa.PrivateKey, ts string, body []byte) http.Header {
	t.Helper()
	d := sha256.Sum256(append([]byte(ts), body...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set(HeaderSendGridSignature, base64.StdEncoding.EncodeToString(sig))
	h.Set(HeaderSendGridTimestamp, ts)
	return h
}

func TestSendGrid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	secret := base64.StdEncoding.EncodeToString(der)
	body := []byte(`[{"event":"delivered","email":"a@x.example","timestamp":1795694400,"sg_event_id":"e1",
"sg_message_id":"XMID.filterdrecv-1","mailos_message_id":"` + msgID + `"},
{"event":"bounce","type":"bounce","email":"b@x.example","sg_event_id":"e2","sg_message_id":"XMID.f","reason":"550 unknown"},
{"event":"bounce","type":"blocked","email":"c@x.example","sg_event_id":"e3","sg_message_id":"XMID.f"},
{"event":"spamreport","email":"d@x.example","sg_event_id":"e4","sg_message_id":"XMID.f"},
{"event":"open","email":"a@x.example","sg_event_id":"e5"}]`)
	ts := strconv.FormatInt(now.Unix(), 10)
	v := verifier(nil)
	res, err := v.Parse(context.Background(), provider.KindSendGrid, secret, Request{Header: sendGridSigned(t, key, ts, body), Body: body})
	if err != nil {
		t.Fatal(err)
	}
	want := []message.EventType{message.EventDelivered, message.EventBounced, message.EventSoftBounced, message.EventComplained}
	if len(res.Events) != len(want) {
		t.Fatalf("events %+v", res.Events)
	}
	for i, w := range want {
		if res.Events[i].Type != w || res.Events[i].ProviderMessageID != "XMID" {
			t.Fatalf("event %d: %+v", i, res.Events[i])
		}
	}
	if res.Events[0].MessageID != msgID || res.Events[0].ProviderEventID != "e1" {
		t.Fatalf("first %+v", res.Events[0])
	}

	tampered := append([]byte{}, body...)
	tampered[10] = 'X'
	_, err = v.Parse(context.Background(), provider.KindSendGrid, secret, Request{Header: sendGridSigned(t, key, ts, body), Body: tampered})
	mustUnauthenticated(t, err)
	stale := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	_, err = v.Parse(context.Background(), provider.KindSendGrid, secret, Request{Header: sendGridSigned(t, key, stale, body), Body: body})
	mustUnauthenticated(t, err)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = v.Parse(context.Background(), provider.KindSendGrid, secret, Request{Header: sendGridSigned(t, other, ts, body), Body: body})
	mustUnauthenticated(t, err)
}

// --- Mailgun ---

func mailgunBodyFor(key, ts, token string, event string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(ts + token))
	return []byte(fmt.Sprintf(`{"signature":{"timestamp":%q,"token":%q,"signature":%q},"event-data":%s}`,
		ts, token, hex.EncodeToString(mac.Sum(nil)), event))
}

func TestMailgun(t *testing.T) {
	ts := strconv.FormatInt(now.Unix(), 10)
	event := `{"id":"ev1","event":"failed","severity":"permanent","recipient":"a@x.example","timestamp":1795694400.5,
"message":{"headers":{"message-id":"2026.abc@mg.example"}},"user-variables":{"mailos_message_id":"` + msgID + `"},
"delivery-status":{"code":550,"message":"5.1.1 unknown","description":""}}`
	v := verifier(nil)
	ev := one(t)(v.Parse(context.Background(), provider.KindMailgun, "signing-key", Request{Body: mailgunBodyFor("signing-key", ts, "tok", event)}))
	if ev.Type != message.EventBounced || ev.MessageID != msgID || ev.ProviderMessageID != "2026.abc@mg.example" || ev.ProviderEventID != "ev1" {
		t.Fatalf("%+v", ev)
	}
	_, err := v.Parse(context.Background(), provider.KindMailgun, "signing-key", Request{Body: mailgunBodyFor("wrong-key", ts, "tok", event)})
	mustUnauthenticated(t, err)
	stale := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	_, err = v.Parse(context.Background(), provider.KindMailgun, "signing-key", Request{Body: mailgunBodyFor("signing-key", stale, "tok", event)})
	mustUnauthenticated(t, err)
	soft := `{"event":"failed","severity":"temporary","recipient":"a@x.example"}`
	ev = one(t)(v.Parse(context.Background(), provider.KindMailgun, "signing-key", Request{Body: mailgunBodyFor("signing-key", ts, "t2", soft)}))
	if ev.Type != message.EventSoftBounced {
		t.Fatalf("%+v", ev)
	}
}

// --- Resend (Svix) ---

func TestResend(t *testing.T) {
	secret := "whsec_" + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	body := []byte(`{"type":"email.bounced","created_at":"2026-11-20T11:59:59Z","data":{"email_id":"re-1","to":["a@x.example"],
"tags":{"mailos_message_id":"` + msgID + `"},"bounce":{"type":"Permanent","subType":"General","message":"no such user"}}}`)
	ts := strconv.FormatInt(now.Unix(), 10)
	sig, _ := SvixSign(secret, "msg_1", ts, body)
	h := http.Header{}
	h.Set(HeaderSvixID, "msg_1")
	h.Set(HeaderSvixTimestamp, ts)
	h.Set(HeaderSvixSignature, "v1,bogus v1,"+sig)
	v := verifier(nil)
	ev := one(t)(v.Parse(context.Background(), provider.KindResend, secret, Request{Header: h, Body: body}))
	if ev.Type != message.EventBounced || ev.MessageID != msgID || ev.ProviderMessageID != "re-1" {
		t.Fatalf("%+v", ev)
	}
	_, err := v.Parse(context.Background(), provider.KindResend, secret, Request{Header: h, Body: append(body, ' ')})
	mustUnauthenticated(t, err)
	stale := h.Clone()
	old := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	oldSig, _ := SvixSign(secret, "msg_1", old, body)
	stale.Set(HeaderSvixTimestamp, old)
	stale.Set(HeaderSvixSignature, "v1,"+oldSig)
	_, err = v.Parse(context.Background(), provider.KindResend, secret, Request{Header: stale, Body: body})
	mustUnauthenticated(t, err)

	list := []byte(`{"type":"email.delivered","data":{"email_id":"re-2","to":["a@x.example"],"tags":[{"name":"mailos_message_id","value":"` + msgID + `"}]}}`)
	sig, _ = SvixSign(secret, "msg_2", ts, list)
	h.Set(HeaderSvixID, "msg_2")
	h.Set(HeaderSvixSignature, "v1,"+sig)
	ev = one(t)(v.Parse(context.Background(), provider.KindResend, secret, Request{Header: h, Body: list}))
	if ev.Type != message.EventDelivered || ev.MessageID != msgID || !ev.OccurredAt.Equal(now) {
		t.Fatalf("%+v", ev)
	}
}

// --- Providers authenticated by the URL's password ---

func TestBasicAuthProviders(t *testing.T) {
	cases := []struct {
		kind provider.Kind
		body string
		want message.EventType
		mid  string
		pmid string
	}{
		{provider.KindPostmark, `{"RecordType":"Bounce","ID":42,"Type":"HardBounce","MessageID":"pm-1","Email":"a@x.example",
"BouncedAt":"2026-11-20T11:00:00Z","Metadata":{"mailos_message_id":"` + msgID + `"}}`, message.EventBounced, msgID, "pm-1"},
		{provider.KindPostmark, `{"RecordType":"Delivery","MessageID":"pm-2","Recipient":"a@x.example"}`, message.EventDelivered, "", "pm-2"},
		{provider.KindPostmark, `{"RecordType":"SpamComplaint","ID":7,"Type":"SpamComplaint","MessageID":"pm-3","Email":"a@x.example"}`, message.EventComplained, "", "pm-3"},
		{provider.KindSparkPost, `[{"msys":{"message_event":{"type":"bounce","bounce_class":"10","transmission_id":"sp-1","rcpt_to":"a@x.example",
"event_id":"e1","timestamp":"1795694400","rcpt_meta":{"mailos_message_id":"` + msgID + `"}}}}]`, message.EventBounced, msgID, "sp-1"},
		{provider.KindSparkPost, `[{"msys":{"message_event":{"type":"bounce","bounce_class":"21","transmission_id":"sp-2","rcpt_to":"a@x.example"}}}]`, message.EventSoftBounced, "", "sp-2"},
		{provider.KindBrevo, `{"event":"hard_bounce","email":"a@x.example","message-id":"<br-1@smtp-relay>","ts_event":1795694400,"reason":"unknown"}`, message.EventBounced, "", "br-1@smtp-relay"},
		{provider.KindBrevo, `{"event":"spam","email":"a@x.example","message-id":"<br-2@smtp-relay>"}`, message.EventComplained, "", "br-2@smtp-relay"},
		{provider.KindMailjet, `{"event":"bounce","hard_bounce":true,"email":"a@x.example","MessageID":19421777835146490,"CustomID":"` + msgID + `","time":1795694400}`, message.EventBounced, msgID, "19421777835146490"},
		{provider.KindMailjet, `[{"event":"sent","email":"a@x.example","MessageID":1},{"event":"open","email":"a@x.example","MessageID":1}]`, message.EventDelivered, "", "1"},
	}
	v := verifier(nil)
	for _, c := range cases {
		ev := one(t)(v.Parse(context.Background(), c.kind, "pw", Request{Header: basic("pw"), Body: []byte(c.body)}))
		if ev.Type != c.want || ev.MessageID != c.mid || ev.ProviderMessageID != c.pmid || ev.Recipient != "a@x.example" || ev.OccurredAt.IsZero() {
			t.Fatalf("%s %s: %+v", c.kind, c.body, ev)
		}
		_, err := v.Parse(context.Background(), c.kind, "pw", Request{Header: basic("wrong"), Body: []byte(c.body)})
		mustUnauthenticated(t, err)
		_, err = v.Parse(context.Background(), c.kind, "pw", Request{Header: http.Header{}, Body: []byte(c.body)})
		mustUnauthenticated(t, err)
	}
	// Brevo may send the password as a bearer token; the others may not.
	bearer := http.Header{}
	bearer.Set("Authorization", "Bearer pw")
	if _, err := v.Parse(context.Background(), provider.KindBrevo, "pw", Request{Header: bearer, Body: []byte(`{"event":"delivered"}`)}); err != nil {
		t.Fatal(err)
	}
	_, err := v.Parse(context.Background(), provider.KindPostmark, "pw", Request{Header: bearer, Body: []byte(`{}`)})
	mustUnauthenticated(t, err)
}

func TestParseRefusesUnconfigured(t *testing.T) {
	v := verifier(nil)
	if _, err := v.Parse(context.Background(), provider.KindPostmark, " ", Request{Header: basic("")}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.Parse(context.Background(), provider.KindSMTP, "pw", Request{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
}
