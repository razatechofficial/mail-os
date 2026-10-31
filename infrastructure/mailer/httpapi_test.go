package mailer

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// apiServer is an httptest TLS server whose handler the test sets.
type apiServer struct {
	*httptest.Server
	calls   atomic.Int32
	handler atomic.Value // http.HandlerFunc
}

func newAPIServer(t *testing.T) *apiServer {
	t.Helper()
	s := &apiServer{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		s.handler.Load().(http.HandlerFunc)(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *apiServer) handle(h http.HandlerFunc) { s.handler.Store(h) }

func (s *apiServer) opts(kind provider.Kind) Options {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return Options{RootCAs: pool, BaseURLs: map[provider.Kind]string{kind: s.URL}, BackoffBase: time.Millisecond, Timeout: 5 * time.Second}
}

func reply(status int, body string, headers ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestSendGrid(t *testing.T) {
	srv := newAPIServer(t)
	var got map[string]any
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/mail/send" || r.Header.Get("Authorization") != "Bearer SG.key" {
			t.Errorf("%s %s", r.URL.Path, r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("X-Message-Id", "sg-123")
		w.WriteHeader(http.StatusAccepted)
	})
	snd, err := NewSendGrid(provider.Settings{}, provider.Credentials{APIKey: "SG.key"}, srv.opts(provider.KindSendGrid))
	if err != nil {
		t.Fatal(err)
	}
	res, err := snd.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderMessageID != "sg-123" {
		t.Fatalf("%v %v", res, err)
	}
	content := got["content"].([]any)
	if content[0].(map[string]any)["type"] != "text/plain" || got["custom_args"].(map[string]any)["mailos_message_id"] == nil {
		t.Fatalf("payload %v", got)
	}

	srv.handle(reply(400, `{"errors":[{"message":"Does not contain a valid address.","field":"personalizations.0.to.0.email"}]}`))
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonInvalidRecipient {
		t.Fatalf("%v", err)
	}
	srv.handle(reply(401, `{"errors":[{"message":"The provided authorization grant is invalid"}]}`))
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonAuth || !se.Permanent() || strings.Contains(se.Error(), "SG.key") {
		t.Fatalf("%v", err)
	}
}

func TestMailgun(t *testing.T) {
	srv := newAPIServer(t)
	var form url.Values
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if r.URL.Path != "/v3/mg.bank.example/messages" || user != "api" || pass != "key-1" {
			t.Errorf("%s %s:%s", r.URL.Path, user, pass)
		}
		_ = r.ParseForm()
		form = r.PostForm
		reply(200, `{"id":"<20261031.1@mg.bank.example>","message":"Queued. Thank you."}`)(w, r)
	})
	snd, err := NewMailgun(provider.Settings{Domain: "mg.bank.example"}, provider.Credentials{APIKey: "key-1"}, srv.opts(provider.KindMailgun))
	if err != nil {
		t.Fatal(err)
	}
	out := sampleOutgoing()
	out.Tags = []string{"a", "b", "c", "d"}
	res, err := snd.Send(context.Background(), out)
	if err != nil || res.ProviderMessageID != "20261031.1@mg.bank.example" {
		t.Fatalf("%v %v", res, err)
	}
	if len(form["o:tag"]) != 3 || form.Get("v:mailos_message_id") != out.MessageID || form.Get("h:List-Unsubscribe") == "" || form.Get("h:Reply-To") == "" {
		t.Fatalf("form %v", form)
	}
	srv.handle(reply(404, `{"message":"Domain not found: mg.bank.example"}`))
	_, err = snd.Send(context.Background(), out)
	if se := sendErr(t, err); se.Reason != message.ReasonConfig {
		t.Fatalf("%v", err)
	}
}

func TestPostmark(t *testing.T) {
	srv := newAPIServer(t)
	var got pmRequest
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/email" || r.Header.Get("X-Postmark-Server-Token") != "pm-token" {
			t.Errorf("%s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		reply(200, `{"ErrorCode":0,"Message":"OK","MessageID":"pm-1"}`)(w, r)
	})
	snd, _ := NewPostmark(provider.Settings{MessageStream: "otp"}, provider.Credentials{ServerToken: "pm-token"}, srv.opts(provider.KindPostmark))
	res, err := snd.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderMessageID != "pm-1" || got.MessageStream != "otp" || got.Tag != "otp" || got.Metadata["mailos_message_id"] == "" {
		t.Fatalf("%v %v %+v", res, err, got)
	}
	for _, c := range []struct {
		status int
		body   string
		want   message.Reason
	}{
		{422, `{"ErrorCode":406,"Message":"You tried to send to recipient(s) that have been marked as inactive."}`, message.ReasonInvalidRecipient},
		{401, `{"ErrorCode":10,"Message":"Bad or missing Server API token."}`, message.ReasonAuth},
		{422, `{"ErrorCode":400,"Message":"The 'From' address you supplied is not a Sender Signature."}`, message.ReasonConfig},
		{500, `{}`, message.ReasonUnavailable},
	} {
		srv.handle(reply(c.status, c.body))
		_, err := snd.Send(context.Background(), sampleOutgoing())
		if se := sendErr(t, err); se.Reason != c.want {
			t.Errorf("%d %s: %v", c.status, c.body, err)
		}
	}
}

func TestSESSignsAndClassifies(t *testing.T) {
	srv := newAPIServer(t)
	var got sesRequest
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		date := time.Now().UTC().Format("20060102")
		if r.URL.Path != "/v2/email/outbound-emails" || !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIATEST/"+date+"/eu-west-1/ses/aws4_request") ||
			!strings.Contains(auth, "SignedHeaders=") || r.Header.Get("X-Amz-Date") == "" {
			t.Errorf("path %s auth %q", r.URL.Path, auth)
		}
		if strings.Contains(auth, "secret-key") {
			t.Error("secret sent")
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		reply(200, `{"MessageId":"010001-ses"}`)(w, r)
	})
	creds := provider.Credentials{AccessKeyID: "AKIATEST", SecretAccessKey: "secret-key"}
	snd, err := NewSES(provider.Settings{Region: "eu-west-1", ConfigurationSet: "events"}, creds, srv.opts(provider.KindSES))
	if err != nil {
		t.Fatal(err)
	}
	res, err := snd.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderMessageID != "010001-ses" {
		t.Fatalf("%v %v", res, err)
	}
	if got.ConfigurationSetName != "events" || got.Content.Simple.Body.HTML == nil || len(got.Content.Simple.Headers) != 2 || got.EmailTags[0].Name != "mailos_message_id" {
		t.Fatalf("payload %+v", got)
	}
	for _, c := range []struct {
		status  int
		body    string
		errType string
		want    message.Reason
	}{
		{400, `{"message":"Email address is not verified."}`, "MessageRejected", message.ReasonConfig},
		{400, `{"message":"Message rejected"}`, "MessageRejected:http://internal.amazon.com/", message.ReasonRejected},
		{403, `{"message":"The security token included in the request is invalid."}`, "UnrecognizedClientException", message.ReasonAuth},
		{429, `{"message":"Maximum sending rate exceeded."}`, "TooManyRequestsException", message.ReasonRateLimited},
	} {
		srv.handle(reply(c.status, c.body, "X-Amzn-ErrorType", c.errType, "Retry-After", "60"))
		_, err := snd.Send(context.Background(), sampleOutgoing())
		if se := sendErr(t, err); se.Reason != c.want {
			t.Errorf("%s: %v", c.errType, err)
		}
	}
}

func TestHTTPRetriesOnlyWhenNotTaken(t *testing.T) {
	srv := newAPIServer(t)
	opts := srv.opts(provider.KindPostmark)
	opts.Attempts = 3
	snd, _ := NewPostmark(provider.Settings{}, provider.Credentials{ServerToken: "t"}, opts)

	// 503 then success: retried in place.
	var n atomic.Int32
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			reply(503, `{}`, "Retry-After", "0")(w, r)
			return
		}
		reply(200, `{"ErrorCode":0,"MessageID":"pm-2"}`)(w, r)
	})
	if res, err := snd.Send(context.Background(), sampleOutgoing()); err != nil || res.ProviderMessageID != "pm-2" {
		t.Fatalf("%v %v", res, err)
	}

	// 500 may have been taken: returned to the queue, not retried.
	srv.calls.Store(0)
	srv.handle(reply(500, `{}`))
	_, err := snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonUnavailable || se.Permanent() || srv.calls.Load() != 1 {
		t.Fatalf("%v after %d calls", err, srv.calls.Load())
	}

	// A long Retry-After is handed to the queue instead of waited out.
	srv.calls.Store(0)
	srv.handle(reply(429, `{}`, "Retry-After", "120"))
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if message.RetryAfterOf(err) != 120*time.Second || srv.calls.Load() != 1 {
		t.Fatalf("%v after %d calls", err, srv.calls.Load())
	}
}

func TestHTTPRefusesRedirectsAndUntrustedTLS(t *testing.T) {
	srv := newAPIServer(t)
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://attacker.example/steal", http.StatusTemporaryRedirect)
	})
	snd, _ := NewSendGrid(provider.Settings{}, provider.Credentials{APIKey: "k"}, srv.opts(provider.KindSendGrid))
	_, err := snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonConfig || srv.calls.Load() != 1 {
		t.Fatalf("redirect followed or misclassified: %v", err)
	}

	opts := srv.opts(provider.KindSendGrid)
	opts.RootCAs = x509.NewCertPool() // trusts nothing
	snd, _ = NewSendGrid(provider.Settings{}, provider.Credentials{APIKey: "k"}, opts)
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonConfig || !se.Permanent() {
		t.Fatalf("%v", err)
	}
}

func TestHTTPRefusesPlaintextBaseURL(t *testing.T) {
	opts := Options{BaseURLs: map[provider.Kind]string{provider.KindPostmark: "http://127.0.0.1:1"}}
	if _, err := NewPostmark(provider.Settings{}, provider.Credentials{ServerToken: "t"}, opts); err == nil {
		t.Fatal("http:// accepted")
	}
	opts.AllowPlaintext = true
	if _, err := NewPostmark(provider.Settings{}, provider.Credentials{ServerToken: "t"}, opts); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPInvalidMessageNeverSent(t *testing.T) {
	srv := newAPIServer(t)
	srv.handle(reply(200, `{}`))
	snd, _ := NewSendGrid(provider.Settings{}, provider.Credentials{APIKey: "k"}, srv.opts(provider.KindSendGrid))
	out := sampleOutgoing()
	out.Headers = map[string]string{"Bcc": "x@evil.example"}
	_, err := snd.Send(context.Background(), out)
	if se := sendErr(t, err); se.Reason != message.ReasonInvalid || se.Provider != "sendgrid" || srv.calls.Load() != 0 {
		t.Fatalf("%v", err)
	}
}
