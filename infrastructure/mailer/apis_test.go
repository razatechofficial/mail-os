package mailer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// withIdP points kind's sender and an identity platform at one server.
func (s *apiServer) withIdP(kind provider.Kind, platform string) Options {
	o := s.opts(kind)
	o.BaseURLs[provider.Kind(platform)] = s.URL
	return o
}

func TestMSGraphSendsMIMEAsTheMailbox(t *testing.T) {
	srv := newAPIServer(t)
	tok := fakeJWT(map[string]any{"roles": []string{"Mail.Send"}})
	var mime string
	var tokens int
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tenant-id/oauth2/v2.0/token":
			tokens++
			reply(200, `{"access_token":"`+tok+`","expires_in":3600}`)(w, r)
		case "/v1.0/users/noreply@bank.example/sendMail":
			if r.Header.Get("Authorization") != "Bearer "+tok || r.Header.Get("Content-Type") != "text/plain" {
				t.Errorf("headers %v", r.Header)
			}
			body, _ := io.ReadAll(r.Body)
			raw, _ := base64.StdEncoding.DecodeString(string(body))
			mime = string(raw)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	snd, err := NewMSGraph(provider.Settings{TenantID: "tenant-id", ClientID: "app", AuthMethod: provider.MicrosoftSecret, Sender: "noreply@bank.example"},
		provider.Credentials{ClientSecret: "s"}, srv.withIdP(provider.KindMSGraph, oauthMicrosoft))
	if err != nil {
		t.Fatal(err)
	}
	out := sampleOutgoing()
	res, err := snd.Send(context.Background(), out)
	if err != nil || !strings.HasPrefix(res.ProviderMessageID, out.MessageID+"@") {
		t.Fatalf("%v %v", res, err)
	}
	if !strings.Contains(mime, "Message-ID: <"+out.MessageID) || !strings.Contains(mime, "List-Unsubscribe:") || !strings.Contains(mime, "multipart/alternative") {
		t.Fatalf("mime %s", mime)
	}
	d := Test(context.Background(), provider.KindMSGraph, snd)
	if !d.OK || d.Steps[0].Name != "token" || len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "Send test email") {
		t.Fatalf("%+v", d)
	}
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			reply(200, `{"access_token":"`+tok+`","expires_in":3600}`)(w, r)
			return
		}
		reply(403, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied. Check credentials and try again."}}`)(w, r)
	})
	_, err = snd.Send(context.Background(), out)
	se := sendErr(t, err)
	if se.Reason != message.ReasonAuth || !strings.Contains(Hint(provider.KindMSGraph, "send", se), "Mail.Send") {
		t.Fatalf("%+v", se)
	}
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			reply(200, `{"access_token":"`+tok+`","expires_in":3600}`)(w, r)
			return
		}
		reply(404, `{"error":{"code":"ErrorInvalidUser","message":"The requested user 'noreply@bank.example' is invalid."}}`)(w, r)
	})
	_, err = snd.Send(context.Background(), out)
	if se := sendErr(t, err); se.Reason != message.ReasonConfig {
		t.Fatalf("%+v", se)
	}
}

func TestGmailSendsRawAsTheUser(t *testing.T) {
	cert := newRSACert(t, "sa")
	srv := newAPIServer(t)
	var raw string
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			reply(200, `{"access_token":"g-tok","expires_in":3600}`)(w, r)
		case "/gmail/v1/users/me/messages/send":
			if r.Header.Get("Authorization") != "Bearer g-tok" {
				t.Errorf("auth %q", r.Header.Get("Authorization"))
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			b, _ := base64.URLEncoding.DecodeString(body["raw"])
			raw = string(b)
			reply(200, `{"id":"18c2f","threadId":"18c2f","labelIds":["SENT"]}`)(w, r)
		}
	})
	opts := srv.opts(provider.KindGmail)
	opts.BaseURLs[oauthGoogle] = srv.URL
	snd, err := NewGmail(provider.Settings{Sender: "noreply@bank.example"}, provider.Credentials{ServiceAccountJSON: serviceAccountJSON(t, cert)}, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := sampleOutgoing()
	out.From = message.Address{}
	res, err := snd.Send(context.Background(), out)
	if err != nil || res.ProviderMessageID != "18c2f" || !strings.Contains(raw, "From: <noreply@bank.example>") {
		t.Fatalf("%v %v %s", res, err, raw)
	}
	if d := Test(context.Background(), provider.KindGmail, snd); !d.OK || len(d.Steps) != 1 || !strings.Contains(d.Steps[0].Label, "mailos@bank-proj") {
		t.Fatalf("%+v", d)
	}
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		reply(401, `{"error":"unauthorized_client","error_description":"Client is unauthorized to retrieve access tokens using this method."}`)(w, r)
	})
	d := Test(context.Background(), provider.KindGmail, snd)
	if d.OK || d.Step != "token" || d.ErrorClass != "auth" || !strings.Contains(d.Hint, "domain-wide delegation") {
		t.Fatalf("%+v", d)
	}
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			reply(200, `{"access_token":"g-tok","expires_in":3600}`)(w, r)
			return
		}
		reply(429, `{"error":{"code":429,"message":"User-rate limit exceeded","status":"RESOURCE_EXHAUSTED","errors":[{"reason":"userRateLimitExceeded"}]}}`)(w, r)
	})
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonRateLimited {
		t.Fatalf("%+v", se)
	}
}

func TestACSSignsWithTheAccessKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	srv := newAPIServer(t)
	verify := func(r *http.Request, body []byte) bool {
		sum := sha256.Sum256(body)
		hash := base64.StdEncoding.EncodeToString(sum[:])
		toSign := r.Method + "\n" + r.URL.RequestURI() + "\n" + r.Header.Get("x-ms-date") + ";" + r.Host + ";" + hash
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(toSign))
		want := "HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		return r.Header.Get("x-ms-content-sha256") == hash && r.Header.Get("Authorization") == want
	}
	var got map[string]any
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !verify(r, body) {
			reply(401, `{"error":{"code":"Denied","message":"Denied by the resource provider."}}`)(w, r)
			return
		}
		if r.Method == http.MethodGet {
			reply(404, `{"error":{"code":"NotFound","message":"operation not found"}}`)(w, r)
			return
		}
		if r.URL.Path != "/emails:send" || r.URL.Query().Get("api-version") != acsAPIVersion {
			t.Errorf("%s", r.URL)
		}
		_ = json.Unmarshal(body, &got)
		reply(202, `{"id":"op-1","status":"Running"}`, "Operation-Location", "https://x/emails/operations/op-1")(w, r)
	})
	set := provider.Settings{Endpoint: "https://bank.unitedstates.communication.azure.com"}
	snd, err := NewACS(set, provider.Credentials{AccessKey: base64.StdEncoding.EncodeToString(key)}, srv.opts(provider.KindACS))
	if err != nil {
		t.Fatal(err)
	}
	res, err := snd.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderMessageID != "op-1" || got["senderAddress"] != "security@mail.bank.example" {
		t.Fatalf("%v %v %v", res, err, got)
	}
	if d := Test(context.Background(), provider.KindACS, snd); !d.OK {
		t.Fatalf("%+v", d)
	}
	bad, _ := NewACS(set, provider.Credentials{AccessKey: base64.StdEncoding.EncodeToString([]byte("wrong"))}, srv.opts(provider.KindACS))
	d := Test(context.Background(), provider.KindACS, bad)
	if d.OK || d.ErrorClass != "auth" || !strings.Contains(d.Hint, "Azure") {
		t.Fatalf("%+v", d)
	}
	if _, err := NewACS(provider.Settings{Endpoint: "https://evil.example"}, provider.Credentials{AccessKey: "a2V5"}, Options{}); err == nil {
		t.Fatal("a non-Azure endpoint was accepted")
	}
}

func TestSparkPost(t *testing.T) {
	srv := newAPIServer(t)
	var got map[string]any
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "sp-key" {
			reply(401, `{"errors":[{"message":"Unauthorized."}]}`)(w, r)
			return
		}
		switch r.URL.Path {
		case "/api/v1/transmissions":
			_ = json.NewDecoder(r.Body).Decode(&got)
			reply(200, `{"results":{"total_rejected_recipients":0,"total_accepted_recipients":1,"id":"tx-1"}}`)(w, r)
		case "/api/v1/account":
			reply(403, `{"errors":[{"message":"Forbidden."}]}`)(w, r)
		}
	})
	snd, _ := NewSparkPost(provider.Settings{}, provider.Credentials{APIKey: "sp-key"}, srv.opts(provider.KindSparkPost))
	res, err := snd.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderMessageID != "tx-1" || got["metadata"].(map[string]any)["mailos_message_id"] == nil {
		t.Fatalf("%v %v %v", res, err, got)
	}
	if d := Test(context.Background(), provider.KindSparkPost, snd); !d.OK || len(d.Warnings) != 1 {
		t.Fatalf("a key without Account: Read: %+v", d)
	}
	srv.handle(reply(200, `{"results":{"total_rejected_recipients":1,"total_accepted_recipients":0,"id":"tx-2"}}`))
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonInvalidRecipient {
		t.Fatalf("%+v", se)
	}
	srv.handle(reply(400, `{"errors":[{"message":"Invalid domain","description":"Unconfigured Sending Domain <mail.bank.example>","code":"7001"}]}`))
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonConfig {
		t.Fatalf("%+v", se)
	}
	bad, _ := NewSparkPost(provider.Settings{}, provider.Credentials{APIKey: "nope"}, srv.opts(provider.KindSparkPost))
	srv.handle(reply(401, `{"errors":[{"message":"Unauthorized."}]}`))
	if d := Test(context.Background(), provider.KindSparkPost, bad); d.OK || d.ErrorClass != "auth" {
		t.Fatalf("%+v", d)
	}
}

func TestBrevo(t *testing.T) {
	srv := newAPIServer(t)
	var got brevoRequest
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("api-key") != "xkeysib-1" {
			reply(401, `{"code":"unauthorized","message":"Key not found"}`)(w, r)
			return
		}
		if r.Method == http.MethodGet {
			reply(200, `{"email":"ops@bank.example"}`)(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		reply(201, `{"messageId":"<202611.1@smtp-relay.mailin.fr>"}`)(w, r)
	})
	snd, _ := NewBrevo(provider.Settings{}, provider.Credentials{APIKey: "xkeysib-1"}, srv.opts(provider.KindBrevo))
	res, err := snd.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderMessageID != "202611.1@smtp-relay.mailin.fr" || got.Headers["X-Mailos-Message-Id"] == "" || got.ReplyTo == nil {
		t.Fatalf("%v %v %+v", res, err, got)
	}
	if d := Test(context.Background(), provider.KindBrevo, snd); !d.OK || !strings.Contains(d.Steps[0].Detail, "ops@bank.example") {
		t.Fatalf("%+v", d)
	}
	srv.handle(reply(400, `{"code":"invalid_parameter","message":"email is not valid in to"}`))
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonInvalidRecipient {
		t.Fatalf("%+v", se)
	}
	srv.handle(reply(401, `{"code":"unauthorized","message":"We have detected you are using an unrecognised IP address"}`))
	d := TestSend(context.Background(), provider.KindBrevo, snd, sampleOutgoing())
	if d.OK || d.ErrorClass != "auth" || !strings.Contains(d.Hint, "authorised IPs") {
		t.Fatalf("%+v", d)
	}
}

func TestMailjet(t *testing.T) {
	srv := newAPIServer(t)
	var got map[string][]mjMessage
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "pub" || p != "priv" {
			reply(401, `{"ErrorIdentifier":"x","StatusCode":401,"ErrorMessage":"API key authentication/authorization failure."}`)(w, r)
			return
		}
		if r.Method == http.MethodGet {
			reply(200, `{"Count":1,"Data":[{"ID":1}]}`)(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		reply(200, `{"Messages":[{"Status":"success","To":[{"Email":"zoe@example.com","MessageUUID":"u-1","MessageID":576460753004591401}]}]}`)(w, r)
	})
	snd, _ := NewMailjet(provider.Settings{}, provider.Credentials{APIKey: "pub", APISecret: "priv"}, srv.opts(provider.KindMailjet))
	out := sampleOutgoing()
	res, err := snd.Send(context.Background(), out)
	if err != nil || res.ProviderMessageID != "576460753004591401" || got["Messages"][0].CustomID != out.MessageID {
		t.Fatalf("%v %v %+v", res, err, got)
	}
	if d := Test(context.Background(), provider.KindMailjet, snd); !d.OK {
		t.Fatalf("%+v", d)
	}
	srv.handle(reply(400, `{"Messages":[{"Status":"error","Errors":[{"ErrorCode":"mj-0013","StatusCode":400,"ErrorMessage":"\"zoe@\" is an invalid email address.","ErrorRelatedTo":["To[0].Email"]}]}]}`))
	_, err = snd.Send(context.Background(), out)
	if se := sendErr(t, err); se.Reason != message.ReasonInvalidRecipient || !strings.HasPrefix(se.Detail, "mj-0013") {
		t.Fatalf("%+v", se)
	}
	bad, _ := NewMailjet(provider.Settings{}, provider.Credentials{APIKey: "pub", APISecret: "wrong"}, srv.opts(provider.KindMailjet))
	srv.handle(reply(401, `{"ErrorMessage":"API key authentication/authorization failure."}`))
	if d := Test(context.Background(), provider.KindMailjet, bad); d.OK || d.ErrorClass != "auth" {
		t.Fatalf("%+v", d)
	}
}

func TestMandrill(t *testing.T) {
	srv := newAPIServer(t)
	var got map[string]any
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got["key"] != "md-key" {
			reply(500, `{"status":"error","code":-1,"name":"Invalid_Key","message":"Invalid API key"}`)(w, r)
			return
		}
		switch r.URL.Path {
		case "/api/1.0/users/ping2":
			reply(200, `{"PING":"PONG!"}`)(w, r)
		case "/api/1.0/messages/send":
			reply(200, `[{"email":"zoe@example.com","status":"sent","_id":"md-1"}]`)(w, r)
		}
	})
	snd, _ := NewMandrill(provider.Settings{Subaccount: "otp"}, provider.Credentials{APIKey: "md-key"}, srv.opts(provider.KindMandrill))
	res, err := snd.Send(context.Background(), sampleOutgoing())
	if err != nil || res.ProviderMessageID != "md-1" || got["message"].(map[string]any)["subaccount"] != "otp" {
		t.Fatalf("%v %v %v", res, err, got)
	}
	if d := Test(context.Background(), provider.KindMandrill, snd); !d.OK {
		t.Fatalf("%+v", d)
	}
	srv.handle(reply(200, `[{"email":"zoe@example.com","status":"rejected","reject_reason":"unsigned","_id":"md-2"}]`))
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonConfig {
		t.Fatalf("%+v", se)
	}
	bad, _ := NewMandrill(provider.Settings{}, provider.Credentials{APIKey: "nope"}, srv.opts(provider.KindMandrill))
	srv.handle(reply(500, `{"status":"error","code":-1,"name":"Invalid_Key","message":"Invalid API key"}`))
	d := Test(context.Background(), provider.KindMandrill, bad)
	if d.OK || d.ErrorClass != "auth" || srv.calls.Load() > 6 {
		t.Fatalf("a refused key must not be retried as an outage: %+v (%d calls)", d, srv.calls.Load())
	}
}

func TestResend(t *testing.T) {
	srv := newAPIServer(t)
	var idem string
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer re_1" {
			reply(401, `{"statusCode":401,"name":"invalid_api_key","message":"API key is invalid"}`)(w, r)
			return
		}
		if r.Method == http.MethodGet {
			reply(401, `{"statusCode":401,"name":"restricted_api_key","message":"This API key is restricted to only send emails"}`)(w, r)
			return
		}
		idem = r.Header.Get("Idempotency-Key")
		reply(200, `{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}`)(w, r)
	})
	snd, _ := NewResend(provider.Settings{}, provider.Credentials{APIKey: "re_1"}, srv.opts(provider.KindResend))
	out := sampleOutgoing()
	res, err := snd.Send(context.Background(), out)
	if err != nil || res.ProviderMessageID != "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794" || idem != out.MessageID {
		t.Fatalf("%v %v %q", res, err, idem)
	}
	if d := Test(context.Background(), provider.KindResend, snd); !d.OK || !strings.Contains(d.Steps[0].Detail, "sending-only") {
		t.Fatalf("%+v", d)
	}
	srv.handle(reply(403, `{"statusCode":403,"name":"validation_error","message":"The mail.bank.example domain is not verified. Please, add and verify your domain."}`))
	_, err = snd.Send(context.Background(), out)
	if se := sendErr(t, err); se.Reason != message.ReasonConfig {
		t.Fatalf("%+v", se)
	}
	bad, _ := NewResend(provider.Settings{}, provider.Credentials{APIKey: "re_x"}, srv.opts(provider.KindResend))
	srv.handle(reply(401, `{"statusCode":401,"name":"invalid_api_key","message":"API key is invalid"}`))
	if d := Test(context.Background(), provider.KindResend, bad); d.OK || d.ErrorClass != "auth" {
		t.Fatalf("%+v", d)
	}
}

func TestExistingAPIsCheck(t *testing.T) {
	srv := newAPIServer(t)
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/email/account":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIA") {
				t.Errorf("unsigned")
			}
			reply(200, `{"SendingEnabled":true,"ProductionAccessEnabled":false,"SendQuota":{"Max24HourSend":200}}`)(w, r)
		case "/v3/scopes":
			reply(200, `{"scopes":["user.profile.read"]}`)(w, r)
		case "/v3/domains/mg.bank.example":
			reply(200, `{"domain":{"name":"mg.bank.example","state":"unverified"}}`)(w, r)
		case "/server":
			reply(200, `{"ID":1,"Name":"Bank OTP"}`)(w, r)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	ses, _ := NewSES(provider.Settings{Region: "eu-west-1"}, provider.Credentials{AccessKeyID: "AKIA1", SecretAccessKey: "s"}, srv.opts(provider.KindSES))
	if d := Test(context.Background(), provider.KindSES, ses); !d.OK || len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "sandbox") {
		t.Fatalf("ses %+v", d)
	}
	sg, _ := NewSendGrid(provider.Settings{}, provider.Credentials{APIKey: "SG.k"}, srv.opts(provider.KindSendGrid))
	if d := Test(context.Background(), provider.KindSendGrid, sg); d.OK || d.ErrorClass != "auth" || !strings.Contains(d.Detail, "Mail Send") {
		t.Fatalf("sendgrid without mail.send %+v", d)
	}
	mg, _ := NewMailgun(provider.Settings{Domain: "mg.bank.example"}, provider.Credentials{APIKey: "k"}, srv.opts(provider.KindMailgun))
	if d := Test(context.Background(), provider.KindMailgun, mg); !d.OK || len(d.Warnings) != 1 {
		t.Fatalf("mailgun %+v", d)
	}
	pm, _ := NewPostmark(provider.Settings{}, provider.Credentials{ServerToken: "t"}, srv.opts(provider.KindPostmark))
	if d := Test(context.Background(), provider.KindPostmark, pm); !d.OK || !strings.Contains(d.Steps[0].Detail, "Bank OTP") {
		t.Fatalf("postmark %+v", d)
	}
	srv.handle(reply(403, `{"__type":"AccessDeniedException","message":"not authorized to perform ses:GetAccount"}`))
	if d := Test(context.Background(), provider.KindSES, ses); !d.OK || len(d.Warnings) != 1 {
		t.Fatalf("ses without GetAccount %+v", d)
	}
	srv.handle(reply(403, `{"__type":"UnrecognizedClientException","message":"The security token included in the request is invalid."}`))
	if d := Test(context.Background(), provider.KindSES, ses); d.OK || d.ErrorClass != "auth" {
		t.Fatalf("ses bad key %+v", d)
	}
}

func TestNewBuildsNewKinds(t *testing.T) {
	cert := newRSACert(t, "x")
	opts := Options{}
	cases := []Configured{
		{provider.Provider{Kind: provider.KindMSGraph, Settings: provider.Settings{TenantID: "t", ClientID: "c", Sender: "a@b.example",
			AuthMethod: provider.MicrosoftCertificate, ClientCertificate: cert.certPEM}}, provider.Credentials{CertificateKey: cert.keyPEM}},
		{provider.Provider{Kind: provider.KindGmail, Settings: provider.Settings{Sender: "a@b.example"}}, provider.Credentials{ServiceAccountJSON: serviceAccountJSON(t, cert)}},
		{provider.Provider{Kind: provider.KindACS, Settings: provider.Settings{Endpoint: "https://r.communication.azure.com"}}, provider.Credentials{AccessKey: "a2V5"}},
		{provider.Provider{Kind: provider.KindSparkPost, Settings: provider.Settings{Region: provider.RegionEU}}, provider.Credentials{APIKey: "k"}},
		{provider.Provider{Kind: provider.KindBrevo}, provider.Credentials{APIKey: "k"}},
		{provider.Provider{Kind: provider.KindMailjet}, provider.Credentials{APIKey: "k", APISecret: "s"}},
		{provider.Provider{Kind: provider.KindMandrill}, provider.Credentials{APIKey: "k"}},
		{provider.Provider{Kind: provider.KindResend}, provider.Credentials{APIKey: "k"}},
		{provider.Provider{Kind: provider.KindSMTP, Settings: provider.Settings{Host: "smtp.gmail.com", Port: 587, AuthMechanism: provider.AuthXOAUTH2,
			OAuthProvider: provider.OAuthGoogle, Username: "a@b.example"}}, provider.Credentials{ServiceAccountJSON: serviceAccountJSON(t, cert)}},
	}
	for _, c := range cases {
		if s, err := New(c.Provider, c.Credentials, opts); err != nil || s == nil {
			t.Errorf("%s: %v", c.Provider.Kind, err)
		}
	}
	if _, err := New(provider.Provider{Kind: provider.KindMSGraph, Settings: provider.Settings{TenantID: "t", ClientID: "c", Sender: "a@b.example"}},
		provider.Credentials{}, opts); err == nil {
		t.Fatal("Graph without a secret built")
	}
}
