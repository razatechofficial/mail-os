package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/application/applications"
	"github.com/razatechofficial/mail-os/application/applications/appstest"
	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/application/smtpcred"
	"github.com/razatechofficial/mail-os/config"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/smtpcredential"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	"github.com/razatechofficial/mail-os/internal/testutil/tlstest"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

const tenant = "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"

func TestMain(m *testing.M) {
	_ = logger.InitSimple("fatal", "console")
	os.Exit(m.Run())
}

// harness is a running listener over the real application registry,
// credential and message use cases, with in-memory storage, IAM faked
// and the provider recorded.
type harness struct {
	t        *testing.T
	srv      *Server
	addr     string
	implicit string
	ca       *x509.CertPool
	iam      *fakeiam.IAM
	app      domainapp.Application
	apps     *applications.Service
	appRepo  *appstest.Repo
	creds    *smtpcred.Service
	msgs     *memMessages
	messages *appmsg.Service
	sender   *sender
	audit    *auditLog
}

func legacyApp() domainapp.Application {
	now := time.Now().UTC()
	return domainapp.Application{ID: id.New(), TenantID: tenant, Name: "Core banking", Kind: domainapp.KindServer,
		ClientID: "core-banking", Status: domainapp.StatusActive, Environment: domainapp.EnvLive,
		Stream: domainapp.StreamTransactional, MessageTypes: []string{domainapp.RawType},
		Senders: []string{"*@alerts.bank.example"}, RatePerMinute: 100, DailyQuota: 1000, SMTPPasswordAuth: true,
		CreatedAt: now, UpdatedAt: now}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newHarness(t *testing.T, mutate func(*config.SMTPSubmission, *domainapp.Application)) *harness {
	t.Helper()
	pki := tlstest.New(t)
	iam, iamSrv := fakeiam.NewServer(t)
	h := &harness{t: t, iam: iam, app: legacyApp(), msgs: &memMessages{msgs: map[string]domainmsg.Message{}},
		sender: &sender{}, audit: &auditLog{}}
	cfg := config.SMTPSubmission{Enabled: true, Host: "127.0.0.1", Port: 0, Hostname: "localhost",
		CertFile: pki.ServerCert, KeyFile: pki.ServerKey, MinTLSVersion: "1.2", PasswordAuth: true,
		MaxMessageBytes: 1 << 20, MaxRecipients: 5, MaxConnections: 20, MaxConnectionsPerIP: 10,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxSessionDuration: time.Minute,
		AuthFailuresPerIP: 10, AuthFailureWindow: 15 * time.Minute}
	if mutate != nil {
		mutate(&cfg, &h.app)
	}

	h.appRepo = appstest.NewRepo(h.app)
	h.apps = applications.NewService(h.appRepo, appstest.AllVerified{}, &appstest.Counter{}, nopTenants{}, h.audit,
		applications.Config{AllowPlaintext: true})
	h.creds = smtpcred.NewService(&memCreds{creds: map[string]smtpcredential.Credential{}}, h.apps, h.audit, smtpcred.Config{})
	h.messages = appmsg.NewService(appmsg.Deps{Applications: h.apps, Repo: h.msgs, Queue: nopQueue{},
		Suppressions: noSuppressions{}, Tenants: nopTenants{}, Sender: h.sender, Audit: h.audit},
		appmsg.Config{Attachments: domainmsg.AttachmentLimits{MaxBytes: 1 << 20, MaxTotalBytes: 2 << 20, MaxCount: 5}})
	verifier := jwt.NewVerifier(jwt.Config{Issuer: iamSrv.URL, Audience: "mailos"})

	srv, err := NewServer(cfg, Deps{Tokens: verifier, Apps: h.apps, Credentials: h.creds, Messages: h.messages,
		Counter: &appstest.Counter{}, Audit: h.audit})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	h.srv = srv
	addrs := srv.Addrs()
	h.addr = addrs[0].String()
	if len(addrs) > 1 {
		h.implicit = addrs[1].String()
	}
	pem, _ := os.ReadFile(pki.CA)
	h.ca = x509.NewCertPool()
	h.ca.AppendCertsFromPEM(pem)
	return h
}

func (h *harness) tlsConfig() *tls.Config {
	return &tls.Config{RootCAs: h.ca, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

// dial connects and says EHLO, without TLS.
func (h *harness) dial() *smtp.Client {
	h.t.Helper()
	c, err := smtp.Dial(h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := c.Hello("legacy.bank.example"); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = c.Close() })
	return c
}

// dialTLS connects, says EHLO and STARTTLS.
func (h *harness) dialTLS() *smtp.Client {
	h.t.Helper()
	c := h.dial()
	if err := c.StartTLS(h.tlsConfig()); err != nil {
		h.t.Fatal(err)
	}
	return c
}

// credential generates an SMTP credential for the application.
func (h *harness) credential() (string, string) {
	h.t.Helper()
	c, password, err := h.creds.Create(context.Background(), tenant, h.app.ID, "batch host", "admin")
	if err != nil {
		h.t.Fatal(err)
	}
	return c.Username, password
}

// session is a client authenticated with a fresh credential.
func (h *harness) session() *smtp.Client {
	h.t.Helper()
	c := h.dialTLS()
	user, password := h.credential()
	if err := c.Auth(smtp.PlainAuth("", user, password, "127.0.0.1")); err != nil {
		h.t.Fatal(err)
	}
	return c
}

// code is the SMTP reply code of a client error (0 for success).
func code(err error) int {
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code
	}
	if err != nil {
		return -1
	}
	return 0
}

// send runs one transaction and returns the first refusal.
func send(c *smtp.Client, from string, to []string, msg string) error {
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(strings.ReplaceAll(msg, "\n", "\r\n"))); err != nil {
		return err
	}
	return w.Close()
}

func statement(from, extra string) string {
	return fmt.Sprintf("From: Core Banking <%s>\nTo: Amna <amna@example.com>\nBcc: audit@bank.example\n%sSubject: Statement ready\n"+
		"Message-ID: <%s@core.bank.example>\nContent-Type: text/plain; charset=utf-8\n\nYour October statement is ready.\n",
		from, extra, id.New())
}

// bearerAuth is SASL OAUTHBEARER or XOAUTH2 for net/smtp.
type bearerAuth struct{ mech, token string }

func (a bearerAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	if a.mech == MechXOAuth2 {
		return a.mech, []byte("user=core-banking\x01auth=Bearer " + a.token + "\x01\x01"), nil
	}
	return a.mech, []byte("n,a=core-banking,\x01host=localhost\x01port=587\x01auth=Bearer " + a.token + "\x01\x01"), nil
}

func (a bearerAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	if a.mech == MechXOAuth2 {
		return []byte{}, nil
	}
	return []byte{1}, nil // RFC 7628 §3.2.3: the client's answer to an error
}

// cmd sends a raw command and reads the reply.
func cmd(c *smtp.Client, format string, args ...any) (int, string) {
	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return -1, err.Error()
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, _ := c.Text.ReadResponse(0)
	return code, msg
}

func TestSTARTTLSIsRequiredBeforeAuthAndMail(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial()
	if ok, _ := c.Extension("STARTTLS"); !ok {
		t.Fatal("STARTTLS is advertised")
	}
	if ok, _ := c.Extension("AUTH"); ok {
		t.Fatal("AUTH is not advertised before TLS")
	}
	user, password := h.credential()
	if code, msg := cmd(c, "AUTH PLAIN %s", base64.StdEncoding.EncodeToString([]byte("\x00"+user+"\x00"+password))); code != 530 ||
		!strings.HasPrefix(msg, "5.7.0") {
		t.Fatalf("AUTH before TLS: %d %s", code, msg)
	}
	if err := c.Mail("statements@alerts.bank.example"); code(err) != 530 || !strings.Contains(err.Error(), "5.7.0") {
		t.Fatalf("MAIL before TLS: %v", err)
	}
	if err := c.StartTLS(h.tlsConfig()); err != nil {
		t.Fatal(err)
	}
	if ok, mechs := c.Extension("AUTH"); !ok || mechs != "OAUTHBEARER XOAUTH2 PLAIN LOGIN" {
		t.Fatalf("AUTH after TLS: %v %q", ok, mechs)
	}
	// Never an open relay: no MAIL without AUTH, even over TLS.
	if err := c.Mail("statements@alerts.bank.example"); code(err) != 530 {
		t.Fatalf("MAIL without AUTH: %v", err)
	}
	if len(h.msgs.all()) != 0 {
		t.Fatal("nothing was queued")
	}
}

func TestTLSBelow12IsRefused(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial()
	cfg := h.tlsConfig()
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	if err := c.StartTLS(cfg); err == nil {
		t.Fatal("TLS 1.1 is refused")
	}
}

// plain is an AUTH PLAIN command's initial response.
func plain(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + password))
}

func TestPasswordAuth(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dialTLS()
	user, password := h.credential()
	if code, msg := cmd(c, "AUTH PLAIN %s", plain(user, password+"x")); code != 535 || !strings.HasPrefix(msg, "5.7.8") {
		t.Fatalf("a wrong password: %d %s", code, msg)
	}
	if e, ok := h.audit.find("smtp.auth_failed"); !ok || e.meta["reason"] != smtpcred.ReasonBadPassword || e.meta["smtp_username"] != user {
		t.Fatalf("the failure is audited with its reason: %+v", e)
	}
	if code, msg := cmd(c, "AUTH PLAIN %s", plain("smtp_aaaaaaaaaaaaaaaaaaaaaaaa", password)); code != 535 {
		t.Fatalf("an unknown username: %d %s", code, msg)
	}
	if err := c.Auth(smtp.PlainAuth("", user, password, "127.0.0.1")); err != nil {
		t.Fatalf("the right password: %v", err)
	}
	if e, ok := h.audit.find("smtp.authenticated"); !ok || e.meta["application_id"] != h.app.ID || e.meta["method"] != "smtp_credential" {
		t.Fatalf("the sign-in is audited: %+v", e)
	}
	if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, statement("statements@alerts.bank.example", "")); err != nil {
		t.Fatalf("send: %v", err)
	}

	// LOGIN, as old clients send it.
	l := h.dialTLS()
	if code, _ := cmd(l, "AUTH LOGIN"); code != 334 {
		t.Fatal("LOGIN asks for the username")
	}
	if code, _ := cmd(l, "%s", base64.StdEncoding.EncodeToString([]byte(user))); code != 334 {
		t.Fatal("LOGIN asks for the password")
	}
	if code, msg := cmd(l, "%s", base64.StdEncoding.EncodeToString([]byte(password))); code != 235 {
		t.Fatalf("LOGIN: %d %s", code, msg)
	}
}

func TestRepeatedAuthFailuresCloseTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dialTLS()
	user, _ := h.credential()
	for i := 0; i < maxAuthFailures; i++ {
		if code, msg := cmd(c, "AUTH PLAIN %s", plain(user, "guess")); code != 535 {
			t.Fatalf("attempt %d: %d %s", i, code, msg)
		}
	}
	if code, msg := cmd(c, "AUTH PLAIN %s", plain(user, "guess")); code != 421 {
		t.Fatalf("after %d failures: %d %s", maxAuthFailures, code, msg)
	}
	if err := c.Noop(); err == nil {
		t.Fatal("the connection is closed")
	}
}

func TestAuthFailuresAreThrottledPerAddress(t *testing.T) {
	h := newHarness(t, func(c *config.SMTPSubmission, _ *domainapp.Application) { c.AuthFailuresPerIP = 2 })
	user, password := h.credential()
	c := h.dialTLS()
	for i := 0; i < 2; i++ {
		if code, _ := cmd(c, "AUTH PLAIN %s", plain(user, "guess")); code != 535 {
			t.Fatalf("attempt %d", i)
		}
	}
	// From the same address, on a new connection, even the right password
	// waits for the window to pass.
	d := h.dialTLS()
	if code, msg := cmd(d, "AUTH PLAIN %s", plain(user, password)); code != 454 || !strings.HasPrefix(msg, "4.7.0") {
		t.Fatalf("throttled: %d %s", code, msg)
	}
}

func TestPasswordAuthNeedsTheApplicationsOptIn(t *testing.T) {
	h := newHarness(t, nil)
	user, password := h.credential()
	a := h.app
	a.SMTPPasswordAuth = false
	if err := h.appRepo.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	c := h.dialTLS()
	if err := c.Auth(smtp.PlainAuth("", user, password, "127.0.0.1")); code(err) != 535 {
		t.Fatalf("opt-in off: %v", err)
	}
	if e, _ := h.audit.find("smtp.auth_failed"); e.meta["reason"] != smtpcred.ReasonNotEnabled {
		t.Fatalf("reason %+v", e)
	}
}

func TestPasswordAuthOffInConfiguration(t *testing.T) {
	h := newHarness(t, func(c *config.SMTPSubmission, _ *domainapp.Application) { c.PasswordAuth = false })
	c := h.dialTLS()
	if _, mechs := c.Extension("AUTH"); mechs != "OAUTHBEARER XOAUTH2" {
		t.Fatalf("mechanisms %q", mechs)
	}
	if code, _ := cmd(c, "AUTH PLAIN"); code != 504 {
		t.Fatalf("PLAIN is refused: %d", code)
	}
}

func TestOAuthBearerAndXOAuth2(t *testing.T) {
	h := newHarness(t, nil)
	for _, mech := range []string{MechOAuthBearer, MechXOAuth2} {
		c := h.dialTLS()
		if err := c.Auth(bearerAuth{mech, h.iam.ServiceToken("core-banking", tenant)}); err != nil {
			t.Fatalf("%s: %v", mech, err)
		}
		if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, statement("statements@alerts.bank.example", "")); err != nil {
			t.Fatalf("%s send: %v", mech, err)
		}
	}
	msgs := h.msgs.all()
	if len(msgs) != 2 || msgs[0].Actor.ID != "core-banking" || msgs[0].Metadata["smtp_auth"] != "iam_token" {
		t.Fatalf("messages %+v", msgs)
	}

	refused := map[string]string{
		"unknown client":   h.iam.ServiceToken("not-an-application", tenant),
		"another tenant":   h.iam.ServiceToken("core-banking", "0a1b2c3d-0000-4000-8000-000000000009"),
		"user token":       h.iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_admin"}}),
		"dpop-bound token": h.iam.UserToken(fakeiam.User{ClientID: "core-banking", JKT: "abc"}),
		"not a token":      "abc.def.ghi",
	}
	for name, token := range refused {
		for _, mech := range []string{MechOAuthBearer, MechXOAuth2} {
			c := h.dialTLS()
			if err := c.Auth(bearerAuth{mech, token}); code(err) != 535 || !strings.Contains(err.Error(), "5.7.8") {
				t.Errorf("%s over %s: %v", name, mech, err)
			}
		}
	}
}

func TestSenderMustBeTheApplications(t *testing.T) {
	h := newHarness(t, nil)
	c := h.session()
	err := c.Mail("ceo@bank.example")
	if code(err) != 550 || !strings.Contains(err.Error(), "5.7.1") {
		t.Fatalf("envelope sender not allowed: %v", err)
	}
	if e, ok := h.audit.find(applications.AuditSendRefused); !ok || e.meta["reason"] != "sender_not_allowed" {
		t.Fatalf("refusal audited: %+v", e)
	}
	if err := c.Reset(); err != nil {
		t.Fatal(err)
	}
	// An allowed envelope does not let the header From be someone else.
	err = send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, statement("ceo@bank.example", ""))
	if code(err) != 550 || !strings.Contains(err.Error(), "5.7.1") {
		t.Fatalf("header From not allowed: %v", err)
	}
	if len(h.msgs.all()) != 0 {
		t.Fatal("nothing was queued")
	}
}

func TestRawContentMustBeAllowed(t *testing.T) {
	h := newHarness(t, func(_ *config.SMTPSubmission, a *domainapp.Application) { a.MessageTypes = []string{"statement-ready"} })
	c := h.session()
	if err := c.Mail("statements@alerts.bank.example"); code(err) != 550 {
		t.Fatalf("an application without raw: %v", err)
	}
}

func TestLiveSubmissionGoesThroughThePipeline(t *testing.T) {
	h := newHarness(t, nil)
	c := h.session()
	msg := statement("statements@alerts.bank.example", "Cc: Raza <raza@example.com>\n")
	msg = strings.Replace(msg, "Content-Type: text/plain; charset=utf-8\n\nYour October statement is ready.\n",
		"Content-Type: text/html\n\n<p onclick=\"steal()\">Your statement</p><script>alert(1)</script>\n", 1)
	if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com", "raza@example.com", "AMNA@example.com"}, msg); err != nil {
		t.Fatal(err)
	}
	msgs := h.msgs.all()
	if len(msgs) != 2 {
		t.Fatalf("one message per distinct recipient: %d", len(msgs))
	}
	m := msgs[0]
	if m.ApplicationID != h.app.ID || m.FromEmail != "statements@alerts.bank.example" || m.FromName != "Core Banking" ||
		m.ToName != "Amna" || m.Subject != "Statement ready" || m.Sandbox || m.Metadata["source"] != "smtp" {
		t.Fatalf("message %+v", m)
	}
	if strings.Contains(m.HTMLBody, "script") || strings.Contains(m.HTMLBody, "onclick") {
		t.Fatalf("HTML is sanitised like any direct send: %q", m.HTMLBody)
	}
	if msgs[1].ToName != "Raza" {
		t.Fatalf("Cc display name: %q", msgs[1].ToName)
	}
	// The worker delivers it: MailOS's own Message-ID, no Bcc, one recipient.
	if err := h.messages.Deliver(context.Background(), tenant, m.ID); err != nil {
		t.Fatal(err)
	}
	out := h.sender.sent()
	if len(out) != 1 || out[0].To.Email != "amna@example.com" || out[0].MessageID != m.ID || len(out[0].Headers) != 0 {
		t.Fatalf("outgoing %+v", out)
	}
	if got, _ := h.msgs.Get(context.Background(), tenant, m.ID); got.Status != domainmsg.StatusSent {
		t.Fatalf("status %s", got.Status)
	}
}

func TestRetriedTransactionIsNotSentTwice(t *testing.T) {
	h := newHarness(t, nil)
	c := h.session()
	msg := statement("statements@alerts.bank.example", "")
	for i := 0; i < 2; i++ {
		if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, msg); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.msgs.all()); n != 1 {
		t.Fatalf("the same Message-ID and content twice: %d messages", n)
	}
	// Another message reusing the Message-ID is still sent.
	other := strings.Replace(msg, "Your October statement", "Your November statement", 1)
	if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, other); err != nil {
		t.Fatal(err)
	}
	if n := len(h.msgs.all()); n != 2 {
		t.Fatalf("other content with a reused Message-ID: %d messages", n)
	}
}

func TestSandboxCapturesInsteadOfDelivering(t *testing.T) {
	h := newHarness(t, func(_ *config.SMTPSubmission, a *domainapp.Application) { a.Environment = domainapp.EnvSandbox })
	c := h.session()
	if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, statement("statements@alerts.bank.example", "")); err != nil {
		t.Fatal(err)
	}
	msgs := h.msgs.all()
	if len(msgs) != 1 || !msgs[0].Sandbox {
		t.Fatalf("sandbox message %+v", msgs)
	}
	if err := h.messages.Deliver(context.Background(), tenant, msgs[0].ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.msgs.Get(context.Background(), tenant, msgs[0].ID); got.Status != domainmsg.StatusCaptured {
		t.Fatalf("status %s", got.Status)
	}
	if len(h.sender.sent()) != 0 {
		t.Fatal("no provider is called for a sandbox application")
	}
}

func TestMessageSizeLimit(t *testing.T) {
	h := newHarness(t, func(c *config.SMTPSubmission, _ *domainapp.Application) { c.MaxMessageBytes = 64 << 10 })
	c := h.session()
	if ok, size := c.Extension("SIZE"); !ok || size != "65536" {
		t.Fatalf("SIZE %q", size)
	}
	big := statement("statements@alerts.bank.example", "") + strings.Repeat("0123456789abcdef\n", 5000)
	err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, big)
	if code(err) != 552 || !strings.Contains(err.Error(), "5.3.4") {
		t.Fatalf("too large: %v", err)
	}
	if code, _ := cmd(c, "MAIL FROM:<statements@alerts.bank.example> SIZE=100000"); code != 552 {
		t.Fatalf("a declared SIZE over the limit: %d", code)
	}
	if len(h.msgs.all()) != 0 {
		t.Fatal("nothing was queued")
	}
}

func TestRecipientLimitAndAddresses(t *testing.T) {
	h := newHarness(t, func(c *config.SMTPSubmission, _ *domainapp.Application) { c.MaxRecipients = 2 })
	c := h.session()
	if err := c.Mail("statements@alerts.bank.example"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("not an address@"); code(err) == 0 {
		t.Fatal("an invalid recipient is refused")
	}
	for _, r := range []string{"a@example.com", "b@example.com"} {
		if err := c.Rcpt(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Rcpt("c@example.com"); code(err) != 452 {
		t.Fatalf("a recipient over the limit: %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t, func(_ *config.SMTPSubmission, a *domainapp.Application) { a.RatePerMinute = 2 })
	c := h.session()
	for i := 0; i < 2; i++ {
		if err := send(c, "statements@alerts.bank.example", []string{fmt.Sprintf("r%d@example.com", i)}, statement("statements@alerts.bank.example", "")); err != nil {
			t.Fatal(err)
		}
	}
	err := send(c, "statements@alerts.bank.example", []string{"r9@example.com"}, statement("statements@alerts.bank.example", ""))
	if code(err) != 451 || !strings.Contains(err.Error(), "4.7.1") {
		t.Fatalf("over the per-minute rate: %v", err)
	}
	if e, ok := h.audit.find(applications.AuditSendRefused); !ok || e.meta["reason"] != "rate_limited" {
		t.Fatalf("audited: %+v", e)
	}
}

func TestDailyQuota(t *testing.T) {
	h := newHarness(t, func(_ *config.SMTPSubmission, a *domainapp.Application) { a.DailyQuota = 1 })
	c := h.session()
	if err := send(c, "statements@alerts.bank.example", []string{"a@example.com"}, statement("statements@alerts.bank.example", "")); err != nil {
		t.Fatal(err)
	}
	if err := send(c, "statements@alerts.bank.example", []string{"b@example.com"}, statement("statements@alerts.bank.example", "")); code(err) != 452 {
		t.Fatalf("over the daily quota: %v", err)
	}
}

func TestBroadcastNeedsListUnsubscribe(t *testing.T) {
	h := newHarness(t, func(_ *config.SMTPSubmission, a *domainapp.Application) { a.Stream = domainapp.StreamBroadcast })
	c := h.session()
	err := send(c, "news@alerts.bank.example", []string{"amna@example.com"}, statement("news@alerts.bank.example", ""))
	if code(err) != 550 {
		t.Fatalf("broadcast without List-Unsubscribe: %v", err)
	}
	unsub := "List-Unsubscribe: <https://bank.example/u/1>\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\n"
	if err := send(c, "news@alerts.bank.example", []string{"amna@example.com"}, statement("news@alerts.bank.example", unsub)); err != nil {
		t.Fatal(err)
	}
	m := h.msgs.all()[0]
	if m.Type != domainmsg.TypeMarketing || m.Stream != domainmsg.StreamBroadcast {
		t.Fatalf("broadcast mail is marketing: %s %s", m.Type, m.Stream)
	}
	if err := h.messages.Deliver(context.Background(), tenant, m.ID); err != nil {
		t.Fatal(err)
	}
	out := h.sender.sent()
	if len(out) != 1 || out[0].Headers["List-Unsubscribe"] != "<https://bank.example/u/1>" ||
		out[0].Headers["List-Unsubscribe-Post"] != "List-Unsubscribe=One-Click" {
		t.Fatalf("one-click unsubscribe reaches the provider: %+v", out)
	}
}

func TestAttachmentsAreQueuedAndChecked(t *testing.T) {
	h := newHarness(t, nil)
	c := h.session()
	msg := "From: statements@alerts.bank.example\nSubject: s\nContent-Type: multipart/mixed; boundary=x\n\n--x\n" +
		"Content-Type: text/plain\n\nsee attached\n--x\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=a.pdf\n" +
		"Content-Transfer-Encoding: base64\n\nJVBERi0=\n--x--\n"
	if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, msg); err != nil {
		t.Fatalf("attachment: %v", err)
	}
	m := h.msgs.all()[0]
	if len(m.Attachments) != 1 || m.Attachments[0].Filename != "a.pdf" || string(m.Attachments[0].Data) != "%PDF-" {
		t.Fatalf("stored %+v", m.Attachments)
	}
	if err := h.messages.Deliver(context.Background(), tenant, m.ID); err != nil {
		t.Fatal(err)
	}
	if out := h.sender.sent(); len(out) != 1 || len(out[0].Attachments) != 1 {
		t.Fatalf("delivered %+v", out)
	}
	// An executable is refused with the pipeline's reason.
	bad := strings.Replace(msg, "filename=a.pdf", "filename=setup.exe", 1)
	if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, bad); code(err) != 554 || !strings.Contains(err.Error(), ".exe") {
		t.Fatalf("executable: %v", err)
	}
}

func TestRevokedCredentialStopsAnOpenSession(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dialTLS()
	user, password := h.credential()
	if err := c.Auth(smtp.PlainAuth("", user, password, "127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	list, _ := h.creds.List(context.Background(), tenant, h.app.ID)
	if err := h.creds.Revoke(context.Background(), tenant, h.app.ID, list[0].ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("statements@alerts.bank.example"); code(err) != 421 {
		t.Fatalf("MAIL after revocation: %v", err)
	}
	if err := c.Noop(); err == nil {
		t.Fatal("the connection is closed")
	}
}

func TestSuspendedApplicationIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	c := h.session()
	if _, err := h.apps.Suspend(context.Background(), tenant, h.app.ID, "incident", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("statements@alerts.bank.example"); code(err) != 421 {
		t.Fatalf("MAIL after suspension: %v", err)
	}
}

func TestImplicitTLS(t *testing.T) {
	port := freePort(t)
	h := newHarness(t, func(c *config.SMTPSubmission, _ *domainapp.Application) { c.ImplicitTLSPort = port })
	conn, err := tls.Dial("tcp", h.implicit, h.tlsConfig())
	if err != nil {
		t.Fatal(err)
	}
	c, err := smtp.NewClient(conn, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("legacy.bank.example"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		t.Fatal("no STARTTLS on the implicit TLS port")
	}
	user, password := h.credential()
	if err := c.Auth(smtp.PlainAuth("", user, password, "127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, statement("statements@alerts.bank.example", "")); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionLimitPerAddress(t *testing.T) {
	h := newHarness(t, func(c *config.SMTPSubmission, _ *domainapp.Application) { c.MaxConnectionsPerIP = 1 })
	_ = h.dial()
	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := textproto.NewReader(bufioReader(conn)).ReadLine()
	if err != nil || !strings.HasPrefix(line, "421 4.7.0") {
		t.Fatalf("a second connection from the address: %q %v", line, err)
	}
}

func TestGracefulShutdown(t *testing.T) {
	h := newHarness(t, nil)
	c := h.session()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- h.srv.Shutdown(ctx)
	}()
	// The open session finishes its transaction, then quits.
	time.Sleep(100 * time.Millisecond)
	if err := send(c, "statements@alerts.bank.example", []string{"amna@example.com"}, statement("statements@alerts.bank.example", "")); err != nil {
		t.Fatalf("a transaction in flight during shutdown: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if _, err := net.DialTimeout("tcp", h.addr, time.Second); err == nil {
		t.Fatal("no new connections after shutdown")
	}
}

func bufioReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }
