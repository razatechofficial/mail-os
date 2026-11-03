package mailer

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

func TestSMTPLoginAndCRAMMD5WithHELOName(t *testing.T) {
	ca := newTestCA(t)
	for _, mech := range []string{provider.AuthLogin, provider.AuthCRAMMD5} {
		srv := startSMTP(t, ca, func(s *smtpServer) { s.user, s.pass, s.mechs = "u", "p@ss", "PLAIN LOGIN CRAM-MD5" })
		cfg := smtpConfig(srv, provider.TLSStartTLS)
		cfg.Auth, cfg.HELOName = mech, "mailos.bank.example"
		snd, err := NewSMTP(cfg, testOpts(ca))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := snd.Send(context.Background(), sampleOutgoing()); err != nil {
			t.Fatalf("%s: %v", mech, err)
		}
		helo, _, got := srv.seen()
		if helo != "mailos.bank.example" || got != strings.ToUpper(mech) || len(srv.messages()) != 1 {
			t.Fatalf("%s: helo %q mech %q", mech, helo, got)
		}
	}
}

func TestSMTPMechanismNotOffered(t *testing.T) {
	ca := newTestCA(t)
	srv := startSMTP(t, ca, func(s *smtpServer) { s.user, s.pass = "u", "p" })
	cfg := smtpConfig(srv, provider.TLSStartTLS)
	cfg.Auth = provider.AuthLogin
	snd, _ := NewSMTP(cfg, testOpts(ca))
	d := Test(context.Background(), provider.KindSMTP, snd)
	if d.OK || d.Step != "auth" || d.ErrorClass != string(message.ReasonConfig) || !strings.Contains(d.Detail, "offers PLAIN") || d.Hint == "" {
		t.Fatalf("%+v", d)
	}
}

func TestSMTPXOAUTH2WithMicrosoftToken(t *testing.T) {
	ca := newTestCA(t)
	idp := newAPIServer(t)
	idp.handle(reply(200, `{"access_token":"`+fakeJWT(map[string]any{"roles": []string{"SMTP.SendAsApp"}})+`","expires_in":3600}`))
	tok := fakeJWT(map[string]any{"roles": []string{"SMTP.SendAsApp"}})
	srv := startSMTP(t, ca, func(s *smtpServer) { s.user, s.mechs, s.token = "box@bank.example", "LOGIN XOAUTH2", tok })
	opts := testOpts(ca)
	opts.RootCAs = ca.pool.Clone()
	opts.RootCAs.AddCert(idp.Certificate())
	opts.BaseURLs = map[provider.Kind]string{oauthMicrosoft: idp.URL}
	snd, err := NewSMTPProvider(provider.Settings{Host: "127.0.0.1", Port: srv.port(), TLSMode: provider.TLSStartTLS,
		AuthMechanism: provider.AuthXOAUTH2, Username: "box@bank.example", OAuthProvider: provider.OAuthMicrosoft,
		TenantID: "contoso.example", ClientID: "app", AuthMethod: provider.MicrosoftSecret, FromEmail: "noreply@bank.example"},
		provider.Credentials{ClientSecret: "s"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	d := Test(context.Background(), provider.KindSMTP, snd)
	names := []string{}
	for _, s := range d.Steps {
		names = append(names, s.Name)
	}
	// The only warning is the test certificate's near expiry.
	if !d.OK || strings.Join(names, ",") != "token,connect,hello,tls,auth" || len(d.Warnings) != 1 ||
		!strings.Contains(d.Warnings[0], "expires") || len(srv.messages()) != 0 {
		t.Fatalf("%+v", d)
	}
	if _, err := snd.Send(context.Background(), sampleOutgoing()); err != nil {
		t.Fatal(err)
	}
	if _, _, mech := srv.seen(); mech != "XOAUTH2" {
		t.Fatalf("mech %s", mech)
	}
	// A refused token is an auth failure, and the next attempt fetches a
	// new token.
	idp.handle(reply(200, `{"access_token":"stale","expires_in":3600}`))
	snd.cfg.Token.Invalidate()
	calls := idp.calls.Load()
	_, err = snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonAuth {
		t.Fatalf("%v", err)
	}
	_, _ = snd.Send(context.Background(), sampleOutgoing())
	if idp.calls.Load() != calls+2 {
		t.Fatal("a refused token was reused")
	}
}

func TestSMTPPrivateCAAndClientCertificate(t *testing.T) {
	ca := newTestCA(t)
	client := newRSACert(t, "mailos-client")
	srv := startSMTP(t, ca, func(s *smtpServer) { s.tlsCfg.ClientAuth = tls.RequireAnyClientCert })
	// No RootCAs: the system roots plus the configured private CA.
	opts := Options{AllowLoopback: true}
	pair, _ := tls.X509KeyPair([]byte(client.certPEM), []byte(client.keyPEM))
	cfg := smtpConfig(srv, provider.TLSStartTLS)
	cfg.CACertPEM, cfg.ClientCert = ca.caPEM, &pair
	snd, err := NewSMTP(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snd.Send(context.Background(), sampleOutgoing()); err != nil {
		t.Fatal(err)
	}
	if _, cn, _ := srv.seen(); cn != "mailos-client" {
		t.Fatalf("client certificate not presented: %q", cn)
	}
	cfg.CACertPEM = ""
	snd, _ = NewSMTP(cfg, opts)
	d := Test(context.Background(), provider.KindSMTP, snd)
	if d.OK || d.Step != "tls" || d.ErrorClass != string(message.ReasonConfig) || !strings.Contains(d.Hint, "CA") {
		t.Fatalf("untrusted relay: %+v", d)
	}
	if _, err := NewSMTPProvider(provider.Settings{Host: "h.example", Port: 587, ClientCert: client.certPEM}, provider.Credentials{}, opts); err == nil {
		t.Fatal("a client certificate without its key was accepted")
	}
}

func TestSMTPCheckSendsNothingAndReportsFailures(t *testing.T) {
	ca := newTestCA(t)
	srv := startSMTP(t, ca, func(s *smtpServer) { s.user, s.pass = "u", "right" })
	cfg := smtpConfig(srv, provider.TLSStartTLS)
	snd, _ := NewSMTP(cfg, testOpts(ca))
	d := Test(context.Background(), provider.KindSMTP, snd)
	if !d.OK || len(d.Steps) != 4 || !strings.HasPrefix(d.Steps[3].Label, "Authenticate as u") || len(srv.messages()) != 0 {
		t.Fatalf("%+v", d)
	}
	if !strings.Contains(d.Steps[2].Detail, "TLS 1.") {
		t.Fatalf("tls detail %q", d.Steps[2].Detail)
	}
	cfg.Password = "wrong"
	snd, _ = NewSMTP(cfg, testOpts(ca))
	d = Test(context.Background(), provider.KindSMTP, snd)
	if d.OK || d.Step != "auth" || d.ErrorClass != "auth" || !strings.Contains(d.Detail, "535") || strings.Contains(d.Detail, "wrong") {
		t.Fatalf("%+v", d)
	}

	srv.Close()
	d = Test(context.Background(), provider.KindSMTP, snd)
	if d.OK || d.Step != "connect" || d.ErrorClass != "network" || d.Hint == "" {
		t.Fatalf("closed relay: %+v", d)
	}
	// The send test reports the provider's id on success.
	srv2 := startSMTP(t, ca, nil)
	snd, _ = NewSMTP(smtpConfig(srv2, provider.TLSStartTLS), testOpts(ca))
	d = TestSend(context.Background(), provider.KindSMTP, snd, sampleOutgoing())
	if !d.OK || d.Kind != provider.TestSend || d.ProviderMessageID == "" || len(srv2.messages()) != 1 {
		t.Fatalf("%+v", d)
	}
	_ = http.StatusOK
}

func (s *smtpServer) Close() { _ = s.ln.Close() }
