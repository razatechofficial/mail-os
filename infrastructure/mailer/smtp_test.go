package mailer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// testCA is a CA and a server certificate for 127.0.0.1 it signed.
type testCA struct {
	pool *x509.CertPool
	cert tls.Certificate
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "MailOS test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return testCA{pool: pool, cert: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}
}

// received is one message the test server accepted.
type received struct {
	from, rcpt string
	data       []byte
	tls        uint16 // negotiated version, 0 for plaintext
	authUser   string
}

// smtpServer is a minimal RFC 5321 server: EHLO, STARTTLS, AUTH PLAIN,
// MAIL, RCPT, DATA, QUIT, with replies the test can override.
type smtpServer struct {
	t        *testing.T
	ln       net.Listener
	tlsCfg   *tls.Config
	implicit bool
	startTLS bool
	user     string
	pass     string
	// replies override the reply to a verb ("RCPT", "MAIL", "DATA").
	replies map[string]string

	mu   sync.Mutex
	msgs []received
	// plainMail counts MAIL commands seen without TLS.
	plainMail int
}

func startSMTP(t *testing.T, ca testCA, configure func(*smtpServer)) *smtpServer {
	t.Helper()
	s := &smtpServer{t: t, startTLS: true, replies: map[string]string{},
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{ca.cert}, MinVersion: tls.VersionTLS12}}
	if configure != nil {
		configure(s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if s.implicit {
		ln = tls.NewListener(ln, s.tlsCfg)
	}
	s.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *smtpServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpServer) messages() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.msgs...)
}

func (s *smtpServer) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var version uint16
	if tc, ok := c.(*tls.Conn); ok {
		if tc.Handshake() != nil {
			return
		}
		version = tc.ConnectionState().Version
	}
	tp := textproto.NewConn(c)
	reply := func(line string) { _ = tp.PrintfLine("%s", line) }
	reply("220 test ESMTP")
	var cur received
	authed := s.user == ""
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		if r, ok := s.replies[verb]; ok {
			reply(r)
			continue
		}
		switch verb {
		case "EHLO", "HELO":
			lines := []string{"250-test"}
			if s.startTLS && version == 0 {
				lines = append(lines, "250-STARTTLS")
			}
			if s.user != "" {
				lines = append(lines, "250-AUTH PLAIN")
			}
			lines = append(lines, "250 8BITMIME")
			for _, l := range lines {
				reply(l)
			}
		case "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(c, s.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			version = tc.ConnectionState().Version
			c = tc
			tp = textproto.NewConn(tc)
			reply = func(line string) { _ = tp.PrintfLine("%s", line) }
		case "AUTH":
			parts := strings.Fields(arg)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			f := bytes.Split(raw, []byte{0})
			if len(f) == 3 && string(f[1]) == s.user && string(f[2]) == s.pass {
				authed = true
				cur.authUser = s.user
				reply("235 ok")
			} else {
				reply("535 5.7.8 authentication failed")
			}
		case "MAIL":
			if version == 0 {
				s.mu.Lock()
				s.plainMail++
				s.mu.Unlock()
			}
			if !authed {
				reply("530 5.7.0 authentication required")
				continue
			}
			cur.from = strings.Trim(strings.Fields(strings.TrimPrefix(arg, "FROM:"))[0], "<>")
			reply("250 ok")
		case "RCPT":
			cur.rcpt = strings.Trim(strings.Fields(strings.TrimPrefix(arg, "TO:"))[0], "<>")
			reply("250 ok")
		case "DATA":
			reply("354 go")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			cur.data, cur.tls = data, version
			s.mu.Lock()
			s.msgs = append(s.msgs, cur)
			s.mu.Unlock()
			reply("250 2.0.0 queued as ABC123")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}

func smtpConfig(s *smtpServer, mode string) SMTPConfig {
	return SMTPConfig{Host: "127.0.0.1", Port: s.port(), TLSMode: mode, Username: s.user, Password: s.pass,
		From: message.Address{Name: "Bank", Email: "noreply@bank.example"}}
}

func testOpts(ca testCA) Options {
	return Options{RootCAs: ca.pool, AllowLoopback: true, Timeout: 5 * time.Second}
}

func sendErr(t *testing.T, err error) *message.SendError {
	t.Helper()
	se, ok := message.AsSendError(err)
	if !ok {
		t.Fatalf("not a send error: %v", err)
	}
	return se
}

func TestSMTPStartTLSAuthAndDKIM(t *testing.T) {
	ca := newTestCA(t)
	srv := startSMTP(t, ca, func(s *smtpServer) { s.user, s.pass = "mailer", "s3cret" })
	snd, err := NewSMTP(smtpConfig(srv, provider.TLSStartTLS), testOpts(ca))
	if err != nil {
		t.Fatal(err)
	}
	key, lookup := signingKey(t, "bank.example")
	out := sampleOutgoing()
	out.From = message.Address{} // the relay's default sender
	out.DKIM = key
	res, err := snd.Send(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	if res.ProviderMessageID != "0192f0c4-7b1e-7cc0-9d2e-1a2b3c4d5e6f@bank.example" {
		t.Fatalf("id %q", res.ProviderMessageID)
	}
	msgs := srv.messages()
	if len(msgs) != 1 || srv.plainMail != 0 {
		t.Fatalf("messages %d, plaintext MAIL %d", len(msgs), srv.plainMail)
	}
	m := msgs[0]
	if m.tls < tls.VersionTLS12 || m.authUser != "mailer" || m.from != "noreply@bank.example" || m.rcpt != "zoe@example.com" {
		t.Fatalf("session tls=%x user=%q from=%q rcpt=%q", m.tls, m.authUser, m.from, m.rcpt)
	}
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(m.data), &dkim.VerifyOptions{LookupTXT: lookup})
	if err != nil || len(vs) != 1 || vs[0].Err != nil {
		t.Fatalf("dkim: %v %+v", err, vs)
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	ca := newTestCA(t)
	srv := startSMTP(t, ca, func(s *smtpServer) { s.implicit, s.startTLS = true, false })
	snd, _ := NewSMTP(smtpConfig(srv, provider.TLSImplicit), testOpts(ca))
	if _, err := snd.Send(context.Background(), sampleOutgoing()); err != nil {
		t.Fatal(err)
	}
	if m := srv.messages(); len(m) != 1 || m[0].tls < tls.VersionTLS12 {
		t.Fatalf("%+v", m)
	}
}

func TestSMTPRefusesUntrustedCertificate(t *testing.T) {
	ca := newTestCA(t)
	srv := startSMTP(t, ca, nil)
	opts := testOpts(ca)
	opts.RootCAs = newTestCA(t).pool // another CA
	snd, _ := NewSMTP(smtpConfig(srv, provider.TLSStartTLS), opts)
	_, err := snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonConfig || !se.Permanent() {
		t.Fatalf("%v", err)
	}
	if len(srv.messages()) != 0 || srv.plainMail != 0 {
		t.Fatal("mail sent over an untrusted connection")
	}
}

func TestSMTPRefusesMissingSTARTTLS(t *testing.T) {
	ca := newTestCA(t)
	srv := startSMTP(t, ca, func(s *smtpServer) { s.startTLS = false })
	snd, _ := NewSMTP(smtpConfig(srv, provider.TLSStartTLS), testOpts(ca))
	_, err := snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonConfig {
		t.Fatalf("%v", err)
	}
	if srv.plainMail != 0 {
		t.Fatal("downgraded to plaintext")
	}
}

func TestSMTPPlaintextOnlyWhenAllowed(t *testing.T) {
	ca := newTestCA(t)
	srv := startSMTP(t, ca, func(s *smtpServer) { s.startTLS = false })
	if _, err := NewSMTP(smtpConfig(srv, provider.TLSNone), testOpts(ca)); err == nil {
		t.Fatal("plaintext accepted without AllowPlaintext")
	}
	opts := testOpts(ca)
	opts.AllowPlaintext = true
	snd, err := NewSMTP(smtpConfig(srv, provider.TLSNone), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snd.Send(context.Background(), sampleOutgoing()); err != nil {
		t.Fatal(err)
	}
}

func TestSMTPClassifiesReplies(t *testing.T) {
	ca := newTestCA(t)
	cases := []struct {
		verb, reply string
		user        string
		want        message.Reason
	}{
		{"RCPT", "550 5.1.1 no such user", "", message.ReasonInvalidRecipient},
		{"RCPT", "452 4.2.2 mailbox full", "", message.ReasonUnavailable},
		{"MAIL", "421 4.7.0 too many messages, slow down", "", message.ReasonRateLimited},
		{"DATA", "554 5.7.1 spam detected", "", message.ReasonRejected},
		{"", "", "mailer", message.ReasonAuth}, // wrong password
	}
	for _, c := range cases {
		srv := startSMTP(t, ca, func(s *smtpServer) {
			if c.verb != "" {
				s.replies[c.verb] = c.reply
			}
			if c.user != "" {
				s.user, s.pass = c.user, "right"
			}
		})
		cfg := smtpConfig(srv, provider.TLSStartTLS)
		if c.user != "" {
			cfg.Password = "wrong"
		}
		snd, _ := NewSMTP(cfg, testOpts(ca))
		_, err := snd.Send(context.Background(), sampleOutgoing())
		se := sendErr(t, err)
		if se.Reason != c.want || se.Permanent() != c.want.Permanent() {
			t.Errorf("%s %q: got %v", c.verb, c.reply, err)
		}
		if strings.Contains(se.Error(), "wrong") {
			t.Error("password in error")
		}
	}
}

func TestSMTPGuardRefusesLoopbackForTenants(t *testing.T) {
	ca := newTestCA(t)
	srv := startSMTP(t, ca, nil)
	opts := testOpts(ca)
	opts.AllowLoopback = false
	snd, _ := NewSMTP(smtpConfig(srv, provider.TLSStartTLS), opts)
	_, err := snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonConfig {
		t.Fatalf("%v", err)
	}
	// The platform relay may live on loopback.
	plat, err := NewPlatformSMTP(config.SMTP{Enabled: true, Host: "127.0.0.1", Port: srv.port(), TLSMode: "starttls",
		FromAddr: "noreply@platform.example"}, false, Options{RootCAs: ca.pool})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plat.Send(context.Background(), sampleOutgoing()); err != nil {
		t.Fatal(err)
	}
	if off, err := NewPlatformSMTP(config.SMTP{}, false, Options{}); off != nil || err != nil {
		t.Fatal("disabled relay built")
	}
}

func TestSMTPUnreachableIsTransient(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	snd, _ := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: port, From: message.Address{Email: "a@bank.example"}},
		Options{AllowLoopback: true, Timeout: time.Second})
	_, err := snd.Send(context.Background(), sampleOutgoing())
	if se := sendErr(t, err); se.Reason != message.ReasonNetwork || se.Permanent() || strings.Contains(se.Error(), strconv.Itoa(port)) {
		t.Fatalf("%v", err)
	}
}
