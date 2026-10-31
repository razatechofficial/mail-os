package kafka

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/razatechofficial/mail-os/config"
)

// testPKI is a CA with a broker certificate for 127.0.0.1 and a client
// certificate, written as PEM files under a test directory.
type testPKI struct {
	caFile, clientCert, clientKey string
	pool                          *x509.CertPool
	server                        tls.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test kafka CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, cn string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kder, _ := x509.MarshalECPrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	srvCert, srvKey := issue(2, "broker", x509.ExtKeyUsageServerAuth)
	server, err := tls.X509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, cliKey := issue(3, "mailos", x509.ExtKeyUsageClientAuth)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return testPKI{
		caFile:     write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		clientCert: write("client.pem", cliCert),
		clientKey:  write("client-key.pem", cliKey),
		pool:       pool,
		server:     server,
	}
}

func TestTLSConfig(t *testing.T) {
	pki := newTestPKI(t)
	tc, err := TLSConfig(config.ClientTLS{Enabled: true, CAFile: pki.caFile, CertFile: pki.clientCert, KeyFile: pki.clientKey, ServerName: "kafka.internal"})
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if tc.MinVersion != tls.VersionTLS12 || tc.RootCAs == nil || len(tc.Certificates) != 1 || tc.ServerName != "kafka.internal" || tc.InsecureSkipVerify {
		t.Fatalf("tls config = %+v", tc)
	}
	if tc, err := TLSConfig(config.ClientTLS{Enabled: true}); err != nil || tc.RootCAs != nil {
		t.Fatalf("system roots: %+v, %v", tc, err)
	}

	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(notPEM, []byte("not a certificate"), 0o600)
	for name, c := range map[string]config.ClientTLS{
		"missing CA":  {CAFile: filepath.Join(t.TempDir(), "missing.pem")},
		"CA not PEM":  {CAFile: notPEM},
		"half a pair": {CertFile: pki.clientCert},
		"bad pair":    {CertFile: pki.clientCert, KeyFile: pki.caFile},
	} {
		if _, err := TLSConfig(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMutualTLSToTheBroker(t *testing.T) {
	pki := newTestPKI(t)
	_, cfg := newCluster(t, kfake.TLS(&tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientCAs:    pki.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}))
	cfg.TLS = config.ClientTLS{Enabled: true, CAFile: pki.caFile, CertFile: pki.clientCert, KeyFile: pki.clientKey}
	publish(t, cfg, "a")
	h := newRecorder(nil)
	startConsumer(t, cfg, h)
	h.waitCalls(t, 1)

	// Without the CA the broker's certificate is not trusted; without the
	// client certificate the broker refuses the connection.
	for name, tc := range map[string]config.ClientTLS{
		"system roots":      {Enabled: true, CertFile: pki.clientCert, KeyFile: pki.clientKey},
		"no client cert":    {Enabled: true, CAFile: pki.caFile},
		"wrong server name": {Enabled: true, CAFile: pki.caFile, CertFile: pki.clientCert, KeyFile: pki.clientKey, ServerName: "evil.example"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := cfg
			bad.TLS = tc
			p, err := NewProducer(bad)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := p.Publish(ctx, testTopic, "k", []byte("x"), nil); err == nil {
				t.Fatal("published over an untrusted connection")
			}
		})
	}
}

func TestSCRAMSHA512ToTheBroker(t *testing.T) {
	_, cfg := newCluster(t, kfake.EnableSASL(), kfake.Superuser(config.SASLScramSHA512, "mailos", "s3cret"))
	cfg.SASL = config.SASL{Mechanism: config.SASLScramSHA512, Username: "mailos", Password: "s3cret"}
	publish(t, cfg, "a")
	h := newRecorder(nil)
	startConsumer(t, cfg, h)
	h.waitCalls(t, 1)

	bad := cfg
	bad.SASL.Password = "wrong"
	p, err := NewProducer(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.Publish(ctx, testTopic, "k", []byte("x"), nil); err == nil {
		t.Fatal("published with a wrong SCRAM password")
	}
}

func TestSASLMechanismChoice(t *testing.T) {
	o := newOptions(nil)
	for _, m := range []string{"", config.SASLNone} {
		if mech, err := saslMechanism(config.SASL{Mechanism: m}, o); err != nil || mech != nil {
			t.Errorf("%q: %v, %v", m, mech, err)
		}
	}
	if mech, err := saslMechanism(config.SASL{Mechanism: config.SASLScramSHA512, Username: "u", Password: "p"}, o); err != nil || mech.Name() != "SCRAM-SHA-512" {
		t.Errorf("SCRAM: %v, %v", mech, err)
	}
	if mech, err := saslMechanism(config.SASL{Mechanism: config.SASLOAuthBearer, TokenURL: "https://iam.example/oauth/token", ClientID: "c", ClientSecret: "s"}, o); err != nil || mech.Name() != "OAUTHBEARER" {
		t.Errorf("OAUTHBEARER: %v, %v", mech, err)
	}
	for name, c := range map[string]config.SASL{
		"PLAIN":                 {Mechanism: "PLAIN", Username: "u", Password: "p"},
		"SCRAM without secret":  {Mechanism: config.SASLScramSHA512, Username: "u"},
		"OAUTH without secret":  {Mechanism: config.SASLOAuthBearer, TokenURL: "https://iam.example/oauth/token", ClientID: "c"},
		"OAUTH without the URL": {Mechanism: config.SASLOAuthBearer, ClientID: "c", ClientSecret: "s"},
	} {
		if _, err := saslMechanism(c, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// tokenServer is a client-credentials endpoint counting its calls.
func tokenServer(t *testing.T, expiresIn int, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if err := r.ParseForm(); err != nil || r.Method != http.MethodPost ||
			r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "mailos-kafka" ||
			r.PostForm.Get("client_secret") != "top-secret" || r.PostForm.Get("scope") != "kafka" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"top-secret is wrong"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok-` + strconv.Itoa(int(n)) + `","token_type":"Bearer","expires_in":` + strconv.Itoa(expiresIn) + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func testSASL(url string) config.SASL {
	return config.SASL{Mechanism: config.SASLOAuthBearer, TokenURL: url, ClientID: "mailos-kafka", ClientSecret: "top-secret", Scope: "kafka"}
}

func TestTokenSourceCachesUntil30sBeforeExpiry(t *testing.T) {
	srv, calls := tokenServer(t, 600, http.StatusOK)
	ts, err := NewTokenSource(testSASL(srv.URL), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ts.now = func() time.Time { return now }
	ctx := context.Background()

	for range 3 {
		if tok, err := ts.Token(ctx); err != nil || tok != "tok-1" {
			t.Fatalf("Token = %q, %v", tok, err)
		}
	}
	now = now.Add(600*time.Second - 31*time.Second)
	if tok, _ := ts.Token(ctx); tok != "tok-1" {
		t.Fatalf("refreshed early: %q", tok)
	}
	now = now.Add(2 * time.Second) // within 30 s of expiry
	if tok, _ := ts.Token(ctx); tok != "tok-2" {
		t.Fatalf("not refreshed 30 s before expiry: %q", tok)
	}
	if calls.Load() != 2 {
		t.Fatalf("token endpoint called %d times, want 2", calls.Load())
	}
}

func TestTokenSourceErrorsKeepTheSecretOut(t *testing.T) {
	srv, _ := tokenServer(t, 600, http.StatusUnauthorized)
	ts, _ := NewTokenSource(testSASL(srv.URL), srv.Client())
	_, err := ts.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("err = %v", err)
	}

	bearer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"DPoP","expires_in":60}`))
	}))
	defer bearer.Close()
	ts, _ = NewTokenSource(testSASL(bearer.URL), bearer.Client())
	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("a DPoP token was accepted for OAUTHBEARER")
	}
}

func TestOAuthBearerMechanismSendsTheToken(t *testing.T) {
	srv, _ := tokenServer(t, 600, http.StatusOK)
	ts, _ := NewTokenSource(testSASL(srv.URL), srv.Client())
	_, first, err := ts.Mechanism().Authenticate(context.Background(), "broker:9093")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !strings.Contains(string(first), "auth=Bearer tok-1") {
		t.Fatalf("initial OAUTHBEARER message %q does not carry the token", first)
	}
}

func TestClientOptionsNeedBrokers(t *testing.T) {
	if _, err := NewProducer(config.Kafka{}); err == nil {
		t.Fatal("a producer without brokers was built")
	}
}
