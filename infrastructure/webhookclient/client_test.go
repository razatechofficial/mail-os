package webhookclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostRefusesLoopbackUnlessAllowed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("webhook-signature") == "" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if code, err := New(Options{TLS: tc}).Post(context.Background(), srv.URL, nil, []byte("{}")); err == nil || code != 0 {
		t.Fatalf("loopback reached: %d %v", code, err)
	}
	c := New(Options{TLS: tc, AllowLoopback: true})
	code, err := c.Post(context.Background(), srv.URL, map[string]string{"webhook-signature": "v1,eA=="}, []byte("{}"))
	if err != nil || code != 204 {
		t.Fatal(code, err)
	}
}

func TestPostDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest", http.StatusFound)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c := New(Options{TLS: &tls.Config{RootCAs: pool}, AllowLoopback: true})
	if code, err := c.Post(context.Background(), srv.URL, nil, nil); err != nil || code != http.StatusFound {
		t.Fatal(code, err)
	}
}
