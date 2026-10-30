package tlsconfig_test

import (
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/razatechofficial/mail-os/internal/testutil/tlstest"
	"github.com/razatechofficial/mail-os/pkg/tlsconfig"
)

// serve accepts TLS connections and writes "ok" after the handshake.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if err := c.(*tls.Conn).Handshake(); err == nil {
					_, _ = c.Write([]byte("ok"))
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func dial(addr string, cfg *tls.Config) error {
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	b := make([]byte, 2)
	_, err = io.ReadFull(c, b)
	return err
}

func TestMutualTLS(t *testing.T) {
	f := tlstest.New(t)
	srv, err := tlsconfig.NewServer(tlsconfig.Server{CertFile: f.ServerCert, KeyFile: f.ServerKey, ClientCAFile: f.CA, ClientAuth: "require"})
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, srv)

	withCert, err := tlsconfig.NewClient(tlsconfig.Client{CAFile: f.CA, CertFile: f.ClientCert, KeyFile: f.ClientKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := dial(addr, withCert); err != nil {
		t.Fatalf("client with certificate refused: %v", err)
	}
	noCert, _ := tlsconfig.NewClient(tlsconfig.Client{CAFile: f.CA})
	if err := dial(addr, noCert); err == nil {
		t.Fatal("client without a certificate accepted under require")
	}
	// The server is verified: a client that does not trust the CA fails.
	if err := dial(addr, &tls.Config{MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("untrusted server certificate accepted")
	}
}

func TestOldProtocolsRefused(t *testing.T) {
	f := tlstest.New(t)
	srv, err := tlsconfig.NewServer(tlsconfig.Server{CertFile: f.ServerCert, KeyFile: f.ServerKey})
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, srv)
	client, _ := tlsconfig.NewClient(tlsconfig.Client{CAFile: f.CA})
	old := client.Clone()
	old.MinVersion, old.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	if err := dial(addr, old); err == nil {
		t.Fatal("TLS 1.1 accepted")
	}
	if err := dial(addr, client); err != nil {
		t.Fatalf("TLS 1.2+: %v", err)
	}
}

func TestBadInputs(t *testing.T) {
	f := tlstest.New(t)
	if _, err := tlsconfig.NewServer(tlsconfig.Server{CertFile: f.ServerCert, KeyFile: f.ClientKey}); err == nil {
		t.Fatal("mismatched key pair accepted")
	}
	if _, err := tlsconfig.NewServer(tlsconfig.Server{CertFile: f.ServerCert, KeyFile: f.ServerKey, ClientAuth: "require"}); err == nil {
		t.Fatal("mutual TLS without a CA accepted")
	}
	if _, err := tlsconfig.LoadPool(f.ServerKey); err == nil {
		t.Fatal("a key file read as a CA bundle")
	}
}
