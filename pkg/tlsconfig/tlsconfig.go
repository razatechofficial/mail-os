// Package tlsconfig builds the TLS configurations of MailOS's listeners and
// clients: TLS 1.2 or later, modern AEAD cipher suites only, and optional
// mutual TLS (contract §2; PCI DSS 4.0.1 §4.2.1).
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Client certificate policies.
const (
	ClientAuthNone    = "none"
	ClientAuthRequest = "request"
	ClientAuthRequire = "require"
)

// Server describes a listener's certificate and client-certificate policy.
type Server struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
	ClientAuth   string
	MinVersion   string // "1.2" or "1.3"
}

// cipherSuites are the TLS 1.2 suites allowed: ECDHE with AEAD only (TLS
// 1.3 suites are not configurable and are all AEAD).
var cipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func minVersion(v string) uint16 {
	if v == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// NewServer loads the key pair and, for mutual TLS, the client CA. The key
// pair is reread on each handshake from the files, so a certificate
// rotated on disk (cert-manager) is served without a restart.
func NewServer(s Server) (*tls.Config, error) {
	if _, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile); err != nil {
		return nil, fmt.Errorf("tls key pair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   minVersion(s.MinVersion),
		CipherSuites: cipherSuites,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
			if err != nil {
				return nil, err
			}
			return &c, nil
		},
	}
	switch strings.ToLower(s.ClientAuth) {
	case "", ClientAuthNone:
		cfg.ClientAuth = tls.NoClientCert
	case ClientAuthRequest, ClientAuthRequire:
		pool, err := LoadPool(s.ClientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		if strings.EqualFold(s.ClientAuth, ClientAuthRequire) {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	default:
		return nil, fmt.Errorf("unknown client auth %q", s.ClientAuth)
	}
	return cfg, nil
}

// Client describes how MailOS dials a TLS server.
type Client struct {
	CAFile     string // empty: system roots
	CertFile   string // client certificate (mutual TLS)
	KeyFile    string
	ServerName string
}

// NewClient verifies the server against CAFile (or the system roots) and
// presents the client certificate when one is configured.
func NewClient(c Client) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: cipherSuites, ServerName: c.ServerName}
	if c.CAFile != "" {
		pool, err := LoadPool(c.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if c.CertFile != "" || c.KeyFile != "" {
		pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls client key pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// LoadPool reads a PEM bundle of CA certificates.
func LoadPool(file string) (*x509.CertPool, error) {
	if file == "" {
		return nil, errors.New("a CA file is required")
	}
	pem, err := os.ReadFile(file) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s has no certificates", file)
	}
	return pool, nil
}
