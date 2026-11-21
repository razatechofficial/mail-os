package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ACS is the central authorization service (MailOS ADR 0001 §3.4): MailOS
// checks every platform API request there, and writes the platform role
// activations the IAM attests. With no endpoint the platform API is off
// (its routes answer 503); the tenant plane does not use ACS yet.
//
// MailOS reaches ACS's app gateway over gRPC with its own client
// certificate and an access token for api://acs the IAM issues to that
// certificate (client credentials, tls_client_auth).
type ACS struct {
	// Endpoint is the app gateway (host:port); ServerName its certificate
	// name when it is not the endpoint's host.
	Endpoint   string `yaml:"endpoint" env:"ACS_ENDPOINT" env-default:""`
	ServerName string `yaml:"server_name" env:"ACS_SERVER_NAME" env-default:""`
	// CAFile verifies ACS's and the IAM token endpoint's certificates
	// (system roots when empty).
	CAFile string `yaml:"ca_file" env:"ACS_CA_FILE" env-default:""`
	// CertFile and KeyFile are MailOS's client certificate at ACS and at
	// the IAM's token endpoint.
	CertFile string `yaml:"cert_file" env:"ACS_CERT_FILE" env-default:""`
	KeyFile  string `yaml:"key_file" env:"ACS_KEY_FILE" env-default:""`
	// TokenURL is the IAM's token endpoint; ClientID MailOS's OAuth client
	// registered for ACS.
	TokenURL string `yaml:"token_url" env:"ACS_TOKEN_URL" env-default:""`
	ClientID string `yaml:"client_id" env:"ACS_CLIENT_ID" env-default:""`
	// Insecure dials ACS in plaintext without a client certificate: local,
	// test and e2e only.
	Insecure bool `yaml:"insecure" env:"ACS_INSECURE" env-default:"false"`
	// Timeout bounds each ACS call.
	Timeout time.Duration `yaml:"timeout" env:"ACS_TIMEOUT" env-default:"3s"`
}

// Enabled reports whether ACS is configured.
func (a ACS) Enabled() bool { return strings.TrimSpace(a.Endpoint) != "" }

func (a ACS) validate(plaintext bool) error {
	if !a.Enabled() {
		return nil
	}
	if _, _, err := net.SplitHostPort(a.Endpoint); err != nil {
		return fmt.Errorf("ACS_ENDPOINT must be host:port: %v", err)
	}
	if strings.TrimSpace(a.ClientID) == "" {
		return fmt.Errorf("ACS_CLIENT_ID is required when ACS_ENDPOINT is set")
	}
	u, err := url.Parse(a.TokenURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("ACS_TOKEN_URL must be the IAM's token endpoint (an absolute URL) when ACS_ENDPOINT is set")
	}
	if a.Timeout < 100*time.Millisecond || a.Timeout > 30*time.Second {
		return fmt.Errorf("ACS_TIMEOUT must be between 100ms and 30s")
	}
	if a.Insecure {
		if !plaintext {
			return fmt.Errorf("ACS_INSECURE is refused outside local and test")
		}
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("ACS_TOKEN_URL must be https unless ACS_INSECURE")
	}
	if a.CertFile == "" || a.KeyFile == "" {
		return fmt.Errorf("ACS_CERT_FILE and ACS_KEY_FILE (MailOS's client certificate) are required when ACS_ENDPOINT is set")
	}
	return nil
}
