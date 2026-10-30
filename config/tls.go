package config

import (
	"fmt"
	"strings"
)

// Client certificate policies for a listener (mutual TLS).
const (
	ClientAuthNone    = "none"
	ClientAuthRequest = "request" // verify a certificate when one is sent
	ClientAuthRequire = "require" // refuse a connection without one
)

// ServerTLS is a listener's TLS (contract §2: TLS 1.2+, optional mTLS).
type ServerTLS struct {
	CertFile string `yaml:"cert_file" env:"CERT_FILE" env-default:""`
	KeyFile  string `yaml:"key_file" env:"KEY_FILE" env-default:""`
	// ClientCAFile verifies client certificates; set it with ClientAuth.
	ClientCAFile string `yaml:"client_ca_file" env:"CLIENT_CA_FILE" env-default:""`
	ClientAuth   string `yaml:"client_auth" env:"CLIENT_AUTH" env-default:"none"`
	// MinVersion is 1.2 or 1.3.
	MinVersion string `yaml:"min_version" env:"MIN_VERSION" env-default:"1.2"`
}

// Enabled reports whether the listener serves TLS.
func (t ServerTLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

// validate refuses a plaintext listener outside local and test, half a key
// pair, and mutual TLS without a CA.
func (t ServerTLS) validate(name string, plaintext bool) error {
	if (t.CertFile == "") != (t.KeyFile == "") {
		return fmt.Errorf("%s_TLS_CERT_FILE and %s_TLS_KEY_FILE must be set together", name, name)
	}
	if !t.Enabled() && !plaintext {
		return fmt.Errorf("%s_TLS_CERT_FILE and %s_TLS_KEY_FILE are required outside local and test (contract §2: no plaintext)", name, name)
	}
	switch t.MinVersion {
	case "1.2", "1.3":
	default:
		return fmt.Errorf("%s_TLS_MIN_VERSION must be 1.2 or 1.3", name)
	}
	switch strings.ToLower(t.ClientAuth) {
	case ClientAuthNone:
		if t.ClientCAFile != "" {
			return fmt.Errorf("%s_TLS_CLIENT_CA_FILE is set but %s_TLS_CLIENT_AUTH is none", name, name)
		}
	case ClientAuthRequest, ClientAuthRequire:
		if !t.Enabled() || t.ClientCAFile == "" {
			return fmt.Errorf("%s mutual TLS needs a server certificate and %s_TLS_CLIENT_CA_FILE", name, name)
		}
	default:
		return fmt.Errorf("%s_TLS_CLIENT_AUTH must be none, request or require", name)
	}
	return nil
}

// ClientTLS is how MailOS dials a TLS server (Kafka).
type ClientTLS struct {
	Enabled bool `yaml:"enabled" env:"ENABLED" env-default:"false"`
	// CAFile verifies the server; empty uses the system roots.
	CAFile string `yaml:"ca_file" env:"CA_FILE" env-default:""`
	// CertFile and KeyFile are MailOS's client certificate (mutual TLS).
	CertFile   string `yaml:"cert_file" env:"CERT_FILE" env-default:""`
	KeyFile    string `yaml:"key_file" env:"KEY_FILE" env-default:""`
	ServerName string `yaml:"server_name" env:"SERVER_NAME" env-default:""`
}

func (t ClientTLS) validate(name string, plaintext bool) error {
	if !t.Enabled && !plaintext {
		return fmt.Errorf("%s_TLS_ENABLED must be true outside local and test (contract §2: no plaintext)", name)
	}
	if (t.CertFile == "") != (t.KeyFile == "") {
		return fmt.Errorf("%s_TLS_CERT_FILE and %s_TLS_KEY_FILE must be set together", name, name)
	}
	return nil
}

// validate checks the broker connection used by the event consumer and the
// audit stream.
func (k Kafka) validate(plaintext bool) error {
	if len(k.Brokers) == 0 {
		return fmt.Errorf("KAFKA_BROKERS is required when FEATURE_PUBSUB_INGEST or FEATURE_AUDIT_STREAM is on")
	}
	if strings.TrimSpace(k.GroupID) == "" {
		return fmt.Errorf("KAFKA_GROUP_ID is required")
	}
	if err := k.TLS.validate("KAFKA", plaintext); err != nil {
		return err
	}
	switch k.SASL.Mechanism {
	case SASLNone, "":
		if !plaintext {
			return fmt.Errorf("KAFKA_SASL_MECHANISM must be %s or %s outside local and test", SASLScramSHA512, SASLOAuthBearer)
		}
	case SASLScramSHA512:
		if k.SASL.Username == "" || k.SASL.Password == "" {
			return fmt.Errorf("KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD are required for SCRAM-SHA-512")
		}
	case SASLOAuthBearer:
		if k.SASL.TokenURL == "" || k.SASL.ClientID == "" || k.SASL.ClientSecret == "" {
			return fmt.Errorf("KAFKA_SASL_TOKEN_URL, KAFKA_SASL_CLIENT_ID and KAFKA_SASL_CLIENT_SECRET are required for OAUTHBEARER")
		}
		if !plaintext && !strings.HasPrefix(strings.ToLower(k.SASL.TokenURL), "https://") {
			return fmt.Errorf("KAFKA_SASL_TOKEN_URL must be https outside local and test")
		}
	default:
		return fmt.Errorf("KAFKA_SASL_MECHANISM must be none, %s or %s", SASLScramSHA512, SASLOAuthBearer)
	}
	return nil
}

// validate refuses the platform relay without TLS outside local and test.
func (s SMTP) validate(plaintext bool) error {
	if !s.Enabled {
		return nil
	}
	if s.Host == "" || s.Port < 1 || s.FromAddr == "" {
		return fmt.Errorf("SMTP_HOST, SMTP_PORT and SMTP_FROM_ADDR are required when SMTP_ENABLED is true")
	}
	switch s.TLSMode {
	case SMTPTLSStartTLS, SMTPTLSImplicit:
	case SMTPTLSNone:
		if !plaintext {
			return fmt.Errorf("SMTP_TLS_MODE none is refused outside local and test")
		}
	default:
		return fmt.Errorf("SMTP_TLS_MODE must be starttls, implicit or none")
	}
	return nil
}
