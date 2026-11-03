package config

import (
	"fmt"
	"strings"
	"time"
)

// SMTPSubmission is the SMTP submission listener (transport/smtp): legacy
// applications that can only send over SMTP submit through it, under their
// MailOS application's rules. It is off unless enabled, and it never serves
// without TLS, in any environment: STARTTLS (RFC 3207) is required before
// AUTH or MAIL on Port, and ImplicitTLSPort, when set, is TLS from the first
// byte (RFC 8314).
type SMTPSubmission struct {
	Enabled bool   `yaml:"enabled" env:"SMTP_SUBMISSION_ENABLED" env-default:"false"`
	Host    string `yaml:"host" env:"SMTP_SUBMISSION_HOST" env-default:"0.0.0.0"`
	// Port is the submission port with STARTTLS (RFC 6409: 587).
	Port int `yaml:"port" env:"SMTP_SUBMISSION_PORT" env-default:"587"`
	// ImplicitTLSPort serves submission over implicit TLS (RFC 8314: 465);
	// 0 turns it off.
	ImplicitTLSPort int `yaml:"implicit_tls_port" env:"SMTP_SUBMISSION_IMPLICIT_TLS_PORT" env-default:"0"`
	// Hostname is the name in the greeting and EHLO reply, the name the
	// certificate is for.
	Hostname string `yaml:"hostname" env:"SMTP_SUBMISSION_HOSTNAME" env-default:"localhost"`
	// CertFile and KeyFile are the listener's certificate (reloaded on each
	// handshake, so a rotated certificate is served without a restart).
	CertFile string `yaml:"cert_file" env:"SMTP_SUBMISSION_TLS_CERT_FILE" env-default:""`
	KeyFile  string `yaml:"key_file" env:"SMTP_SUBMISSION_TLS_KEY_FILE" env-default:""`
	// MinTLSVersion is 1.2 or 1.3.
	MinTLSVersion string `yaml:"min_tls_version" env:"SMTP_SUBMISSION_TLS_MIN_VERSION" env-default:"1.2"`
	// PasswordAuth offers AUTH PLAIN and LOGIN for applications opted in to
	// SMTP credentials; off, only IAM tokens (OAUTHBEARER, XOAUTH2) are
	// accepted, whatever the applications say.
	PasswordAuth bool `yaml:"password_auth" env:"SMTP_SUBMISSION_PASSWORD_AUTH" env-default:"true"`
	// MaxMessageBytes is the SIZE limit (RFC 1870) of one message.
	MaxMessageBytes int64 `yaml:"max_message_bytes" env:"SMTP_SUBMISSION_MAX_MESSAGE_BYTES" env-default:"4194304"`
	// MaxRecipients bounds RCPT TO per message.
	MaxRecipients int `yaml:"max_recipients" env:"SMTP_SUBMISSION_MAX_RECIPIENTS" env-default:"50"`
	// MaxConnections and MaxConnectionsPerIP bound concurrent sessions; one
	// more is answered 421 and closed.
	MaxConnections      int `yaml:"max_connections" env:"SMTP_SUBMISSION_MAX_CONNECTIONS" env-default:"200"`
	MaxConnectionsPerIP int `yaml:"max_connections_per_ip" env:"SMTP_SUBMISSION_MAX_CONNECTIONS_PER_IP" env-default:"20"`
	// ReadTimeout is how long the server waits for a command or data line;
	// WriteTimeout bounds one reply.
	ReadTimeout  time.Duration `yaml:"read_timeout" env:"SMTP_SUBMISSION_READ_TIMEOUT" env-default:"2m"`
	WriteTimeout time.Duration `yaml:"write_timeout" env:"SMTP_SUBMISSION_WRITE_TIMEOUT" env-default:"1m"`
	// MaxSessionDuration closes a connection however busy it is.
	MaxSessionDuration time.Duration `yaml:"max_session_duration" env:"SMTP_SUBMISSION_MAX_SESSION_DURATION" env-default:"30m"`
	// AuthFailuresPerIP is how many failed AUTH attempts one address may
	// make in AuthFailureWindow before AUTH is refused from it (454).
	AuthFailuresPerIP int           `yaml:"auth_failures_per_ip" env:"SMTP_SUBMISSION_AUTH_FAILURES_PER_IP" env-default:"10"`
	AuthFailureWindow time.Duration `yaml:"auth_failure_window" env:"SMTP_SUBMISSION_AUTH_FAILURE_WINDOW" env-default:"15m"`
}

// Addr is host:port of the STARTTLS listener.
func (s SMTPSubmission) Addr() string { return fmt.Sprintf("%s:%d", s.Host, s.Port) }

// ImplicitAddr is host:port of the implicit TLS listener ("" when off).
func (s SMTPSubmission) ImplicitAddr() string {
	if s.ImplicitTLSPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", s.Host, s.ImplicitTLSPort)
}

func (s SMTPSubmission) validate() error {
	if !s.Enabled {
		return nil
	}
	if s.CertFile == "" || s.KeyFile == "" {
		return fmt.Errorf("SMTP_SUBMISSION_TLS_CERT_FILE and SMTP_SUBMISSION_TLS_KEY_FILE are required: SMTP submission never runs without TLS")
	}
	if s.Port < 1 || s.Port > 65535 || s.ImplicitTLSPort < 0 || s.ImplicitTLSPort > 65535 || s.ImplicitTLSPort == s.Port {
		return fmt.Errorf("SMTP_SUBMISSION_PORT must be a port, and SMTP_SUBMISSION_IMPLICIT_TLS_PORT 0 or another port")
	}
	if h := strings.TrimSpace(s.Hostname); h == "" || strings.ContainsAny(h, " \r\n") {
		return fmt.Errorf("SMTP_SUBMISSION_HOSTNAME must be a host name")
	}
	switch s.MinTLSVersion {
	case "1.2", "1.3":
	default:
		return fmt.Errorf("SMTP_SUBMISSION_TLS_MIN_VERSION must be 1.2 or 1.3")
	}
	if s.MaxMessageBytes < 64<<10 || s.MaxMessageBytes > 16<<20 {
		return fmt.Errorf("SMTP_SUBMISSION_MAX_MESSAGE_BYTES must be 64 KiB to 16 MiB")
	}
	if s.MaxRecipients < 1 || s.MaxRecipients > 1000 {
		return fmt.Errorf("SMTP_SUBMISSION_MAX_RECIPIENTS must be 1 to 1000")
	}
	if s.MaxConnections < 1 || s.MaxConnectionsPerIP < 1 || s.MaxConnectionsPerIP > s.MaxConnections {
		return fmt.Errorf("SMTP_SUBMISSION_MAX_CONNECTIONS and _PER_IP must be positive, per IP at most the total")
	}
	if s.ReadTimeout < 10*time.Second || s.WriteTimeout < 10*time.Second || s.MaxSessionDuration < time.Minute {
		return fmt.Errorf("SMTP_SUBMISSION read and write timeouts must be at least 10s, the session limit at least 1m")
	}
	if s.AuthFailuresPerIP < 1 || s.AuthFailureWindow < time.Minute {
		return fmt.Errorf("SMTP_SUBMISSION_AUTH_FAILURES_PER_IP must be positive and the window at least 1m")
	}
	return nil
}
