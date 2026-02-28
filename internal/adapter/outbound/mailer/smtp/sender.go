package smtp

import (
	"bytes"
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/google/uuid"
	"github.com/razatechofficial/mail-os/internal/port"
)

var _ port.EmailSender = (*sender)(nil)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	FromAddr string
}

type sender struct {
	cfg Config
}

func New(cfg Config) port.EmailSender {
	return &sender{cfg: cfg}
}

func (s *sender) Name() string {
	return "smtp"
}

func (s *sender) Send(ctx context.Context, req port.SendRequest) (*port.SendResult, error) {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	msg := s.buildMessage(req)

	var auth smtp.Auth
	if s.cfg.Username != "" && s.cfg.Password != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}

	if err := smtp.SendMail(addr, auth, s.cfg.FromAddr, []string{req.ToEmail}, msg); err != nil {
		return nil, err
	}

	return &port.SendResult{
		ProviderMsgID: uuid.New().String(),
		Provider:      s.Name(),
	}, nil
}

func (s *sender) buildMessage(req port.SendRequest) []byte {
	var b bytes.Buffer

	from := s.formatAddr(req.FromName, req.FromEmail)
	to := s.formatAddr(req.ToName, req.ToEmail)

	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + s.encodeHeader(req.Subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")

	if req.HTMLBody != "" && req.TextBody != "" {
		boundary := "----=" + uuid.New().String()
		b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(req.TextBody + "\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		b.WriteString(req.HTMLBody + "\r\n")
		b.WriteString("--" + boundary + "--\r\n")
	} else if req.HTMLBody != "" {
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		b.WriteString(req.HTMLBody + "\r\n")
	} else {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(req.TextBody + "\r\n")
	}

	return b.Bytes()
}

func (s *sender) formatAddr(name, email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}
	if name != "" {
		return fmt.Sprintf("%s <%s>", s.encodeHeader(name), email)
	}
	return email
}

func (s *sender) encodeHeader(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", " ")
	return v
}
