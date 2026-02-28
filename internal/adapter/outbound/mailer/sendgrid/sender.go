package sendgrid

import (
	"context"
	"fmt"

	"github.com/razatechofficial/mail-os/internal/port"
)

var _ port.EmailSender = (*sender)(nil)

type Config struct {
	APIKey string
}

type sender struct {
	cfg Config
}

func New(cfg Config) port.EmailSender {
	return &sender{cfg: cfg}
}

func (s *sender) Name() string {
	return "sendgrid"
}

func (s *sender) Send(ctx context.Context, req port.SendRequest) (*port.SendResult, error) {
	return nil, fmt.Errorf("sendgrid: not implemented")
}
