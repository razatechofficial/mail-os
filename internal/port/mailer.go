package port

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type SendRequest struct {
	FromName  string
	FromEmail string
	ToEmail   string
	ToName    string
	Subject   string
	HTMLBody  string
	TextBody  string
	Tags      []string
	Metadata  map[string]any
}

type SendResult struct {
	ProviderMsgID string
	Provider      string
}

type EmailSender interface {
	Send(ctx context.Context, req SendRequest) (*SendResult, error)
	Name() string
}

type ProviderRouter interface {
	Route(ctx context.Context, orgID domain.OrganizationID, req SendRequest) (*SendResult, error)
}
