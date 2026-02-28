package campaign

import (
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type CreateInput struct {
	OrgID         string
	Name          string
	Subject       string
	FromName      string
	FromEmail     string
	TemplateID    string
	ContactListID string
	Type          domain.CampaignType
	ScheduledAt   *time.Time
	Metadata      map[string]any
}

type UpdateInput struct {
	Name          *string
	Subject       *string
	FromName      *string
	FromEmail     *string
	TemplateID    *string
	ContactListID *string
	Type          *domain.CampaignType
	ScheduledAt   *time.Time
	Metadata      *map[string]any
}

type ListParams struct {
	pagination.Params
}
