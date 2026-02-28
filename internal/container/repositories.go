package container

import (
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/postgres"
	"github.com/razatechofficial/mail-os/internal/core/analytics"
	"github.com/razatechofficial/mail-os/internal/core/apikey"
	"github.com/razatechofficial/mail-os/internal/core/campaign"
	"github.com/razatechofficial/mail-os/internal/core/contact"
	"github.com/razatechofficial/mail-os/internal/core/contactlist"
	"github.com/razatechofficial/mail-os/internal/core/message"
	"github.com/razatechofficial/mail-os/internal/core/organization"
	"github.com/razatechofficial/mail-os/internal/core/provider"
	"github.com/razatechofficial/mail-os/internal/core/sendingdomain"
	"github.com/razatechofficial/mail-os/internal/core/suppression"
	"github.com/razatechofficial/mail-os/internal/core/template"
	"github.com/razatechofficial/mail-os/internal/core/webhook"
)

type Repositories struct {
	Organization  organization.Repository
	APIKey        apikey.Repository
	SendingDomain sendingdomain.Repository
	Provider      provider.Repository
	Template      template.Repository
	Contact       contact.Repository
	ContactList   contactlist.Repository
	Campaign      campaign.Repository
	Message       message.Repository
	Suppression   suppression.Repository
	Webhook       webhook.Repository
	Stats         analytics.StatsRepository
	AuditLog      analytics.AuditLogRepository
	MessageEvent  analytics.MessageEventRepository
}

func (c *Container) buildRepositories() *Repositories {
	pool := c.DB.Pool

	return &Repositories{
		Organization:  postgres.NewOrganizationRepo(pool),
		APIKey:        postgres.NewAPIKeyRepo(pool),
		SendingDomain: postgres.NewSendingDomainRepo(pool),
		Provider:      postgres.NewProviderRepo(pool),
		Template:      postgres.NewTemplateRepo(pool),
		Contact:       postgres.NewContactRepo(pool),
		ContactList:   postgres.NewContactListRepo(pool),
		Campaign:      postgres.NewCampaignRepo(pool),
		Message:       postgres.NewMessageRepo(pool),
		Suppression:   postgres.NewSuppressionRepo(pool),
		Webhook:       postgres.NewWebhookRepo(pool),
		Stats:         postgres.NewSendingStatsRepo(pool),
		AuditLog:      postgres.NewAuditLogRepo(pool),
		MessageEvent:  postgres.NewMessageEventRepo(pool),
	}
}
