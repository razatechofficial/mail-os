package container

import (
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
	tmpl "github.com/razatechofficial/mail-os/internal/core/template"
	"github.com/razatechofficial/mail-os/internal/core/webhook"
)

type Services struct {
	Organization  organization.Service
	APIKey        apikey.Service
	SendingDomain sendingdomain.Service
	Provider      provider.Service
	Template      tmpl.Service
	Contact       contact.Service
	ContactList   contactlist.Service
	Campaign      campaign.Service
	Message       message.Service
	Suppression   suppression.Service
	Webhook       webhook.Service
	Analytics     analytics.Service
}

func (c *Container) buildServices() *Services {
	// Phase 1: independent services (no cross-module deps)
	orgSvc := organization.NewService(c.Repos.Organization)
	apiKeySvc := apikey.NewService(c.Repos.APIKey, c.Adapters.Hasher)
	domainSvc := sendingdomain.NewService(c.Repos.SendingDomain)
	providerSvc := provider.NewService(c.Repos.Provider, c.Adapters.Encryptor)
	templateSvc := tmpl.NewService(
		c.Repos.Template,
		c.Adapters.Renderer,
		tmpl.WithCache(c.Adapters.Cache),
		tmpl.WithEventPublisher(c.Adapters.EventBus),
	)
	contactSvc := contact.NewService(c.Repos.Contact)
	contactListSvc := contactlist.NewService(c.Repos.ContactList)
	suppressionSvc := suppression.NewService(c.Repos.Suppression)
	webhookSvc := webhook.NewService(c.Repos.Webhook, c.Adapters.Signer)
	analyticsSvc := analytics.NewService(c.Repos.Stats, c.Repos.AuditLog, c.Repos.MessageEvent)

	// Phase 2: cross-module adapters
	suppChecker := &suppressionCheckerAdapter{svc: suppressionSvc}
	quotaChecker := &quotaCheckerAdapter{svc: orgSvc}

	// Phase 3: dependent services
	campaignSvc := campaign.NewService(c.Repos.Campaign, c.Pub)

	messageSvc := message.NewService(
		c.Repos.Message,
		suppChecker,
		quotaChecker,
		c.Adapters.Renderer,
		c.Pub,
		c.Adapters.TxManager,
		c.Adapters.EventBus,
	)

	// Phase 4: two-phase setter injection for campaign <-> message
	msgEnqueuer := &messageEnqueuerAdapter{svc: messageSvc}
	if setter, ok := campaignSvc.(campaign.MessageEnqueuerSetter); ok {
		setter.SetMessageEnqueuer(msgEnqueuer)
	}

	return &Services{
		Organization:  orgSvc,
		APIKey:        apiKeySvc,
		SendingDomain: domainSvc,
		Provider:      providerSvc,
		Template:      templateSvc,
		Contact:       contactSvc,
		ContactList:   contactListSvc,
		Campaign:      campaignSvc,
		Message:       messageSvc,
		Suppression:   suppressionSvc,
		Webhook:       webhookSvc,
		Analytics:     analyticsSvc,
	}
}
