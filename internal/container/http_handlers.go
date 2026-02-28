package container

import (
	v1 "github.com/razatechofficial/mail-os/internal/adapter/inbound/http/handler/v1"
)

type HTTPHandlers struct {
	Organization  *v1.OrganizationHandler
	APIKey        *v1.APIKeyHandler
	SendingDomain *v1.SendingDomainHandler
	Provider      *v1.ProviderHandler
	Template      *v1.TemplateHandler
	Contact       *v1.ContactHandler
	ContactList   *v1.ContactListHandler
	Campaign      *v1.CampaignHandler
	Message       *v1.MessageHandler
	Suppression   *v1.SuppressionHandler
	Webhook       *v1.WebhookHandler
	Analytics     *v1.AnalyticsHandler
	Health        *v1.HealthHandler
}

func (c *Container) buildHTTPHandlers() *HTTPHandlers {
	return &HTTPHandlers{
		Organization:  v1.NewOrganizationHandler(c.Services.Organization),
		APIKey:        v1.NewAPIKeyHandler(c.Services.APIKey),
		SendingDomain: v1.NewSendingDomainHandler(c.Services.SendingDomain),
		Provider:      v1.NewProviderHandler(c.Services.Provider),
		Template:      v1.NewTemplateHandler(c.Services.Template),
		Contact:       v1.NewContactHandler(c.Services.Contact),
		ContactList:   v1.NewContactListHandler(c.Services.ContactList),
		Campaign:      v1.NewCampaignHandler(c.Services.Campaign),
		Message:       v1.NewMessageHandler(c.Services.Message),
		Suppression:   v1.NewSuppressionHandler(c.Services.Suppression),
		Webhook:       v1.NewWebhookHandler(c.Services.Webhook),
		Analytics:     v1.NewAnalyticsHandler(c.Services.Analytics),
		Health:        v1.NewHealthHandler(c.DB),
	}
}
