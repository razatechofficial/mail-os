package http

import (
	"github.com/gin-gonic/gin"
	v1 "github.com/razatechofficial/mail-os/internal/adapter/inbound/http/handler/v1"
)

type Handlers struct {
	Organization   *v1.OrganizationHandler
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

func (s *Server) RegisterRoutes(h *Handlers, middlewares ...gin.HandlerFunc) {
	s.engine.Use(middlewares...)

	s.engine.GET("/health", h.Health.Health)
	s.engine.GET("/ready", h.Health.Ready)

	api := s.engine.Group("/api/v1")
	{
		orgs := api.Group("/organizations")
		{
			orgs.POST("", h.Organization.Create)
			orgs.GET("/:id", h.Organization.GetByID)
			orgs.PUT("/:id", h.Organization.Update)
			orgs.DELETE("/:id", h.Organization.Delete)
			orgs.GET("", h.Organization.List)
		}

		keys := api.Group("/api-keys")
		{
			keys.POST("", h.APIKey.Create)
			keys.GET("/:id", h.APIKey.GetByID)
			keys.DELETE("/:id", h.APIKey.Revoke)
			keys.GET("", h.APIKey.List)
		}

		domains := api.Group("/sending-domains")
		{
			domains.POST("", h.SendingDomain.Create)
			domains.GET("/:id", h.SendingDomain.GetByID)
			domains.POST("/:id/verify", h.SendingDomain.Verify)
			domains.DELETE("/:id", h.SendingDomain.Delete)
			domains.GET("", h.SendingDomain.List)
		}

		providers := api.Group("/providers")
		{
			providers.POST("", h.Provider.Create)
			providers.GET("/:id", h.Provider.GetByID)
			providers.PUT("/:id", h.Provider.Update)
			providers.DELETE("/:id", h.Provider.Delete)
			providers.GET("", h.Provider.List)
		}

		templates := api.Group("/templates")
		{
			templates.POST("", h.Template.Create)
			templates.GET("/:id", h.Template.GetByID)
			templates.PUT("/:id", h.Template.Update)
			templates.DELETE("/:id", h.Template.Delete)
			templates.GET("", h.Template.List)
			templates.GET("/:id/active-version", h.Template.GetActiveVersion)
			templates.POST("/:id/versions", h.Template.CreateVersion)
			templates.GET("/:id/versions", h.Template.ListVersions)
		}

		contacts := api.Group("/contacts")
		{
			contacts.POST("", h.Contact.Create)
			contacts.GET("/:id", h.Contact.GetByID)
			contacts.PUT("/:id", h.Contact.Update)
			contacts.DELETE("/:id", h.Contact.Delete)
			contacts.GET("", h.Contact.List)
			contacts.POST("/batch", h.Contact.BatchCreate)
		}

		lists := api.Group("/contact-lists")
		{
			lists.POST("", h.ContactList.Create)
			lists.GET("/:id", h.ContactList.GetByID)
			lists.PUT("/:id", h.ContactList.Update)
			lists.DELETE("/:id", h.ContactList.Delete)
			lists.GET("", h.ContactList.List)
			lists.POST("/:id/members", h.ContactList.AddMembers)
			lists.DELETE("/:id/members", h.ContactList.RemoveMembers)
			lists.GET("/:id/members", h.ContactList.ListMembers)
		}

		campaigns := api.Group("/campaigns")
		{
			campaigns.POST("", h.Campaign.Create)
			campaigns.GET("/:id", h.Campaign.GetByID)
			campaigns.PUT("/:id", h.Campaign.Update)
			campaigns.DELETE("/:id", h.Campaign.Delete)
			campaigns.GET("", h.Campaign.List)
			campaigns.POST("/:id/launch", h.Campaign.Launch)
			campaigns.POST("/:id/pause", h.Campaign.Pause)
			campaigns.POST("/:id/resume", h.Campaign.Resume)
			campaigns.POST("/:id/cancel", h.Campaign.Cancel)
		}

		messages := api.Group("/messages")
		{
			messages.POST("/send", h.Message.Send)
			messages.POST("/batch", h.Message.BatchSend)
			messages.GET("/:id", h.Message.GetByID)
			messages.GET("", h.Message.List)
			messages.POST("/:id/cancel", h.Message.Cancel)
		}

		suppressions := api.Group("/suppressions")
		{
			suppressions.POST("", h.Suppression.Add)
			suppressions.DELETE("", h.Suppression.Remove)
			suppressions.GET("", h.Suppression.List)
		}

		webhooks := api.Group("/webhooks")
		{
			webhooks.POST("", h.Webhook.Create)
			webhooks.GET("/:id", h.Webhook.GetByID)
			webhooks.PUT("/:id", h.Webhook.Update)
			webhooks.DELETE("/:id", h.Webhook.Delete)
			webhooks.GET("", h.Webhook.List)
		}

		analytics := api.Group("/analytics")
		{
			analytics.GET("/stats", h.Analytics.GetStats)
			analytics.GET("/audit-logs", h.Analytics.GetAuditLogs)
		}
	}
}
