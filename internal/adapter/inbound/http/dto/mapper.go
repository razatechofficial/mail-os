package dto

import (
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/internal/core/organization"
	"github.com/razatechofficial/mail-os/internal/core/apikey"
	"github.com/razatechofficial/mail-os/internal/core/sendingdomain"
	"github.com/razatechofficial/mail-os/internal/core/provider"
	"github.com/razatechofficial/mail-os/internal/core/template"
	"github.com/razatechofficial/mail-os/internal/core/contact"
	"github.com/razatechofficial/mail-os/internal/core/contactlist"
	"github.com/razatechofficial/mail-os/internal/core/campaign"
	"github.com/razatechofficial/mail-os/internal/core/message"
	"github.com/razatechofficial/mail-os/internal/core/suppression"
	"github.com/razatechofficial/mail-os/internal/core/webhook"
)

func CreateOrganizationReqToInput(req CreateOrganizationRequest) organization.CreateInput {
	return organization.CreateInput{
		Name:          req.Name,
		Slug:          req.Slug,
		WebhookURL:    req.WebhookURL,
		WebhookSecret: req.WebhookSecret,
		Settings:      req.Settings,
	}
}

func UpdateOrganizationReqToInput(req UpdateOrganizationRequest) organization.UpdateInput {
	return organization.UpdateInput{
		Name:          req.Name,
		WebhookURL:    req.WebhookURL,
		WebhookSecret: req.WebhookSecret,
		Settings:      req.Settings,
		IsActive:      req.IsActive,
	}
}

func OrganizationToResponse(o *domain.Organization) OrganizationResponse {
	return OrganizationResponse{
		ID:         string(o.ID),
		Name:       o.Name,
		Slug:       o.Slug,
		WebhookURL: o.WebhookURL,
		IsActive:   o.IsActive,
		Settings:   o.Settings,
		CreatedAt:  o.CreatedAt,
		UpdatedAt:  o.UpdatedAt,
	}
}

func CreateAPIKeyReqToInput(req CreateAPIKeyRequest, orgID string) apikey.CreateInput {
	return apikey.CreateInput{
		OrgID:     orgID,
		Name:      req.Name,
		Scopes:    req.Scopes,
		ExpiresAt: req.ExpiresAt,
	}
}

func APIKeyToResponse(k *domain.APIKey) APIKeyResponse {
	return APIKeyResponse{
		ID:         string(k.ID),
		Name:       k.Name,
		Prefix:     k.Prefix,
		Scopes:     k.Scopes,
		ExpiresAt:  k.ExpiresAt,
		LastUsedAt: k.LastUsedAt,
		IsActive:   k.IsActive,
		CreatedAt:  k.CreatedAt,
	}
}

func CreateSendingDomainReqToInput(req CreateSendingDomainRequest, orgID string) sendingdomain.CreateInput {
	return sendingdomain.CreateInput{
		OrgID:  orgID,
		Domain: req.Domain,
	}
}

func SendingDomainToResponse(s *domain.SendingDomain) SendingDomainResponse {
	return SendingDomainResponse{
		ID:         string(s.ID),
		Domain:     s.Domain,
		Status:     string(s.Status),
		VerifiedAt: s.VerifiedAt,
		CreatedAt:  s.CreatedAt,
		UpdatedAt:  s.UpdatedAt,
	}
}

func CreateProviderReqToInput(req CreateProviderRequest, orgID string) provider.CreateInput {
	return provider.CreateInput{
		OrgID:         orgID,
		Name:          req.Name,
		Type:          req.Type,
		Configuration: req.Configuration,
		Priority:      req.Priority,
		Weight:        req.Weight,
		DailyLimit:    req.DailyLimit,
	}
}

func UpdateProviderReqToInput(req UpdateProviderRequest) provider.UpdateInput {
	return provider.UpdateInput{
		Name:          req.Name,
		Configuration: req.Configuration,
		Priority:      req.Priority,
		Weight:        req.Weight,
		DailyLimit:    req.DailyLimit,
		IsActive:      req.IsActive,
	}
}

func ProviderToResponse(p *domain.Provider) ProviderResponse {
	return ProviderResponse{
		ID:            string(p.ID),
		Name:          p.Name,
		Type:          string(p.Type),
		Configuration: p.Configuration,
		Priority:      p.Priority,
		Weight:        p.Weight,
		DailyLimit:    p.DailyLimit,
		IsActive:      p.IsActive,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
	}
}

func CreateTemplateReqToInput(req CreateTemplateRequest, orgID string) template.CreateInput {
	return template.CreateInput{
		OrgID:       orgID,
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		Category:    req.Category,
	}
}

func UpdateTemplateReqToInput(req UpdateTemplateRequest) template.UpdateInput {
	return template.UpdateInput{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		Category:    req.Category,
		IsActive:    req.IsActive,
	}
}

func CreateTemplateVersionReqToInput(req CreateTemplateVersionRequest, templateID string) template.CreateVersionInput {
	return template.CreateVersionInput{
		TemplateID: templateID,
		Subject:    req.Subject,
		HTMLBody:   req.HTMLBody,
		TextBody:   req.TextBody,
		Variables:  req.Variables,
	}
}

func TemplateToResponse(t *domain.Template) TemplateResponse {
	return TemplateResponse{
		ID:          string(t.ID),
		Name:        t.Name,
		Slug:        t.Slug,
		Category:    string(t.Category),
		Description: t.Description,
		IsActive:    t.IsActive,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}

func TemplateVersionToResponse(v *domain.TemplateVersion) TemplateVersionResponse {
	return TemplateVersionResponse{
		ID:         string(v.ID),
		TemplateID: string(v.TemplateID),
		Version:    v.Version,
		Subject:    v.Subject,
		Variables:  v.Variables,
		IsActive:   v.IsActive,
		CreatedAt:  v.CreatedAt,
	}
}

func CreateContactReqToInput(req CreateContactRequest, orgID string) contact.CreateInput {
	return contact.CreateInput{
		OrgID:     orgID,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Metadata:  req.Metadata,
	}
}

func UpdateContactReqToInput(req UpdateContactRequest) contact.UpdateInput {
	return contact.UpdateInput{
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Metadata:  req.Metadata,
	}
}

func ContactToResponse(c *domain.Contact) ContactResponse {
	return ContactResponse{
		ID:        string(c.ID),
		Email:     c.Email,
		FirstName: c.FirstName,
		LastName:  c.LastName,
		Status:    string(c.Status),
		Metadata:  c.Metadata,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

func CreateContactListReqToInput(req CreateContactListRequest, orgID string) contactlist.CreateInput {
	return contactlist.CreateInput{
		OrgID:       orgID,
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Query:       req.Query,
	}
}

func UpdateContactListReqToInput(req UpdateContactListRequest) contactlist.UpdateInput {
	return contactlist.UpdateInput{
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Query:       req.Query,
	}
}

func ContactListToResponse(cl *domain.ContactList) ContactListResponse {
	return ContactListResponse{
		ID:          string(cl.ID),
		Name:        cl.Name,
		Description: cl.Description,
		Type:        string(cl.Type),
		Query:       cl.Query,
		CreatedAt:   cl.CreatedAt,
		UpdatedAt:   cl.UpdatedAt,
	}
}

func CreateCampaignReqToInput(req CreateCampaignRequest, orgID string) campaign.CreateInput {
	return campaign.CreateInput{
		OrgID:         orgID,
		Name:          req.Name,
		Subject:       req.Subject,
		FromName:      req.FromName,
		FromEmail:     req.FromEmail,
		TemplateID:    req.TemplateID,
		ContactListID: req.ContactListID,
		Type:          req.Type,
		ScheduledAt:   req.ScheduledAt,
		Metadata:      req.Metadata,
	}
}

func UpdateCampaignReqToInput(req UpdateCampaignRequest) campaign.UpdateInput {
	return campaign.UpdateInput{
		Name:          req.Name,
		Subject:       req.Subject,
		FromName:      req.FromName,
		FromEmail:     req.FromEmail,
		TemplateID:    req.TemplateID,
		ContactListID: req.ContactListID,
		Type:          req.Type,
		ScheduledAt:   req.ScheduledAt,
		Metadata:      req.Metadata,
	}
}

func CampaignToResponse(c *domain.Campaign) CampaignResponse {
	return CampaignResponse{
		ID:              string(c.ID),
		Name:            c.Name,
		Subject:         c.Subject,
		FromName:        c.FromName,
		FromEmail:       c.FromEmail,
		TemplateID:      string(c.TemplateID),
		ContactListID:   string(c.ContactListID),
		Type:            string(c.Type),
		Status:          string(c.Status),
		ScheduledAt:     c.ScheduledAt,
		TotalRecipients: c.TotalRecipients,
		SentCount:       c.SentCount,
		FailedCount:     c.FailedCount,
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
	}
}

func SendEmailReqToInput(req SendEmailRequest, orgID string) message.SendEmailInput {
	return message.SendEmailInput{
		OrgID:          orgID,
		FromName:       req.FromName,
		FromEmail:      req.FromEmail,
		ToEmail:        req.ToEmail,
		ToName:         req.ToName,
		Subject:        req.Subject,
		HTMLBody:       req.HTMLBody,
		TextBody:       req.TextBody,
		TemplateSlug:   req.TemplateSlug,
		TemplateVars:   req.TemplateVars,
		Tags:           req.Tags,
		Metadata:       req.Metadata,
		Priority:       req.Priority,
		IdempotencyKey: req.IdempotencyKey,
		ScheduleAt:     req.ScheduleAt,
	}
}

func MessageToResponse(m *domain.Message) MessageResponse {
	return MessageResponse{
		ID:        string(m.ID),
		CampaignID: string(m.CampaignID),
		FromName:  m.FromName,
		FromEmail: m.FromEmail,
		ToEmail:   m.ToEmail,
		ToName:    m.ToName,
		Subject:   m.Subject,
		Type:      string(m.Type),
		Status:    string(m.Status),
		Tags:      m.Tags,
		Metadata:  m.Metadata,
		SentAt:    m.SentAt,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}

func AddSuppressionReqToInput(req AddSuppressionRequest, orgID string) suppression.AddInput {
	return suppression.AddInput{
		OrgID:  orgID,
		Email:  req.Email,
		Type:   req.Type,
		Reason: req.Reason,
		Source: req.Source,
	}
}

func SuppressionToResponse(s *domain.Suppression) SuppressionResponse {
	return SuppressionResponse{
		ID:        s.ID,
		Email:     s.Email,
		Type:      string(s.Type),
		Reason:    s.Reason,
		Source:    s.Source,
		CreatedAt: s.CreatedAt,
	}
}

func CreateWebhookReqToInput(req CreateWebhookRequest, orgID string) webhook.CreateInput {
	return webhook.CreateInput{
		OrgID:  orgID,
		URL:    req.URL,
		Secret: req.Secret,
		Events: req.Events,
	}
}

func UpdateWebhookReqToInput(req UpdateWebhookRequest) webhook.UpdateInput {
	return webhook.UpdateInput{
		URL:      req.URL,
		Secret:   req.Secret,
		Events:   req.Events,
		IsActive: req.IsActive,
	}
}

func WebhookToResponse(w *domain.Webhook) WebhookResponse {
	return WebhookResponse{
		ID:        string(w.ID),
		URL:       w.URL,
		Events:    w.Events,
		IsActive:  w.IsActive,
		CreatedAt: w.CreatedAt,
		UpdatedAt: w.UpdatedAt,
	}
}

func SendingStatsToResponse(s *domain.SendingStats) StatsResponse {
	return StatsResponse{
		PeriodType:  string(s.PeriodType),
		PeriodStart: s.PeriodStart,
		Sent:        s.Sent,
		Delivered:   s.Delivered,
		Bounced:     s.Bounced,
		Complained:  s.Complained,
		Opened:      s.Opened,
		Clicked:     s.Clicked,
		Failed:      s.Failed,
	}
}

func AuditLogToResponse(a *domain.AuditLog) AuditLogResponse {
	return AuditLogResponse{
		ID:         a.ID,
		ActorType:  string(a.ActorType),
		ActorID:    a.ActorID,
		Action:     a.Action,
		Resource:   a.Resource,
		ResourceID: a.ResourceID,
		Changes:    a.Changes,
		IPAddress:  a.IPAddress,
		UserAgent:  a.UserAgent,
		CreatedAt:  a.CreatedAt,
	}
}
