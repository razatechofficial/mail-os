package dto

import (
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type CreateOrganizationRequest struct {
	Name          string         `json:"name" binding:"required"`
	Slug          string         `json:"slug" binding:"required"`
	WebhookURL    string         `json:"webhook_url"`
	WebhookSecret string         `json:"webhook_secret"`
	Settings      map[string]any `json:"settings"`
}

type UpdateOrganizationRequest struct {
	Name          *string         `json:"name"`
	WebhookURL    *string         `json:"webhook_url"`
	WebhookSecret *string         `json:"webhook_secret"`
	Settings      map[string]any  `json:"settings"`
	IsActive      *bool           `json:"is_active"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type CreateSendingDomainRequest struct {
	Domain string `json:"domain" binding:"required"`
}

type CreateProviderRequest struct {
	Name          string         `json:"name" binding:"required"`
	Type          domain.ProviderType `json:"type" binding:"required"`
	Configuration map[string]any `json:"configuration"`
	Priority      int            `json:"priority"`
	Weight        int            `json:"weight"`
	DailyLimit    int            `json:"daily_limit"`
}

type UpdateProviderRequest struct {
	Name          *string         `json:"name"`
	Configuration map[string]any  `json:"configuration"`
	Priority      *int            `json:"priority"`
	Weight        *int            `json:"weight"`
	DailyLimit    *int            `json:"daily_limit"`
	IsActive      *bool           `json:"is_active"`
}

type CreateTemplateRequest struct {
	Name        string                   `json:"name" binding:"required"`
	Slug        string                   `json:"slug" binding:"required"`
	Description string                   `json:"description"`
	Category    domain.TemplateCategory  `json:"category"`
}

type UpdateTemplateRequest struct {
	Name        *string                  `json:"name"`
	Slug        *string                  `json:"slug"`
	Description *string                  `json:"description"`
	Category    *domain.TemplateCategory `json:"category"`
	IsActive    *bool                    `json:"is_active"`
}

type CreateTemplateVersionRequest struct {
	Subject  string   `json:"subject" binding:"required"`
	HTMLBody string   `json:"html_body"`
	TextBody string   `json:"text_body"`
	Variables []string `json:"variables"`
}

type CreateContactRequest struct {
	Email     string         `json:"email" binding:"required,email"`
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Metadata  map[string]any `json:"metadata"`
}

type UpdateContactRequest struct {
	Email     *string         `json:"email"`
	FirstName *string         `json:"first_name"`
	LastName  *string         `json:"last_name"`
	Metadata  *map[string]any `json:"metadata"`
}

type BatchCreateContactsRequest struct {
	Contacts []CreateContactRequest `json:"contacts" binding:"required,dive"`
}

type CreateContactListRequest struct {
	Name        string              `json:"name" binding:"required"`
	Description string              `json:"description"`
	Type        domain.ListType     `json:"type"`
	Query       string              `json:"query"`
}

type UpdateContactListRequest struct {
	Name        *string             `json:"name"`
	Description *string             `json:"description"`
	Type        *domain.ListType    `json:"type"`
	Query       *string             `json:"query"`
}

type AddMembersRequest struct {
	ContactIDs []string `json:"contact_ids" binding:"required"`
}

type RemoveMembersRequest struct {
	ContactIDs []string `json:"contact_ids" binding:"required"`
}

type CreateCampaignRequest struct {
	Name          string                 `json:"name" binding:"required"`
	Subject       string                 `json:"subject" binding:"required"`
	FromName      string                 `json:"from_name" binding:"required"`
	FromEmail     string                 `json:"from_email" binding:"required,email"`
	TemplateID    string                 `json:"template_id" binding:"required"`
	ContactListID string                 `json:"contact_list_id" binding:"required"`
	Type          domain.CampaignType    `json:"type"`
	ScheduledAt   *time.Time             `json:"scheduled_at"`
	Metadata      map[string]any         `json:"metadata"`
}

type UpdateCampaignRequest struct {
	Name          *string                `json:"name"`
	Subject       *string                `json:"subject"`
	FromName      *string                `json:"from_name"`
	FromEmail     *string                `json:"from_email"`
	TemplateID    *string                `json:"template_id"`
	ContactListID *string                `json:"contact_list_id"`
	Type          *domain.CampaignType   `json:"type"`
	ScheduledAt   *time.Time             `json:"scheduled_at"`
	Metadata      *map[string]any         `json:"metadata"`
}

type SendEmailRequest struct {
	FromName       string         `json:"from_name" binding:"required"`
	FromEmail      string         `json:"from_email" binding:"required,email"`
	ToEmail        string         `json:"to_email" binding:"required,email"`
	ToName         string         `json:"to_name"`
	Subject        string         `json:"subject" binding:"required"`
	HTMLBody       string         `json:"html_body"`
	TextBody       string         `json:"text_body"`
	TemplateSlug   string         `json:"template_slug"`
	TemplateVars   map[string]any `json:"template_vars"`
	Tags           []string       `json:"tags"`
	Metadata       map[string]any `json:"metadata"`
	Priority       int            `json:"priority"`
	IdempotencyKey string        `json:"idempotency_key"`
	ScheduleAt     *time.Time    `json:"schedule_at"`
}

type BatchSendEmailRequest struct {
	Messages []SendEmailRequest `json:"messages" binding:"required,dive"`
}

type AddSuppressionRequest struct {
	Email  string                 `json:"email" binding:"required,email"`
	Type   domain.SuppressionType `json:"type" binding:"required"`
	Reason string                 `json:"reason"`
	Source string                 `json:"source"`
}

type RemoveSuppressionRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type CreateWebhookRequest struct {
	URL    string   `json:"url" binding:"required"`
	Secret string   `json:"secret"`
	Events []string `json:"events"`
}

type UpdateWebhookRequest struct {
	URL      *string  `json:"url"`
	Secret   *string  `json:"secret"`
	Events   *[]string `json:"events"`
	IsActive *bool    `json:"is_active"`
}
