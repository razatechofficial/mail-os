package organization

import "github.com/razatechofficial/mail-os/pkg/pagination"

type CreateInput struct {
	Name          string
	Slug          string
	WebhookURL    string
	WebhookSecret string
	Settings      map[string]any
}

type UpdateInput struct {
	Name          *string
	WebhookURL    *string
	WebhookSecret *string
	Settings      map[string]any
	IsActive      *bool
}

type ListParams struct {
	pagination.Params
}
