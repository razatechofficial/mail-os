package webhook

import "github.com/razatechofficial/mail-os/pkg/pagination"

type CreateInput struct {
	OrgID  string
	URL    string
	Secret string
	Events []string
}

type UpdateInput struct {
	URL      *string
	Secret   *string
	Events   *[]string
	IsActive *bool
}

type ListParams struct {
	OrgID string
	pagination.Params
}
