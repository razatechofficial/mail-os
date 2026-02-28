package contact

import "github.com/razatechofficial/mail-os/pkg/pagination"

type CreateInput struct {
	OrgID     string
	Email     string
	FirstName string
	LastName  string
	Metadata  map[string]any
}

type UpdateInput struct {
	Email     *string
	FirstName *string
	LastName  *string
	Metadata  *map[string]any
}

type ListParams struct {
	OrgID  string
	Status string
	Search string
	pagination.Params
}
