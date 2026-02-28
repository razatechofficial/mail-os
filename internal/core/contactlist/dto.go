package contactlist

import (
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type CreateInput struct {
	OrgID       string
	Name        string
	Description string
	Type        domain.ListType
	Query       string
}

type UpdateInput struct {
	Name        *string
	Description *string
	Type        *domain.ListType
	Query       *string
}

type ListParams struct {
	pagination.Params
}
