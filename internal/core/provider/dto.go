package provider

import (
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type CreateInput struct {
	OrgID         string
	Name          string
	Type          domain.ProviderType
	Configuration map[string]any
	Priority      int
	Weight        int
	DailyLimit    int
}

type UpdateInput struct {
	Name          *string
	Configuration map[string]any
	Priority      *int
	Weight        *int
	DailyLimit    *int
	IsActive      *bool
}

type ListParams struct {
	pagination.Params
}
