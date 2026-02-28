package suppression

import (
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type AddInput struct {
	OrgID  string
	Email  string
	Type   domain.SuppressionType
	Reason string
	Source string
}

type ListParams struct {
	OrgID  string
	Type   string
	pagination.Params
}
