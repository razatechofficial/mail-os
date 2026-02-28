package apikey

import (
	"time"

	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type CreateInput struct {
	OrgID     string
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

type ListParams struct {
	pagination.Params
}
