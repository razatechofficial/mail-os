package sendingdomain

import "github.com/razatechofficial/mail-os/pkg/pagination"

type CreateInput struct {
	OrgID  string
	Domain string
}

type ListParams struct {
	pagination.Params
}
