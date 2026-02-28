package message

import (
	"time"

	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type SendEmailInput struct {
	OrgID           string
	FromName        string
	FromEmail       string
	ToEmail         string
	ToName          string
	Subject         string
	HTMLBody        string
	TextBody        string
	TemplateSlug    string
	TemplateVars    map[string]any
	Tags            []string
	Metadata        map[string]any
	Priority        int
	IdempotencyKey  string
	ScheduleAt      *time.Time
}

type SendEmailOutput struct {
	MessageID string
	Status    string
}

type BatchSendInput struct {
	OrgID    string
	Messages []SendEmailInput
}

type BatchSendOutput struct {
	Results     []SendEmailOutput
	SuccessCount int
	FailCount   int
}

type ScheduleEmailInput struct {
	SendEmailInput
	ScheduleAt time.Time
}

type ProcessEmailInput struct {
	MessageID string
}

type MessageListParams struct {
	OrgID   string
	Status  string
	Type    string
	pagination.Params
}
