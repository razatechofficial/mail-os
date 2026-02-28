package analytics

import (
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type RecordEventInput struct {
	MessageID string
	OrgID    string
	Type     domain.EventType
	Provider string
	Metadata map[string]any
}

type StatsParams struct {
	PeriodType domain.PeriodType
	From       time.Time
	To         time.Time
}

type AuditLogParams struct {
	Resource string
	pagination.Params
}

type AuditLogInput struct {
	OrgID      string
	ActorType  domain.ActorType
	ActorID    string
	Action     string
	Resource   string
	ResourceID string
	IPAddress  string
	UserAgent  string
	Changes    map[string]any
}
