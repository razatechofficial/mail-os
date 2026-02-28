package domain

import "time"

type JobStatus string

const (
	JobStatusPending    JobStatus = "pending"
	JobStatusProcessing JobStatus = "processing"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
	JobStatusDead       JobStatus = "dead"
)

type ScheduledJob struct {
	ID          string
	OrgID       OrganizationID
	Type        string
	Payload     map[string]any
	Status      JobStatus
	RunAt       time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	Attempts    int
	MaxAttempts int
	LastError   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
