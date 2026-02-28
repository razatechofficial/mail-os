package domain

import "time"

type SendingDomainID string

type DomainStatus string

const (
	DomainStatusPending  DomainStatus = "pending"
	DomainStatusVerified DomainStatus = "verified"
	DomainStatusFailed   DomainStatus = "failed"
)

type SendingDomain struct {
	ID             SendingDomainID
	OrgID          OrganizationID
	Domain         string
	DKIMPublicKey  string
	DKIMPrivateKey string
	SPFRecord      string
	DMARCRecord    string
	Status         DomainStatus
	VerifiedAt     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
}
