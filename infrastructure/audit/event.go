// Package audit writes MailOS's audit log in IAM's event format (contract
// §6): the same fields as IAM's iam.audit.events stream, a tier, and an RFC
// 5424 severity, so the bank's SIEM reads both products' events the same
// way. Every admin change and every service call is recorded with its
// actor, tenant and request ID; secrets are never written.
package audit

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/domain/access"
)

// Service names MailOS in every event (IAM's events say "iam" by stream).
const Service = "mailos"

// Tier separates security-critical events from high-volume activity.
const (
	TierCritical = "critical"
	TierActivity = "activity"
)

// Actor types (IAM's audit_logs_actor_type_chk values).
const (
	ActorUser    = "user"
	ActorService = "service"
	ActorSystem  = "system"
)

// Event is the canonical audit payload, IAM's Event plus the service name
// and the computed severity.
type Event struct {
	EventID          uuid.UUID      `json:"event_id"`
	Service          string         `json:"service"`
	Tier             string         `json:"tier"`
	Severity         Severity       `json:"severity"`
	ActorUUID        *uuid.UUID     `json:"actor_uuid,omitempty"`
	ActorType        string         `json:"actor_type,omitempty"`
	TenantUUID       *uuid.UUID     `json:"tenant_uuid,omitempty"`
	OrganizationUUID *uuid.UUID     `json:"organization_uuid,omitempty"`
	ResourceType     string         `json:"resource_type"`
	ResourceID       string         `json:"resource_id"`
	Action           string         `json:"action"`
	IPAddress        string         `json:"ip_address,omitempty"`
	UserAgent        string         `json:"user_agent,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
}

// criticalActions are always tier=critical (CloudTrail-style management events).
var criticalActions = map[string]struct{}{
	"template.published":      {},
	"template.restored":       {},
	"template.test_sent":      {},
	"message.body_viewed":     {},
	"message.body_exported":   {},
	"message.resent":          {},
	"message.cancelled":       {},
	"messages.purged":         {},
	"mailos.message_rejected": {},
	"event.refused":           {},
	"access_denied":           {},
	"step_up_required":        {},
}

// Classify returns TierCritical or TierActivity for an action name.
func Classify(action string) string {
	if _, ok := criticalActions[action]; ok {
		return TierCritical
	}
	if strings.HasPrefix(action, "audit_log.") || strings.HasPrefix(action, "encryption_key.") ||
		isChangeAction(action) {
		return TierCritical
	}
	return TierActivity
}

// NewEvent builds an Event for action on a resource, filling the actor,
// tenant and request metadata from ctx.
func NewEvent(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) Event {
	meta := make(map[string]any, len(metadata)+2)
	for k, v := range metadata {
		meta[k] = v
	}
	ev := Event{
		EventID:      uuid.Must(uuid.NewV7()),
		Service:      Service,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       action,
		ActorType:    ActorSystem,
		CreatedAt:    time.Now().UTC(),
		Metadata:     meta,
	}
	if p, ok := access.FromContext(ctx); ok {
		if p.IsService() {
			ev.ActorType = ActorService
			meta["client_id"] = p.ClientID
		} else {
			ev.ActorType = ActorUser
			if id, err := uuid.Parse(p.Subject); err == nil {
				ev.ActorUUID = &id
			} else {
				meta["actor"] = p.Subject
			}
			if p.ClientID != "" {
				meta["client_id"] = p.ClientID
			}
		}
		ev.TenantUUID = parseUUID(p.TenantID)
		ev.OrganizationUUID = parseUUID(p.OrgID)
	}
	if t := tenantFromContext(ctx); t != "" {
		ev.TenantUUID = parseUUID(t)
	}
	if m, ok := requestMetaFromContext(ctx); ok {
		ev.IPAddress = m.IP
		ev.UserAgent = m.UserAgent
		if m.RequestID != "" {
			meta["request_id"] = m.RequestID
		}
	}
	ev.Tier = Classify(action)
	ev.Severity = SeverityOf(ev)
	return ev
}

func parseUUID(s string) *uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}
