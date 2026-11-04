package message

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// EventType is what a provider reported about a message after accepting
// it (its delivery webhooks).
type EventType string

// Provider event types. A soft bounce or a delay is recorded but changes
// nothing: the provider keeps trying.
const (
	EventDelivered   EventType = "delivered"    // the receiving server accepted it
	EventBounced     EventType = "bounced"      // hard bounce: the address does not exist or refuses mail
	EventSoftBounced EventType = "soft_bounced" // a temporary refusal
	EventDeferred    EventType = "deferred"     // delayed; the provider retries
	EventComplained  EventType = "complained"   // the recipient reported it as spam
)

// Valid reports whether t is known.
func (t EventType) Valid() bool {
	switch t {
	case EventDelivered, EventBounced, EventSoftBounced, EventDeferred, EventComplained:
		return true
	}
	return false
}

// Status is the message status the event moves a message to, or "" when
// it changes none.
func (t EventType) Status() Status {
	switch t {
	case EventDelivered:
		return StatusDelivered
	case EventBounced:
		return StatusBounced
	case EventComplained:
		return StatusComplained
	}
	return ""
}

// maxReason bounds the provider's reason kept with an event.
const maxReason = 500

// ProviderEvent is one provider delivery event, normalised from the
// provider's webhook payload. MessageID is MailOS's id when the provider
// echoes the custom argument MailOS sent with the message; otherwise the
// message is found by ProviderMessageID.
type ProviderEvent struct {
	Type              EventType
	MessageID         string
	ProviderMessageID string
	Recipient         string
	// Reason is the provider's diagnostic (bounce code and text), one
	// line, without the recipient's mailbox data.
	Reason string
	// ProviderEventID identifies the event at the provider, to drop
	// redeliveries; Key derives one when the provider sends none.
	ProviderEventID string
	OccurredAt      time.Time
}

// Normalize trims the fields and bounds the reason.
func (e *ProviderEvent) Normalize() {
	e.MessageID = strings.TrimSpace(e.MessageID)
	e.ProviderMessageID = strings.Trim(strings.TrimSpace(e.ProviderMessageID), "<>")
	e.Recipient = strings.ToLower(strings.TrimSpace(e.Recipient))
	e.Reason = strings.Join(strings.Fields(e.Reason), " ")
	if len(e.Reason) > maxReason {
		e.Reason = e.Reason[:maxReason]
	}
	e.ProviderEventID = strings.TrimSpace(e.ProviderEventID)
}

// Key is the event's de-duplication key: the provider's event id, or a
// hash of what identifies the event.
func (e ProviderEvent) Key() string {
	if id := e.ProviderEventID; id != "" && len(id) <= 128 {
		return id
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{string(e.Type), e.ProviderEventID, e.MessageID, e.ProviderMessageID,
		e.Recipient, e.OccurredAt.UTC().Format(time.RFC3339Nano)}, "\x00")))
	return "h:" + hex.EncodeToString(sum[:16])
}

// DeliveryEvent is a recorded event of a message: what the provider
// reported, when, through which provider.
type DeliveryEvent struct {
	ID         string
	MessageID  string
	TenantID   string
	Type       EventType
	ProviderID string
	Key        string
	Reason     string
	OccurredAt time.Time
	CreatedAt  time.Time
}
