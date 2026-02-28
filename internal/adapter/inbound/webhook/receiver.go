package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Note: nethttp is not imported here since we only parse bodies. HTTP handling
// can be done in a separate layer that calls these methods.

type Receiver struct {
	events port.EventPublisher
	signer port.Signer
}

func NewReceiver(events port.EventPublisher, signer port.Signer) *Receiver {
	return &Receiver{events: events, signer: signer}
}

// ProviderEvent normalizes provider-specific webhook payloads into domain events.
type ProviderEvent struct {
	Provider  string
	EventType domain.EventType
	MessageID string
	Email     string
	Metadata  map[string]any
	RawBody   []byte
}

// sesNotification represents the top-level SES/SNS webhook payload structure.
type sesNotification struct {
	Type string `json:"Type"`
	// SNS wrapper
	Message *string `json:"Message"`
	// Direct SES (when not via SNS)
	NotificationType string     `json:"notificationType"`
	Mail             *sesMail   `json:"mail"`
	Bounce           *sesBounce `json:"bounce"`
	Complaint        *sesComplaint `json:"complaint"`
	Delivery         *sesDelivery `json:"delivery"`
}

type sesMail struct {
	MessageID string `json:"messageId"`
	Source    string `json:"source"`
}

type sesBounce struct {
	BouncedRecipients []struct {
		EmailAddress string `json:"emailAddress"`
	} `json:"bouncedRecipients"`
}

type sesComplaint struct {
	ComplainedRecipients []struct {
		EmailAddress string `json:"emailAddress"`
	} `json:"complainedRecipients"`
}

type sesDelivery struct {
	Recipients []string `json:"recipients"`
}

func (r *Receiver) HandleSES(ctx context.Context, body []byte) (*ProviderEvent, error) {
	var outer sesNotification
	if err := json.Unmarshal(body, &outer); err != nil {
		return nil, fmt.Errorf("parse SES payload: %w", err)
	}

	// SNS subscription confirmation or other SNS wrapper
	if outer.Type == "SubscriptionConfirmation" || outer.Type == "Notification" {
		if outer.Message != nil {
			// Parse inner SES message when wrapped by SNS
			var inner sesNotification
			if err := json.Unmarshal([]byte(*outer.Message), &inner); err != nil {
				return nil, fmt.Errorf("parse SES inner message: %w", err)
			}
			return r.parseSESPayload(ctx, body, &inner)
		}
	}

	return r.parseSESPayload(ctx, body, &outer)
}

func (r *Receiver) parseSESPayload(ctx context.Context, raw []byte, n *sesNotification) (*ProviderEvent, error) {
	ev := &ProviderEvent{
		Provider: "ses",
		Metadata: make(map[string]any),
		RawBody:  raw,
	}

	if n.Mail != nil {
		ev.MessageID = n.Mail.MessageID
		ev.Email = n.Mail.Source
	}

	switch n.NotificationType {
	case "Bounce", "bounce":
		ev.EventType = domain.EventTypeBounced
		if n.Bounce != nil && len(n.Bounce.BouncedRecipients) > 0 {
			ev.Email = n.Bounce.BouncedRecipients[0].EmailAddress
		}
	case "Complaint", "complaint":
		ev.EventType = domain.EventTypeComplained
		if n.Complaint != nil && len(n.Complaint.ComplainedRecipients) > 0 {
			ev.Email = n.Complaint.ComplainedRecipients[0].EmailAddress
		}
	case "Delivery", "delivery":
		ev.EventType = domain.EventTypeDelivered
		if n.Delivery != nil && len(n.Delivery.Recipients) > 0 {
			ev.Email = n.Delivery.Recipients[0]
		}
	default:
		ev.EventType = domain.EventTypeSent
	}

	logger.Debug("parsed SES webhook", logger.String("type", string(ev.EventType)), logger.String("messageId", ev.MessageID))
	return ev, nil
}

// sendGridEvent represents a single SendGrid webhook event (array of events).
type sendGridEvent struct {
	Email       string `json:"email"`
	Event       string `json:"event"`
	MessageID   string `json:"sg_message_id"`
	Timestamp   int64  `json:"timestamp"`
}

func (r *Receiver) HandleSendGrid(ctx context.Context, body []byte) ([]*ProviderEvent, error) {
	var events []sendGridEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, fmt.Errorf("parse SendGrid payload: %w", err)
	}

	result := make([]*ProviderEvent, 0, len(events))
	for _, e := range events {
		ev := &ProviderEvent{
			Provider:  "sendgrid",
			Email:     e.Email,
			MessageID: e.MessageID,
			Metadata: map[string]any{
				"timestamp": e.Timestamp,
			},
			RawBody: body,
		}
		switch e.Event {
		case "delivered":
			ev.EventType = domain.EventTypeDelivered
		case "open":
			ev.EventType = domain.EventTypeOpened
		case "click":
			ev.EventType = domain.EventTypeClicked
		case "bounce", "dropped":
			ev.EventType = domain.EventTypeBounced
		case "spamreport":
			ev.EventType = domain.EventTypeComplained
		case "unsubscribe", "group_unsubscribe":
			ev.EventType = domain.EventTypeUnsubscribed
		default:
			ev.EventType = domain.EventTypeSent
		}
		result = append(result, ev)
	}

	logger.Debug("parsed SendGrid webhook", logger.Any("count", len(result)))
	return result, nil
}

// mailgunEvent represents Mailgun webhook payload.
type mailgunEvent struct {
	Event       string            `json:"event"`
	MessageID   string            `json:"Message-Id"`
	Recipient   string            `json:"recipient"`
	Timestamp   int64             `json:"timestamp"`
	UserAgent   string            `json:"user-agent"`
}

func (r *Receiver) HandleMailgun(ctx context.Context, body []byte) (*ProviderEvent, error) {
	var e mailgunEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("parse Mailgun payload: %w", err)
	}

	ev := &ProviderEvent{
		Provider:  "mailgun",
		Email:     e.Recipient,
		MessageID: e.MessageID,
		Metadata: map[string]any{
			"timestamp":  e.Timestamp,
			"user_agent": e.UserAgent,
		},
		RawBody: body,
	}
	switch e.Event {
	case "delivered":
		ev.EventType = domain.EventTypeDelivered
	case "opened":
		ev.EventType = domain.EventTypeOpened
	case "clicked":
		ev.EventType = domain.EventTypeClicked
	case "failed", "permanent_fail":
		ev.EventType = domain.EventTypeBounced
	case "complained":
		ev.EventType = domain.EventTypeComplained
	case "unsubscribed":
		ev.EventType = domain.EventTypeUnsubscribed
	default:
		ev.EventType = domain.EventTypeSent
	}

	logger.Debug("parsed Mailgun webhook", logger.String("type", string(ev.EventType)), logger.String("messageId", ev.MessageID))
	return ev, nil
}

// postmarkEvent represents Postmark webhook payload.
type postmarkEvent struct {
	MessageID string `json:"MessageID"`
	Recipient string `json:"Recipient"`
	Type      string `json:"Type"`
	RecordType string `json:"RecordType"`
}

func (r *Receiver) HandlePostmark(ctx context.Context, body []byte) (*ProviderEvent, error) {
	var e postmarkEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("parse Postmark payload: %w", err)
	}

	ev := &ProviderEvent{
		Provider:  "postmark",
		Email:     e.Recipient,
		MessageID: e.MessageID,
		Metadata:  make(map[string]any),
		RawBody:   body,
	}
	t := e.Type
	if t == "" {
		t = e.RecordType
	}
	switch t {
	case "Delivery":
		ev.EventType = domain.EventTypeDelivered
	case "Open":
		ev.EventType = domain.EventTypeOpened
	case "Click":
		ev.EventType = domain.EventTypeClicked
	case "Bounce":
		ev.EventType = domain.EventTypeBounced
	case "SpamComplaint":
		ev.EventType = domain.EventTypeComplained
	case "SubscriptionChange":
		ev.EventType = domain.EventTypeUnsubscribed
	default:
		ev.EventType = domain.EventTypeSent
	}

	logger.Debug("parsed Postmark webhook", logger.String("type", string(ev.EventType)), logger.String("messageId", ev.MessageID))
	return ev, nil
}

// ReadBody reads and returns the request body. Helper for HTTP handlers.
func ReadBody(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20 // 1 MB default
	}
	limited := io.LimitReader(r, maxBytes)
	return io.ReadAll(limited)
}
