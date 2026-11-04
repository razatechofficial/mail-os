package providerhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
)

// The payloads of the providers authenticated by the event URL's password.
// They are read only after basicAuth accepted the request.

// postmark reads one Postmark webhook (Delivery, Bounce, SpamComplaint).
func postmark(body []byte) ([]message.ProviderEvent, error) {
	var e struct {
		RecordType  string            `json:"RecordType"`
		ID          json.Number       `json:"ID"`
		Type        string            `json:"Type"`
		MessageID   string            `json:"MessageID"`
		Recipient   string            `json:"Recipient"`
		Email       string            `json:"Email"`
		DeliveredAt string            `json:"DeliveredAt"`
		BouncedAt   string            `json:"BouncedAt"`
		Description string            `json:"Description"`
		Details     string            `json:"Details"`
		Metadata    map[string]string `json:"Metadata"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("%w: not a Postmark webhook", ErrMalformed)
	}
	ev := message.ProviderEvent{MessageID: e.Metadata[customArg], ProviderMessageID: e.MessageID}
	switch e.RecordType {
	case "Delivery":
		ev.Type, ev.Recipient, ev.Reason, ev.OccurredAt = message.EventDelivered, e.Recipient, e.Details, parseTime(e.DeliveredAt)
		ev.ProviderEventID = "delivery:" + e.MessageID + ":" + strings.ToLower(e.Recipient)
	case "Bounce", "SpamComplaint":
		switch {
		case e.RecordType == "SpamComplaint" || e.Type == "SpamComplaint":
			ev.Type = message.EventComplained
		case e.Type == "HardBounce" || e.Type == "BadEmailAddress":
			ev.Type = message.EventBounced
		default:
			ev.Type = message.EventSoftBounced
		}
		ev.Recipient, ev.OccurredAt = e.Email, parseTime(e.BouncedAt)
		ev.Reason = strings.TrimSpace(e.Type + ": " + e.Description + " " + e.Details)
		if e.ID != "" {
			ev.ProviderEventID = "bounce:" + e.ID.String()
		}
	default:
		return nil, nil
	}
	return []message.ProviderEvent{ev}, nil
}

// sparkPostHard are the bounce classes of a permanent failure: invalid
// recipient, no RCPT, unsubscribe.
var sparkPostHard = map[string]bool{"10": true, "30": true, "90": true}

// sparkPost reads a SparkPost event batch ([{"msys": {"message_event": …}}]).
func sparkPost(body []byte) ([]message.ProviderEvent, error) {
	var batch []struct {
		Msys map[string]map[string]any `json:"msys"`
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&batch); err != nil {
		return nil, fmt.Errorf("%w: the event batch is not a JSON array", ErrMalformed)
	}
	var out []message.ProviderEvent
	for _, item := range batch {
		for _, e := range item.Msys {
			var t message.EventType
			switch str(e["type"]) {
			case "delivery":
				t = message.EventDelivered
			case "bounce", "out_of_band":
				t = message.EventSoftBounced
				if sparkPostHard[str(e["bounce_class"])] {
					t = message.EventBounced
				}
			case "delay":
				t = message.EventDeferred
			case "spam_complaint":
				t = message.EventComplained
			default:
				continue
			}
			ev := message.ProviderEvent{Type: t, ProviderMessageID: str(e["transmission_id"]), Recipient: str(e["rcpt_to"]),
				ProviderEventID: str(e["event_id"]), Reason: strings.TrimSpace(str(e["bounce_class"]) + " " + str(e["raw_reason"]))}
			if meta, ok := e["rcpt_meta"].(map[string]any); ok {
				ev.MessageID = str(meta[customArg])
			}
			if at, ok := unixTime(str(e["timestamp"])); ok {
				ev.OccurredAt = at
			}
			out = append(out, ev)
		}
	}
	return out, nil
}

// brevo reads one Brevo transactional webhook.
func brevo(body []byte) ([]message.ProviderEvent, error) {
	var e map[string]any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&e); err != nil {
		return nil, fmt.Errorf("%w: not a Brevo webhook", ErrMalformed)
	}
	var t message.EventType
	switch str(e["event"]) {
	case "delivered":
		t = message.EventDelivered
	case "hard_bounce", "invalid_email":
		t = message.EventBounced
	case "soft_bounce", "blocked":
		t = message.EventSoftBounced
	case "deferred":
		t = message.EventDeferred
	case "spam", "complaint":
		t = message.EventComplained
	default:
		return nil, nil
	}
	ev := message.ProviderEvent{Type: t, ProviderMessageID: str(e["message-id"]), Recipient: str(e["email"]), Reason: str(e["reason"])}
	if at, ok := unixTime(str(e["ts_event"])); ok {
		ev.OccurredAt = at
	}
	return []message.ProviderEvent{ev}, nil
}

// mailjet reads a Mailjet event, or a batch of them when grouping is on.
func mailjet(body []byte) ([]message.ProviderEvent, error) {
	var batch []map[string]any
	d := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(body)))
	d.UseNumber()
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		var one map[string]any
		if err := d.Decode(&one); err != nil {
			return nil, fmt.Errorf("%w: not a Mailjet event", ErrMalformed)
		}
		batch = append(batch, one)
	} else if err := d.Decode(&batch); err != nil {
		return nil, fmt.Errorf("%w: not a Mailjet event", ErrMalformed)
	}
	var out []message.ProviderEvent
	for _, e := range batch {
		var t message.EventType
		switch str(e["event"]) {
		case "sent":
			t = message.EventDelivered
		case "bounce":
			t = message.EventSoftBounced
			if b, _ := e["hard_bounce"].(bool); b {
				t = message.EventBounced
			}
		case "blocked":
			t = message.EventSoftBounced
		case "spam":
			t = message.EventComplained
		default:
			continue
		}
		ev := message.ProviderEvent{Type: t, MessageID: str(e["CustomID"]), ProviderMessageID: str(e["MessageID"]),
			Recipient: str(e["email"]), Reason: strings.TrimSpace(str(e["error_related_to"]) + " " + str(e["error"]) + " " + str(e["comment"]))}
		if at, ok := unixTime(str(e["time"])); ok {
			ev.OccurredAt = at
		}
		out = append(out, ev)
	}
	return out, nil
}
