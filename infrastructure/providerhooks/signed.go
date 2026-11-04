package providerhooks

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
)

// customArg is the custom argument (tag, metadata, variable) the senders
// attach with MailOS's message id.
const customArg = "mailos_message_id"

// SendGrid Signed Event Webhook headers.
const (
	HeaderSendGridSignature = "X-Twilio-Email-Event-Webhook-Signature"
	HeaderSendGridTimestamp = "X-Twilio-Email-Event-Webhook-Timestamp"
)

// sendGridKey reads the verification key: base64 DER (as SendGrid shows
// it) or PEM.
func sendGridKey(secret string) (*ecdsa.PublicKey, error) {
	secret = strings.TrimSpace(secret)
	var der []byte
	if block, _ := pem.Decode([]byte(secret)); block != nil {
		der = block.Bytes
	} else {
		var err error
		if der, err = base64.StdEncoding.DecodeString(secret); err != nil {
			return nil, err
		}
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key")
	}
	return pub, nil
}

// sendGrid verifies the ECDSA signature over timestamp + body and reads
// the event batch.
func (v *Verifier) sendGrid(secret string, r Request) ([]message.ProviderEvent, error) {
	pub, err := sendGridKey(secret)
	if err != nil {
		return nil, fmt.Errorf("%w: the verification key cannot be read", ErrUnauthenticated)
	}
	ts := strings.TrimSpace(r.Header.Get(HeaderSendGridTimestamp))
	at, ok := unixTime(ts)
	if !ok {
		return nil, fmt.Errorf("%w: no signature timestamp", ErrUnauthenticated)
	}
	if err := within(v.now(), at, v.tolerance()); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.Header.Get(HeaderSendGridSignature)))
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("%w: no signature", ErrUnauthenticated)
	}
	digest := sha256.Sum256(append([]byte(ts), r.Body...))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil, fmt.Errorf("%w: the signature does not verify", ErrUnauthenticated)
	}
	var batch []map[string]any
	if err := json.Unmarshal(r.Body, &batch); err != nil {
		return nil, fmt.Errorf("%w: the event batch is not a JSON array", ErrMalformed)
	}
	var out []message.ProviderEvent
	for _, e := range batch {
		var t message.EventType
		switch str(e["event"]) {
		case "delivered":
			t = message.EventDelivered
		case "bounce":
			t = message.EventBounced
			if str(e["type"]) == "blocked" {
				t = message.EventSoftBounced
			}
		case "deferred":
			t = message.EventDeferred
		case "spamreport":
			t = message.EventComplained
		default:
			continue
		}
		pmid, _, _ := strings.Cut(str(e["sg_message_id"]), ".")
		reason := strings.TrimSpace(str(e["status"]) + " " + str(e["reason"]) + " " + str(e["response"]))
		ev := message.ProviderEvent{Type: t, MessageID: str(e[customArg]), ProviderMessageID: pmid, Recipient: str(e["email"]),
			Reason: reason, ProviderEventID: str(e["sg_event_id"])}
		if at, ok := unixTime(str(e["timestamp"])); ok {
			ev.OccurredAt = at
		}
		out = append(out, ev)
	}
	return out, nil
}

// mailgunBody is a Mailgun webhook (one event per request).
type mailgunBody struct {
	Signature struct {
		Timestamp string `json:"timestamp"`
		Token     string `json:"token"`
		Signature string `json:"signature"`
	} `json:"signature"`
	EventData struct {
		ID        string  `json:"id"`
		Event     string  `json:"event"`
		Severity  string  `json:"severity"`
		Reason    string  `json:"reason"`
		Recipient string  `json:"recipient"`
		Timestamp float64 `json:"timestamp"`
		Message   struct {
			Headers struct {
				MessageID string `json:"message-id"`
			} `json:"headers"`
		} `json:"message"`
		UserVariables  map[string]any `json:"user-variables"`
		DeliveryStatus struct {
			Code        any    `json:"code"`
			Message     string `json:"message"`
			Description string `json:"description"`
		} `json:"delivery-status"`
	} `json:"event-data"`
}

// mailgun verifies HMAC-SHA256(signing key, timestamp + token) and reads
// the event.
func (v *Verifier) mailgun(secret string, r Request) ([]message.ProviderEvent, error) {
	var b mailgunBody
	if err := json.Unmarshal(r.Body, &b); err != nil {
		return nil, fmt.Errorf("%w: not a Mailgun webhook", ErrUnauthenticated)
	}
	at, ok := unixTime(b.Signature.Timestamp)
	if !ok || b.Signature.Token == "" {
		return nil, fmt.Errorf("%w: no signature", ErrUnauthenticated)
	}
	if err := within(v.now(), at, v.tolerance()); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(b.Signature.Timestamp + b.Signature.Token))
	if !equal(hex.EncodeToString(mac.Sum(nil)), strings.ToLower(b.Signature.Signature)) {
		return nil, fmt.Errorf("%w: the signature does not verify", ErrUnauthenticated)
	}
	e := b.EventData
	var t message.EventType
	switch e.Event {
	case "delivered":
		t = message.EventDelivered
	case "failed":
		t = message.EventSoftBounced
		if e.Severity == "permanent" {
			t = message.EventBounced
		}
	case "complained":
		t = message.EventComplained
	default:
		return nil, nil
	}
	reason := strings.TrimSpace(fmt.Sprint(e.DeliveryStatus.Code) + " " + e.DeliveryStatus.Message + " " + e.DeliveryStatus.Description)
	if e.DeliveryStatus.Code == nil {
		reason = strings.TrimSpace(e.DeliveryStatus.Message + " " + e.DeliveryStatus.Description)
	}
	if reason == "" {
		reason = e.Reason
	}
	ev := message.ProviderEvent{Type: t, MessageID: str(e.UserVariables[customArg]), ProviderMessageID: e.Message.Headers.MessageID,
		Recipient: e.Recipient, Reason: reason, ProviderEventID: e.ID}
	if at, ok := unixTime(strconv.FormatFloat(e.Timestamp, 'f', -1, 64)); ok {
		ev.OccurredAt = at
	}
	return []message.ProviderEvent{ev}, nil
}

// Svix (Resend) headers.
const (
	HeaderSvixID        = "svix-id"
	HeaderSvixTimestamp = "svix-timestamp"
	HeaderSvixSignature = "svix-signature"
)

// SvixSign is the v1 signature of a Svix webhook: base64 HMAC-SHA256 of
// "id.timestamp.body" with the secret's key (whsec_ prefix removed).
func SvixSign(secret, id, timestamp string, body []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(secret), "whsec_"))
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// resendBody is a Resend webhook.
type resendBody struct {
	Type      string `json:"type"`
	CreatedAt string `json:"created_at"`
	Data      struct {
		EmailID   string          `json:"email_id"`
		To        []string        `json:"to"`
		CreatedAt string          `json:"created_at"`
		Tags      json.RawMessage `json:"tags"`
		Bounce    *struct {
			Type    string `json:"type"`
			SubType string `json:"subType"`
			Message string `json:"message"`
		} `json:"bounce"`
	} `json:"data"`
}

// resendTag reads MailOS's id from the tags: an object or a list of
// {name, value}.
func resendTag(raw json.RawMessage) string {
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil {
		return str(obj[customArg])
	}
	var list []struct{ Name, Value string }
	if json.Unmarshal(raw, &list) == nil {
		for _, t := range list {
			if t.Name == customArg {
				return t.Value
			}
		}
	}
	return ""
}

// resend verifies the Svix signature and reads the event.
func (v *Verifier) resend(secret string, r Request) ([]message.ProviderEvent, error) {
	id, ts := strings.TrimSpace(r.Header.Get(HeaderSvixID)), strings.TrimSpace(r.Header.Get(HeaderSvixTimestamp))
	at, ok := unixTime(ts)
	if id == "" || !ok {
		return nil, fmt.Errorf("%w: no Svix id or timestamp", ErrUnauthenticated)
	}
	if err := within(v.now(), at, v.tolerance()); err != nil {
		return nil, err
	}
	want, err := SvixSign(secret, id, ts, r.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: the signing secret cannot be read", ErrUnauthenticated)
	}
	matched := false
	for _, s := range strings.Fields(r.Header.Get(HeaderSvixSignature)) {
		if version, sig, ok := strings.Cut(s, ","); ok && version == "v1" && equal(sig, want) {
			matched = true
		}
	}
	if !matched {
		return nil, fmt.Errorf("%w: the signature does not verify", ErrUnauthenticated)
	}
	var b resendBody
	if err := json.Unmarshal(r.Body, &b); err != nil {
		return nil, fmt.Errorf("%w: the event is not JSON", ErrMalformed)
	}
	var t message.EventType
	reason := ""
	switch b.Type {
	case "email.delivered":
		t = message.EventDelivered
	case "email.bounced":
		t = message.EventBounced
		if b.Data.Bounce != nil {
			if b.Data.Bounce.Type == "Transient" {
				t = message.EventSoftBounced
			}
			reason = strings.TrimSpace(b.Data.Bounce.Type + " " + b.Data.Bounce.SubType + ": " + b.Data.Bounce.Message)
		}
	case "email.complained":
		t = message.EventComplained
	case "email.delivery_delayed":
		t = message.EventDeferred
	default:
		return nil, nil
	}
	occurred := parseTime(b.CreatedAt)
	var out []message.ProviderEvent
	for _, to := range b.Data.To {
		out = append(out, message.ProviderEvent{Type: t, MessageID: resendTag(b.Data.Tags), ProviderMessageID: b.Data.EmailID,
			Recipient: to, Reason: reason, ProviderEventID: id + ":" + to, OccurredAt: occurred})
	}
	return out, nil
}

// str is v as text: strings as they are, numbers in full.
func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}
