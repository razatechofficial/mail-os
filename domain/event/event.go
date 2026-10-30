// Package event is the inbound pub/sub event: the envelope IAM publishes
// (its eventbus.Event, serialised as JSON) and the reasons MailOS rejects a
// message (contract §2). It parses and validates the envelope only; whether
// the message was signed by IAM is infrastructure/msgsig's, and whether its
// sender may publish the topic is domain/access's.
package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// MaxSize caps a message value. IAM's notification events are a few KiB; a
// larger value is refused before it is decoded.
const MaxSize = 256 << 10

// Limits on the envelope's identifying fields.
const (
	maxTypeLen   = 128
	maxIDLen     = 128
	maxSourceLen = 128
)

// Event is the envelope IAM publishes, compatible with its eventbus.Event.
type Event struct {
	// ID is IAM's event id (optional; IAM also uses it as the signature jti).
	ID string `json:"id,omitempty"`
	// Type names the event, e.g. iam.auth.password_reset_requested. IAM
	// publishes each event on the topic of the same name.
	Type   string `json:"type"`
	Source string `json:"source,omitempty"`
	// Data is the event's payload, always a JSON object.
	Data             json.RawMessage   `json:"data"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	Timestamp        time.Time         `json:"timestamp"`
	TenantUUID       string            `json:"tenant_uuid,omitempty"`
	OrganizationUUID string            `json:"organization_uuid,omitempty"`
}

// typePattern is dot-separated lower-case segments, at least two of them:
// iam.auth.login, iam.auth.password_reset_requested.
var typePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// uuidPattern is the canonical textual UUID (RFC 9562 §4).
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidType reports whether t is a well-formed event type.
func ValidType(t string) bool {
	return len(t) <= maxTypeLen && typePattern.MatchString(t)
}

// Parse decodes and validates a message value. Every failure is a
// Rejection with ReasonMalformed; its message never quotes the value.
func Parse(value []byte) (Event, error) {
	if len(value) > MaxSize {
		return Event{}, Reject(ReasonMalformed, fmt.Errorf("the message is %d bytes, over the %d byte limit", len(value), MaxSize))
	}
	var e Event
	dec := json.NewDecoder(bytes.NewReader(value))
	if err := dec.Decode(&e); err != nil {
		return Event{}, Reject(ReasonMalformed, errors.New("the message is not a JSON event envelope"))
	}
	if dec.More() {
		return Event{}, Reject(ReasonMalformed, errors.New("the message has data after the event envelope"))
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	e.TenantUUID = strings.ToLower(e.TenantUUID)
	e.OrganizationUUID = strings.ToLower(e.OrganizationUUID)
	return e, nil
}

// Validate checks the envelope: a well-formed type, data that is a JSON
// object, and well-formed optional fields.
func (e Event) Validate() error {
	if !ValidType(e.Type) {
		return Reject(ReasonMalformed, errors.New("the event type is missing or not dot-separated lower-case segments"))
	}
	if !isJSONObject(e.Data) {
		return Reject(ReasonMalformed, errors.New("the event data is not a JSON object"))
	}
	if len(e.ID) > maxIDLen || !printable(e.ID) {
		return Reject(ReasonMalformed, errors.New("the event id is too long or not printable"))
	}
	if len(e.Source) > maxSourceLen || !printable(e.Source) {
		return Reject(ReasonMalformed, errors.New("the event source is too long or not printable"))
	}
	if e.TenantUUID != "" && !uuidPattern.MatchString(e.TenantUUID) {
		return Reject(ReasonMalformed, errors.New("tenant_uuid is not a UUID"))
	}
	if e.OrganizationUUID != "" && !uuidPattern.MatchString(e.OrganizationUUID) {
		return Reject(ReasonMalformed, errors.New("organization_uuid is not a UUID"))
	}
	return nil
}

// isJSONObject reports whether raw is a JSON object (not null, an array or
// a scalar). The envelope decoder has already checked it is valid JSON.
func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && json.Valid(trimmed)
}

// printable reports whether s has no control characters, so it is safe to
// log and to use as a key.
func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
