// Package message is one email to one recipient: what was asked for (the
// event, template and data, or a rendered body), where it is in delivery,
// and what a provider sends (Outgoing).
//
// Bodies and template data hold one-time codes and personal data (contract
// §6): they are kept only for the retention period (PurgeBody), and the
// values of the template variables named in SecretKeys are masked wherever
// a message is shown (MaskedTemplateData, Redact).
package message

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/provider"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Type is why the message is sent; marketing mail honours unsubscribes.
type Type string

// Message types.
const (
	TypeTransactional Type = "transactional"
	TypeMarketing     Type = "marketing"
	TypeNotification  Type = "notification"
)

// Valid reports whether t is known.
func (t Type) Valid() bool {
	return t == TypeTransactional || t == TypeMarketing || t == TypeNotification
}

// Status is where the message is in delivery.
type Status string

// Message statuses.
const (
	StatusQueued     Status = "queued"     // waiting for a worker
	StatusScheduled  Status = "scheduled"  // waiting for ScheduledAt
	StatusSending    Status = "sending"    // a worker is handing it to a provider
	StatusSent       Status = "sent"       // a provider accepted it
	StatusDelivered  Status = "delivered"  // the receiving server accepted it
	StatusBounced    Status = "bounced"    // the recipient does not exist or refused it
	StatusFailed     Status = "failed"     // gave up: permanent error or attempts exhausted
	StatusCancelled  Status = "cancelled"  // cancelled before it was sent
	StatusSuppressed Status = "suppressed" // the recipient is on the suppression list
)

// Statuses lists every status.
var Statuses = []Status{StatusQueued, StatusScheduled, StatusSending, StatusSent, StatusDelivered,
	StatusBounced, StatusFailed, StatusCancelled, StatusSuppressed}

// Valid reports whether s is known.
func (s Status) Valid() bool { return slices.Contains(Statuses, s) }

// transitions are the legal status changes. Sent mail can still bounce or
// be reported failed (dropped) by the provider; delivered mail can still
// bounce late. A failed message may be queued again by an operator.
var transitions = map[Status][]Status{
	StatusQueued:    {StatusSending, StatusScheduled, StatusCancelled, StatusSuppressed, StatusFailed},
	StatusScheduled: {StatusQueued, StatusCancelled, StatusSuppressed},
	StatusSending:   {StatusSent, StatusQueued, StatusFailed, StatusBounced},
	StatusSent:      {StatusDelivered, StatusBounced, StatusFailed},
	StatusDelivered: {StatusBounced},
	StatusFailed:    {StatusQueued},
}

// CanTransition reports whether a message may go from one status to
// another.
func CanTransition(from, to Status) bool {
	return slices.Contains(transitions[from], to)
}

// Final reports whether the message's body is no longer needed for
// sending: it was handed over, or it never will be.
func (s Status) Final() bool {
	switch s {
	case StatusSent, StatusDelivered, StatusBounced, StatusFailed, StatusCancelled, StatusSuppressed:
		return true
	}
	return false
}

// Priority orders the queue; higher goes first.
type Priority int

// Priorities.
const (
	PriorityLow    Priority = 1
	PriorityNormal Priority = 5
	PriorityHigh   Priority = 10
)

// ActorType says who asked for the message.
type ActorType string

// Actor types.
const (
	ActorUser    ActorType = "user"    // a console user (IAM user id)
	ActorService ActorType = "service" // an IAM service client (client_id)
	ActorSystem  ActorType = "system"  // MailOS itself (campaign runs, resends)
)

// Actor is who asked for the message, for audit.
type Actor struct {
	Type ActorType `json:"type"`
	ID   string    `json:"id"`
}

// String is "type:id".
func (a Actor) String() string { return string(a.Type) + ":" + a.ID }

// Retention defaults (contract §6).
const DefaultBodyRetention = 30 * 24 * time.Hour

// Mask replaces secret values in views and logs.
const Mask = "••••••"

// Limits.
const (
	MaxTags           = 10
	MaxTagLen         = 64
	MaxSecretKeys     = 50
	MaxMetadataKeys   = 50
	MaxIdempotencyKey = 255
	MaxSubjectLen     = 998
	maxLine           = 255
	// minSecretLen is the shortest secret value Redact replaces: shorter
	// values would mask unrelated text.
	minSecretLen = 4
)

// Message is one email to one recipient.
type Message struct {
	ID string
	// OrgID is the IAM tenant (column org_id).
	OrgID      string
	CampaignID string

	FromName  string
	FromEmail string
	ToEmail   string
	ToName    string
	ReplyTo   string
	Subject   string
	HTMLBody  string
	TextBody  string

	Type     Type
	Status   Status
	Priority Priority
	Tags     []string
	Metadata map[string]any

	// Topic is the event topic that produced the message, if any.
	Topic             string
	TemplateID        string
	TemplateVersionID string
	Locale            string
	// TemplateData is the event payload the template is rendered with.
	TemplateData map[string]any
	// SecretKeys name the TemplateData variables (dotted paths for nested
	// values) whose values are masked in views: one-time codes, tokens.
	SecretKeys []string
	// EventID is the producer's event id (the message signature's jti for
	// pub/sub), for tracing and de-duplication.
	EventID string
	Actor   Actor

	IdempotencyKey    string
	ProviderID        string
	ProviderMessageID string
	Attempts          int
	// LastError is the last send failure, safe to show (no secrets).
	LastError string

	ScheduledAt   *time.Time
	LastAttemptAt *time.Time
	SentAt        *time.Time
	DeliveredAt   *time.Time
	BouncedAt     *time.Time
	FailedAt      *time.Time
	CancelledAt   *time.Time
	OpenedAt      *time.Time
	ClickedAt     *time.Time
	// BodyPurgedAt is when the bodies and template data were erased.
	BodyPurgedAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Normalize trims the text fields and fills defaults: transactional,
// normal priority, queued.
func (m *Message) Normalize() {
	for _, p := range []*string{&m.FromName, &m.FromEmail, &m.ToEmail, &m.ToName, &m.ReplyTo,
		&m.Topic, &m.TemplateID, &m.TemplateVersionID, &m.Locale, &m.EventID, &m.IdempotencyKey} {
		*p = strings.TrimSpace(*p)
	}
	if m.Type == "" {
		m.Type = TypeTransactional
	}
	if m.Priority == 0 {
		m.Priority = PriorityNormal
	}
	if m.Status == "" {
		m.Status = StatusQueued
	}
}

// Validate checks a message before it is queued. A message may carry a
// rendered body or a template to render; the subject comes from the
// template when there is one. Failures are one 422 with an entry per field.
func (m *Message) Validate() error {
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: field, Code: code, Message: msg})
	}
	oneLine := func(field, v string, max int) {
		if len(v) > max || strings.ContainsAny(v, "\r\n\x00") {
			add(field, "invalid", fmt.Sprintf("%s must be one line of at most %d characters", field, max))
		}
	}
	if m.OrgID == "" {
		add("org_id", "required", "tenant is required")
	}
	switch {
	case m.ToEmail == "":
		add("to_email", "required", "recipient is required")
	case !provider.ValidEmail(m.ToEmail):
		add("to_email", "invalid", "recipient is not a valid address")
	}
	if m.FromEmail != "" && !provider.ValidEmail(m.FromEmail) {
		add("from_email", "invalid", "sender is not a valid address")
	}
	if m.ReplyTo != "" && !provider.ValidEmail(m.ReplyTo) {
		add("reply_to", "invalid", "reply-to is not a valid address")
	}
	oneLine("from_name", m.FromName, maxLine)
	oneLine("to_name", m.ToName, maxLine)
	oneLine("subject", m.Subject, MaxSubjectLen)
	if m.TemplateID == "" {
		if strings.TrimSpace(m.Subject) == "" {
			add("subject", "required", "subject is required without a template")
		}
		if m.HTMLBody == "" && m.TextBody == "" {
			add("body", "required", "an HTML or text body is required without a template")
		}
	}
	if !m.Type.Valid() {
		add("type", "invalid", "type must be transactional, marketing or notification")
	}
	if !m.Status.Valid() {
		add("status", "invalid", "unknown status")
	}
	if m.Status == StatusScheduled && m.ScheduledAt == nil {
		add("scheduled_at", "required", "a scheduled message needs a send time")
	}
	if m.Priority < PriorityLow || m.Priority > PriorityHigh {
		add("priority", "out_of_range", "priority must be between 1 and 10")
	}
	if len(m.Tags) > MaxTags {
		add("tags", "too_many", fmt.Sprintf("at most %d tags", MaxTags))
	}
	for i, t := range m.Tags {
		if !validTag(t) || slices.Index(m.Tags, t) != i {
			add("tags", "invalid", "tags must be unique letters, digits, '-', '_', '.' or ':' of at most 64 characters")
			break
		}
	}
	if len(m.Metadata) > MaxMetadataKeys {
		add("metadata", "too_many", fmt.Sprintf("at most %d metadata keys", MaxMetadataKeys))
	}
	oneLine("idempotency_key", m.IdempotencyKey, MaxIdempotencyKey)
	oneLine("topic", m.Topic, maxLine)
	oneLine("event_id", m.EventID, maxLine)
	if m.Locale != "" && !validLocale(m.Locale) {
		add("locale", "invalid", "locale must be a language tag such as en or pt-BR")
	}
	if m.TemplateVersionID != "" && m.TemplateID == "" {
		add("template_version_id", "not_allowed", "a template version needs its template")
	}
	if len(m.SecretKeys) > MaxSecretKeys {
		add("secret_keys", "too_many", fmt.Sprintf("at most %d secret keys", MaxSecretKeys))
	}
	for _, k := range m.SecretKeys {
		if k == "" || len(k) > 128 {
			add("secret_keys", "invalid", "secret keys must be variable names of at most 128 characters")
			break
		}
	}
	switch m.Actor.Type {
	case "":
	case ActorUser, ActorService, ActorSystem:
		if m.Actor.ID == "" && m.Actor.Type != ActorSystem {
			add("actor", "required", "actor id is required")
		}
	default:
		add("actor", "invalid", "actor type must be user, service or system")
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

func validTag(t string) bool {
	if t == "" || len(t) > MaxTagLen {
		return false
	}
	for _, r := range t {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:", r)) {
			return false
		}
	}
	return true
}

// validLocale accepts BCP 47-shaped tags: letters and digits in subtags of
// 1–8 separated by '-' (or '_', which callers send often).
func validLocale(s string) bool {
	if len(s) > 35 {
		return false
	}
	for _, sub := range strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(sub) > 8 {
			return false
		}
		for _, r := range sub {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return s[0] != '-' && s[0] != '_' && !strings.HasSuffix(s, "-") && !strings.HasSuffix(s, "_")
}

// Transition moves the message to status to, stamping the matching time.
// An illegal change is a conflict (another worker moved it first).
func (m *Message) Transition(to Status, now time.Time) error {
	if !CanTransition(m.Status, to) {
		return apperrors.Conflict(fmt.Sprintf("a %s message cannot become %s", m.Status, to))
	}
	m.Status = to
	m.UpdatedAt = now
	switch to {
	case StatusSending:
		m.Attempts++
		m.LastAttemptAt = &now
	case StatusSent:
		m.SentAt = &now
		m.LastError = ""
	case StatusDelivered:
		m.DeliveredAt = &now
	case StatusBounced:
		m.BouncedAt = &now
	case StatusFailed:
		m.FailedAt = &now
	case StatusCancelled:
		m.CancelledAt = &now
	}
	return nil
}

// MarkSent records the provider's acceptance.
func (m *Message) MarkSent(providerID, providerMessageID string, now time.Time) error {
	if err := m.Transition(StatusSent, now); err != nil {
		return err
	}
	m.ProviderID = providerID
	m.ProviderMessageID = providerMessageID
	return nil
}

// RecordSendFailure records a failed attempt of a sending message and
// reports whether it should be retried: an invalid recipient bounces,
// another permanent error fails, and a transient one is queued again until
// maxAttempts attempts were made.
func (m *Message) RecordSendFailure(err error, maxAttempts int, now time.Time) (retry bool, _ error) {
	m.LastError = SafeDetail(err)
	se, _ := AsSendError(err)
	switch {
	case se != nil && se.Reason == ReasonInvalidRecipient:
		return false, m.Transition(StatusBounced, now)
	case IsPermanent(err), m.Attempts >= maxAttempts:
		return false, m.Transition(StatusFailed, now)
	}
	return true, m.Transition(StatusQueued, now)
}

// BodyPurgeDue reports whether the retention period has passed for a
// message that no longer needs its body.
func (m *Message) BodyPurgeDue(retention time.Duration, now time.Time) bool {
	return m.BodyPurgedAt == nil && m.Status.Final() && !now.Before(m.CreatedAt.Add(retention))
}

// PurgeBody erases the bodies and template data, and masks secret values
// in the subject, keeping the delivery record.
func (m *Message) PurgeBody(now time.Time) {
	m.Subject = m.Redact(m.Subject)
	m.HTMLBody = ""
	m.TextBody = ""
	m.TemplateData = nil
	m.BodyPurgedAt = &now
	m.UpdatedAt = now
}

// secretValues returns the string forms of the secret variables' values.
func (m *Message) secretValues() []string {
	var out []string
	for _, k := range m.SecretKeys {
		v, ok := lookup(m.TemplateData, k)
		if !ok || v == nil {
			continue
		}
		s := fmt.Sprint(v)
		if len(s) >= minSecretLen {
			out = append(out, s)
		}
	}
	// Longest first, so a value containing another is masked whole.
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// Redact replaces every secret value found in s with Mask: a rendered
// subject or body shown in the console, or a log line.
func (m *Message) Redact(s string) string {
	for _, v := range m.secretValues() {
		s = strings.ReplaceAll(s, v, Mask)
	}
	return s
}

// MaskedTemplateData returns a copy of the template data with the secret
// variables' values replaced by Mask.
func (m *Message) MaskedTemplateData() map[string]any {
	if m.TemplateData == nil {
		return nil
	}
	out := deepCopy(m.TemplateData).(map[string]any)
	for _, k := range m.SecretKeys {
		mask(out, strings.Split(k, "."))
	}
	return out
}

// lookup reads a dotted path from nested maps.
func lookup(data map[string]any, path string) (any, bool) {
	var cur any = data
	for _, part := range strings.Split(path, ".") {
		mp, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mp[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func mask(data map[string]any, path []string) {
	v, ok := data[path[0]]
	if !ok {
		return
	}
	if len(path) == 1 {
		data[path[0]] = Mask
		return
	}
	if child, ok := v.(map[string]any); ok {
		mask(child, path[1:])
	}
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = deepCopy(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopy(x)
		}
		return out
	}
	return v
}

// ErrBodyPurged is returned when a message whose body was erased is sent.
var ErrBodyPurged = apperrors.Conflict("the message body was erased under the retention policy")

// Outgoing returns what a provider sends for the message. The bodies must
// be rendered.
func (m *Message) Outgoing() (Outgoing, error) {
	if m.BodyPurgedAt != nil {
		return Outgoing{}, ErrBodyPurged
	}
	out := Outgoing{
		TenantID:  m.OrgID,
		MessageID: m.ID,
		From:      Address{Name: m.FromName, Email: m.FromEmail},
		To:        Address{Name: m.ToName, Email: m.ToEmail},
		Subject:   m.Subject,
		HTML:      m.HTMLBody,
		Text:      m.TextBody,
		Tags:      slices.Clone(m.Tags),
	}
	if m.ReplyTo != "" {
		out.ReplyTo = Address{Email: m.ReplyTo}
	}
	return out, nil
}
