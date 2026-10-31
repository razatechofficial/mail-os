package contact

import (
	"strconv"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// ListType is how a list chooses its members.
type ListType string

// List types. A static list holds the contacts added to it. Dynamic
// (segment query) lists are not evaluated yet, so they are refused rather
// than stored as lists no campaign could reach.
const (
	ListStatic  ListType = "static"
	ListDynamic ListType = "dynamic"
)

// Limits.
const (
	MaxDescriptionLen = 1000
	MaxQueryLen       = 4000
	// MaxMembersPerCall is the most contacts one add or remove names.
	MaxMembersPerCall = 1000
)

// List is a named group of a tenant's contacts that campaigns are sent to.
type List struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        ListType  `json:"type"`
	Query       string    `json:"query"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Check normalizes and validates a list (422 with every failing field).
func (l *List) Check() error {
	l.Name = strings.TrimSpace(l.Name)
	l.Description = strings.TrimSpace(l.Description)
	l.Query = strings.TrimSpace(l.Query)
	if l.Type == "" {
		l.Type = ListStatic
	}
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: field, Code: code, Message: msg})
	}
	switch {
	case l.Name == "":
		add("name", "required", "name is required")
	case len(l.Name) > MaxNameLen || strings.ContainsAny(l.Name, "\r\n"):
		add("name", "invalid", "name must be one line of at most 255 characters")
	}
	if len(l.Description) > MaxDescriptionLen {
		add("description", "too_long", "description must be at most "+strconv.Itoa(MaxDescriptionLen)+" characters")
	}
	switch l.Type {
	case ListStatic:
		if l.Query != "" {
			add("query", "not_allowed", "a static list has no segment query")
		}
	case ListDynamic:
		add("type", "unsupported", "dynamic (segment query) lists are not supported yet; use a static list")
	default:
		add("type", "invalid", "type must be static")
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

// CheckMembers validates the contact ids of an add or remove, dropping
// blanks and repeats.
func CheckMembers(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	switch {
	case len(out) == 0:
		return nil, apperrors.Invalid("contact_ids", "required", "contact_ids must name at least one contact")
	case len(out) > MaxMembersPerCall:
		return nil, apperrors.Invalid("contact_ids", "too_many", "at most "+strconv.Itoa(MaxMembersPerCall)+" contacts per call")
	}
	return out, nil
}
