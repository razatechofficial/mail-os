// Package access holds who may do what in MailOS: the IAM roles the console
// releases (contract §5), the permissions each grants, the authenticated
// principal behind a request, and the service-client allow-list (§4).
package access

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

// Role is an IAM role released in the access token's roles claim.
type Role string

// MailOS roles (contract §5). A token without one of them has no access.
const (
	RoleAdmin             Role = "mailos_admin"
	RoleTemplateEditor    Role = "mailos_template_editor"
	RoleTemplatePublisher Role = "mailos_template_publisher"
	RoleOperator          Role = "mailos_operator"
	RoleAuditor           Role = "mailos_auditor"
	RoleViewer            Role = "mailos_viewer"
)

// Roles lists every MailOS role, most privileged first.
var Roles = []Role{RoleAdmin, RoleTemplateEditor, RoleTemplatePublisher, RoleOperator, RoleAuditor, RoleViewer}

// ParseRole reports whether s is a MailOS role. IAM releases every role the
// user holds; only these mean anything here.
func ParseRole(s string) (Role, bool) {
	r := Role(strings.TrimSpace(s))
	return r, slices.Contains(Roles, r)
}

// Permission is one action a role allows.
type Permission string

// Permissions. Read permissions never include message bodies: reading a
// body is its own permission, audited and behind step-up.
const (
	PermTemplatesRead    Permission = "templates:read"
	PermTemplatesEdit    Permission = "templates:edit" // create, metadata, drafts, restore, preview, test send
	PermTemplatesPublish Permission = "templates:publish"
	PermTemplatesDelete  Permission = "templates:delete"
	PermBrandingEdit     Permission = "branding:edit"

	PermProvidersRead   Permission = "providers:read"
	PermProvidersManage Permission = "providers:manage" // providers and their credentials
	PermDomainsRead     Permission = "domains:read"
	PermDomainsManage   Permission = "domains:manage" // sending domains and DKIM keys
	PermWebhooksRead    Permission = "webhooks:read"
	PermWebhooksManage  Permission = "webhooks:manage"
	PermSettingsRead    Permission = "settings:read"
	PermSettingsManage  Permission = "settings:manage" // four-eyes, retention
	PermRolesView       Permission = "roles:view"      // the caller's and users' MailOS roles

	PermMessagesRead     Permission = "messages:read"      // metadata, never bodies
	PermMessageBodies    Permission = "messages:read_body" // read or export bodies
	PermMessagesOperate  Permission = "messages:operate"   // send, cancel, resend, queues
	PermSuppressionsRead Permission = "suppressions:read"
	PermSuppressionsEdit Permission = "suppressions:manage"
	PermContactsRead     Permission = "contacts:read"
	PermContactsManage   Permission = "contacts:manage"
	PermCampaignsRead    Permission = "campaigns:read"
	PermCampaignsManage  Permission = "campaigns:manage"
	PermAnalyticsRead    Permission = "analytics:read"

	PermAuditRead   Permission = "audit:read"
	PermAuditExport Permission = "audit:export"

	// PermEventsDispatch is a service client publishing an event; the topic
	// is checked against its allow-list as well.
	PermEventsDispatch Permission = "events:dispatch"
)

// readOnly is what every role may read: everything except message bodies
// and the audit log.
var readOnly = []Permission{
	PermTemplatesRead, PermProvidersRead, PermDomainsRead, PermWebhooksRead, PermSettingsRead,
	PermMessagesRead, PermSuppressionsRead, PermContactsRead, PermCampaignsRead, PermAnalyticsRead,
}

func with(base []Permission, extra ...Permission) []Permission {
	return append(slices.Clone(base), extra...)
}

// rolePermissions is contract §5's table.
var rolePermissions = map[Role][]Permission{
	RoleAdmin: with(readOnly,
		PermTemplatesEdit, PermTemplatesPublish, PermTemplatesDelete, PermBrandingEdit,
		PermProvidersManage, PermDomainsManage, PermWebhooksManage, PermSettingsManage, PermRolesView,
		PermMessageBodies, PermMessagesOperate, PermSuppressionsEdit, PermContactsManage, PermCampaignsManage,
		PermAuditRead, PermAuditExport),
	RoleTemplateEditor:    with(readOnly, PermTemplatesEdit),
	RoleTemplatePublisher: with(readOnly, PermTemplatesPublish),
	RoleOperator: with(readOnly, PermMessagesOperate, PermMessageBodies, PermSuppressionsEdit,
		PermContactsManage, PermCampaignsManage),
	RoleAuditor: with(readOnly, PermMessageBodies, PermAuditRead, PermAuditExport),
	RoleViewer:  slices.Clone(readOnly),
}

// stepUpPermissions need a fresh multi-factor sign-in (contract §5):
// credential, domain and DKIM changes, publishing, reading or exporting
// message bodies, audit export, and the security settings themselves.
var stepUpPermissions = map[Permission]bool{
	PermProvidersManage:  true,
	PermDomainsManage:    true,
	PermWebhooksManage:   true,
	PermTemplatesPublish: true,
	PermMessageBodies:    true,
	PermAuditExport:      true,
	PermSettingsManage:   true,
}

// NeedsStepUp reports whether p needs a fresh multi-factor sign-in.
func NeedsStepUp(p Permission) bool { return stepUpPermissions[p] }

// PermissionsOf is the union of the roles' permissions.
func PermissionsOf(roles []Role) []Permission {
	var out []Permission
	for _, r := range roles {
		for _, p := range rolePermissions[r] {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Kind is who is calling: a person through the console, or a service.
type Kind string

// Principal kinds.
const (
	KindUser    Kind = "user"
	KindService Kind = "service"
)

// Principal is the verified identity behind a request.
type Principal struct {
	Kind Kind
	// Subject is the IAM user UUID, or "client:<client_id>" for a service.
	Subject string
	// ClientID is the service's OAuth client, or the client a user's token
	// was issued to.
	ClientID string
	TenantID string
	OrgID    string
	// Roles are the MailOS roles among the token's roles; a service has none.
	Roles     []Role
	ACR       string
	AMR       []string
	AuthTime  time.Time
	SessionID string
	TokenID   string
	// DPoPThumbprint is cnf.jkt of a sender-constrained token (RFC 9449).
	DPoPThumbprint string
	// Delegated marks a token someone acts with on the subject's behalf
	// (RFC 8693 act): it never proves the subject re-authenticated.
	Delegated bool
}

// IsService reports a service caller.
func (p Principal) IsService() bool { return p.Kind == KindService }

// Can reports whether the principal's roles allow perm. Services hold only
// PermEventsDispatch, narrowed by the allow-list.
func (p Principal) Can(perm Permission) bool {
	if p.IsService() {
		return perm == PermEventsDispatch
	}
	for _, r := range p.Roles {
		if slices.Contains(rolePermissions[r], perm) {
			return true
		}
	}
	return false
}

// Actor is how audit records name the principal: the user UUID, or the
// service's client_id.
func (p Principal) Actor() string {
	if p.IsService() {
		return p.ClientID
	}
	return p.Subject
}

// Authentication context class references IAM asserts (OIDC Core §2 acr),
// weakest first. Each satisfies a request for any weaker one.
const (
	ACRPassword          = "urn:iam:acr:password"
	ACRMFA               = "urn:iam:acr:mfa"
	ACRPhishingResistant = "urn:iam:acr:phishing-resistant"
)

func acrRank(acr string) int {
	switch acr {
	case ACRPassword:
		return 1
	case ACRMFA:
		return 2
	case ACRPhishingResistant:
		return 3
	default:
		return 0
	}
}

// ACRSatisfies reports whether a sign-in at got is at least as strong as want.
func ACRSatisfies(got, want string) bool {
	if want == "" {
		return true
	}
	return acrRank(want) > 0 && acrRank(got) >= acrRank(want)
}

// StepUpPolicy is the fresh-MFA rule.
type StepUpPolicy struct {
	MaxAge time.Duration
	ACR    string
}

// Step-up refusals; the transport turns them into the RFC 9470 challenge.
var (
	ErrStepUpStale     = errors.New("a more recent sign-in is required")
	ErrStepUpWeak      = errors.New("a sign-in with a second factor is required")
	ErrStepUpDelegated = errors.New("this operation cannot be done on someone else's behalf")
)

// Check refuses a delegated token, a sign-in older than MaxAge (or with no
// auth_time) and one weaker than ACR.
func (s StepUpPolicy) Check(p Principal, now time.Time) error {
	if p.Delegated {
		return ErrStepUpDelegated
	}
	if p.AuthTime.IsZero() || now.Sub(p.AuthTime) > s.MaxAge {
		return ErrStepUpStale
	}
	if !ACRSatisfies(p.ACR, s.ACR) {
		return ErrStepUpWeak
	}
	return nil
}

type principalKey struct{}

// WithPrincipal stores the verified principal in ctx.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the principal stored by WithPrincipal.
func FromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
