// Package platformrole is the MailOS platform plane's roles (ADR 0001
// §3.4, contract C4): the nine role families of the ACS module mailos/,
// how long each may be active, and the permissions the platform API's
// routes are guarded by. ACS holds who has which role and answers every
// check; this package only names them, so MailOS and its tests agree with
// authz/module.zed (TestPermissionsMatchModule).
package platformrole

import (
	"slices"
	"strings"
	"time"
)

// Role is a MailOS platform role (an ACS relation on mailos/platform:global).
type Role string

// The nine roles.
const (
	Owner             Role = "platform_owner"
	Operator          Role = "platform_operator"
	TemplateEditor    Role = "platform_template_editor"
	TemplatePublisher Role = "platform_template_publisher"
	KeyCustodian      Role = "platform_key_custodian"
	AbuseAnalyst      Role = "platform_abuse_analyst"
	Support           Role = "platform_support"
	LogAdmin          Role = "platform_log_admin"
	Auditor           Role = "platform_auditor"
)

// Roles lists every role, in the ADR's order.
var Roles = []Role{Owner, Operator, TemplateEditor, TemplatePublisher, KeyCustodian, AbuseAnalyst, Support, LogAdmin, Auditor}

// Parse reports whether s names a role.
func Parse(s string) (Role, bool) {
	r := Role(s)
	return r, slices.Contains(Roles, r)
}

// MaxActivationCeiling is the longest any activation may last: ACS's
// expiry horizon on the activation relations (authz/grant.yaml).
const MaxActivationCeiling = 8 * time.Hour

// MaxActivation is how long one activation of r may last (ADR 0001 §3.4).
func (r Role) MaxActivation() time.Duration {
	if r.NeedsSecondApprover() {
		return 4 * time.Hour
	}
	return MaxActivationCeiling
}

// NeedsSecondApprover reports the roles whose activation a second platform
// owner approves.
func (r Role) NeedsSecondApprover() bool {
	return r == Owner || r == TemplatePublisher || r == KeyCustodian
}

// Relation is the activation relation; EligibleRelation the eligibility
// relation.
func (r Role) Relation() string         { return string(r) }
func (r Role) EligibleRelation() string { return "eligible_" + string(r) }

// RoleOfRelation maps an ACS relation back to its role and whether it is
// the eligibility relation.
func RoleOfRelation(rel string) (role Role, eligible bool, ok bool) {
	if rest, cut := strings.CutPrefix(rel, "eligible_"); cut {
		role, ok = Parse(rest)
		return role, true, ok
	}
	role, ok = Parse(rel)
	return role, false, ok
}

// ACS names of the module's one object.
const (
	ObjectType = "mailos/platform"
	ObjectID   = "global"
	// SubjectType is the core type every platform subject is.
	SubjectType = "user"
)

// Permission is a platform route guard, a permission of the ACS module.
type Permission string

// Permissions (contract C4).
const (
	ViewOverview     Permission = "view_overview"
	ViewTenants      Permission = "view_tenants"
	ManageTenants    Permission = "manage_tenants"
	StopSend         Permission = "stop_send"
	ViewConnectors   Permission = "view_connectors"
	ViewTemplates    Permission = "view_templates"
	EditTemplates    Permission = "edit_templates"
	PublishTemplates Permission = "publish_templates"
	ViewConfig       Permission = "view_config"
	ProposeConfig    Permission = "propose_config"
	ApproveConfig    Permission = "approve_config"
	ManageKeys       Permission = "manage_keys"
	ViewAudit        Permission = "view_audit"
	VerifyAudit      Permission = "verify_audit"
	ExportAudit      Permission = "export_audit"
)

// Permissions is contract C4's table: each permission and the roles that
// reach it. ACS decides; this is the reference MailOS's tests and the e2e
// fake ACS use.
var Permissions = []struct {
	Permission Permission
	Roles      []Role
}{
	{ViewOverview, Roles},
	{ViewTenants, []Role{Owner, Operator, AbuseAnalyst, Support, Auditor}},
	{ManageTenants, []Role{Operator}},
	{StopSend, []Role{Operator, AbuseAnalyst}},
	{ViewConnectors, []Role{Owner, Operator, Auditor}},
	{ViewTemplates, []Role{Owner, Operator, TemplateEditor, TemplatePublisher, Auditor}},
	{EditTemplates, []Role{TemplateEditor}},
	{PublishTemplates, []Role{TemplatePublisher}},
	{ViewConfig, []Role{Owner, Operator, KeyCustodian, Auditor}},
	{ProposeConfig, []Role{Operator, KeyCustodian}},
	{ApproveConfig, []Role{Operator, KeyCustodian}},
	{ManageKeys, []Role{KeyCustodian}},
	{ViewAudit, []Role{Owner, LogAdmin, Auditor}},
	{VerifyAudit, []Role{LogAdmin}},
	{ExportAudit, []Role{LogAdmin}},
}

// AllPermissions lists every permission, in the table's order.
func AllPermissions() []Permission {
	out := make([]Permission, len(Permissions))
	for i, p := range Permissions {
		out[i] = p.Permission
	}
	return out
}

// Grants reports whether holding any of roles reaches perm (per the table).
func Grants(roles []Role, perm Permission) bool {
	for _, p := range Permissions {
		if p.Permission != perm {
			continue
		}
		for _, r := range roles {
			if slices.Contains(p.Roles, r) {
				return true
			}
		}
	}
	return false
}
