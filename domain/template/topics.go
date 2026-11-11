package template

import (
	"slices"
	"strconv"
	"strings"
)

// Kind is the type of a variable's value, which decides how event data is
// checked and whether the console masks the value.
type Kind string

// Variable kinds.
const (
	KindText     Kind = "text"
	KindURL      Kind = "url"
	KindEmail    Kind = "email"
	KindDatetime Kind = "datetime" // RFC 3339
	KindNumber   Kind = "number"
	// KindSecret is a one-time code. The console masks it in previews and
	// message views, and logs never show it (contract §6).
	KindSecret Kind = "secret"
)

// Sources of topics: the service that publishes the event.
const (
	SourceIAM    = "iam"
	SourceMailOS = "mailos"
)

// Variable is one value a topic's events carry, offered in the designer.
type Variable struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Kind   Kind   `json:"kind"`
	Sample string `json:"sample"`
	// Required variables must be in every event of the topic. Optional
	// ones follow the publisher's omitempty fields and are checked only
	// when present.
	Required bool `json:"-"`
}

// Topic is an event a template can serve, with the variables its data
// carries: the topic's own, brand.* where IAM adds the tenant's brand, and
// the common variables every topic offers.
type Topic struct {
	Key         string     `json:"topic"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Source      string     `json:"source"`
	Variables   []Variable `json:"variables"`
}

// Topics IAM publishes, from iam/server/pkg/events and its lifecycle
// worker.
const (
	TopicSecurityNotice    = "iam.account.security_notice"
	TopicApprovalRequested = "iam.approval.requested"
	TopicInvite            = "iam.auth.invite_requested"
	TopicMagicLink         = "iam.auth.magic_link_requested"
	TopicPasswordReset     = "iam.auth.password_reset_requested"
	TopicEmailVerification = "iam.user.email_verification_requested"
	TopicMFAEmailCode      = "iam.auth.mfa_email_code_requested"
	TopicPasskeyEnrolment  = "iam.auth.passkey_enrolment_requested"
	TopicDeletionRequested = "iam.user.deletion_requested"
	TopicAccessReview      = "iam.access_review.started"
	TopicLifecycleEmail    = "iam.lifecycle.email"
)

// Tenant domain topics (contract §7): one event per tenant administrator,
// payload pkg/events.DomainNotice.
const (
	TopicDomainVerified           = "iam.domain.verified"
	TopicDomainClaimExpiring      = "iam.domain.claim_expiring"
	TopicDomainClaimReleased      = "iam.domain.claim_released"
	TopicDomainVerificationLapsed = "iam.domain.verification_lapsed"
	TopicDomainTransferRequested  = "iam.domain.transfer_requested"
	TopicDomainTransferred        = "iam.domain.transferred"
	TopicDomainRevoked            = "iam.domain.revoked"
)

// Workspace request topics (IAM's tenant sign-up governance), payload
// pkg/events.TenantSignupNotice. The first three go to the person who
// asked for a workspace; review_requested goes to each platform
// administrator once the requester's address is confirmed.
const (
	TopicTenantSignupEmailVerification = "iam.tenant_signup.email_verification_requested"
	TopicTenantSignupApproved          = "iam.tenant_signup.approved"
	TopicTenantSignupRejected          = "iam.tenant_signup.rejected"
	TopicTenantSignupReviewRequested   = "iam.tenant_signup.review_requested"
)

// Governance topics IAM publishes (application/accessrequest, pim,
// accessreview, apps, platformgov and the tenant status notifier).
const (
	TopicPatternExceptionExpired   = "iam.application.pattern_exception_expired"
	TopicAccessRequestSubmitted    = "iam.access_request.submitted"
	TopicAccessRequestDecided      = "iam.access_request.decided"
	TopicAccessRequestExpired      = "iam.access_request.expired"
	TopicAccessReviewCompleted     = "iam.access_review.completed"
	TopicPrivilegedAccessRequested = "iam.privileged_access.requested"
	TopicPrivilegedAccessApproved  = "iam.privileged_access.approved"
	TopicPrivilegedAccessDenied    = "iam.privileged_access.denied"
	TopicBreakGlassUsed            = "iam.security.break_glass_used"
	TopicGovernanceAlert           = "iam.platform.governance_alert"
	TopicTenantStatusChanged       = "iam.tenant.status_changed"
)

// TopicCampaign is MailOS's own topic: a campaign sent to contacts.
const TopicCampaign = "mailos.campaign"

func req(key, label string, kind Kind, sample string) Variable {
	return Variable{Key: key, Label: label, Kind: kind, Sample: sample, Required: true}
}

func opt(key, label string, kind Kind, sample string) Variable {
	return Variable{Key: key, Label: label, Kind: kind, Sample: sample}
}

var recipientEmail = req("email", "Email", KindEmail, "amna@example.com")

// commonVariables are offered by every topic; MailOS fills them from the
// recipient and the organization's branding when the event does not.
var commonVariables = []Variable{
	opt("user.name", "Recipient name", KindText, "Amna Khan"),
	opt("user.email", "Recipient email", KindEmail, "amna@example.com"),
	opt("brand.company_name", "Company name", KindText, "Averox"),
	opt("unsubscribe_url", "Unsubscribe link", KindURL, "https://mail.example.com/unsubscribe/sample"),
}

// brandVariables are the "brand" object IAM's brand mail adds to the
// events it renders as email to a person (infrastructure/brandmail). A
// brand is cosmetic, so every field is optional.
var brandVariables = []Variable{
	opt("brand.name", "Brand name", KindText, "Averox"),
	opt("brand.logo_url", "Brand logo", KindURL, "https://iam.example.com/branding/logo.png"),
	opt("brand.primary_color", "Brand primary colour", KindText, "#2563eb"),
	opt("brand.accent_color", "Brand accent colour", KindText, "#0ea5e9"),
	opt("brand.support_text", "Support text", KindText, "Contact support@example.com"),
}

// topicSpec is a topic before the shared variables are added.
type topicSpec struct {
	Topic
	branded bool
}

var catalogue = []topicSpec{
	{Topic: Topic{Key: TopicSecurityNotice, Name: "Account security notice", Source: SourceIAM,
		Description: "A factor, password or sign-in change on the user's own account",
		Variables: []Variable{recipientEmail,
			req("user_uuid", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
			req("kind", "Kind of change", KindText, "factor_added"),
			opt("credential", "Credential", KindText, "Authenticator app"),
			opt("ip", "IP address", KindText, "203.0.113.10"),
			opt("user_agent", "Device", KindText, "Firefox on Windows"),
			req("occurred_at", "When", KindDatetime, "2026-10-31T09:30:00Z"),
			opt("link", "Review link", KindURL, "https://iam.example.com/account/security"),
		}}, branded: true},
	{Topic: Topic{Key: TopicApprovalRequested, Name: "Approval requested", Source: SourceIAM,
		Description: "A change held for a second administrator to approve",
		Variables: []Variable{recipientEmail,
			opt("user_id", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
			opt("tenant_id", "Tenant ID or platform", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
			opt("scope_name", "Scope", KindText, "Averox"),
			opt("request_id", "Request ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000006"),
			opt("operation", "Operation key", KindText, "policy.update"),
			req("operation_label", "Operation", KindText, "Change access policy"),
			req("summary", "Summary", KindText, "PUT access policy Default"),
			opt("requester_id", "Requester ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000007"),
			opt("requester_email", "Requested by", KindEmail, "bilal@example.com"),
			opt("requested_at", "Requested", KindDatetime, "2026-10-31T09:30:00Z"),
			req("expires_at", "Expires", KindDatetime, "2026-11-01T09:30:00Z"),
			req("approval_link", "Approval link", KindURL, "https://iam.example.com/approvals/sample"),
		}}},
	{Topic: Topic{Key: TopicInvite, Name: "Invitation", Source: SourceIAM,
		Description: "An invitation to join an organization",
		Variables: []Variable{recipientEmail,
			req("org_name", "Organization", KindText, "Averox"),
			req("link", "Invitation link", KindURL, "https://iam.example.com/invite/sample"),
		}}, branded: true},
	{Topic: Topic{Key: TopicMagicLink, Name: "Magic sign-in link", Source: SourceIAM,
		Description: "A one-time link that signs the user in",
		Variables: []Variable{recipientEmail,
			req("link", "Sign-in link", KindURL, "https://iam.example.com/magic/sample"),
		}}, branded: true},
	{Topic: Topic{Key: TopicPasswordReset, Name: "Password reset", Source: SourceIAM,
		Description: "A link to choose a new password",
		Variables: []Variable{recipientEmail,
			req("reset_link", "Reset link", KindURL, "https://iam.example.com/reset/sample"),
			opt("organization_uuid", "Organization ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000002"),
		}}, branded: true},
	{Topic: Topic{Key: TopicEmailVerification, Name: "Email verification", Source: SourceIAM,
		Description: "A link that confirms the user owns the address",
		Variables: []Variable{recipientEmail,
			req("verify_link", "Verification link", KindURL, "https://iam.example.com/verify/sample"),
		}}, branded: true},
	{Topic: Topic{Key: TopicMFAEmailCode, Name: "Email sign-in code", Source: SourceIAM,
		Description: "A one-time code sent as a second factor",
		Variables: []Variable{recipientEmail,
			req("code", "Code", KindSecret, "482913"),
			req("purpose", "Purpose", KindText, "sign_in"),
			req("expires_in_minutes", "Expires in (minutes)", KindNumber, "10"),
		}}},
	{Topic: Topic{Key: TopicPasskeyEnrolment, Name: "Passkey enrolment", Source: SourceIAM,
		Description: "A link to register a passkey",
		Variables: []Variable{recipientEmail,
			req("link", "Enrolment link", KindURL, "https://iam.example.com/passkeys/enrol/sample"),
			req("expires_at", "Expires", KindDatetime, "2026-11-01T09:30:00Z"),
		}}},
	{Topic: Topic{Key: TopicDeletionRequested, Name: "Account deletion requested", Source: SourceIAM,
		Description: "The account will be deleted unless the user cancels",
		Variables: []Variable{recipientEmail,
			req("cancel_link", "Cancel link", KindURL, "https://iam.example.com/account/deletion/cancel/sample"),
			opt("scheduled_for", "Deletion date", KindDatetime, "2026-11-30T09:30:00Z"),
		}}},
	{Topic: Topic{Key: TopicAccessReview, Name: "Access review started", Source: SourceIAM,
		Description: "The user has access decisions to make in a review",
		Variables: []Variable{recipientEmail,
			req("pending_count", "Pending decisions", KindNumber, "12"),
			req("review_link", "Review link", KindURL, "https://iam.example.com/access-reviews/my"),
			opt("review_name", "Review", KindText, "Quarterly access review"),
			opt("due_at", "Due", KindDatetime, "2026-11-15T17:00:00Z"),
		}}},
	{Topic: Topic{Key: TopicLifecycleEmail, Name: "Lifecycle workflow email", Source: SourceIAM,
		Description: "A message a tenant's lifecycle workflow sends, written by its administrator",
		Variables: []Variable{recipientEmail,
			req("user_uuid", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
			req("tenant_uuid", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
			req("subject", "Subject", KindText, "Welcome to Averox"),
			req("body", "Body", KindText, "Your account is ready."),
			req("occurred_at", "When", KindDatetime, "2026-10-31T09:30:00Z"),
		}}},
	domainTopic(TopicDomainVerified, "Domain verified", "The tenant proved control of a domain for the first time",
		req("domain_id", "Domain ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000004")),
	domainTopic(TopicDomainClaimExpiring, "Domain claim expiring", "An unverified domain claim expires soon",
		req("domain_id", "Domain ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000004"),
		req("expires_at", "Expires", KindDatetime, "2026-11-01T09:30:00Z")),
	domainTopic(TopicDomainClaimReleased, "Domain claim released", "The tenant's unverified domain claim is gone",
		req("domain_id", "Domain ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000004"),
		req("reason", "Reason", KindText, "expired")),
	domainTopic(TopicDomainVerificationLapsed, "Domain verification lapsed", "Re-verification failed and the domain is an expiring claim again",
		req("domain_id", "Domain ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000004"),
		opt("reason", "Reason", KindText, "dns_record_missing"),
		req("expires_at", "Expires", KindDatetime, "2026-11-07T09:30:00Z")),
	domainTopic(TopicDomainTransferRequested, "Domain transfer requested", "A platform operator opened a transfer of a domain to this tenant",
		req("reason", "Reason", KindText, "Merger of the two workspaces"),
		req("dns_name", "DNS record name", KindText, "_iam-challenge.example.com"),
		req("dns_value", "DNS record value", KindText, "iam-domain-verification=3f2a9c"),
		req("expires_at", "Expires", KindDatetime, "2026-11-07T09:30:00Z")),
	domainTopic(TopicDomainTransferred, "Domain transferred", "A domain moved between tenants after approval and a fresh DNS proof",
		req("domain_id", "Domain ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000004"),
		req("reason", "Reason", KindText, "Merger of the two workspaces"),
		req("direction", "Direction", KindText, "to"),
		opt("other_tenant_name", "Other tenant", KindText, "Averox Labs")),
	domainTopic(TopicDomainRevoked, "Domain revoked", "A platform operator removed a verified domain from this tenant",
		req("domain_id", "Domain ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000004"),
		req("reason", "Reason", KindText, "Ownership dispute upheld")),
	signupTopic(TopicTenantSignupEmailVerification, "Workspace request: confirm your email",
		"A link that confirms the address of someone asking for a workspace",
		req("verify_link", "Verification link", KindURL, "https://iam.example.com/signup/workspace/verify#token=sample"),
		opt("expires_at", "Link expires", KindDatetime, "2026-11-01T09:30:00Z")),
	signupTopic(TopicTenantSignupApproved, "Workspace request approved",
		"A platform administrator approved the request and the workspace was created",
		req("workspace_name", "Workspace", KindText, "Averox Labs"),
		opt("workspace_slug", "Workspace slug", KindText, "averox-labs"),
		req("link", "Sign-in link", KindURL, "https://iam.example.com/login")),
	signupTopic(TopicTenantSignupRejected, "Workspace request rejected",
		"A platform administrator rejected the request",
		opt("reason", "Reason", KindText, "We could not confirm the organization")),
	signupTopic(TopicTenantSignupReviewRequested, "Workspace request waiting for review",
		"A workspace request with a confirmed address waits for a platform administrator",
		req("workspace_name", "Workspace", KindText, "Averox Labs"),
		opt("workspace_slug", "Workspace slug", KindText, "averox-labs"),
		req("requester_email", "Requester email", KindEmail, "founder@averox-labs.example"),
		opt("requester_name", "Requester name", KindText, "Sara Ahmed"),
		opt("domain", "Email domain", KindText, "averox-labs.example"),
		opt("expires_at", "Request expires", KindDatetime, "2026-11-07T09:30:00Z"),
		req("link", "Review link", KindURL, "https://iam.example.com/platform/workspace-requests?request=sample")),
	{Topic: Topic{Key: TopicPatternExceptionExpired, Name: "Pattern exception expired", Source: SourceIAM,
		Description: "An application's sign-in pattern exception expired, so its MFA-only connections are refused",
		Variables: []Variable{recipientEmail,
			req("user_id", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
			req("tenant_id", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
			req("application_id", "Application ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000008"),
			req("application_name", "Application", KindText, "T24 Transact"),
			req("expires_at", "Expired", KindDatetime, "2026-11-10T09:00:00Z"),
			req("application_link", "Application link", KindURL, "https://iam.example.com/applications/sample"),
		}}},
	accessRequestTopic(TopicAccessRequestSubmitted, "Access request submitted",
		"Someone asked for access to an application that this person may approve",
		req("requester_id", "Requester ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000007"),
		opt("requester_email", "Requester email", KindEmail, "alice@example.com"),
		opt("justification", "Justification", KindText, "Branch cover"),
		req("requested_at", "Requested", KindDatetime, "2026-11-10T09:00:00Z"),
		opt("duration_days", "Duration (days)", KindNumber, "7"),
		req("review_link", "Review link", KindURL, "https://iam.example.com/account/access-requests?request=sample")),
	accessRequestTopic(TopicAccessRequestDecided, "Access request decided",
		"The requester's access request was approved or denied",
		req("decision", "Decision", KindText, "approved"),
		opt("note", "Approver's note", KindText, "Approved for the branch cover"),
		opt("ticket_ref", "Service desk ticket", KindText, "RITM0010001"),
		opt("access_expires_at", "Access ends", KindDatetime, "2026-11-17T09:00:00Z")),
	accessRequestTopic(TopicAccessRequestExpired, "Access request expired",
		"Time-bound access granted by a request ended",
		req("expired_at", "Ended", KindDatetime, "2026-11-17T09:00:00Z")),
	{Topic: Topic{Key: TopicAccessReviewCompleted, Name: "Access review completed", Source: SourceIAM,
		Description: "An access review the person started is complete",
		Variables: []Variable{recipientEmail,
			req("user_id", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
			opt("name", "Reviewer name", KindText, "Amna Khan"),
			req("tenant_id", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
			opt("tenant_name", "Tenant", KindText, "Averox"),
			req("review_id", "Review ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000009"),
			req("review_name", "Review", KindText, "Quarterly access review"),
			req("total", "Decisions", KindNumber, "40"),
			req("kept", "Kept", KindNumber, "35"),
			req("removed", "Removed", KindNumber, "4"),
			req("not_decided", "Not decided", KindNumber, "1"),
			req("failed", "Removals that failed", KindNumber, "0"),
			req("manual", "Removals to make by hand", KindNumber, "0"),
			req("review_link", "Review link", KindURL, "https://iam.example.com/access-reviews/sample"),
		}}},
	{Topic: Topic{Key: TopicPrivilegedAccessRequested, Name: "Privileged access requested", Source: SourceIAM,
		Description: "A user asked to activate a privileged role this person may approve",
		Variables: []Variable{recipientEmail,
			req("tenant_id", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
			req("activation_id", "Activation ID", KindText, "0190f5e2-7c1a-7b3e-9f00-00000000000a"),
			req("requester_id", "Requester ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000007"),
			opt("requester_email", "Requester email", KindEmail, "bilal@example.com"),
			opt("role_kind", "Role kind", KindText, "tenant"),
			opt("role_name", "Role", KindText, "Tenant administrator"),
			req("duration_minutes", "Duration (minutes)", KindNumber, "60"),
			opt("justification", "Justification", KindText, "Incident INC-2041"),
			opt("ticket_ref", "Ticket", KindText, "INC-2041"),
			req("review_link", "Review link", KindURL, "https://iam.example.com/privileged-access/requests"),
		}}},
	privilegedDecisionTopic(TopicPrivilegedAccessApproved, "Privileged access approved",
		"The person's privileged role activation was approved and is active",
		req("expires_at", "Active until", KindDatetime, "2026-11-10T10:00:00Z")),
	privilegedDecisionTopic(TopicPrivilegedAccessDenied, "Privileged access denied",
		"The person's privileged role activation was denied"),
	{Topic: Topic{Key: TopicBreakGlassUsed, Name: "Emergency account signed in", Source: SourceIAM,
		Description: "A workspace's emergency (break-glass) account signed in",
		Variables: []Variable{recipientEmail,
			req("tenant_id", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
			req("account_id", "Emergency account ID", KindText, "0190f5e2-7c1a-7b3e-9f00-00000000000b"),
			opt("account_email", "Emergency account", KindEmail, "breakglass@example.com"),
			opt("ip", "IP address", KindText, "203.0.113.10"),
			req("at", "When", KindDatetime, "2026-11-10T09:30:00Z"),
			req("review_link", "Audit log link", KindURL, "https://iam.example.com/audit-logs"),
		}}},
	{Topic: Topic{Key: TopicGovernanceAlert, Name: "Platform governance alert", Source: SourceIAM,
		Description: "A platform governance alert for every platform owner; IAM writes the title and detail of each kind",
		Variables: []Variable{recipientEmail,
			req("user_id", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
			req("kind", "Alert kind", KindText, "admin_passkey_enrolment"),
			req("title", "Title", KindText, "A platform administrator is adding a passkey or security key"),
			req("detail", "Detail", KindText, "owner1@example.com signed in from 203.0.113.10 and is enrolling a passkey."),
			req("severity", "Severity", KindText, "high"),
			req("link", "Console link", KindURL, "https://iam.example.com/platform/administrators"),
			req("at", "When", KindDatetime, "2026-11-10T09:30:00Z"),
			opt("brand_scope", "Brand scope", KindText, "platform"),
		}}},
	{Topic: Topic{Key: TopicTenantStatusChanged, Name: "Workspace status changed", Source: SourceIAM,
		Description: "A platform operator suspended, reactivated or cancelled the owner's workspace",
		Variables: []Variable{recipientEmail,
			req("user_id", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
			req("tenant_id", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
			opt("tenant_uuid", "Tenant UUID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
			req("tenant_name", "Workspace", KindText, "Averox"),
			req("action", "Action", KindText, "suspended"),
			req("category", "Category", KindText, "security_incident"),
			req("category_label", "Category label", KindText, "Security incident"),
			opt("purge_after", "Data kept until", KindDatetime, "2027-02-08T09:00:00Z"),
			req("at", "When", KindDatetime, "2026-11-10T09:00:00Z"),
		}}},
	{Topic: Topic{Key: TopicCampaign, Name: "Campaign", Source: SourceMailOS,
		Description: "A marketing campaign sent to a contact list",
		Variables: []Variable{
			req("contact.email", "Contact email", KindEmail, "amna@example.com"),
			opt("contact.first_name", "First name", KindText, "Amna"),
			opt("contact.last_name", "Last name", KindText, "Khan"),
		}}},
}

// domainTopic is a §7 topic: the fields every DomainNotice carries, then
// the topic's own.
func domainTopic(key, name, description string, extra ...Variable) topicSpec {
	vars := []Variable{recipientEmail,
		req("user_id", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
		req("tenant_id", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
		opt("tenant_name", "Tenant", KindText, "Averox"),
		req("domain", "Domain", KindText, "example.com"),
		req("occurred_at", "When", KindDatetime, "2026-10-31T09:30:00Z"),
		req("link", "Domains page", KindURL, "https://iam.example.com/settings/domains"),
	}
	return topicSpec{Topic: Topic{Key: key, Name: name, Description: description, Source: SourceIAM, Variables: append(vars, extra...)}}
}

// accessRequestTopic is an access request topic: the fields every access
// request message carries, then the topic's own.
func accessRequestTopic(key, name, description string, extra ...Variable) topicSpec {
	vars := []Variable{recipientEmail,
		req("user_id", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
		req("tenant_id", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
		req("request_id", "Request ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000006"),
		req("application_id", "Application ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000008"),
		req("application_name", "Application", KindText, "T24 Transact"),
		opt("role_key", "Role key", KindText, "teller"),
		opt("role_name", "Role", KindText, "Teller"),
		req("requests_link", "My requests link", KindURL, "https://iam.example.com/account/access-requests"),
	}
	return topicSpec{Topic: Topic{Key: key, Name: name, Description: description, Source: SourceIAM, Variables: append(vars, extra...)}}
}

// privilegedDecisionTopic is a decision on a privileged role activation,
// sent to the person who asked.
func privilegedDecisionTopic(key, name, description string, extra ...Variable) topicSpec {
	vars := []Variable{recipientEmail,
		req("user_id", "User ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000001"),
		req("tenant_id", "Tenant ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000003"),
		req("activation_id", "Activation ID", KindText, "0190f5e2-7c1a-7b3e-9f00-00000000000a"),
		opt("note", "Approver's note", KindText, "Approved for INC-2041"),
		req("link", "Privileged access link", KindURL, "https://iam.example.com/privileged-access"),
	}
	return topicSpec{Topic: Topic{Key: key, Name: name, Description: description, Source: SourceIAM, Variables: append(vars, extra...)}}
}

// signupTopic is a workspace request topic: the fields every
// TenantSignupNotice carries, then the topic's own.
func signupTopic(key, name, description string, extra ...Variable) topicSpec {
	vars := []Variable{recipientEmail,
		req("request_id", "Request ID", KindText, "0190f5e2-7c1a-7b3e-9f00-000000000005"),
		req("organization_name", "Organization", KindText, "Averox Labs"),
		req("occurred_at", "When", KindDatetime, "2026-10-31T09:30:00Z"),
	}
	return topicSpec{Topic: Topic{Key: key, Name: name, Description: description, Source: SourceIAM, Variables: append(vars, extra...)}}
}

// topics is the catalogue with the shared variables added, by key.
var (
	topics     []Topic
	topicIndex = map[string]int{}
)

func init() {
	for _, spec := range catalogue {
		t := spec.Topic
		vars := slices.Clone(t.Variables)
		if spec.branded {
			vars = append(vars, brandVariables...)
		}
		t.Variables = append(vars, commonVariables...)
		topicIndex[t.Key] = len(topics)
		topics = append(topics, t)
	}
}

// Topics returns the catalogue, in a fixed order. The caller may change
// the copy it gets.
func Topics() []Topic {
	out := make([]Topic, len(topics))
	for i, t := range topics {
		out[i] = t.clone()
	}
	return out
}

// TopicByKey finds a topic.
func TopicByKey(key string) (Topic, bool) {
	i, ok := topicIndex[key]
	if !ok {
		return Topic{}, false
	}
	return topics[i].clone(), true
}

func (t Topic) clone() Topic {
	t.Variables = slices.Clone(t.Variables)
	return t
}

// Variable finds one of the topic's variables.
func (t Topic) Variable(key string) (Variable, bool) {
	for _, v := range t.Variables {
		if v.Key == key {
			return v, true
		}
	}
	return Variable{}, false
}

// variablesOf is the topic's variables, or the common ones for "" or an
// unknown topic.
func variablesOf(topic string) []Variable {
	if i, ok := topicIndex[topic]; ok {
		return topics[i].Variables
	}
	return commonVariables
}

// SecretKeys lists the topic's secret variables, such as an email code.
// Their values are masked in console views and never logged.
func SecretKeys(topic string) []string {
	var keys []string
	for _, v := range variablesOf(topic) {
		if v.Kind == KindSecret {
			keys = append(keys, v.Key)
		}
	}
	return keys
}

// SampleData is event data built from the topic's samples, nested by key
// ({"user":{"name":…}}), for previews. Numbers are float64, as decoded JSON
// is. "" or an unknown topic gets the common variables.
func SampleData(topic string) map[string]any {
	data := map[string]any{}
	for _, v := range variablesOf(topic) {
		var val any = v.Sample
		if v.Kind == KindNumber {
			if f, err := strconv.ParseFloat(v.Sample, 64); err == nil {
				val = f
			}
		}
		setPath(data, v.Key, val)
	}
	return data
}

func setPath(data map[string]any, key string, val any) {
	segs := strings.Split(key, ".")
	cur := data
	for _, s := range segs[:len(segs)-1] {
		next, ok := cur[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = val
}
