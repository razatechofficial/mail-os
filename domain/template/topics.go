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
			opt("scope_name", "Scope", KindText, "Averox"),
			req("operation_label", "Operation", KindText, "Change access policy"),
			req("summary", "Summary", KindText, "PUT access policy Default"),
			opt("requester_email", "Requested by", KindEmail, "bilal@example.com"),
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
	{Topic: Topic{Key: TopicCampaign, Name: "Campaign", Source: SourceMailOS,
		Description: "A marketing campaign sent to a contact list",
		Variables: []Variable{
			req("contact.email", "Contact email", KindEmail, "amna@example.com"),
			opt("contact.first_name", "First name", KindText, "Amna"),
			opt("contact.last_name", "Last name", KindText, "Khan"),
		}}},
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
