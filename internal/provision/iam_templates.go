package provision

import (
	"fmt"
	"html"
	"regexp"
	"strings"

	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
)

// content is the wording of one IAM topic's default email. Paragraphs may
// hold {{variables}} and <b>; the rest is plain text.
type content struct {
	Name, Subject, Preheader, Heading string
	Paragraphs                        []string
	Button, ButtonVar                 string
	// Code is a variable shown large (a one-time code).
	Code string
}

// iamContent is the default wording for every IAM topic in the template
// catalogue: the same messages the IAM demo seeds, without a bank's name or
// logo (the header and footer use brand.company_name from the tenant's
// template branding). Administrators replace them in the console; the
// bootstrap never overwrites a published template.
var iamContent = map[string]content{
	domaintemplate.TopicEmailVerification: {Name: "Verify your email address", Subject: "Verify your email address",
		Preheader: "Confirm your address to finish setting up your account", Heading: "Confirm your email address",
		Paragraphs: []string{"Hello {{user.name}},", "Please confirm that {{email}} is your email address. The link expires in 24 hours.", "If you did not create an account, ignore this message."},
		Button:     "Verify email", ButtonVar: "verify_link"},
	domaintemplate.TopicMFAEmailCode: {Name: "Sign-in code", Subject: "Your sign-in code",
		Preheader: "Use this code to finish signing in", Heading: "Your one-time code",
		Paragraphs: []string{"Hello {{user.name}},", "Use this code to {{purpose}}. It expires in {{expires_in_minutes}} minutes.", "We will never ask you for this code. Do not share it with anyone."},
		Code:       "code"},
	domaintemplate.TopicApprovalRequested: {Name: "Approval requested (four-eyes)", Subject: "Approval needed: {{operation_label}}",
		Preheader: "A second administrator must approve this change", Heading: "A change is waiting for your approval",
		Paragraphs: []string{"Hello {{user.name}},", "{{requester_email}} asked to <b>{{operation_label}}</b> in {{scope_name}}.", "{{summary}}", "The request expires at {{expires_at}}. You cannot approve your own requests."},
		Button:     "Review request", ButtonVar: "approval_link"},
	domaintemplate.TopicInvite: {Name: "Invitation", Subject: "You're invited to {{org_name}}",
		Preheader: "Accept your invitation", Heading: "You've been invited",
		Paragraphs: []string{"Hello {{user.name}},", "You have been invited to join {{org_name}}.", "Accept the invitation to set your password and sign in. If you did not expect it, ignore this message."},
		Button:     "Accept invitation", ButtonVar: "link"},
	domaintemplate.TopicPasswordReset: {Name: "Password reset", Subject: "Reset your password",
		Preheader: "A password reset was requested", Heading: "Reset your password",
		Paragraphs: []string{"Hello {{user.name}},", "We received a request to reset the password for {{email}}.", "If you did not ask for this, contact your service desk immediately."},
		Button:     "Reset password", ButtonVar: "reset_link"},
	domaintemplate.TopicMagicLink: {Name: "Sign-in link", Subject: "Your sign-in link",
		Preheader: "Sign in without a password", Heading: "Sign in",
		Paragraphs: []string{"Hello {{user.name}},", "Use the button below to sign in as {{email}}. The link works once and expires soon."},
		Button:     "Sign in", ButtonVar: "link"},
	domaintemplate.TopicSecurityNotice: {Name: "Security notice", Subject: "Security notice for your account",
		Preheader: "A change was made to your account", Heading: "A security change was made",
		Paragraphs: []string{"Hello {{user.name}},", "Change: <b>{{kind}}</b> ({{credential}}) at {{occurred_at}}.", "From {{ip}} using {{user_agent}}.", "If this wasn't you, review your account security now."},
		Button:     "Review account security", ButtonVar: "link"},
	domaintemplate.TopicPasskeyEnrolment: {Name: "Passkey enrolment", Subject: "Set up your passkey",
		Preheader: "Register a passkey for phishing-resistant sign-in", Heading: "Set up a passkey",
		Paragraphs: []string{"Hello {{user.name}},", "Your administrator asked you to register a passkey for phishing-resistant sign-in.", "The link expires at {{expires_at}}."},
		Button:     "Set up passkey", ButtonVar: "link"},
	domaintemplate.TopicDeletionRequested: {Name: "Account deletion requested", Subject: "Your account is scheduled for deletion",
		Preheader: "You can still cancel", Heading: "Account deletion requested",
		Paragraphs: []string{"Hello {{user.name}},", "Deletion of the account {{email}} was requested.", "If this was a mistake, cancel it before the grace period ends."},
		Button:     "Cancel deletion", ButtonVar: "cancel_link"},
	domaintemplate.TopicAccessReview: {Name: "Access review started", Subject: "Access review: {{pending_count}} decisions needed",
		Preheader: "Access certification", Heading: "Your access review is open",
		Paragraphs: []string{"Hello {{user.name}},", "You have {{pending_count}} access decisions to make in {{review_name}}."},
		Button:     "Start review", ButtonVar: "review_link"},
	domaintemplate.TopicDomainVerified: {Name: "Domain verified", Subject: "{{domain}} is verified for {{tenant_name}}",
		Preheader: "Your domain is now verified", Heading: "Domain verified",
		Paragraphs: []string{"Hello {{user.name}},", "{{tenant_name}} proved control of <b>{{domain}}</b> on {{occurred_at}}.", "Accounts with this domain can now be routed to your workspace."},
		Button:     "View domains", ButtonVar: "link"},
	domaintemplate.TopicDomainClaimExpiring: {Name: "Domain claim expiring", Subject: "Action needed: verify {{domain}} before {{expires_at}}",
		Preheader: "Your domain claim expires soon", Heading: "Your domain claim is about to expire",
		Paragraphs: []string{"Hello {{user.name}},", "The claim on <b>{{domain}}</b> is not verified yet and expires at {{expires_at}}.", "Publish the DNS TXT record shown on the Domains page to keep it."},
		Button:     "Verify domain", ButtonVar: "link"},
	domaintemplate.TopicDomainClaimReleased: {Name: "Domain claim released", Subject: "Your claim on {{domain}} was released",
		Preheader: "A domain claim is gone", Heading: "Domain claim released",
		Paragraphs: []string{"Hello {{user.name}},", "The unverified claim on <b>{{domain}}</b> was released ({{reason}})."},
		Button:     "View domains", ButtonVar: "link"},
	domaintemplate.TopicDomainVerificationLapsed: {Name: "Domain verification lapsed", Subject: "{{domain}} verification lapsed",
		Preheader: "Re-verify your domain", Heading: "Domain verification lapsed",
		Paragraphs: []string{"Hello {{user.name}},", "Re-verification of <b>{{domain}}</b> failed ({{reason}}).", "It is a claim again and expires at {{expires_at}} unless you verify it."},
		Button:     "Re-verify domain", ButtonVar: "link"},
	domaintemplate.TopicDomainTransferRequested: {Name: "Domain transfer requested", Subject: "Transfer of {{domain}} to {{tenant_name}} requested",
		Preheader: "Publish a DNS record to accept the transfer", Heading: "A domain transfer was opened",
		Paragraphs: []string{"Hello {{user.name}},", "A platform operator opened a transfer of <b>{{domain}}</b> to {{tenant_name}}: {{reason}}.", "Publish TXT {{dns_name}} = {{dns_value}} before {{expires_at}}."},
		Button:     "Open domains", ButtonVar: "link"},
	domaintemplate.TopicDomainTransferred: {Name: "Domain transferred", Subject: "{{domain}} was transferred",
		Preheader: "A domain moved between workspaces", Heading: "Domain transferred",
		Paragraphs: []string{"Hello {{user.name}},", "<b>{{domain}}</b> was transferred ({{direction}} {{other_tenant_name}}) after four-eyes approval and a fresh DNS proof.", "Reason: {{reason}}."},
		Button:     "View domains", ButtonVar: "link"},
	domaintemplate.TopicDomainRevoked: {Name: "Domain revoked", Subject: "{{domain}} was removed from {{tenant_name}}",
		Preheader: "A verified domain was revoked", Heading: "Domain revoked",
		Paragraphs: []string{"Hello {{user.name}},", "A platform operator removed <b>{{domain}}</b> from {{tenant_name}} after four-eyes approval.", "Reason: {{reason}}."},
		Button:     "View domains", ButtonVar: "link"},
	domaintemplate.TopicTenantSignupReviewRequested: {Name: "Workspace request waiting", Subject: "Workspace request waiting: {{workspace_name}}",
		Preheader: "A confirmed workspace request needs a decision", Heading: "A workspace request is waiting for review",
		Paragraphs: []string{"Hello {{user.name}},", "{{requester_email}} asked for the workspace <b>{{workspace_name}}</b> for {{organization_name}} and confirmed their address.", "Review the request and approve or reject it. Requested at {{occurred_at}}."},
		Button:     "Review request", ButtonVar: "link"},
	domaintemplate.TopicLifecycleEmail: {Name: "Lifecycle notification", Subject: "{{subject}}",
		Preheader: "Joiner, mover and leaver notification", Heading: "{{subject}}",
		Paragraphs: []string{"{{body}}"}},
}

// contentFor is the topic's wording, or a plain notice built from the
// catalogue for a topic added after this table (never an empty mail).
func contentFor(t domaintemplate.Topic) content {
	if c, ok := iamContent[t.Key]; ok {
		return c
	}
	return content{Name: t.Name, Subject: t.Name, Heading: t.Name, Paragraphs: []string{"Hello {{user.name}},", t.Description + "."}}
}

var varRe = regexp.MustCompile(`\{\{\s*([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*)\s*\}\}`)

const brandColor = "#2563eb"

// compile renders email-safe HTML and plain text with the placeholders left
// for MailOS to fill (it escapes values by context), and lists the
// variables the content uses.
func compile(c content) (htmlBody, textBody string, vars []string) {
	seen := map[string]bool{}
	collect := func(s string) {
		for _, m := range varRe.FindAllStringSubmatch(s, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				vars = append(vars, m[1])
			}
		}
	}
	plain := strings.NewReplacer("<b>", "", "</b>", "")
	collect(c.Subject)
	collect(c.Heading)
	collect("{{brand.company_name}}")
	var body, text strings.Builder
	fmt.Fprintf(&body, `<h2 style="margin:0 0 16px;font-size:20px;color:#0f172a">%s</h2>`, c.Heading)
	fmt.Fprintf(&text, "%s\n\n", c.Heading)
	for _, p := range c.Paragraphs {
		collect(p)
		fmt.Fprintf(&body, `<p style="margin:0 0 14px;font-size:15px;line-height:1.6;color:#0f172a">%s</p>`, p)
		fmt.Fprintf(&text, "%s\n\n", plain.Replace(p))
	}
	if c.Code != "" {
		collect("{{" + c.Code + "}}")
		fmt.Fprintf(&body, `<p style="margin:8px 0 18px;font-size:32px;letter-spacing:6px;font-weight:bold;color:%s">{{%s}}</p>`, brandColor, c.Code)
		fmt.Fprintf(&text, "Code: {{%s}}\n\n", c.Code)
	}
	if c.Button != "" {
		collect("{{" + c.ButtonVar + "}}")
		fmt.Fprintf(&body, `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:8px 0 8px"><tr><td style="background:%s;border-radius:6px;padding:12px 22px"><a href="{{%s}}" style="color:#ffffff;text-decoration:none;font-weight:bold;font-size:15px">%s</a></td></tr></table>`,
			brandColor, c.ButtonVar, html.EscapeString(c.Button))
		fmt.Fprintf(&text, "%s: {{%s}}\n\n", c.Button, c.ButtonVar)
	}
	text.WriteString("--\n{{brand.company_name}}. This is an automated message; please do not reply.\n")
	htmlBody = fmt.Sprintf(`<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>%s</title></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif">
<div style="display:none;max-height:0;overflow:hidden">%s</div>
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f1f5f9"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%%;background:#ffffff;border-radius:8px;overflow:hidden">
<tr><td style="background:#ffffff;padding:18px 24px;border-bottom:3px solid %s"><span style="font-size:18px;font-weight:bold;color:#0f172a">{{brand.company_name}}</span></td></tr>
<tr><td style="padding:28px 24px 8px">%s</td></tr>
<tr><td style="padding:16px 24px 24px;border-top:1px solid #e2e8f0;font-size:12px;color:#64748b;text-align:center">{{brand.company_name}}. This is an automated message; please do not reply.</td></tr>
</table></td></tr></table></body></html>`, html.EscapeString(c.Name), html.EscapeString(c.Preheader), brandColor, body.String())
	return htmlBody, text.String(), vars
}

// slugOf is the template slug of a topic: iam.auth.invite_requested →
// iam-auth-invite-requested.
func slugOf(topic string) string {
	return strings.NewReplacer(".", "-", "_", "-").Replace(topic)
}
