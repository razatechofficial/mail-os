package mailer

import (
	"testing"

	"github.com/razatechofficial/mail-os/domain/message"
)

// Real replies from common relays and receiving servers (text after the
// reply code, as net/textproto returns it). Only replies that name the
// recipient may bounce: a bounce suppresses the address tenant-wide.
func TestClassifyPermanent_RealWorldReplies(t *testing.T) {
	cases := []struct {
		relay, stage string
		code         int
		msg          string
		want         message.Reason
	}{
		// Sender and "send as" refusals at RCPT: configuration, never a bounce.
		{"Exchange Online (UAT)", stageRcpt, 550, "5.7.60 SMTP; Client does not have permissions to send as this sender", message.ReasonConfig},
		{"Exchange Online (UAT)", stageRcpt, 550, "Cannot send a message as no-reply@bank.example. Please send as contact@bank.example", message.ReasonConfig},
		{"Exchange Online", stageMail, 550, "5.7.60 SMTP; Client does not have permissions to send as this sender [BN8PR04MB6211.namprd04.prod.outlook.com]", message.ReasonConfig},
		{"Exchange Online", stageRcpt, 550, "5.7.64 TenantAttribution; Relay Access Denied [SN1NAM02FT0123.eop-nam02.prod.protection.outlook.com]", message.ReasonConfig},
		{"Exchange Online", stageRcpt, 550, "5.7.708 Service unavailable. Access denied, traffic not accepted from this IP.", message.ReasonConfig},
		{"Exchange Online", stageRcpt, 550, "5.7.750 Service unavailable. Client blocked from sending from unregistered domains.", message.ReasonConfig},
		{"Exchange Online", stageMail, 530, "5.7.57 Client not authenticated to send mail. Error: 535 5.7.139 Authentication unsuccessful", message.ReasonAuth},
		{"Exchange Online", stageMail, 550, "5.7.1 Client does not have permissions to send as this sender", message.ReasonConfig},
		{"Postfix", stageRcpt, 553, "5.7.1 <no-reply@bank.example>: Sender address rejected: not owned by user contact@bank.example", message.ReasonConfig},
		{"Postfix", stageRcpt, 554, "5.7.1 <user@other.example>: Relay access denied", message.ReasonConfig},
		{"Postfix", stageRcpt, 550, "5.1.0 <no-reply@bank.example>: Sender address rejected: User unknown in local recipient table", message.ReasonConfig},
		{"Postfix", stageRcpt, 450, "4.1.8 <no-reply@bank.example>: Sender address rejected: Domain not found", message.ReasonConfig},
		{"Postfix", stageMail, 553, "5.1.8 <no-reply@bank.example>: Sender address rejected: Domain not found", message.ReasonConfig},
		{"Exim", stageRcpt, 550, "relay not permitted", message.ReasonConfig},
		{"Exim", stageRcpt, 550, "Verification failed for <no-reply@bank.example>\nNo Such User Here\nSender verify failed", message.ReasonConfig},
		{"Exim", stageMail, 550, "Your message was rejected: authentication required", message.ReasonAuth},
		{"Gmail", stageMail, 530, "5.7.0 Authentication Required. Learn more at https://support.google.com/mail/?p=WantAuthError", message.ReasonAuth},
		{"Gmail", stageData, 550, "5.7.26 Unauthenticated email from bank.example is not accepted due to domain's DMARC policy.", message.ReasonConfig},
		{"Gmail", stageData, 550, "5.7.1 [203.0.113.5] The IP you're using to send mail is not authorized to send email directly to our servers.", message.ReasonConfig},
		{"Gmail", stageData, 550, "5.7.23 The message was rejected because of Sender Policy Framework violation (SPF).", message.ReasonConfig},
		{"Google Workspace relay", stageRcpt, 550, "5.7.0 Mail relay denied [203.0.113.5]. Invalid credentials for relay for one of the domains in: bank.example", message.ReasonAuth},
		{"Amazon SES", stageData, 554, "Message rejected: Email address is not verified. The following identities failed the check in region EU-WEST-1: no-reply@bank.example", message.ReasonConfig},
		{"Amazon SES", stageMail, 530, "Authentication required", message.ReasonAuth},
		{"SendGrid", stageData, 550, "The from address does not match a verified Sender Identity. Mail cannot be sent until this error is resolved.", message.ReasonConfig},
		{"Mailgun", stageRcpt, 550, "5.7.1 Relaying denied", message.ReasonConfig},
		{"Mailgun", stageRcpt, 421, "Domain bank.example is not allowed to send: Free accounts are for test purposes only.", message.ReasonConfig},
		{"Mailgun", stageRcpt, 550, "Sandbox subdomains are for test purposes only. Please add your own domain or add the address to authorized recipients in Account Settings.", message.ReasonConfig},
		{"Zoho", stageRcpt, 553, "Relaying disallowed as no-reply@bank.example", message.ReasonConfig},
		{"Zoho", stageRcpt, 553, "Sender is not allowed to relay emails", message.ReasonConfig},
		{"Zoho", stageRcpt, 550, "5.4.6 Unusual sending activity detected. Please verify your account.", message.ReasonConfig},
		{"Spamhaus via relay", stageRcpt, 554, "5.7.1 Service unavailable; Client host [203.0.113.5] blocked using zen.spamhaus.org", message.ReasonConfig},

		// Genuine recipient failures: bounce (and suppress).
		{"Gmail", stageRcpt, 550, "5.1.1 The email account that you tried to reach does not exist. Please try double-checking the recipient's email address for typos or unnecessary spaces.", message.ReasonInvalidRecipient},
		{"Exchange Online", stageRcpt, 550, "5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP address lookup", message.ReasonInvalidRecipient},
		{"Exchange Online", stageRcpt, 550, "5.4.1 Recipient address rejected: Access denied. AS(201806281) [DM6NAM10FT0123.eop-nam10.prod.protection.outlook.com]", message.ReasonRejected},
		{"Postfix", stageRcpt, 550, "5.1.1 <gone@other.example>: Recipient address rejected: User unknown in virtual mailbox table", message.ReasonInvalidRecipient},
		{"Postfix", stageRcpt, 450, "4.1.2 <a@nowhere.example>: Recipient address rejected: Domain not found", message.ReasonInvalidRecipient},
		{"Exim", stageRcpt, 550, "Unrouteable address", message.ReasonInvalidRecipient},
		{"Exim", stageRcpt, 550, "No Such User Here", message.ReasonInvalidRecipient},
		{"Zoho", stageRcpt, 550, "5.1.1 User does not exist - gone@zoho.example", message.ReasonInvalidRecipient},
		{"Yahoo", stageRcpt, 554, "delivery error: dd This user doesn't have a yahoo.com account (gone@yahoo.com) [0] - mta1.mail.yahoo.com", message.ReasonInvalidRecipient},
		{"generic", stageRcpt, 550, "5.2.1 The email account that you tried to reach is disabled.", message.ReasonInvalidRecipient},
		{"generic", stageRcpt, 550, "Requested action not taken: mailbox unavailable", message.ReasonInvalidRecipient},

		// The address exists or nothing names it: the message fails, no bounce.
		{"Gmail", stageRcpt, 552, "5.2.2 The email account that you tried to reach is over quota.", message.ReasonRejected},
		{"generic", stageData, 552, "5.3.4 Message size exceeds fixed maximum message size", message.ReasonRejected},
		{"generic", stageData, 554, "5.7.1 Message rejected as spam by Content Filtering.", message.ReasonRejected},
		{"generic", stageRcpt, 550, "Administrative prohibition", message.ReasonRejected},
		{"generic", stageRcpt, 554, "Transaction failed", message.ReasonRejected},
		{"generic", stageMail, 550, "Not accepted", message.ReasonConfig},
	}
	for _, c := range cases {
		if c.code < 500 {
			// 4xx replies are transient before classifyPermanent; the text
			// classes still hold for the permanent variant.
			c.code += 100
		}
		if got := classifyPermanent(c.stage, c.code, c.msg); got != c.want {
			t.Errorf("%s at %s: %d %q = %s, want %s", c.relay, c.stage, c.code, c.msg, got, c.want)
		}
	}
}

// A sender refusal is the provider's fault, so the router tries the next
// provider; it is permanent, so the queue does not retry the same one.
func TestClassifyPermanent_SenderRefusalIsProviderFault(t *testing.T) {
	r := classifyPermanent(stageRcpt, 550, "5.7.60 SMTP; Client does not have permissions to send as this sender")
	if !r.ProviderFault() || !r.Permanent() || r == message.ReasonInvalidRecipient {
		t.Fatalf("reason %s", r)
	}
}
