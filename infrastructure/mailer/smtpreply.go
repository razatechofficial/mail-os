package mailer

import (
	"regexp"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
)

// A 5xx reply refuses the transaction permanently (RFC 5321 §4.2.1), but
// not always the recipient: relays refuse the sender, the "send as"
// identity, relaying or an unauthenticated session at RCPT time as often
// as at MAIL. Only a reply that names the recipient as the problem may
// bounce the message, because a bounce puts the address on the tenant's
// suppression list. A refusal of the sender, the session or the sending
// domain's policy is the provider's configuration: no suppression, the
// router tries the next provider, and the provider is marked failing.

// enhancedCode finds the RFC 3463 enhanced status code (class.subject.detail).
var enhancedCode = regexp.MustCompile(`\b[245]\.\d{1,3}\.\d{1,3}\b`)

// Enhanced codes that name the sender, the session or the sending domain
// (RFC 3463 §3.2, §3.8; Exchange Online and Gmail extensions).
var senderCodes = map[string]bool{
	"5.1.7": true, "5.1.8": true, // bad sender mailbox / sender's system address
	"5.7.8":  true,                                                 // authentication credentials invalid
	"5.7.23": true, "5.7.25": true, "5.7.26": true, "5.7.27": true, // SPF / PTR / DMARC / DKIM of the sending domain
	"5.7.57":  true,                                   // client not authenticated to send
	"5.7.60":  true,                                   // no permission to send as this sender
	"5.7.64":  true,                                   // tenant attribution relay denied
	"5.7.501": true, "5.7.502": true, "5.7.503": true, // sending account banned (spam)
	"5.7.506": true, "5.7.508": true, "5.7.510": true, "5.7.511": true, // sending IP / account blocked
	"5.7.700": true, "5.7.703": true, "5.7.704": true, "5.7.705": true, "5.7.708": true, "5.7.750": true, // Exchange Online tenant / IP blocks
}

// authCodes name an unauthenticated or refused session.
var authCodes = map[string]bool{"5.7.8": true, "5.7.57": true, "5.7.139": true}

// Enhanced codes that name the recipient's address or mailbox.
var recipientCodes = map[string]bool{
	"5.1.0": true, "5.1.1": true, "5.1.2": true, "5.1.3": true, "5.1.6": true, "5.1.10": true, "5.2.1": true,
}

var (
	// senderText is a refusal of the sender, its identity, relaying, the
	// session or the sending domain's policy.
	senderText = regexp.MustCompile(strings.Join([]string{
		`\bsend(ing)?( a| the)?( message| mail| email| e-mail)? as\b`, // "send as this sender", "cannot send a message as"
		`\bsendas\b`, `\bsend on behalf\b`, `\bsendasdenied\b`,
		`\bsender\b`, // "sender address rejected", "sender verify failed", "sender identity"
		`\bnot owned by( the)? user\b`,
		`\bfrom address\b`, `\bmail from\b`, `\benvelope from\b`, `\bfrom: ?header\b`,
		`\brelay(ing)?\b`, `\brcpthosts\b`,
		`\bnot (authorized|authorised|allowed|permitted) to send\b`,
		`\b(email address|identity|identities|domain) (is |are )?not verified\b`, `\bidentities failed the check\b`,
		`\bdmarc\b`, `\bspf\b`, `\bdkim\b`, `\bunauthenticated email\b`,
		`\bauthenticat(e|ed|ion)\b`, `\bauth(entication)? required\b`, `\blogin required\b`,
		`\bclient host .* blocked\b`, `\bblocked using\b`, `\bblacklist`, `\bblocklist`, `\bbanned sending\b`,
		`\bsending (account|domain|ip)\b`, `\bunusual sending activity\b`, `\bfree accounts are for test\b`, `\bsandbox\b`,
	}, "|"))
	// authText names an unauthenticated session or refused credentials.
	authText = regexp.MustCompile(`\bauthenticat(e|ed|ion)\b|\bauth(entication)? required\b|\blogin required\b|\bcredentials\b`)
	// recipientText names the recipient's address or mailbox as unknown,
	// invalid or disabled.
	recipientText = regexp.MustCompile(strings.Join([]string{
		`\buser unknown\b`, `\bunknown user\b`, `\bno such (user|recipient|mailbox|address|account)\b`,
		`\brecipient (not found|unknown|does not exist|invalid)\b`, `\binvalid recipient\b`, `\bunknown recipient\b`,
		`\bmailbox (unavailable|not found|does not exist|is disabled|disabled|inactive)\b`, `\bno mailbox\b`,
		`\b(account|address|user|email account|mailbox) (that you tried to reach )?does not exist\b`,
		`\b(account|mailbox) (is )?(disabled|inactive|suspended)\b`, `\buser not found\b`, `\bnot a valid (mailbox|recipient)\b`,
		`\buser doesn'?t have an? [\w.-]+ account\b`, `\bunrouteable address\b`, `\brecipnotfound\b`, `\bmailbox unavailable\b`, `\bno such domain\b`, `\bdomain not found\b`,
	}, "|"))
	// contentText is a refusal of this message's content or size.
	contentText = regexp.MustCompile(`\bspam\b|\bcontent\b|\bvirus\b|\bmalware\b|\bsize\b|\btoo (large|big)\b|\bmessage rejected\b|\bphish`)
	// fullText is a recipient's full mailbox: it exists, so no bounce.
	fullText = regexp.MustCompile(`\bmailbox (is )?full\b|\bquota\b|\bover ?quota\b|\binsufficient (storage|space)\b`)
)

// classifyPermanent decides the reason of a 5xx reply at MAIL, RCPT or
// DATA. Sender evidence wins over recipient evidence: Postfix answers an
// unknown sender with "Sender address rejected: User unknown".
func classifyPermanent(stage string, code int, msg string) message.Reason {
	text := strings.ToLower(msg)
	enh := enhancedCode.FindString(text)
	senderish := senderCodes[enh] || senderText.MatchString(text)
	switch {
	case authCodes[enh] || code == 530 || code == 535 || (senderish && authText.MatchString(text)):
		return message.ReasonAuth
	case senderish:
		return message.ReasonConfig
	case code == 552 || enh == "5.2.2" || enh == "5.3.4" || fullText.MatchString(text):
		// A full mailbox or an oversized message: the address exists.
		return message.ReasonRejected
	}
	switch stage {
	case stageMail:
		// A refusal of MAIL FROM is a refusal of the sender.
		return message.ReasonConfig
	case stageRcpt, stageData:
		if recipientCodes[enh] || recipientText.MatchString(text) {
			return message.ReasonInvalidRecipient
		}
		if strings.HasPrefix(enh, "5.7.") && !(stage == stageData && contentText.MatchString(text)) {
			// A policy refusal that names no recipient problem: the relay
			// or its account is refused.
			return message.ReasonConfig
		}
	}
	// Permanent for this message, with no evidence against the address.
	return message.ReasonRejected
}
