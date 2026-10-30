package event

import "errors"

// AuditMessageRejected is the audit action for a refused message. The audit
// entry carries the reason, the topic and the sender, never the body
// (contract §2).
const AuditMessageRejected = "mailos.message_rejected"

// Reason is why a message was rejected, in the order of the contract §2
// checks.
type Reason string

// Rejection reasons.
const (
	// ReasonMissingSignature: the message has no iam-msg-sig header.
	ReasonMissingSignature Reason = "missing_signature"
	// ReasonMalformed: the signature or the envelope cannot be read, or a
	// required claim is missing.
	ReasonMalformed Reason = "malformed"
	// ReasonBadSignature: check 1, the JWS does not verify against a key
	// IAM publishes, or is not a message signature (typ).
	ReasonBadSignature Reason = "bad_signature"
	// ReasonWrongIssuer: check 2, iss is not the IAM issuer.
	ReasonWrongIssuer Reason = "wrong_issuer"
	// ReasonWrongAudience: check 2, aud is not MailOS.
	ReasonWrongAudience Reason = "wrong_audience"
	// ReasonExpired: check 2, outside iat..exp with the clock skew.
	ReasonExpired Reason = "expired"
	// ReasonTopicMismatch: check 3, signed for another topic.
	ReasonTopicMismatch Reason = "topic_mismatch"
	// ReasonBodyMismatch: check 4, body_sha256 is not the value's hash.
	ReasonBodyMismatch Reason = "body_mismatch"
	// ReasonReplayed: check 5, the jti was already used.
	ReasonReplayed Reason = "replayed"
	// ReasonNotAllowed: check 6, the sender may not publish the topic or
	// act for the event's tenant (contract §4).
	ReasonNotAllowed Reason = "not_allowed"
)

// Rejection is a permanent refusal of a message: delivering it again cannot
// succeed, so the consumer commits past it after auditing the reason.
type Rejection struct {
	Reason Reason
	// Err is the detail, for logs. It never quotes the message body.
	Err error
}

// Reject returns a Rejection for reason with detail err (may be nil).
func Reject(reason Reason, err error) *Rejection {
	return &Rejection{Reason: reason, Err: err}
}

func (r *Rejection) Error() string {
	if r.Err == nil {
		return "message rejected: " + string(r.Reason)
	}
	return "message rejected: " + string(r.Reason) + ": " + r.Err.Error()
}

func (r *Rejection) Unwrap() error { return r.Err }

// Permanent marks the rejection as not worth redelivering; the Kafka
// consumer commits past errors that report it.
func (r *Rejection) Permanent() bool { return true }

// ReasonOf returns the reason of a Rejection in err's chain.
func ReasonOf(err error) (Reason, bool) {
	var r *Rejection
	if errors.As(err, &r) {
		return r.Reason, true
	}
	return "", false
}
