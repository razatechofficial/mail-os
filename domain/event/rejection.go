package event

import "errors"

// AuditMessageRejected is the audit action for a refused message. The audit
// entry carries the reason, the topic and the sender, never the body
// (contract §2).
const AuditMessageRejected = "mailos.message_rejected"

// Reason is why a message was rejected. The names are the contract's
// (§2 change log), shared with IAM's reference verifier (pkg/msgsig).
type Reason string

// Rejection reasons, in the order of the contract §2 checks.
const (
	// ReasonMalformed: the signature or the envelope cannot be read, a
	// required claim is missing, or the envelope does not match its
	// signature (jti is not the event id).
	ReasonMalformed Reason = "malformed"
	// ReasonType: check 1, the JWS typ is not mailos-msg+jwt.
	ReasonType Reason = "type"
	// ReasonUnknownKey: check 1, the kid is not in IAM's JWKS.
	ReasonUnknownKey Reason = "unknown_key"
	// ReasonAlgorithm: check 1, the alg is not the key's algorithm.
	ReasonAlgorithm Reason = "algorithm"
	// ReasonSignature: check 1, the signature does not verify.
	ReasonSignature Reason = "signature"
	// ReasonIssuer: check 2, iss is not the IAM issuer.
	ReasonIssuer Reason = "issuer"
	// ReasonAudience: check 2, aud is not MailOS.
	ReasonAudience Reason = "audience"
	// ReasonLifetime: check 2, exp - iat is over five minutes.
	ReasonLifetime Reason = "lifetime"
	// ReasonExpired: check 2, at or past exp plus the clock skew.
	ReasonExpired Reason = "expired"
	// ReasonNotYetValid: check 2, iat is beyond the clock skew ahead.
	ReasonNotYetValid Reason = "not_yet_valid"
	// ReasonTopic: check 3, signed for another topic, or the event type is
	// not the topic it arrived on.
	ReasonTopic Reason = "topic"
	// ReasonBodyHash: check 4, body_sha256 is not the value's hash.
	ReasonBodyHash Reason = "body_hash"
	// ReasonReplay: check 5, the jti was already used.
	ReasonReplay Reason = "replay"
	// ReasonReplayGuardUnavailable: check 5 could not run. The rejection is
	// Transient: the message is redelivered, not dropped.
	ReasonReplayGuardUnavailable Reason = "replay_guard_unavailable"
	// ReasonUnknownClient: check 6, the sender is not allow-listed (§4).
	ReasonUnknownClient Reason = "unknown_client"
	// ReasonUnauthorisedTopic: check 6, the sender may not publish the
	// topic, or act for the event's tenant (§4).
	ReasonUnauthorisedTopic Reason = "unauthorised_topic"
)

// Rejection is a refusal of a message with its reason. It is permanent
// (delivering it again cannot succeed, so the consumer commits past it after
// auditing the reason) unless Transient is set.
type Rejection struct {
	Reason Reason
	// Err is the detail, for logs. It never quotes the message body.
	Err error
	// Transient marks a check that could not run (the replay guard is
	// down): the message is audited as rejected but redelivered.
	Transient bool
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

// Permanent reports whether redelivering cannot help; the Kafka consumer
// commits past errors that report it.
func (r *Rejection) Permanent() bool { return !r.Transient }

// ReasonOf returns the reason of a Rejection in err's chain.
func ReasonOf(err error) (Reason, bool) {
	var r *Rejection
	if errors.As(err, &r) {
		return r.Reason, true
	}
	return "", false
}
