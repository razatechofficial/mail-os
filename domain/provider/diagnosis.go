package provider

import "time"

// Test kinds: a connection test reaches the provider and checks the
// credentials without sending mail; a test send delivers one message.
const (
	TestConnection = "connection"
	TestSend       = "send"
	// TestDelivery is not a test: a live send failed for the provider's
	// own reasons (credentials, sender identity, relay policy), or the
	// next one through it succeeded. The console shows the provider failing
	// until then.
	TestDelivery = "delivery"
)

// Step is one stage of a test: connect, TLS, authenticate, call the API.
type Step struct {
	Name       string `json:"name"`
	Label      string `json:"label"`
	OK         bool   `json:"ok"`
	Detail     string `json:"detail,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Diagnosis is a test's outcome, for the administrator: the steps run, the
// one that failed with its error class (message.Reason), what the provider
// said, and what to check. It never carries a secret.
type Diagnosis struct {
	OK   bool      `json:"ok"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
	// Steps are the stages run, in order; the last failed when !OK.
	Steps []Step `json:"steps"`
	// Step is the failed stage; ErrorClass is the failure's class (auth,
	// config, network, rate_limited, unavailable, rejected,
	// invalid_recipient, invalid).
	Step       string   `json:"step,omitempty"`
	ErrorClass string   `json:"error_class,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	Hint       string   `json:"hint,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	// MessageID and ProviderMessageID identify a test send.
	MessageID         string `json:"message_id,omitempty"`
	ProviderMessageID string `json:"provider_message_id,omitempty"`
}

// LastTest is the summary of a provider's last test, kept on the provider.
type LastTest struct {
	Kind       string    `json:"kind"`
	OK         bool      `json:"ok"`
	At         time.Time `json:"at"`
	Step       string    `json:"step,omitempty"`
	ErrorClass string    `json:"error_class,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	Hint       string    `json:"hint,omitempty"`
	ToEmail    string    `json:"to_email,omitempty"`
	MessageID  string    `json:"message_id,omitempty"`
}

// Summary is the diagnosis as a LastTest.
func (d Diagnosis) Summary(toEmail string) LastTest {
	return LastTest{Kind: d.Kind, OK: d.OK, At: d.At, Step: d.Step, ErrorClass: d.ErrorClass,
		Detail: d.Detail, Hint: d.Hint, ToEmail: toEmail, MessageID: d.MessageID}
}
