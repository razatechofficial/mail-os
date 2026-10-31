//go:build e2e

package harness

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MailTimeout is how long a Mailbox waits: mail goes through the worker
// queue, so it lags the request that caused it.
const MailTimeout = 20 * time.Second

// Message is one email the server captured instead of sending
// (MAILOS_E2E_HOOKS).
type Message struct {
	ID      string    `json:"id"`
	To      string    `json:"to"`
	From    string    `json:"from"`
	Subject string    `json:"subject"`
	HTML    string    `json:"html"`
	Text    string    `json:"text"`
	Tags    []string  `json:"tags"`
	SentAt  time.Time `json:"sent_at"`
}

// Mailbox reads the captured mail for one recipient through the hook route
// GET /e2e/v1/messages?to=.
type Mailbox struct {
	Address string
	env     *Env
}

// Mailbox returns the captured-mail inbox of address.
func (e *Env) Mailbox(address string) *Mailbox { return &Mailbox{Address: address, env: e} }

// NewMailbox returns the inbox of a new address unique to the run.
func (e *Env) NewMailbox(tag string) *Mailbox { return e.Mailbox(NewEmail(tag)) }

// Messages returns every message captured for the address so far, oldest
// first as the server lists them.
func (m *Mailbox) Messages(t T) []Message {
	t.Helper()
	c := m.env.NewClient().WithBearer(m.env.HookToken)
	r := c.Expect(t, http.StatusOK, http.MethodGet, "/e2e/v1/messages?"+url.Values{"to": {m.Address}}.Encode(), nil)
	var out []Message
	r.Decode(t, &out)
	return out
}

// Wait polls until a message matching match arrives and returns the first
// one; a nil match takes any message.
func (m *Mailbox) Wait(t T, match func(Message) bool) Message {
	t.Helper()
	var got Message
	Eventually(t, "mail to "+m.Address, MailTimeout, func() bool {
		for _, msg := range m.Messages(t) {
			if match == nil || match(msg) {
				got = msg
				return true
			}
		}
		return false
	})
	return got
}

// WaitSubject waits for a message whose subject contains substr.
func (m *Mailbox) WaitSubject(t T, substr string) Message {
	t.Helper()
	return m.Wait(t, func(msg Message) bool { return strings.Contains(msg.Subject, substr) })
}

// WaitAfter waits for a message that was not among seen (the IDs from an
// earlier Messages call), to catch the mail an action sends.
func (m *Mailbox) WaitAfter(t T, seen []Message) Message {
	t.Helper()
	old := make(map[string]bool, len(seen))
	for _, s := range seen {
		old[s.ID] = true
	}
	return m.Wait(t, func(msg Message) bool { return !old[msg.ID] })
}

// Empty fails the test if any mail reached the address within wait (for
// suppressions and refusals: nothing may be sent).
func (m *Mailbox) Empty(t T, wait time.Duration) {
	t.Helper()
	time.Sleep(wait)
	if msgs := m.Messages(t); len(msgs) > 0 {
		t.Fatalf("mail to %s, want none: %q", m.Address, msgs[0].Subject)
	}
}

// Unique returns a short random string for names unique to the run.
func Unique() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// EmailDomain is the recipient domain of test mail (RFC 2606: never routable).
const EmailDomain = "mailos.test"

// NewEmail returns an address in the test domain unique to the run.
func NewEmail(tag string) string { return tag + "-" + Unique() + "@" + EmailDomain }

// JSON is a helper for the hooks' raw fields in failure messages.
func (m Message) JSON() string {
	raw, _ := json.Marshal(m)
	return string(raw)
}
