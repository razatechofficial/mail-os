package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Mandrill sends through the Mailchimp Transactional (Mandrill) API. The
// key travels in the JSON body, and the API answers every error with 500.
type Mandrill struct {
	api        *httpAPI
	base       string
	key        string
	subaccount string
	from       message.Address
}

// NewMandrill returns a Mandrill sender.
func NewMandrill(s provider.Settings, c provider.Credentials, opts Options) (*Mandrill, error) {
	opts = opts.withDefaults()
	if c.APIKey == "" {
		return nil, message.NewSendError(string(provider.KindMandrill), message.ReasonConfig, 0, "the Mandrill API key is required")
	}
	base, err := opts.baseURL(provider.KindMandrill, "https://mandrillapp.com")
	if err != nil {
		return nil, err
	}
	return &Mandrill{api: newHTTPAPI(provider.KindMandrill, opts), base: base + "/api/1.0", key: c.APIKey, subaccount: s.Subaccount,
		from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (m *Mandrill) CloseIdleConnections() { m.api.CloseIdleConnections() }

type mandrillTo struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type"`
}

type mandrillMessage struct {
	HTML       string            `json:"html,omitempty"`
	Text       string            `json:"text,omitempty"`
	Subject    string            `json:"subject"`
	FromEmail  string            `json:"from_email"`
	FromName   string            `json:"from_name,omitempty"`
	To         []mandrillTo      `json:"to"`
	Headers    map[string]string `json:"headers,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Subaccount string            `json:"subaccount,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	// TrackOpens and TrackClicks are sent only to turn tracking off
	// (NoTracking); left out, the account's sending defaults apply.
	TrackOpens  *bool `json:"track_opens,omitempty"`
	TrackClicks *bool `json:"track_clicks,omitempty"`
	// Attachments, and Images: inline images named by their Content-ID.
	Attachments []mandrillFile `json:"attachments,omitempty"`
	Images      []mandrillFile `json:"images,omitempty"`
}

type mandrillFile struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// Send calls POST /messages/send; each recipient comes back with a status.
func (m *Mandrill) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(m.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindMandrill)
	}
	msg := mandrillMessage{HTML: out.HTML, Text: out.Text, Subject: out.Subject, FromEmail: out.From.Email, FromName: out.From.Name,
		To: []mandrillTo{{Email: out.To.Email, Name: out.To.Name, Type: "to"}}, Tags: out.Tags, Subaccount: m.subaccount}
	if len(out.Headers) > 0 || !out.ReplyTo.IsZero() {
		msg.Headers = map[string]string{}
		for k, v := range out.Headers {
			msg.Headers[k] = v
		}
		if !out.ReplyTo.IsZero() {
			msg.Headers["Reply-To"] = out.ReplyTo.String()
		}
	}
	if out.MessageID != "" {
		msg.Metadata = map[string]string{"mailos_message_id": out.MessageID}
	}
	if out.NoTracking {
		off := false
		msg.TrackOpens, msg.TrackClicks = &off, &off
	}
	for _, a := range out.Attachments {
		if a.Inline && a.ContentID != "" && strings.HasPrefix(a.ContentType, "image/") {
			msg.Images = append(msg.Images, mandrillFile{Type: a.ContentType, Name: a.ContentID, Content: b64(a.Data)})
		} else {
			msg.Attachments = append(msg.Attachments, mandrillFile{Type: a.ContentType, Name: a.Filename, Content: b64(a.Data)})
		}
	}
	payload, err := json.Marshal(map[string]any{"key": m.key, "message": msg})
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindMandrill), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	data, _, err := m.api.post(ctx, request{url: m.base + "/messages/send", contentType: "application/json", body: payload, classify: classifyMandrill})
	if err != nil {
		return Result{}, err
	}
	var res []struct {
		Email        string `json:"email"`
		Status       string `json:"status"`
		RejectReason string `json:"reject_reason"`
		ID           string `json:"_id"`
	}
	if json.Unmarshal(data, &res) != nil || len(res) == 0 {
		return Result{}, message.NewSendError(string(provider.KindMandrill), message.ReasonUnavailable, http.StatusOK, "Mandrill returned no result")
	}
	r := res[0]
	switch r.Status {
	case "sent", "queued", "scheduled":
		return Result{ProviderMessageID: r.ID}, nil
	case "invalid":
		return Result{}, message.NewSendError(string(provider.KindMandrill), message.ReasonInvalidRecipient, http.StatusOK, "Mandrill: the recipient address is invalid")
	}
	e := message.NewSendError(string(provider.KindMandrill), message.ReasonRejected, http.StatusOK, "Mandrill rejected the message: "+r.RejectReason)
	switch r.RejectReason {
	case "hard-bounce", "unsub", "spam", "custom":
		e.Reason = message.ReasonInvalidRecipient // on Mandrill's rejection blacklist
	case "invalid-sender", "unsigned", "test-mode-limit":
		e.Reason = message.ReasonConfig
	}
	return Result{}, e
}

// Check pings with the key.
func (m *Mandrill) Check(ctx context.Context, p *Probe) error {
	return p.Step("api", "Authenticate to the Mandrill API", func() (string, error) {
		payload, _ := json.Marshal(map[string]string{"key": m.key})
		if _, _, err := m.api.post(ctx, request{url: m.base + "/users/ping2", contentType: "application/json", body: payload, classify: classifyMandrill}); err != nil {
			return "", err
		}
		return "API key accepted", nil
	})
}

// classifyMandrill reads {"status":"error","name","message"}.
func classifyMandrill(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		Status  string `json:"status"`
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &b) != nil || b.Status != "error" {
		return
	}
	e.Detail = b.Name + ": " + truncate(b.Message, 200)
	switch b.Name {
	case "Invalid_Key":
		e.Reason = message.ReasonAuth
	case "PaymentRequired", "Unknown_Subaccount", "Unknown_Sender":
		e.Reason = message.ReasonConfig
	case "ValidationError":
		e.Reason = message.ReasonRejected
	case "GeneralError":
		e.Reason = message.ReasonUnavailable
	}
}
