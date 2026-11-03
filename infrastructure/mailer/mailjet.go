package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Mailjet sends through the Mailjet Send API v3.1.
type Mailjet struct {
	api    *httpAPI
	base   string
	key    string
	secret string
	from   message.Address
}

// NewMailjet returns a Mailjet sender.
func NewMailjet(s provider.Settings, c provider.Credentials, opts Options) (*Mailjet, error) {
	opts = opts.withDefaults()
	if c.APIKey == "" || c.APISecret == "" {
		return nil, message.NewSendError(string(provider.KindMailjet), message.ReasonConfig, 0, "the Mailjet API key and secret key are required")
	}
	base, err := opts.baseURL(provider.KindMailjet, "https://api.mailjet.com")
	if err != nil {
		return nil, err
	}
	return &Mailjet{api: newHTTPAPI(provider.KindMailjet, opts), base: base, key: c.APIKey, secret: c.APISecret,
		from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (m *Mailjet) CloseIdleConnections() { m.api.CloseIdleConnections() }

type mjAddress struct {
	Email string `json:"Email"`
	Name  string `json:"Name,omitempty"`
}

type mjMessage struct {
	From     mjAddress         `json:"From"`
	To       []mjAddress       `json:"To"`
	ReplyTo  *mjAddress        `json:"ReplyTo,omitempty"`
	Subject  string            `json:"Subject"`
	TextPart string            `json:"TextPart,omitempty"`
	HTMLPart string            `json:"HTMLPart,omitempty"`
	Headers  map[string]string `json:"Headers,omitempty"`
	CustomID string            `json:"CustomID,omitempty"`
}

func (m *Mailjet) auth(r *http.Request) error {
	r.SetBasicAuth(m.key, m.secret)
	return nil
}

// mjError is one entry of a message's Errors.
type mjError struct {
	ErrorCode      string   `json:"ErrorCode"`
	ErrorMessage   string   `json:"ErrorMessage"`
	ErrorRelatedTo []string `json:"ErrorRelatedTo"`
}

type mjResponse struct {
	Messages []struct {
		Status string `json:"Status"`
		To     []struct {
			MessageID   json.Number `json:"MessageID"`
			MessageUUID string      `json:"MessageUUID"`
		} `json:"To"`
		Errors []mjError `json:"Errors"`
	} `json:"Messages"`
	ErrorMessage string `json:"ErrorMessage"`
}

// Send calls POST /v3.1/send. The MessageID is what Mailjet's event
// webhooks carry.
func (m *Mailjet) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(m.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindMailjet)
	}
	msg := mjMessage{From: mjAddress{Email: out.From.Email, Name: out.From.Name}, To: []mjAddress{{Email: out.To.Email, Name: out.To.Name}},
		Subject: out.Subject, TextPart: out.Text, HTMLPart: out.HTML, Headers: out.Headers, CustomID: out.MessageID}
	if !out.ReplyTo.IsZero() {
		msg.ReplyTo = &mjAddress{Email: out.ReplyTo.Email, Name: out.ReplyTo.Name}
	}
	payload, err := json.Marshal(map[string]any{"Messages": []mjMessage{msg}})
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindMailjet), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	data, _, err := m.api.post(ctx, request{url: m.base + "/v3.1/send", contentType: "application/json", body: payload,
		prepare: m.auth, classify: classifyMailjet})
	if err != nil {
		return Result{}, err
	}
	var res mjResponse
	if json.Unmarshal(data, &res) != nil || len(res.Messages) == 0 {
		return Result{}, message.NewSendError(string(provider.KindMailjet), message.ReasonUnavailable, http.StatusOK, "Mailjet returned no message")
	}
	first := res.Messages[0]
	if first.Status != "success" || len(first.To) == 0 {
		e := message.NewSendError(string(provider.KindMailjet), message.ReasonRejected, http.StatusOK, "Mailjet refused the message")
		applyMailjetErrors(e, first.Errors)
		return Result{}, e
	}
	id := first.To[0].MessageID.String()
	if id == "" {
		id = first.To[0].MessageUUID
	}
	return Result{ProviderMessageID: id}, nil
}

// Check reads the API key's user.
func (m *Mailjet) Check(ctx context.Context, p *Probe) error {
	return p.Step("api", "Authenticate to the Mailjet API", func() (string, error) {
		if _, _, err := m.api.post(ctx, request{method: http.MethodGet, url: m.base + "/v3/REST/user", prepare: m.auth, classify: classifyMailjet}); err != nil {
			return "", err
		}
		return "API key and secret accepted", nil
	})
}

// classifyMailjet reads the per-message errors of a 400, or a top-level
// ErrorMessage (401).
func classifyMailjet(e *message.SendError, body []byte, _ http.Header) {
	var res mjResponse
	if json.Unmarshal(body, &res) != nil {
		return
	}
	if res.ErrorMessage != "" {
		e.Detail = truncate(res.ErrorMessage, 200)
	}
	if len(res.Messages) > 0 {
		applyMailjetErrors(e, res.Messages[0].Errors)
	}
}

func applyMailjetErrors(e *message.SendError, errs []mjError) {
	if len(errs) == 0 {
		return
	}
	first := errs[0]
	e.Detail = first.ErrorCode + ": " + truncate(first.ErrorMessage, 200)
	related := strings.Join(first.ErrorRelatedTo, ",")
	switch {
	case strings.Contains(related, "To") || strings.Contains(related, "Recipient"):
		e.Reason = message.ReasonInvalidRecipient
	case strings.Contains(related, "From"), strings.Contains(strings.ToLower(first.ErrorMessage), "sender"):
		e.Reason = message.ReasonConfig // the sender is not validated in Mailjet
	}
}
