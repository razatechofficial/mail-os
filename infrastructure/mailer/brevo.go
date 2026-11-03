package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Brevo sends through the Brevo transactional email API.
type Brevo struct {
	api  *httpAPI
	base string
	key  string
	from message.Address
}

// NewBrevo returns a Brevo sender.
func NewBrevo(s provider.Settings, c provider.Credentials, opts Options) (*Brevo, error) {
	opts = opts.withDefaults()
	if c.APIKey == "" {
		return nil, message.NewSendError(string(provider.KindBrevo), message.ReasonConfig, 0, "the Brevo API key is required")
	}
	base, err := opts.baseURL(provider.KindBrevo, "https://api.brevo.com")
	if err != nil {
		return nil, err
	}
	return &Brevo{api: newHTTPAPI(provider.KindBrevo, opts), base: base + "/v3", key: c.APIKey,
		from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (b *Brevo) CloseIdleConnections() { b.api.CloseIdleConnections() }

type brevoAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type brevoRequest struct {
	Sender      brevoAddress      `json:"sender"`
	To          []brevoAddress    `json:"to"`
	ReplyTo     *brevoAddress     `json:"replyTo,omitempty"`
	Subject     string            `json:"subject"`
	HTMLContent string            `json:"htmlContent,omitempty"`
	TextContent string            `json:"textContent,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

func (b *Brevo) auth(r *http.Request) error {
	r.Header.Set("api-key", b.key)
	return nil
}

// Send calls POST /smtp/email (201 {"messageId"}).
func (b *Brevo) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(b.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindBrevo)
	}
	body := brevoRequest{
		Sender: brevoAddress{Email: out.From.Email, Name: out.From.Name}, To: []brevoAddress{{Email: out.To.Email, Name: out.To.Name}},
		Subject: out.Subject, HTMLContent: out.HTML, TextContent: out.Text, Tags: out.Tags,
	}
	if !out.ReplyTo.IsZero() {
		body.ReplyTo = &brevoAddress{Email: out.ReplyTo.Email, Name: out.ReplyTo.Name}
	}
	if len(out.Headers) > 0 || out.MessageID != "" {
		body.Headers = map[string]string{}
		for k, v := range out.Headers {
			body.Headers[k] = v
		}
		if out.MessageID != "" {
			body.Headers["X-Mailos-Message-Id"] = out.MessageID
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindBrevo), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	data, _, err := b.api.post(ctx, request{url: b.base + "/smtp/email", contentType: "application/json", body: payload,
		prepare: b.auth, classify: classifyBrevo})
	if err != nil {
		return Result{}, err
	}
	var res struct {
		MessageID string `json:"messageId"`
	}
	if json.Unmarshal(data, &res) != nil || res.MessageID == "" {
		return Result{}, message.NewSendError(string(provider.KindBrevo), message.ReasonUnavailable, http.StatusOK, "Brevo returned no message id")
	}
	return Result{ProviderMessageID: strings.Trim(res.MessageID, "<>")}, nil
}

// Check reads the account.
func (b *Brevo) Check(ctx context.Context, p *Probe) error {
	return p.Step("api", "Authenticate to the Brevo API", func() (string, error) {
		data, _, err := b.api.post(ctx, request{method: http.MethodGet, url: b.base + "/account", prepare: b.auth, classify: classifyBrevo})
		if err != nil {
			return "", err
		}
		var acct struct {
			Email string `json:"email"`
		}
		_ = json.Unmarshal(data, &acct)
		if acct.Email != "" {
			return "API key accepted for the account " + acct.Email, nil
		}
		return "API key accepted", nil
	})
}

// classifyBrevo reads {"code","message"}.
func classifyBrevo(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &b) != nil || b.Code == "" {
		return
	}
	e.Detail = b.Code
	if b.Message != "" {
		e.Detail += ": " + truncate(b.Message, 200)
	}
	lower := strings.ToLower(b.Message)
	switch b.Code {
	case "unauthorized", "permission_denied":
		e.Reason = message.ReasonAuth
	case "account_under_validation", "not_enough_credits", "not_acceptable":
		e.Reason = message.ReasonConfig
	case "invalid_parameter", "missing_parameter":
		e.Reason = message.ReasonRejected
		if strings.Contains(lower, "to") && strings.Contains(lower, "email") || strings.Contains(lower, "recipient") {
			e.Reason = message.ReasonInvalidRecipient
		}
		if strings.Contains(lower, "sender") {
			e.Reason = message.ReasonConfig
		}
	}
}
