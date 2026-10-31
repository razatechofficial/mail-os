package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// SendGrid sends through the SendGrid v3 Mail Send API.
type SendGrid struct {
	api  *httpAPI
	url  string
	key  string
	from message.Address
}

// NewSendGrid returns a SendGrid sender (EU data residency when the
// settings' region is "eu").
func NewSendGrid(s provider.Settings, c provider.Credentials, opts Options) (*SendGrid, error) {
	opts = opts.withDefaults()
	if c.APIKey == "" {
		return nil, message.NewSendError(string(provider.KindSendGrid), message.ReasonConfig, 0, "the SendGrid API key is required")
	}
	def := "https://api.sendgrid.com"
	if s.Region == provider.SendGridEU {
		def = "https://api.eu.sendgrid.com"
	}
	base, err := opts.baseURL(provider.KindSendGrid, def)
	if err != nil {
		return nil, err
	}
	return &SendGrid{api: newHTTPAPI(provider.KindSendGrid, opts), url: base + "/v3/mail/send", key: c.APIKey,
		from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (s *SendGrid) CloseIdleConnections() { s.api.CloseIdleConnections() }

type sgAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type sgContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type sgRequest struct {
	Personalizations []struct {
		To []sgAddress `json:"to"`
	} `json:"personalizations"`
	From       sgAddress         `json:"from"`
	ReplyTo    *sgAddress        `json:"reply_to,omitempty"`
	Subject    string            `json:"subject"`
	Content    []sgContent       `json:"content"`
	Headers    map[string]string `json:"headers,omitempty"`
	Categories []string          `json:"categories,omitempty"`
	CustomArgs map[string]string `json:"custom_args,omitempty"`
}

// Send calls POST /v3/mail/send. The message id comes back in
// X-Message-Id.
func (s *SendGrid) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(s.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindSendGrid)
	}
	body := sgRequest{
		Personalizations: []struct {
			To []sgAddress `json:"to"`
		}{{To: []sgAddress{{Email: out.To.Email, Name: out.To.Name}}}},
		From:       sgAddress{Email: out.From.Email, Name: out.From.Name},
		Subject:    out.Subject,
		Headers:    out.Headers,
		Categories: out.Tags,
	}
	if !out.ReplyTo.IsZero() {
		body.ReplyTo = &sgAddress{Email: out.ReplyTo.Email, Name: out.ReplyTo.Name}
	}
	// text/plain must come before text/html.
	if out.Text != "" {
		body.Content = append(body.Content, sgContent{Type: "text/plain", Value: out.Text})
	}
	if out.HTML != "" {
		body.Content = append(body.Content, sgContent{Type: "text/html", Value: out.HTML})
	}
	if out.MessageID != "" {
		body.CustomArgs = map[string]string{"mailos_message_id": out.MessageID}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindSendGrid), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	_, h, err := s.api.post(ctx, request{
		url: s.url, contentType: "application/json", body: payload,
		prepare: func(r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+s.key)
			return nil
		},
		classify: classifySendGrid,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{ProviderMessageID: h.Get("X-Message-Id")}, nil
}

// classifySendGrid reads {"errors":[{"message","field"}]}: an error on a
// recipient's email field is an invalid recipient.
func classifySendGrid(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		Errors []struct {
			Message string `json:"message"`
			Field   string `json:"field"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &b) != nil || len(b.Errors) == 0 {
		return
	}
	first := b.Errors[0]
	e.Detail = truncate(first.Message, 200)
	if e.Status == http.StatusBadRequest && strings.HasPrefix(first.Field, "personalizations") && strings.Contains(first.Field, "email") {
		e.Reason = message.ReasonInvalidRecipient
	}
}
