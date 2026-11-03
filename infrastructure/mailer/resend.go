package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Resend sends through the Resend email API.
type Resend struct {
	api  *httpAPI
	base string
	key  string
	from message.Address
}

// NewResend returns a Resend sender.
func NewResend(s provider.Settings, c provider.Credentials, opts Options) (*Resend, error) {
	opts = opts.withDefaults()
	if c.APIKey == "" {
		return nil, message.NewSendError(string(provider.KindResend), message.ReasonConfig, 0, "the Resend API key is required")
	}
	base, err := opts.baseURL(provider.KindResend, "https://api.resend.com")
	if err != nil {
		return nil, err
	}
	return &Resend{api: newHTTPAPI(provider.KindResend, opts), base: base, key: c.APIKey,
		from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (r *Resend) CloseIdleConnections() { r.api.CloseIdleConnections() }

type resendTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type resendRequest struct {
	From    string            `json:"from"`
	To      []string          `json:"to"`
	Subject string            `json:"subject"`
	HTML    string            `json:"html,omitempty"`
	Text    string            `json:"text,omitempty"`
	ReplyTo []string          `json:"reply_to,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Tags    []resendTag       `json:"tags,omitempty"`
}

// Send calls POST /emails with the MailOS id as the idempotency key, so a
// retry after an ambiguous failure does not send twice.
func (r *Resend) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(r.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindResend)
	}
	body := resendRequest{From: out.From.String(), To: []string{out.To.String()}, Subject: out.Subject,
		HTML: out.HTML, Text: out.Text, Headers: out.Headers}
	if !out.ReplyTo.IsZero() {
		body.ReplyTo = []string{out.ReplyTo.String()}
	}
	if out.MessageID != "" {
		body.Tags = append(body.Tags, resendTag{Name: "mailos_message_id", Value: sesTagValue(out.MessageID)})
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindResend), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	data, _, err := r.api.post(ctx, request{url: r.base + "/emails", contentType: "application/json", body: payload,
		prepare: func(req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+r.key)
			if out.MessageID != "" {
				req.Header.Set("Idempotency-Key", out.MessageID)
			}
			return nil
		},
		classify: classifyResend})
	if err != nil {
		return Result{}, err
	}
	var res struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &res) != nil || res.ID == "" {
		return Result{}, message.NewSendError(string(provider.KindResend), message.ReasonUnavailable, http.StatusOK, "Resend returned no id")
	}
	return Result{ProviderMessageID: res.ID}, nil
}

// Check lists domains. A sending-only key is refused that call with
// restricted_api_key, which still proves the key.
func (r *Resend) Check(ctx context.Context, p *Probe) error {
	return p.Step("api", "Authenticate to the Resend API", func() (string, error) {
		_, _, err := r.api.post(ctx, request{method: http.MethodGet, url: r.base + "/domains",
			prepare: func(req *http.Request) error {
				req.Header.Set("Authorization", "Bearer "+r.key)
				return nil
			},
			classify: classifyResend})
		if se, ok := message.AsSendError(err); ok && strings.HasPrefix(se.Detail, "restricted_api_key") {
			return "sending-only API key accepted", nil
		}
		if err != nil {
			return "", err
		}
		return "API key accepted", nil
	})
}

// classifyResend reads {"statusCode","name","message"}.
func classifyResend(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &b) != nil || b.Name == "" {
		return
	}
	e.Detail = b.Name + ": " + truncate(b.Message, 200)
	lower := strings.ToLower(b.Message)
	switch b.Name {
	case "missing_api_key", "invalid_api_key", "restricted_api_key":
		e.Reason = message.ReasonAuth
	case "rate_limit_exceeded", "daily_quota_exceeded", "monthly_quota_exceeded":
		e.Reason = message.ReasonRateLimited
	case "validation_error", "invalid_parameter", "missing_required_field":
		e.Reason = message.ReasonRejected
		switch {
		case strings.Contains(lower, "domain") && strings.Contains(lower, "verif"):
			e.Reason = message.ReasonConfig
		case strings.Contains(lower, "`to`") || strings.Contains(lower, "recipient"):
			e.Reason = message.ReasonInvalidRecipient
		}
	case "invalid_from_address":
		e.Reason = message.ReasonConfig
	}
}
