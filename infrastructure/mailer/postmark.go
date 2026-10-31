package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Postmark sends through the Postmark Email API.
type Postmark struct {
	api    *httpAPI
	url    string
	token  string
	stream string
	from   message.Address
}

// NewPostmark returns a Postmark sender for the settings' message stream.
func NewPostmark(s provider.Settings, c provider.Credentials, opts Options) (*Postmark, error) {
	opts = opts.withDefaults()
	if c.ServerToken == "" {
		return nil, message.NewSendError(string(provider.KindPostmark), message.ReasonConfig, 0, "the Postmark server token is required")
	}
	base, err := opts.baseURL(provider.KindPostmark, "https://api.postmarkapp.com")
	if err != nil {
		return nil, err
	}
	return &Postmark{api: newHTTPAPI(provider.KindPostmark, opts), url: base + "/email", token: c.ServerToken,
		stream: s.PostmarkStream(), from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (p *Postmark) CloseIdleConnections() { p.api.CloseIdleConnections() }

type pmHeader struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

type pmRequest struct {
	From          string            `json:"From"`
	To            string            `json:"To"`
	ReplyTo       string            `json:"ReplyTo,omitempty"`
	Subject       string            `json:"Subject"`
	HTMLBody      string            `json:"HtmlBody,omitempty"`
	TextBody      string            `json:"TextBody,omitempty"`
	Headers       []pmHeader        `json:"Headers,omitempty"`
	Tag           string            `json:"Tag,omitempty"`
	Metadata      map[string]string `json:"Metadata,omitempty"`
	MessageStream string            `json:"MessageStream"`
}

// Postmark API error codes
// (https://postmarkapp.com/developer/api/overview#error-codes).
const (
	pmInvalidToken       = 10
	pmInvalidEmail       = 300
	pmSenderNotFound     = 400
	pmSenderNotConfirmed = 401
	pmNotAllowed         = 405 // the account ran out of credits
	pmInactiveRecipient  = 406
	pmAccountPending     = 412
)

// Send calls POST /email.
func (p *Postmark) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(p.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindPostmark)
	}
	body := pmRequest{
		From: out.From.String(), To: out.To.String(), Subject: out.Subject,
		HTMLBody: out.HTML, TextBody: out.Text, MessageStream: p.stream,
	}
	if !out.ReplyTo.IsZero() {
		body.ReplyTo = out.ReplyTo.String()
	}
	for k, v := range out.Headers {
		body.Headers = append(body.Headers, pmHeader{Name: k, Value: v})
	}
	if len(out.Tags) > 0 {
		body.Tag = out.Tags[0] // Postmark takes one tag
	}
	if out.MessageID != "" {
		body.Metadata = map[string]string{"mailos_message_id": out.MessageID}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindPostmark), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	data, _, err := p.api.post(ctx, request{
		url: p.url, contentType: "application/json", body: payload,
		prepare: func(r *http.Request) error {
			r.Header.Set("X-Postmark-Server-Token", p.token)
			return nil
		},
		classify: classifyPostmark,
	})
	if err != nil {
		return Result{}, err
	}
	var res struct {
		ErrorCode int    `json:"ErrorCode"`
		MessageID string `json:"MessageID"`
	}
	if json.Unmarshal(data, &res) != nil || res.ErrorCode != 0 || res.MessageID == "" {
		return Result{}, message.NewSendError(string(provider.KindPostmark), message.ReasonUnavailable, http.StatusOK, "Postmark returned no message id")
	}
	return Result{ProviderMessageID: res.MessageID}, nil
}

// classifyPostmark reads {"ErrorCode", "Message"} (sent with 401 and 422).
func classifyPostmark(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		ErrorCode int    `json:"ErrorCode"`
		Message   string `json:"Message"`
	}
	if json.Unmarshal(body, &b) != nil || b.ErrorCode == 0 {
		return
	}
	e.Detail = truncate(b.Message, 200)
	switch b.ErrorCode {
	case pmInvalidToken:
		e.Reason = message.ReasonAuth
	case pmInactiveRecipient:
		// Postmark suppressed the recipient after a hard bounce or complaint.
		e.Reason = message.ReasonInvalidRecipient
	case pmSenderNotFound, pmSenderNotConfirmed, pmNotAllowed, pmAccountPending:
		e.Reason = message.ReasonConfig
	case pmInvalidEmail:
		e.Reason = message.ReasonRejected
		if strings.Contains(b.Message, "'To'") {
			e.Reason = message.ReasonInvalidRecipient
		}
	}
}
