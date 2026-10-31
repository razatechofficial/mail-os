package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Mailgun sends through the Mailgun Messages API.
type Mailgun struct {
	api  *httpAPI
	url  string
	key  string
	from message.Address
}

// mailgunMaxTags is Mailgun's limit of o:tag values per message.
const mailgunMaxTags = 3

// NewMailgun returns a Mailgun sender for the settings' domain and region.
func NewMailgun(s provider.Settings, c provider.Credentials, opts Options) (*Mailgun, error) {
	opts = opts.withDefaults()
	if c.APIKey == "" || s.Domain == "" {
		return nil, message.NewSendError(string(provider.KindMailgun), message.ReasonConfig, 0, "the Mailgun domain and API key are required")
	}
	base, err := opts.baseURL(provider.KindMailgun, s.MailgunBaseURL())
	if err != nil {
		return nil, err
	}
	return &Mailgun{api: newHTTPAPI(provider.KindMailgun, opts), url: base + "/v3/" + url.PathEscape(s.Domain) + "/messages",
		key: c.APIKey, from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (m *Mailgun) CloseIdleConnections() { m.api.CloseIdleConnections() }

// Send posts the message as a form.
func (m *Mailgun) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(m.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindMailgun)
	}
	form := url.Values{
		"from":    {out.From.String()},
		"to":      {out.To.String()},
		"subject": {out.Subject},
	}
	if out.Text != "" {
		form.Set("text", out.Text)
	}
	if out.HTML != "" {
		form.Set("html", out.HTML)
	}
	if !out.ReplyTo.IsZero() {
		form.Set("h:Reply-To", out.ReplyTo.String())
	}
	for k, v := range out.Headers {
		form.Set("h:"+k, v)
	}
	for i, t := range out.Tags {
		if i == mailgunMaxTags {
			break
		}
		form.Add("o:tag", t)
	}
	if out.MessageID != "" {
		form.Set("v:mailos_message_id", out.MessageID)
	}
	data, _, err := m.api.post(ctx, request{
		url: m.url, contentType: "application/x-www-form-urlencoded", body: []byte(form.Encode()),
		prepare: func(r *http.Request) error {
			r.SetBasicAuth("api", m.key)
			return nil
		},
		classify: classifyMailgun,
	})
	if err != nil {
		return Result{}, err
	}
	var res struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &res) != nil || res.ID == "" {
		return Result{}, message.NewSendError(string(provider.KindMailgun), message.ReasonUnavailable, http.StatusOK, "Mailgun returned no message id")
	}
	return Result{ProviderMessageID: strings.Trim(res.ID, "<>")}, nil
}

// classifyMailgun reads {"message": "..."}: a 400 naming the to
// parameter is an invalid recipient.
func classifyMailgun(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &b) != nil || b.Message == "" {
		return
	}
	e.Detail = truncate(b.Message, 200)
	lower := strings.ToLower(b.Message)
	if e.Status == http.StatusBadRequest && (strings.Contains(lower, "'to'") || strings.Contains(lower, "to parameter")) {
		e.Reason = message.ReasonInvalidRecipient
	}
}
