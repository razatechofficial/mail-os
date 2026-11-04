package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// SparkPost sends through the SparkPost Transmissions API.
type SparkPost struct {
	api  *httpAPI
	base string
	key  string
	from message.Address
}

// NewSparkPost returns a SparkPost sender for the settings' region.
func NewSparkPost(s provider.Settings, c provider.Credentials, opts Options) (*SparkPost, error) {
	opts = opts.withDefaults()
	if c.APIKey == "" {
		return nil, message.NewSendError(string(provider.KindSparkPost), message.ReasonConfig, 0, "the SparkPost API key is required")
	}
	def := "https://api.sparkpost.com"
	if s.Region == provider.RegionEU {
		def = "https://api.eu.sparkpost.com"
	}
	base, err := opts.baseURL(provider.KindSparkPost, def)
	if err != nil {
		return nil, err
	}
	return &SparkPost{api: newHTTPAPI(provider.KindSparkPost, opts), base: base + "/api/v1", key: c.APIKey,
		from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (s *SparkPost) CloseIdleConnections() { s.api.CloseIdleConnections() }

type spAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type spFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
}

type spRequest struct {
	Options struct {
		Transactional bool `json:"transactional"`
	} `json:"options"`
	Recipients []struct {
		Address spAddress `json:"address"`
	} `json:"recipients"`
	Content struct {
		From    spAddress         `json:"from"`
		Subject string            `json:"subject"`
		HTML    string            `json:"html,omitempty"`
		Text    string            `json:"text,omitempty"`
		ReplyTo string            `json:"reply_to,omitempty"`
		Headers map[string]string `json:"headers,omitempty"`
		// Attachments and InlineImages: an inline image's name is its
		// Content-ID.
		Attachments  []spFile `json:"attachments,omitempty"`
		InlineImages []spFile `json:"inline_images,omitempty"`
	} `json:"content"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CampaignID string            `json:"campaign_id,omitempty"`
}

func (s *SparkPost) auth(r *http.Request) error {
	r.Header.Set("Authorization", s.key)
	return nil
}

// Send calls POST /transmissions. A recipient SparkPost refuses comes back
// as 200 with total_rejected_recipients.
func (s *SparkPost) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(s.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindSparkPost)
	}
	var body spRequest
	body.Options.Transactional = true
	body.Recipients = []struct {
		Address spAddress `json:"address"`
	}{{Address: spAddress{Email: out.To.Email, Name: out.To.Name}}}
	body.Content.From = spAddress{Email: out.From.Email, Name: out.From.Name}
	body.Content.Subject, body.Content.HTML, body.Content.Text = out.Subject, out.HTML, out.Text
	if !out.ReplyTo.IsZero() {
		body.Content.ReplyTo = out.ReplyTo.String()
	}
	body.Content.Headers = out.Headers
	for _, a := range out.Attachments {
		if a.Inline && a.ContentID != "" && strings.HasPrefix(a.ContentType, "image/") {
			body.Content.InlineImages = append(body.Content.InlineImages, spFile{Name: a.ContentID, Type: a.ContentType, Data: b64(a.Data)})
		} else {
			body.Content.Attachments = append(body.Content.Attachments, spFile{Name: a.Filename, Type: a.ContentType, Data: b64(a.Data)})
		}
	}
	if out.MessageID != "" {
		body.Metadata = map[string]string{"mailos_message_id": out.MessageID}
	}
	if len(out.Tags) > 0 {
		body.CampaignID = truncate(out.Tags[0], 64)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindSparkPost), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	data, _, err := s.api.post(ctx, request{url: s.base + "/transmissions", contentType: "application/json", body: payload,
		prepare: s.auth, classify: classifySparkPost})
	if err != nil {
		return Result{}, err
	}
	var res struct {
		Results struct {
			ID       string `json:"id"`
			Accepted int    `json:"total_accepted_recipients"`
			Rejected int    `json:"total_rejected_recipients"`
		} `json:"results"`
	}
	if json.Unmarshal(data, &res) != nil || res.Results.ID == "" {
		return Result{}, message.NewSendError(string(provider.KindSparkPost), message.ReasonUnavailable, http.StatusOK, "SparkPost returned no transmission id")
	}
	if res.Results.Accepted == 0 && res.Results.Rejected > 0 {
		return Result{}, message.NewSendError(string(provider.KindSparkPost), message.ReasonInvalidRecipient, http.StatusOK, "SparkPost rejected the recipient")
	}
	return Result{ProviderMessageID: res.Results.ID}, nil
}

// Check reads the account. A key without Account: Read gets 403 after it
// was authenticated, which proves the key.
func (s *SparkPost) Check(ctx context.Context, p *Probe) error {
	return p.Step("api", "Authenticate to the SparkPost API", func() (string, error) {
		_, _, err := s.api.post(ctx, request{method: http.MethodGet, url: s.base + "/account", prepare: s.auth, classify: classifySparkPost})
		if se, ok := message.AsSendError(err); ok && se.Status == http.StatusForbidden {
			p.Warn("The key lacks Account: Read, so only authentication was checked. Sending needs Transmissions: Read/Write.")
			return "API key accepted", nil
		}
		if err != nil {
			return "", err
		}
		return "API key accepted", nil
	})
}

// classifySparkPost reads {"errors":[{"message","code","description"}]}.
func classifySparkPost(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		Errors []struct {
			Message     string `json:"message"`
			Code        string `json:"code"`
			Description string `json:"description"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &b) != nil || len(b.Errors) == 0 {
		return
	}
	first := b.Errors[0]
	e.Detail = truncate(strings.TrimSpace(first.Message+" "+first.Description), 200)
	lower := strings.ToLower(e.Detail)
	switch {
	case strings.Contains(lower, "sending domain") || strings.Contains(lower, "unconfigured") || strings.Contains(lower, "suspended"):
		e.Reason = message.ReasonConfig
	case strings.Contains(lower, "limit"):
		e.Reason = message.ReasonRateLimited
	case e.Status == http.StatusBadRequest && strings.Contains(lower, "recipient"):
		e.Reason = message.ReasonInvalidRecipient
	}
}
