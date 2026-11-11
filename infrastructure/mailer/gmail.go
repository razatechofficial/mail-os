package mailer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Gmail sends through the Gmail API as one Google Workspace user, with a
// service account's domain-wide delegation for the gmail.send scope.
type Gmail struct {
	api    *httpAPI
	url    string
	tokens *tokenSource
	from   message.Address
}

// NewGmail returns a Gmail API sender.
func NewGmail(s provider.Settings, c provider.Credentials, opts Options) (*Gmail, error) {
	opts = opts.withDefaults()
	if !provider.ValidEmail(s.Sender) {
		return nil, message.NewSendError(string(provider.KindGmail), message.ReasonConfig, 0, "the sending user is required")
	}
	base, err := opts.baseURL(provider.KindGmail, "https://gmail.googleapis.com")
	if err != nil {
		return nil, err
	}
	tokens, err := googleTokens(provider.KindGmail, c.ServiceAccountJSON, s.Sender, scopeGmailSend, opts)
	if err != nil {
		return nil, err
	}
	name, email := s.DefaultFrom()
	return &Gmail{api: newHTTPAPI(provider.KindGmail, opts), url: base + "/gmail/v1/users/me/messages/send",
		tokens: tokens, from: message.Address{Name: name, Email: email}}, nil
}

// CloseIdleConnections drops pooled connections.
func (g *Gmail) CloseIdleConnections() { g.api.CloseIdleConnections() }

// Send posts the MIME message as {"raw": base64url}.
func (g *Gmail) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(g.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindGmail)
	}
	raw, _ := buildMIME(out, time.Now())
	if out.DKIM != nil {
		// Gmail keeps a signature added before submission and adds its own.
		// A key that cannot sign is refused, as on the SMTP relay: mail
		// from a domain with DKIM must never leave unsigned.
		signed, err := signDKIM(raw, out.From.Email, *out.DKIM)
		if err != nil {
			return Result{}, &message.SendError{Provider: string(provider.KindGmail), Reason: message.ReasonConfig, Err: err, Detail: "the DKIM key cannot be used"}
		}
		raw = signed
	}
	payload, _ := json.Marshal(map[string]string{"raw": base64.URLEncoding.EncodeToString(raw)})
	tok, err := g.tokens.Token(ctx)
	if err != nil {
		return Result{}, err
	}
	data, _, err := g.api.post(ctx, request{
		url: g.url, contentType: "application/json", body: payload,
		prepare: func(r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+tok)
			return nil
		},
		classify: classifyGoogleAPI,
	})
	if err != nil {
		if se, ok := message.AsSendError(err); ok && se.Status == http.StatusUnauthorized {
			g.tokens.Invalidate()
		}
		return Result{}, err
	}
	var res struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &res) != nil || res.ID == "" {
		return Result{}, message.NewSendError(string(provider.KindGmail), message.ReasonUnavailable, http.StatusOK, "Gmail returned no message id")
	}
	return Result{ProviderMessageID: res.ID}, nil
}

// Check gets a token: Google issues one only when the service account's
// delegation covers the scope for that user, which is the whole setup.
func (g *Gmail) Check(ctx context.Context, p *Probe) error {
	_, err := g.tokens.step(ctx, p, "")
	return err
}

// classifyGoogleAPI reads {"error":{"code","message","status","errors":[{"reason"}]}}.
func classifyGoogleAPI(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &b) != nil || b.Error.Message == "" {
		return
	}
	e.Detail = truncate(b.Error.Message, 200)
	reason := ""
	if len(b.Error.Errors) > 0 {
		reason = b.Error.Errors[0].Reason
	}
	switch {
	case reason == "rateLimitExceeded" || reason == "userRateLimitExceeded" || reason == "dailyLimitExceeded" || b.Error.Status == "RESOURCE_EXHAUSTED":
		e.Reason = message.ReasonRateLimited
	case reason == "failedPrecondition" || b.Error.Status == "FAILED_PRECONDITION":
		e.Reason = message.ReasonConfig // Gmail is not enabled for the user
	case b.Error.Status == "UNAUTHENTICATED" || b.Error.Status == "PERMISSION_DENIED":
		e.Reason = message.ReasonAuth
	case e.Status == http.StatusBadRequest && strings.Contains(strings.ToLower(b.Error.Message), "recipient"):
		e.Reason = message.ReasonInvalidRecipient
	}
}
