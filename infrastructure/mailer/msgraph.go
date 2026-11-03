package mailer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// MSGraph sends through Microsoft Graph sendMail as one Exchange Online
// mailbox, with an Entra ID application's client credentials. The message
// goes as MIME, so its Message-ID, headers and text/HTML alternatives are
// kept exactly; Exchange signs it with the tenant's DKIM keys.
type MSGraph struct {
	api    *httpAPI
	url    string
	sender string
	tokens *tokenSource
	from   message.Address
}

// NewMSGraph returns a Graph sender.
func NewMSGraph(s provider.Settings, c provider.Credentials, opts Options) (*MSGraph, error) {
	opts = opts.withDefaults()
	if !provider.ValidEmail(s.Sender) {
		return nil, message.NewSendError(string(provider.KindMSGraph), message.ReasonConfig, 0, "the sending mailbox is required")
	}
	_, graphHost := s.MicrosoftEndpoints()
	base, err := opts.baseURL(provider.KindMSGraph, graphHost)
	if err != nil {
		return nil, err
	}
	tokens, err := microsoftTokens(provider.KindMSGraph, s, c, graphHost+scopeGraph, opts)
	if err != nil {
		return nil, err
	}
	name, email := s.DefaultFrom()
	return &MSGraph{api: newHTTPAPI(provider.KindMSGraph, opts), url: base + "/v1.0/users/" + url.PathEscape(s.Sender) + "/sendMail",
		sender: s.Sender, tokens: tokens, from: message.Address{Name: name, Email: email}}, nil
}

// CloseIdleConnections drops pooled connections.
func (g *MSGraph) CloseIdleConnections() { g.api.CloseIdleConnections() }

// Send posts the MIME message, base64-encoded, to sendMail (202, no body).
func (g *MSGraph) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(g.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindMSGraph)
	}
	raw, msgID := buildMIME(out, time.Now())
	if err := g.post(ctx, []byte(base64.StdEncoding.EncodeToString(raw))); err != nil {
		return Result{}, err
	}
	return Result{ProviderMessageID: strings.Trim(msgID, "<>")}, nil
}

func (g *MSGraph) post(ctx context.Context, body []byte) error {
	tok, err := g.tokens.Token(ctx)
	if err != nil {
		return err
	}
	_, _, err = g.api.post(ctx, request{
		url: g.url, contentType: "text/plain", body: body,
		prepare: func(r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+tok)
			return nil
		},
		classify: classifyGraph,
	})
	if se, ok := message.AsSendError(err); ok && se.Status == http.StatusUnauthorized {
		g.tokens.Invalidate()
	}
	return err
}

// Check gets a token and warns when it lacks Mail.Send. Graph has no
// harmless call that needs only Mail.Send, so the mailbox itself is proven
// by a test send.
func (g *MSGraph) Check(ctx context.Context, p *Probe) error {
	_, err := g.tokens.step(ctx, p, "Mail.Send")
	if err == nil {
		p.Warn("Graph checks the mailbox (" + g.sender + ") only when sending: use Send test email to confirm the app may send as it.")
	}
	return err
}

// classifyGraph reads {"error":{"code","message"}}.
func classifyGraph(e *message.SendError, body []byte, _ http.Header) {
	var b struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &b) != nil || b.Error.Code == "" {
		return
	}
	e.Detail = b.Error.Code
	if b.Error.Message != "" {
		e.Detail += ": " + truncate(b.Error.Message, 200)
	}
	switch b.Error.Code {
	case "ErrorAccessDenied", "Authorization_RequestDenied", "InvalidAuthenticationToken", "AccessDenied":
		e.Reason = message.ReasonAuth
	case "ErrorSendAsDenied", "ErrorInvalidUser", "ResourceNotFound", "MailboxNotEnabledForRESTAPI", "MailboxNotSupportedForRESTAPI",
		"ErrorMailboxStoreUnavailable", "ErrorNonExistentMailbox":
		e.Reason = message.ReasonConfig
	case "ErrorInvalidRecipients":
		e.Reason = message.ReasonInvalidRecipient
	case "ErrorMessageSizeExceeded", "ErrorMimeContentInvalid", "ErrorMimeContentConversionFailed", "ErrorMessageSubmissionBlocked":
		e.Reason = message.ReasonRejected
	case "ApplicationThrottled", "ErrorExceededMessageLimit", "ErrorQuotaExceeded", "TooManyRequests":
		e.Reason = message.ReasonRateLimited
	}
}
