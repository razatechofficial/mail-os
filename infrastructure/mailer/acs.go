package mailer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// acsAPIVersion is the Azure Communication Services Email GA API.
const acsAPIVersion = "2023-03-31"

// ACS sends through Azure Communication Services Email, signing each
// request with the resource's access key (HMAC-SHA256).
type ACS struct {
	api  *httpAPI
	base string
	key  []byte
	from message.Address
}

// NewACS returns an Azure Communication Services sender. The endpoint must
// be an ACS host, so the key is only ever used with Azure.
func NewACS(s provider.Settings, c provider.Credentials, opts Options) (*ACS, error) {
	opts = opts.withDefaults()
	invalid := func(d string) error {
		return message.NewSendError(string(provider.KindACS), message.ReasonConfig, 0, d)
	}
	if !provider.ACSEndpointAllowed(s.Endpoint) {
		return nil, invalid("the endpoint must be an Azure Communication Services endpoint")
	}
	key, err := base64.StdEncoding.DecodeString(c.AccessKey)
	if err != nil || len(key) == 0 {
		return nil, invalid("the access key is not a base64 Azure key")
	}
	base, err := opts.baseURL(provider.KindACS, strings.TrimSuffix(s.Endpoint, "/"))
	if err != nil {
		return nil, err
	}
	return &ACS{api: newHTTPAPI(provider.KindACS, opts), base: base, key: key,
		from: message.Address{Name: s.FromName, Email: s.FromEmail}}, nil
}

// CloseIdleConnections drops pooled connections.
func (a *ACS) CloseIdleConnections() { a.api.CloseIdleConnections() }

type acsAddress struct {
	Address     string `json:"address"`
	DisplayName string `json:"displayName,omitempty"`
}

type acsRequest struct {
	SenderAddress string `json:"senderAddress"`
	Content       struct {
		Subject   string `json:"subject"`
		PlainText string `json:"plainText,omitempty"`
		HTML      string `json:"html,omitempty"`
	} `json:"content"`
	Recipients struct {
		To []acsAddress `json:"to"`
	} `json:"recipients"`
	ReplyTo                        []acsAddress      `json:"replyTo,omitempty"`
	Headers                        map[string]string `json:"headers,omitempty"`
	UserEngagementTrackingDisabled bool              `json:"userEngagementTrackingDisabled"`
	// Attachments; an inline one carries its contentId.
	Attachments []acsFile `json:"attachments,omitempty"`
}

type acsFile struct {
	Name            string `json:"name"`
	ContentType     string `json:"contentType"`
	ContentInBase64 string `json:"contentInBase64"`
	ContentID       string `json:"contentId,omitempty"`
}

// sign sets the HMAC-SHA256 authorization: the string to sign is the
// method, path and query, date, host and content hash.
func (a *ACS) sign(r *http.Request, body []byte) error {
	sum := sha256.Sum256(body)
	hash := base64.StdEncoding.EncodeToString(sum[:])
	date := time.Now().UTC().Format(http.TimeFormat)
	toSign := r.Method + "\n" + r.URL.RequestURI() + "\n" + date + ";" + r.URL.Host + ";" + hash
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(toSign))
	r.Header.Set("x-ms-date", date)
	r.Header.Set("x-ms-content-sha256", hash)
	r.Header.Set("Authorization", "HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+
		base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return nil
}

// Send calls POST /emails:send (202 with the operation id). ACS takes the
// sender's display name from the domain's configuration, not the request.
func (a *ACS) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(a.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindACS)
	}
	var body acsRequest
	body.SenderAddress = out.From.Email
	body.Content.Subject, body.Content.PlainText, body.Content.HTML = out.Subject, out.Text, out.HTML
	body.Recipients.To = []acsAddress{{Address: out.To.Email, DisplayName: out.To.Name}}
	if !out.ReplyTo.IsZero() {
		body.ReplyTo = []acsAddress{{Address: out.ReplyTo.Email, DisplayName: out.ReplyTo.Name}}
	}
	body.Headers = out.Headers
	body.UserEngagementTrackingDisabled = true
	for _, a := range out.Attachments {
		f := acsFile{Name: a.Filename, ContentType: a.ContentType, ContentInBase64: b64(a.Data)}
		if a.Inline {
			f.ContentID = a.ContentID
		}
		body.Attachments = append(body.Attachments, f)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindACS), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	data, h, err := a.api.post(ctx, request{
		url: a.base + "/emails:send?api-version=" + acsAPIVersion, contentType: "application/json", body: payload,
		prepare: func(r *http.Request) error {
			if out.MessageID != "" {
				r.Header.Set("x-ms-client-request-id", out.MessageID)
			}
			return a.sign(r, payload)
		},
		classify: classifyACS,
	})
	if err != nil {
		return Result{}, err
	}
	var res struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(data, &res)
	if res.ID == "" {
		res.ID = h.Get("Operation-Id")
	}
	if res.ID == "" {
		return Result{}, message.NewSendError(string(provider.KindACS), message.ReasonUnavailable, http.StatusAccepted, "Azure returned no operation id")
	}
	return Result{ProviderMessageID: res.ID}, nil
}

// Check reads the status of an operation that does not exist: a valid
// signature gets 404, a bad one 401.
func (a *ACS) Check(ctx context.Context, p *Probe) error {
	u, _ := url.Parse(a.base)
	return p.Step("api", "Authenticate to "+u.Host, func() (string, error) {
		_, _, err := a.api.post(ctx, request{
			method: http.MethodGet, url: a.base + "/emails/operations/" + id.New() + "?api-version=" + acsAPIVersion,
			prepare:  func(r *http.Request) error { return a.sign(r, nil) },
			classify: classifyACS,
		})
		if se, ok := message.AsSendError(err); ok && se.Status == http.StatusNotFound {
			return "access key accepted", nil
		}
		if err == nil {
			return "access key accepted", nil
		}
		return "", err
	})
}

// classifyACS reads {"error":{"code","message"}}.
func classifyACS(e *message.SendError, body []byte, _ http.Header) {
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
	lower := strings.ToLower(b.Error.Code + " " + b.Error.Message)
	switch {
	case e.Status == http.StatusUnauthorized || strings.Contains(lower, "denied"):
		e.Reason = message.ReasonAuth
	case strings.Contains(lower, "sender") || strings.Contains(lower, "domain"):
		e.Reason = message.ReasonConfig
	case strings.Contains(lower, "recipient"):
		e.Reason = message.ReasonInvalidRecipient
	case strings.Contains(lower, "toomanyrequests") || strings.Contains(lower, "throttl"):
		e.Reason = message.ReasonRateLimited
	}
}
