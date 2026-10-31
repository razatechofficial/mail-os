package mailer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// SES sends through the Amazon SES v2 API (SendEmail with simple content),
// signed with SigV4.
type SES struct {
	api    *httpAPI
	url    string
	region string
	creds  aws.Credentials
	cfgSet string
	from   message.Address
	signer *v4.Signer
}

// NewSES returns an SES sender for region.
func NewSES(s provider.Settings, c provider.Credentials, opts Options) (*SES, error) {
	opts = opts.withDefaults()
	if s.Region == "" || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, message.NewSendError(string(provider.KindSES), message.ReasonConfig, 0, "the SES region and access keys are required")
	}
	base, err := opts.baseURL(provider.KindSES, "https://email."+s.Region+".amazonaws.com")
	if err != nil {
		return nil, err
	}
	return &SES{
		api: newHTTPAPI(provider.KindSES, opts), url: base + "/v2/email/outbound-emails", region: s.Region,
		creds:  aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, Source: "mailos"},
		cfgSet: s.ConfigurationSet, from: message.Address{Name: s.FromName, Email: s.FromEmail}, signer: v4.NewSigner(),
	}, nil
}

// CloseIdleConnections drops pooled connections.
func (s *SES) CloseIdleConnections() { s.api.CloseIdleConnections() }

type sesContent struct {
	Data    string `json:"Data"`
	Charset string `json:"Charset"`
}

type sesHeader struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

type sesTag struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

type sesRequest struct {
	FromEmailAddress string `json:"FromEmailAddress"`
	Destination      struct {
		ToAddresses []string `json:"ToAddresses"`
	} `json:"Destination"`
	ReplyToAddresses []string `json:"ReplyToAddresses,omitempty"`
	Content          struct {
		Simple struct {
			Subject sesContent `json:"Subject"`
			Body    struct {
				Text *sesContent `json:"Text,omitempty"`
				HTML *sesContent `json:"Html,omitempty"`
			} `json:"Body"`
			Headers []sesHeader `json:"Headers,omitempty"`
		} `json:"Simple"`
	} `json:"Content"`
	EmailTags            []sesTag `json:"EmailTags,omitempty"`
	ConfigurationSetName string   `json:"ConfigurationSetName,omitempty"`
}

// sesTagValue keeps the characters SES allows in tags.
func sesTagValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// Send calls SendEmail.
func (s *SES) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(s.from)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindSES)
	}
	var body sesRequest
	body.FromEmailAddress = out.From.String()
	body.Destination.ToAddresses = []string{out.To.String()}
	if !out.ReplyTo.IsZero() {
		body.ReplyToAddresses = []string{out.ReplyTo.String()}
	}
	simple := &body.Content.Simple
	simple.Subject = sesContent{Data: out.Subject, Charset: "UTF-8"}
	if out.Text != "" {
		simple.Body.Text = &sesContent{Data: out.Text, Charset: "UTF-8"}
	}
	if out.HTML != "" {
		simple.Body.HTML = &sesContent{Data: out.HTML, Charset: "UTF-8"}
	}
	for k, v := range out.Headers {
		simple.Headers = append(simple.Headers, sesHeader{Name: k, Value: v})
	}
	if out.MessageID != "" {
		body.EmailTags = append(body.EmailTags, sesTag{Name: "mailos_message_id", Value: sesTagValue(out.MessageID)})
	}
	for _, t := range out.Tags {
		body.EmailTags = append(body.EmailTags, sesTag{Name: "tag_" + sesTagValue(t), Value: "1"})
	}
	body.ConfigurationSetName = s.cfgSet
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, message.NewSendError(string(provider.KindSES), message.ReasonInvalid, 0, "the message cannot be encoded")
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	data, _, err := s.api.post(ctx, request{
		url: s.url, contentType: "application/json", body: payload,
		prepare: func(r *http.Request) error {
			return s.signer.SignHTTP(r.Context(), s.creds, r, hash, "ses", s.region, time.Now())
		},
		classify: classifySES,
	})
	if err != nil {
		return Result{}, err
	}
	var res struct {
		MessageID string `json:"MessageId"`
	}
	if json.Unmarshal(data, &res) != nil || res.MessageID == "" {
		return Result{}, message.NewSendError(string(provider.KindSES), message.ReasonUnavailable, http.StatusOK, "SES returned no message id")
	}
	return Result{ProviderMessageID: res.MessageID}, nil
}

// classifySES refines the status from the error type (restJson1:
// X-Amzn-ErrorType, or __type/code in the body).
func classifySES(e *message.SendError, body []byte, h http.Header) {
	var b struct {
		Type    string `json:"__type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &b)
	typ := h.Get("X-Amzn-ErrorType")
	if typ == "" {
		typ = b.Type
	}
	if typ == "" {
		typ = b.Code
	}
	typ, _, _ = strings.Cut(typ, ":")
	if i := strings.LastIndexByte(typ, '#'); i >= 0 {
		typ = typ[i+1:]
	}
	if typ != "" {
		e.Detail = typ
		if b.Message != "" {
			e.Detail += ": " + truncate(b.Message, 200)
		}
	}
	switch typ {
	case "MessageRejected":
		e.Reason = message.ReasonRejected
		if strings.Contains(b.Message, "not verified") {
			// An unverified sender identity, or a sandboxed account.
			e.Reason = message.ReasonConfig
		}
	case "MailFromDomainNotVerifiedException", "AccountSuspendedException", "SendingPausedException", "NotFoundException":
		e.Reason = message.ReasonConfig
	case "TooManyRequestsException", "LimitExceededException", "ThrottlingException":
		e.Reason = message.ReasonRateLimited
	case "UnrecognizedClientException", "InvalidSignatureException", "SignatureDoesNotMatch", "AccessDeniedException", "ExpiredTokenException":
		e.Reason = message.ReasonAuth
	case "BadRequestException":
		e.Reason = message.ReasonRejected
	}
}
