package providerhooks

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SNS SignatureVersion 1 is SHA1withRSA
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
)

// snsHost is the host SNS signing certificates and subscription URLs are
// served from: sns.<region>.amazonaws.com (amazonaws.com.cn in China).
var snsHost = regexp.MustCompile(`^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$`)

// SNSURLAllowed reports whether u is an HTTPS URL on an SNS host, the only
// place a signing certificate or a subscription confirmation may be
// fetched from.
func SNSURLAllowed(u string) bool {
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.User == nil && snsHost.MatchString(p.Hostname()) &&
		(p.Port() == "" || p.Port() == "443")
}

// snsMessage is an SNS HTTP(S) notification.
type snsMessage struct {
	Type             string `json:"Type"`
	MessageID        string `json:"MessageId"`
	Token            string `json:"Token"`
	TopicArn         string `json:"TopicArn"`
	Subject          string `json:"Subject"`
	Message          string `json:"Message"`
	Timestamp        string `json:"Timestamp"`
	SignatureVersion string `json:"SignatureVersion"`
	Signature        string `json:"Signature"`
	SigningCertURL   string `json:"SigningCertURL"`
	SubscribeURL     string `json:"SubscribeURL"`
}

// SNS message types.
const (
	snsNotification   = "Notification"
	snsSubscription   = "SubscriptionConfirmation"
	snsUnsubscription = "UnsubscribeConfirmation"
)

// stringToSign is SNS's canonical form: the signed keys in order, each
// "Key\nValue\n".
func (m snsMessage) stringToSign() string {
	var keys []string
	if m.Type == snsNotification {
		keys = []string{"Message", m.Message, "MessageId", m.MessageID}
		if m.Subject != "" {
			keys = append(keys, "Subject", m.Subject)
		}
		keys = append(keys, "Timestamp", m.Timestamp, "TopicArn", m.TopicArn, "Type", m.Type)
	} else {
		keys = []string{"Message", m.Message, "MessageId", m.MessageID, "SubscribeURL", m.SubscribeURL,
			"Timestamp", m.Timestamp, "Token", m.Token, "TopicArn", m.TopicArn, "Type", m.Type}
	}
	var b strings.Builder
	for i := 0; i < len(keys); i += 2 {
		b.WriteString(keys[i] + "\n" + keys[i+1] + "\n")
	}
	return b.String()
}

// ses authenticates an SNS delivery (basic-auth password, then the SNS
// signature) and reads the SES event it carries, or the subscription to
// confirm.
func (v *Verifier) ses(ctx context.Context, secret string, r Request) (Result, error) {
	if err := basicAuth(r.Header, secret, false); err != nil {
		return Result{}, err
	}
	var m snsMessage
	if err := json.Unmarshal(r.Body, &m); err != nil {
		return Result{}, fmt.Errorf("%w: not an SNS message", ErrUnauthenticated)
	}
	if err := v.verifySNS(ctx, m); err != nil {
		return Result{}, err
	}
	switch m.Type {
	case snsSubscription:
		if !SNSURLAllowed(m.SubscribeURL) {
			return Result{}, fmt.Errorf("%w: the subscribe URL is not an SNS URL", ErrUnauthenticated)
		}
		return Result{SubscribeURL: m.SubscribeURL}, nil
	case snsUnsubscription:
		return Result{}, nil
	}
	events, err := sesEvents([]byte(m.Message))
	if err != nil {
		return Result{}, err
	}
	for i := range events {
		events[i].ProviderEventID = m.MessageID + ":" + events[i].Recipient
	}
	return Result{Events: events}, nil
}

// verifySNS checks the signature with the certificate from SigningCertURL
// and the message's timestamp.
func (v *Verifier) verifySNS(ctx context.Context, m snsMessage) error {
	if m.Type != snsNotification && m.Type != snsSubscription && m.Type != snsUnsubscription {
		return fmt.Errorf("%w: unknown SNS message type", ErrUnauthenticated)
	}
	if !SNSURLAllowed(m.SigningCertURL) || !strings.HasSuffix(strings.ToLower(m.SigningCertURL), ".pem") {
		return fmt.Errorf("%w: the signing certificate is not served by SNS", ErrUnauthenticated)
	}
	at, err := time.Parse(time.RFC3339Nano, m.Timestamp)
	if err != nil {
		return fmt.Errorf("%w: no SNS timestamp", ErrUnauthenticated)
	}
	if err := within(v.now(), at, snsTolerance); err != nil {
		return err
	}
	var hash crypto.Hash
	switch m.SignatureVersion {
	case "1":
		hash = crypto.SHA1
	case "2":
		hash = crypto.SHA256
	default:
		return fmt.Errorf("%w: unsupported SNS signature version", ErrUnauthenticated)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("%w: malformed SNS signature", ErrUnauthenticated)
	}
	if v.Certs == nil {
		return fmt.Errorf("%w: SNS certificates cannot be fetched", ErrUnauthenticated)
	}
	raw, err := v.Certs.Certificate(ctx, m.SigningCertURL)
	if err != nil {
		return fmt.Errorf("%w: SNS signing certificate: %v", ErrUnauthenticated, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return fmt.Errorf("%w: the SNS signing certificate is not PEM", ErrUnauthenticated)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: the SNS signing certificate cannot be read", ErrUnauthenticated)
	}
	if now := v.now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("%w: the SNS signing certificate is not valid now", ErrUnauthenticated)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: the SNS signing key is not RSA", ErrUnauthenticated)
	}
	var digest []byte
	if hash == crypto.SHA1 {
		d := sha1.Sum([]byte(m.stringToSign())) //nolint:gosec // SNS SignatureVersion 1
		digest = d[:]
	} else {
		d := sha256.Sum256([]byte(m.stringToSign()))
		digest = d[:]
	}
	if err := rsa.VerifyPKCS1v15(pub, hash, digest, sig); err != nil {
		return fmt.Errorf("%w: the SNS signature does not verify", ErrUnauthenticated)
	}
	return nil
}

// sesEvent is an SES event (configuration set event publishing) or
// notification (identity notifications).
type sesEvent struct {
	EventType        string `json:"eventType"`
	NotificationType string `json:"notificationType"`
	Mail             struct {
		MessageID string              `json:"messageId"`
		Tags      map[string][]string `json:"tags"`
	} `json:"mail"`
	Bounce *struct {
		BounceType        string `json:"bounceType"`
		BounceSubType     string `json:"bounceSubType"`
		Timestamp         string `json:"timestamp"`
		BouncedRecipients []struct {
			EmailAddress   string `json:"emailAddress"`
			DiagnosticCode string `json:"diagnosticCode"`
		} `json:"bouncedRecipients"`
	} `json:"bounce"`
	Complaint *struct {
		Timestamp            string `json:"timestamp"`
		ComplaintFeedback    string `json:"complaintFeedbackType"`
		ComplainedRecipients []struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"complainedRecipients"`
	} `json:"complaint"`
	Delivery *struct {
		Timestamp    string   `json:"timestamp"`
		Recipients   []string `json:"recipients"`
		SMTPResponse string   `json:"smtpResponse"`
	} `json:"delivery"`
	DeliveryDelay *struct {
		Timestamp         string `json:"timestamp"`
		DelayType         string `json:"delayType"`
		DelayedRecipients []struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"delayedRecipients"`
	} `json:"deliveryDelay"`
}

// sesEvents maps one SES event to provider events, one per recipient.
func sesEvents(raw []byte) ([]message.ProviderEvent, error) {
	var e sesEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("%w: the SES event is not JSON", ErrMalformed)
	}
	typ := e.EventType
	if typ == "" {
		typ = e.NotificationType
	}
	base := message.ProviderEvent{ProviderMessageID: e.Mail.MessageID}
	if ids := e.Mail.Tags["mailos_message_id"]; len(ids) > 0 {
		base.MessageID = ids[0]
	}
	var out []message.ProviderEvent
	add := func(t message.EventType, to, reason, at string) {
		ev := base
		ev.Type, ev.Recipient, ev.Reason, ev.OccurredAt = t, to, reason, parseTime(at)
		out = append(out, ev)
	}
	switch typ {
	case "Delivery":
		if e.Delivery != nil {
			for _, to := range e.Delivery.Recipients {
				add(message.EventDelivered, to, e.Delivery.SMTPResponse, e.Delivery.Timestamp)
			}
		}
	case "Bounce":
		if e.Bounce != nil {
			t := message.EventSoftBounced
			if e.Bounce.BounceType == "Permanent" {
				t = message.EventBounced
			}
			for _, r := range e.Bounce.BouncedRecipients {
				reason := strings.TrimSpace(e.Bounce.BounceType + " " + e.Bounce.BounceSubType + ": " + r.DiagnosticCode)
				add(t, r.EmailAddress, reason, e.Bounce.Timestamp)
			}
		}
	case "Complaint":
		if e.Complaint != nil {
			for _, r := range e.Complaint.ComplainedRecipients {
				add(message.EventComplained, r.EmailAddress, e.Complaint.ComplaintFeedback, e.Complaint.Timestamp)
			}
		}
	case "DeliveryDelay":
		if e.DeliveryDelay != nil {
			for _, r := range e.DeliveryDelay.DelayedRecipients {
				add(message.EventDeferred, r.EmailAddress, e.DeliveryDelay.DelayType, e.DeliveryDelay.Timestamp)
			}
		}
	}
	return out, nil
}

// HTTPSFetcher fetches SNS signing certificates over HTTPS from SNS hosts
// only, caching each for a day, and confirms SNS subscriptions.
type HTTPSFetcher struct {
	Client *http.Client
	TTL    time.Duration

	mu    sync.Mutex
	cache map[string]cachedCert
}

type cachedCert struct {
	pem []byte
	at  time.Time
}

// maxCert bounds a certificate download.
const maxCert = 64 << 10

func (f *HTTPSFetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (f *HTTPSFetcher) get(ctx context.Context, u string) ([]byte, error) {
	if !SNSURLAllowed(u) {
		return nil, errors.New("not an SNS URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SNS answered %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxCert))
}

// Certificate implements Certificates.
func (f *HTTPSFetcher) Certificate(ctx context.Context, u string) ([]byte, error) {
	ttl := f.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	f.mu.Lock()
	if c, ok := f.cache[u]; ok && time.Since(c.at) < ttl {
		f.mu.Unlock()
		return c.pem, nil
	}
	f.mu.Unlock()
	raw, err := f.get(ctx, u)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	if f.cache == nil {
		f.cache = map[string]cachedCert{}
	}
	f.cache[u] = cachedCert{pem: raw, at: time.Now()}
	f.mu.Unlock()
	return raw, nil
}

// Confirm visits an SNS SubscribeURL.
func (f *HTTPSFetcher) Confirm(ctx context.Context, u string) error {
	_, err := f.get(ctx, u)
	return err
}
