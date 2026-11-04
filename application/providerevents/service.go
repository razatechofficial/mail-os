// Package providerevents receives a tenant provider's delivery event
// webhook: it opens the provider's webhook secret, has the payload
// authenticated and read (infrastructure/providerhooks), confirms an SNS
// subscription, and records each event on its message (message.Service).
// A refused webhook is audited and answered 401; an event for a message
// still being sent is answered 503 so the provider delivers it again.
package providerevents

import (
	"context"
	"errors"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/providerhooks"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Secrets opens a provider's webhook secret (provider.Service).
type Secrets interface {
	WebhookSecret(ctx context.Context, tenantID, id string) (provider.Kind, string, error)
}

// Parser authenticates and reads a webhook (providerhooks.Verifier).
type Parser interface {
	Parse(ctx context.Context, kind provider.Kind, secret string, r providerhooks.Request) (providerhooks.Result, error)
}

// Confirmer confirms an SNS subscription (providerhooks.HTTPSFetcher).
type Confirmer interface {
	Confirm(ctx context.Context, url string) error
}

// Recorder records one event on its message (message.Service).
type Recorder interface {
	RecordProviderEvent(ctx context.Context, tenantID, providerID string, e domainmsg.ProviderEvent) (appmessage.EventOutcome, error)
}

// Auditor records refusals and subscriptions.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Audit actions.
const (
	AuditRefused   = "provider_webhook.refused"
	AuditConfirmed = "provider_webhook.subscription_confirmed"
)

// Summary is what one webhook recorded.
type Summary struct {
	Recorded   int `json:"recorded"`
	Duplicates int `json:"duplicates"`
	Unknown    int `json:"unknown"`
	// Confirmed is an SNS subscription confirmed by this request.
	Confirmed bool `json:"confirmed,omitempty"`
}

// Service is the provider webhook use case.
type Service struct {
	secrets   Secrets
	parser    Parser
	confirmer Confirmer
	recorder  Recorder
	audit     Auditor
}

// NewService builds the use case; confirmer may be nil (SNS subscriptions
// are then confirmed by hand).
func NewService(secrets Secrets, parser Parser, confirmer Confirmer, recorder Recorder, audit Auditor) *Service {
	return &Service{secrets: secrets, parser: parser, confirmer: confirmer, recorder: recorder, audit: audit}
}

// Errors the transport maps: ErrRefused is 401, ErrRetry 503.
var (
	ErrRefused = apperrors.NewAppError(apperrors.KindUnauthorized, "WEBHOOK_REFUSED", "the webhook is not authenticated")
	ErrRetry   = apperrors.NewAppError(apperrors.KindUnavailable, "RETRY_LATER", "the message is still being sent; deliver the event again later")
)

// Receive handles one webhook for the tenant's provider. An unknown
// provider, one without webhooks or without a webhook secret, and a
// payload that does not authenticate are all refused alike, so the
// answer tells nothing about the tenant's providers.
func (s *Service) Receive(ctx context.Context, tenantID, providerID string, r providerhooks.Request) (Summary, error) {
	ctx = audit.WithTenant(ctx, tenantID)
	kind, secret, err := s.secrets.WebhookSecret(ctx, tenantID, providerID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return Summary{}, ErrRefused
		}
		return Summary{}, err
	}
	res, err := s.parser.Parse(ctx, kind, secret, r)
	if err != nil {
		reason := "unauthenticated"
		switch {
		case errors.Is(err, providerhooks.ErrMalformed):
			return Summary{}, apperrors.NewAppError(apperrors.KindBadRequest, "MALFORMED_WEBHOOK", err.Error())
		case errors.Is(err, providerhooks.ErrNotConfigured):
			reason = "no_webhook_secret"
		case errors.Is(err, providerhooks.ErrUnsupported):
			reason = "unsupported_kind"
		}
		s.auditRefusal(ctx, providerID, kind, reason, err)
		return Summary{}, ErrRefused
	}
	var sum Summary
	if res.SubscribeURL != "" && s.confirmer != nil {
		if err := s.confirmer.Confirm(ctx, res.SubscribeURL); err != nil {
			return Summary{}, apperrors.Wrap(err, apperrors.KindUnavailable, "CONFIRM_FAILED", "the SNS subscription could not be confirmed")
		}
		sum.Confirmed = true
		s.appendAudit(ctx, providerID, AuditConfirmed, map[string]any{"kind": string(kind)})
	}
	retry := false
	for _, e := range res.Events {
		out, err := s.recorder.RecordProviderEvent(ctx, tenantID, providerID, e)
		switch {
		case errors.Is(err, appmessage.ErrStillSending):
			retry = true
		case err != nil:
			return sum, err
		case out == appmessage.OutcomeRecorded:
			sum.Recorded++
		case out == appmessage.OutcomeDuplicate:
			sum.Duplicates++
		default:
			sum.Unknown++
		}
	}
	if retry {
		// The events already recorded are kept; their redelivery is a
		// duplicate.
		return sum, ErrRetry
	}
	return sum, nil
}

func (s *Service) auditRefusal(ctx context.Context, providerID string, kind provider.Kind, reason string, err error) {
	logger.FromContext(ctx).Warn("provider webhook refused", logger.String("provider_id", providerID), logger.Err(err))
	s.appendAudit(ctx, providerID, AuditRefused, map[string]any{"kind": string(kind), "reason": reason})
}

func (s *Service) appendAudit(ctx context.Context, providerID, action string, meta map[string]any) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Append(ctx, "provider", providerID, action, meta); err != nil {
		logger.FromContext(ctx).Warn("audit provider webhook", logger.Err(err))
	}
}
