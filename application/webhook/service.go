// Package webhook is the outbound webhook use case: a tenant's endpoints
// with their signing secrets sealed by the key manager, the message events
// queued for them, and the delivery task that posts each one signed and
// retries with jittered backoff.
package webhook

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/webhook"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// Stored is a webhook with its sealed secret.
type Stored struct {
	Webhook domain.Webhook
	Sealed  string
}

// LegacyRow is a webhook whose secret is stored in plaintext.
type LegacyRow struct {
	ID     string
	Secret string
}

// Repository stores webhooks and their deliveries.
type Repository interface {
	Create(ctx context.Context, s Stored) error
	// Update saves w; sealed nil keeps the stored secret.
	Update(ctx context.Context, w domain.Webhook, sealed *string) error
	Delete(ctx context.Context, tenantID, id string, at time.Time) error
	Get(ctx context.Context, tenantID, id string) (Stored, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Webhook, int, error)
	// Subscribed lists the tenant's active webhooks for event: the
	// tenant-wide ones and, with an application, that application's.
	Subscribed(ctx context.Context, tenantID, applicationID, event string) ([]domain.Webhook, error)
	CreateDelivery(ctx context.Context, d domain.Delivery) error
	// Delivery returns a delivery and its webhook (any tenant: the task
	// carries only the delivery id).
	Delivery(ctx context.Context, id string) (domain.Delivery, Stored, error)
	UpdateDelivery(ctx context.Context, d domain.Delivery) error
	Legacy(ctx context.Context) ([]LegacyRow, error)
	ReplaceLegacy(ctx context.Context, id, sealed string) error
	WithLock(ctx context.Context, fn func(ctx context.Context) error) (bool, error)
}

// Queue schedules a delivery.
type Queue interface {
	EnqueueWebhook(ctx context.Context, deliveryID string) error
}

// Poster sends one signed request; status is 0 when nothing came back.
type Poster interface {
	Post(ctx context.Context, url string, headers map[string]string, body []byte) (status int, err error)
}

// Auditor records changes.
type Auditor interface {
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// Config is the deployment's transport rule.
type Config struct {
	// AllowPlaintext permits http:// endpoints (local and test).
	AllowPlaintext bool
}

// Service is the webhook use case.
type Service struct {
	repo   Repository
	cipher appkm.Cipher
	queue  Queue
	post   Poster
	audit  Auditor
	cfg    Config
	now    func() time.Time
}

// NewService builds the service. cipher is the key manager's webhook
// purpose.
func NewService(repo Repository, cipher appkm.Cipher, queue Queue, post Poster, audit Auditor, cfg Config) *Service {
	return &Service{repo: repo, cipher: cipher, queue: queue, post: post, audit: audit, cfg: cfg,
		now: func() time.Time { return time.Now().UTC() }}
}

// Input is a new webhook. An empty Secret is generated and returned once.
// ApplicationID limits it to one application's messages.
type Input struct {
	ApplicationID string
	URL           string
	Secret        string
	Events        []string
}

// Patch changes a webhook; nil fields are kept.
type Patch struct {
	URL    *string
	Secret *string
	Events *[]string
	Active *bool
}

type record struct {
	ApplicationID string   `json:"application_id,omitempty"`
	URL           string   `json:"url"`
	Events        []string `json:"events"`
	Active        bool     `json:"is_active"`
	Secret        string   `json:"webhook_secret,omitempty"`
}

func recordOf(w domain.Webhook, secretChanged string) record {
	return record{ApplicationID: w.ApplicationID, URL: w.URL, Events: w.Events, Active: w.Active, Secret: secretChanged}
}

// Create adds a webhook and returns its secret (shown once).
func (s *Service) Create(ctx context.Context, tenantID string, in Input, actor string) (domain.Webhook, string, error) {
	now := s.now()
	w := domain.Webhook{ID: id.New(), OrgID: tenantID, ApplicationID: in.ApplicationID, URL: in.URL, Events: in.Events, Active: true,
		CreatedBy: actor, UpdatedBy: actor, CreatedAt: now, UpdatedAt: now}
	if err := w.Validate(s.cfg.AllowPlaintext); err != nil {
		return domain.Webhook{}, "", err
	}
	secret := in.Secret
	if secret == "" {
		var err error
		if secret, err = domain.NewSecret(); err != nil {
			return domain.Webhook{}, "", err
		}
	} else if err := domain.ValidateSecret(secret); err != nil {
		return domain.Webhook{}, "", err
	}
	sealed, err := s.cipher.Seal(ctx, []byte(secret))
	if err != nil {
		return domain.Webhook{}, "", err
	}
	if err := s.repo.Create(ctx, Stored{Webhook: w, Sealed: sealed}); err != nil {
		return domain.Webhook{}, "", err
	}
	if err := s.audit.Change(ctx, "webhook", w.ID, "webhook.created", nil, recordOf(w, "set"), nil); err != nil {
		return domain.Webhook{}, "", err
	}
	return w, secret, nil
}

// Get returns one webhook.
func (s *Service) Get(ctx context.Context, tenantID, id string) (domain.Webhook, error) {
	st, err := s.repo.Get(ctx, tenantID, id)
	return st.Webhook, err
}

// List returns a page of webhooks.
func (s *Service) List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Webhook, int, error) {
	return s.repo.List(ctx, tenantID, limit, offset)
}

// Update changes a webhook.
func (s *Service) Update(ctx context.Context, tenantID, id string, in Patch, actor string) (domain.Webhook, error) {
	st, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return domain.Webhook{}, err
	}
	w := st.Webhook
	before := recordOf(w, "")
	if in.URL != nil {
		w.URL = *in.URL
	}
	if in.Events != nil {
		w.Events = *in.Events
	}
	if in.Active != nil {
		w.Active = *in.Active
	}
	if err := w.Validate(s.cfg.AllowPlaintext); err != nil {
		return domain.Webhook{}, err
	}
	var sealed *string
	changed := ""
	if in.Secret != nil && *in.Secret != "" {
		if err := domain.ValidateSecret(*in.Secret); err != nil {
			return domain.Webhook{}, err
		}
		v, err := s.cipher.Seal(ctx, []byte(*in.Secret))
		if err != nil {
			return domain.Webhook{}, err
		}
		sealed, changed = &v, "rotated"
	}
	w.UpdatedBy, w.UpdatedAt = actor, s.now()
	if err := s.repo.Update(ctx, w, sealed); err != nil {
		return domain.Webhook{}, err
	}
	if err := s.audit.Change(ctx, "webhook", w.ID, "webhook.updated", before, recordOf(w, changed), nil); err != nil {
		return domain.Webhook{}, err
	}
	return w, nil
}

// Delete removes a webhook.
func (s *Service) Delete(ctx context.Context, tenantID, id, actor string) error {
	st, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tenantID, id, s.now()); err != nil {
		return err
	}
	return s.audit.Change(ctx, "webhook", id, "webhook.deleted", recordOf(st.Webhook, ""), nil, map[string]any{"by": actor})
}

// payload is the JSON body a receiver gets (the Standard Webhooks shape:
// type, timestamp, data); its id is the webhook-id header.
type payload struct {
	Type      string         `json:"type"`
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// Notify queues event for every webhook subscribed to it: the tenant's,
// and the sending application's when there is one.
func (s *Service) Notify(ctx context.Context, tenantID, applicationID, event, messageID string, data map[string]any) error {
	hooks, err := s.repo.Subscribed(ctx, tenantID, applicationID, event)
	if err != nil {
		return err
	}
	for _, w := range hooks {
		now := s.now()
		d := domain.Delivery{ID: id.New(), WebhookID: w.ID, MessageID: messageID, Event: event,
			Status: domain.DeliveryPending, CreatedAt: now, UpdatedAt: now}
		if d.Payload, err = json.Marshal(payload{Type: event, Timestamp: now, Data: data}); err != nil {
			return err
		}
		if err := s.repo.CreateDelivery(ctx, d); err != nil {
			return err
		}
		if err := s.queue.EnqueueWebhook(ctx, d.ID); err != nil {
			return err
		}
	}
	return nil
}

// DeliveryError is a failed attempt the task retries.
type DeliveryError struct {
	Status int
	Err    error
}

func (e *DeliveryError) Error() string {
	if e.Err != nil {
		return "webhook delivery failed: " + e.Err.Error()
	}
	return "webhook delivery failed with status " + strconv.Itoa(e.Status)
}

func (e *DeliveryError) Unwrap() error { return e.Err }

// Deliver posts one delivery. A 2xx delivers it; a 4xx other than 408 and
// 429 fails it for good (the receiver refused it); anything else returns a
// DeliveryError for the task to retry, until final, when it fails.
func (s *Service) Deliver(ctx context.Context, deliveryID string, final bool) error {
	d, st, err := s.repo.Delivery(ctx, deliveryID)
	if err != nil {
		return err
	}
	if d.Status != domain.DeliveryPending || !st.Webhook.Active {
		return nil
	}
	secret, err := s.cipher.Open(ctx, st.Sealed)
	if err != nil {
		return err
	}
	now := s.now()
	headers := domain.Headers(string(secret), d.ID, now, d.Payload)
	headers["Content-Type"] = "application/json"
	status, postErr := s.post.Post(ctx, st.Webhook.URL, headers, d.Payload)
	d.Attempts++
	d.StatusCode = status
	d.UpdatedAt = now
	switch {
	case postErr == nil && status >= 200 && status < 300:
		d.Status, d.LastError, d.DeliveredAt = domain.DeliveryDelivered, "", &now
		return s.repo.UpdateDelivery(ctx, d)
	case postErr == nil && status >= 400 && status < 500 && status != 408 && status != 429:
		d.Status, d.LastError = domain.DeliveryFailed, "the receiver answered "+strconv.Itoa(status)
		return s.repo.UpdateDelivery(ctx, d)
	}
	d.LastError = "the receiver answered " + strconv.Itoa(status)
	if postErr != nil {
		d.LastError = "the receiver could not be reached"
	}
	if final {
		d.Status = domain.DeliveryFailed
	}
	if err := s.repo.UpdateDelivery(ctx, d); err != nil {
		return err
	}
	if final {
		return nil
	}
	return &DeliveryError{Status: status, Err: postErr}
}

// Bootstrap seals webhook secrets still stored in plaintext, once, under
// an advisory lock.
func (s *Service) Bootstrap(ctx context.Context) (int, error) {
	n := 0
	_, err := s.repo.WithLock(ctx, func(ctx context.Context) error {
		rows, err := s.repo.Legacy(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			sealed, err := s.cipher.Seal(ctx, []byte(r.Secret))
			if err != nil {
				return err
			}
			if err := s.repo.ReplaceLegacy(ctx, r.ID, sealed); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}
