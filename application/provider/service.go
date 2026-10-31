// Package provider is the mail provider use case: a tenant's providers
// with their credentials sealed by the key manager (contract §6), never
// returned, and audited with the secret values redacted. It also serves
// the router the tenant's active providers with their opened credentials.
package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/provider"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// Stored is a provider with its sealed credentials ("" when none).
type Stored struct {
	Provider domain.Provider
	Sealed   string
}

// LegacyRow is a provider whose configuration still holds plaintext
// secrets (written before credentials were sealed).
type LegacyRow struct {
	ID            string
	Kind          domain.Kind
	Configuration map[string]any
}

// Repository stores providers.
type Repository interface {
	Create(ctx context.Context, s Stored) error
	// Update saves p; sealed nil keeps the stored credentials.
	Update(ctx context.Context, p domain.Provider, sealed *string) error
	Delete(ctx context.Context, tenantID, id string, at time.Time) error
	Get(ctx context.Context, tenantID, id string) (Stored, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Provider, int, error)
	ListActive(ctx context.Context, tenantID string) ([]Stored, error)
	// SentSince counts each provider's messages sent since t.
	SentSince(ctx context.Context, providerIDs []string, t time.Time) (map[string]int, error)
	// Legacy lists rows with plaintext secrets in configuration, and
	// ReplaceLegacy writes their split settings and sealed credentials.
	// WithLock runs fn under the conversion's advisory lock.
	Legacy(ctx context.Context) ([]LegacyRow, error)
	ReplaceLegacy(ctx context.Context, id string, settings domain.Settings, sealed string, hints domain.Hints) error
	WithLock(ctx context.Context, fn func(ctx context.Context) error) (bool, error)
}

// Auditor records changes with secrets redacted.
type Auditor interface {
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// Config is the deployment's transport rule.
type Config struct {
	// AllowPlaintext permits SMTP tls_mode none (local and test).
	AllowPlaintext bool
}

// Service is the provider use case.
type Service struct {
	repo   Repository
	cipher appkm.Cipher
	audit  Auditor
	cfg    Config
	now    func() time.Time
}

// NewService builds the service. cipher is the key manager's provider
// purpose.
func NewService(repo Repository, cipher appkm.Cipher, audit Auditor, cfg Config) *Service {
	return &Service{repo: repo, cipher: cipher, audit: audit, cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
}

// Input is a new provider.
type Input struct {
	Name        string
	Kind        domain.Kind
	Settings    domain.Settings
	Credentials domain.Credentials
	Priority    int
	// Weight defaults to domain.DefaultWeight; 0 is a standby.
	Weight     *int
	DailyLimit int
	// Active defaults to true.
	Active *bool
}

// Patch changes a provider; nil fields are kept. Credentials are merged:
// a blank secret keeps the stored one, unless the kind changes.
type Patch struct {
	Name        *string
	Kind        *domain.Kind
	Settings    *domain.Settings
	Credentials *domain.Credentials
	Priority    *int
	Weight      *int
	DailyLimit  *int
	Active      *bool
}

// record is what the audit log sees: the view plus a fingerprint of the
// credentials, written as [REDACTED] but marked changed when they change.
type record struct {
	domain.View
	Credentials string `json:"credentials,omitempty"`
}

func fingerprint(c domain.Credentials) string {
	if c.Empty() {
		return ""
	}
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func (s *Service) validate(p *domain.Provider, c domain.Credentials) error {
	p.Normalize()
	var details []apperrors.FieldError
	if err := p.Validate(s.cfg.AllowPlaintext); err != nil {
		details = append(details, apperrors.DetailsOf(err)...)
	}
	if p.Kind.Valid() {
		if err := domain.ValidateCredentials(p.Kind, c); err != nil {
			details = append(details, apperrors.DetailsOf(err)...)
		}
	}
	if c.Password != "" && p.Settings.Username == "" {
		details = append(details, apperrors.FieldError{Field: "settings.username", Code: "required", Message: "an SMTP password needs a username"})
	}
	if len(details) > 0 {
		return apperrors.Validation(details...)
	}
	return nil
}

func (s *Service) seal(ctx context.Context, c domain.Credentials) (string, error) {
	if c.Empty() {
		return "", nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return s.cipher.Seal(ctx, raw)
}

func (s *Service) open(ctx context.Context, sealed string) (domain.Credentials, error) {
	var c domain.Credentials
	if sealed == "" {
		return c, nil
	}
	raw, err := s.cipher.Open(ctx, sealed)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(raw, &c)
	return c, err
}

// Create adds a provider.
func (s *Service) Create(ctx context.Context, tenantID string, in Input, actor string) (domain.Provider, error) {
	now := s.now()
	p := domain.Provider{
		ID: id.New(), OrgID: tenantID, Name: in.Name, Kind: in.Kind, Settings: in.Settings,
		Priority: in.Priority, Weight: domain.DefaultWeight, DailyLimit: in.DailyLimit, Active: true,
		CreatedBy: actor, UpdatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}
	if in.Weight != nil {
		p.Weight = *in.Weight
	}
	if in.Active != nil {
		p.Active = *in.Active
	}
	if err := s.validate(&p, in.Credentials); err != nil {
		return domain.Provider{}, err
	}
	sealed, err := s.seal(ctx, in.Credentials)
	if err != nil {
		return domain.Provider{}, err
	}
	p.SetCredentials(in.Credentials)
	if err := s.repo.Create(ctx, Stored{Provider: p, Sealed: sealed}); err != nil {
		return domain.Provider{}, err
	}
	if err := s.audit.Change(ctx, "provider", p.ID, "provider.created", nil,
		record{View: p.View(), Credentials: fingerprint(in.Credentials)}, map[string]any{"kind": string(p.Kind)}); err != nil {
		return domain.Provider{}, err
	}
	return p, nil
}

// Get returns one provider (without credentials).
func (s *Service) Get(ctx context.Context, tenantID, id string) (domain.Provider, error) {
	st, err := s.repo.Get(ctx, tenantID, id)
	return st.Provider, err
}

// List returns a page of providers.
func (s *Service) List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Provider, int, error) {
	return s.repo.List(ctx, tenantID, limit, offset)
}

// Update changes a provider.
func (s *Service) Update(ctx context.Context, tenantID, id string, in Patch, actor string) (domain.Provider, error) {
	st, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return domain.Provider{}, err
	}
	before := st.Provider
	stored, err := s.open(ctx, st.Sealed)
	if err != nil {
		return domain.Provider{}, err
	}
	p := st.Provider
	kindChanged := in.Kind != nil && *in.Kind != p.Kind
	if in.Name != nil {
		p.Name = *in.Name
	}
	if in.Kind != nil {
		p.Kind = *in.Kind
	}
	if in.Settings != nil {
		p.Settings = *in.Settings
	}
	if in.Priority != nil {
		p.Priority = *in.Priority
	}
	if in.Weight != nil {
		p.Weight = *in.Weight
	}
	if in.DailyLimit != nil {
		p.DailyLimit = *in.DailyLimit
	}
	if in.Active != nil {
		p.Active = *in.Active
	}
	creds := stored
	switch {
	case kindChanged && in.Credentials != nil:
		creds = *in.Credentials
	case kindChanged:
		creds = domain.Credentials{}
	case in.Credentials != nil:
		creds = stored.Merge(*in.Credentials)
	}
	if err := s.validate(&p, creds); err != nil {
		return domain.Provider{}, err
	}
	var sealed *string
	if creds != stored {
		v, err := s.seal(ctx, creds)
		if err != nil {
			return domain.Provider{}, err
		}
		sealed = &v
		p.SetCredentials(creds)
	}
	p.UpdatedBy, p.UpdatedAt = actor, s.now()
	if err := s.repo.Update(ctx, p, sealed); err != nil {
		return domain.Provider{}, err
	}
	if err := s.audit.Change(ctx, "provider", p.ID, "provider.updated",
		record{View: before.View(), Credentials: fingerprint(stored)},
		record{View: p.View(), Credentials: fingerprint(creds)}, nil); err != nil {
		return domain.Provider{}, err
	}
	return p, nil
}

// Delete removes a provider.
func (s *Service) Delete(ctx context.Context, tenantID, id, actor string) error {
	st, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tenantID, id, s.now()); err != nil {
		return err
	}
	return s.audit.Change(ctx, "provider", id, "provider.deleted", record{View: st.Provider.View()}, nil, map[string]any{"by": actor})
}

// Opened is a provider with its opened credentials, for sending only.
type Opened struct {
	Provider    domain.Provider
	Credentials domain.Credentials
}

// Active returns the tenant's active providers under their daily limit
// (UTC day), with opened credentials.
func (s *Service) Active(ctx context.Context, tenantID string) ([]Opened, error) {
	list, err := s.repo.ListActive(ctx, tenantID)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	var limited []string
	for _, st := range list {
		if st.Provider.DailyLimit > 0 {
			limited = append(limited, st.Provider.ID)
		}
	}
	sent := map[string]int{}
	if len(limited) > 0 {
		now := s.now()
		if sent, err = s.repo.SentSince(ctx, limited, time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)); err != nil {
			return nil, err
		}
	}
	out := make([]Opened, 0, len(list))
	for _, st := range list {
		if !st.Provider.UnderDailyLimit(sent[st.Provider.ID]) {
			continue
		}
		c, err := s.open(ctx, st.Sealed)
		if err != nil {
			return nil, err
		}
		out = append(out, Opened{Provider: st.Provider, Credentials: c})
	}
	return out, nil
}

// Kinds lists the kinds of the tenant's active providers (for SPF
// includes).
func (s *Service) Kinds(ctx context.Context, tenantID string) ([]domain.Kind, error) {
	list, err := s.repo.ListActive(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []domain.Kind
	for _, st := range list {
		out = append(out, st.Provider.Kind)
	}
	return out, nil
}

// legacySecretKeys map a legacy configuration key to the credential it is.
var legacySecretKeys = map[string]func(c *domain.Credentials, v string){
	"password":          func(c *domain.Credentials, v string) { c.Password = v },
	"api_key":           func(c *domain.Credentials, v string) { c.APIKey = v },
	"api_secret":        func(c *domain.Credentials, v string) { c.APIKey = v },
	"secret":            func(c *domain.Credentials, v string) { c.SecretAccessKey = v },
	"secret_key":        func(c *domain.Credentials, v string) { c.SecretAccessKey = v },
	"secret_access_key": func(c *domain.Credentials, v string) { c.SecretAccessKey = v },
	"access_key":        func(c *domain.Credentials, v string) { c.AccessKeyID = v },
	"access_key_id":     func(c *domain.Credentials, v string) { c.AccessKeyID = v },
	"server_token":      func(c *domain.Credentials, v string) { c.ServerToken = v },
}

// LegacySecretKeys are the configuration keys the conversion treats as
// secrets (the repository's query uses them).
func LegacySecretKeys() []string {
	out := make([]string, 0, len(legacySecretKeys))
	for k := range legacySecretKeys {
		out = append(out, k)
	}
	return out
}

// SplitLegacy turns a legacy configuration into settings and credentials.
// Postmark's token was stored as api_key.
func SplitLegacy(kind domain.Kind, cfg map[string]any) (domain.Settings, domain.Credentials) {
	var c domain.Credentials
	rest := map[string]any{}
	for k, v := range cfg {
		set, secret := legacySecretKeys[k]
		str, isString := v.(string)
		switch {
		case secret && isString:
			set(&c, str)
		case secret:
		case k == "from_addr":
			rest["from_email"] = v
		default:
			rest[k] = v
		}
	}
	if kind == domain.KindPostmark && c.ServerToken == "" {
		c.ServerToken, c.APIKey = c.APIKey, ""
	}
	var s domain.Settings
	raw, _ := json.Marshal(rest)
	_ = json.Unmarshal(raw, &s)
	return s, c
}

// Bootstrap seals any plaintext credentials still in provider
// configurations and removes them, once, under an advisory lock. It is
// idempotent: converted rows no longer match.
func (s *Service) Bootstrap(ctx context.Context) (int, error) {
	n := 0
	_, err := s.repo.WithLock(ctx, func(ctx context.Context) error {
		rows, err := s.repo.Legacy(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			settings, creds := SplitLegacy(r.Kind, r.Configuration)
			sealed, err := s.seal(ctx, creds)
			if err != nil {
				return err
			}
			if err := s.repo.ReplaceLegacy(ctx, r.ID, settings, sealed, creds.Hints()); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// SplitConfiguration separates the console's single configuration map
// into settings and credentials (the secret keys of domain.Credentials).
func SplitConfiguration(cfg map[string]any) (domain.Settings, domain.Credentials, error) {
	secrets := map[string]any{}
	rest := map[string]any{}
	for k, v := range cfg {
		switch strings.ToLower(k) {
		case "password", "access_key_id", "secret_access_key", "api_key", "server_token":
			secrets[strings.ToLower(k)] = v
		default:
			rest[k] = v
		}
	}
	var s domain.Settings
	var c domain.Credentials
	raw, _ := json.Marshal(rest)
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, c, apperrors.Invalid("configuration", "invalid", "configuration has a value of the wrong type")
	}
	raw, _ = json.Marshal(secrets)
	if err := json.Unmarshal(raw, &c); err != nil {
		return s, c, apperrors.Invalid("configuration", "invalid", "credentials must be strings")
	}
	return s, c, nil
}
