// Package sendingdomain is the sending domain use case: a tenant's domains
// with their DKIM keys sealed by the key manager (contract §6), DNS
// verification through a resolver, and the signing key the send path
// uses for a verified sender.
package sendingdomain

import (
	"context"
	"strings"
	"time"

	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	"github.com/razatechofficial/mail-os/domain/provider"
	domain "github.com/razatechofficial/mail-os/domain/sendingdomain"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// Stored is a domain with its sealed DKIM key.
type Stored struct {
	Domain domain.Domain
	Sealed string
}

// LegacyRow is a domain whose DKIM key is still in the plaintext column.
type LegacyRow struct {
	ID            string
	PrivateKeyPEM string
}

// Repository stores sending domains.
type Repository interface {
	// Create fails with apperrors.Conflict when the tenant has the domain.
	Create(ctx context.Context, s Stored) error
	// Update saves d; sealed nil keeps the stored key.
	Update(ctx context.Context, d domain.Domain, sealed *string) error
	Delete(ctx context.Context, tenantID, id string, at time.Time) error
	Get(ctx context.Context, tenantID, id string) (Stored, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Domain, int, error)
	// Verified lists the tenant's verified domains with their keys.
	Verified(ctx context.Context, tenantID string) ([]Stored, error)
	Legacy(ctx context.Context) ([]LegacyRow, error)
	// ReplaceLegacy stores the sealed key and empties the plaintext column.
	ReplaceLegacy(ctx context.Context, id, sealed string) error
	WithLock(ctx context.Context, fn func(ctx context.Context) error) (bool, error)
}

// Resolver reads TXT records. A name that does not exist returns no
// records and no error.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// ProviderKinds lists a tenant's active provider kinds, for the SPF
// includes a new domain publishes.
type ProviderKinds interface {
	Kinds(ctx context.Context, tenantID string) ([]provider.Kind, error)
}

// Auditor records changes.
type Auditor interface {
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// Config sets the records new domains publish.
type Config struct {
	// SPFIncludes are always included (the platform relay's servers).
	SPFIncludes []string
	// DMARCPolicy is the policy of new domains (none by default).
	DMARCPolicy string
}

// Service is the sending domain use case.
type Service struct {
	repo     Repository
	cipher   appkm.Cipher
	resolver Resolver
	kinds    ProviderKinds
	audit    Auditor
	cfg      Config
	now      func() time.Time
}

// NewService builds the service. cipher is the key manager's dkim purpose;
// kinds may be nil.
func NewService(repo Repository, cipher appkm.Cipher, resolver Resolver, kinds ProviderKinds, audit Auditor, cfg Config) *Service {
	return &Service{repo: repo, cipher: cipher, resolver: resolver, kinds: kinds, audit: audit, cfg: cfg,
		now: func() time.Time { return time.Now().UTC() }}
}

// Input is a new domain.
type Input struct {
	Name          string
	Selector      string
	DMARCReportTo string
}

// view is what the audit log sees (never the key).
type view struct {
	Name      string        `json:"name"`
	Selector  string        `json:"dkim_selector"`
	Status    domain.Status `json:"status"`
	PublicKey string        `json:"dkim_public_key"`
}

func viewOf(d domain.Domain) view {
	return view{Name: d.Name, Selector: d.DKIMSelector, Status: d.Status, PublicKey: d.DKIMPublicKey}
}

// Create adds a domain with a new DKIM key.
func (s *Service) Create(ctx context.Context, tenantID string, in Input, actor string) (domain.Domain, error) {
	opts := domain.Options{Selector: in.Selector, DMARCPolicy: s.cfg.DMARCPolicy, DMARCReportTo: strings.TrimSpace(in.DMARCReportTo),
		SPFIncludes: append([]string{}, s.cfg.SPFIncludes...)}
	if s.kinds != nil {
		kinds, err := s.kinds.Kinds(ctx, tenantID)
		if err != nil {
			return domain.Domain{}, err
		}
		for _, k := range kinds {
			if inc := k.SPFInclude(); inc != "" {
				opts.SPFIncludes = append(opts.SPFIncludes, inc)
			}
		}
	}
	d, secrets, err := domain.New(tenantID, in.Name, opts, s.now())
	if err != nil {
		return domain.Domain{}, err
	}
	d.ID, d.CreatedBy = id.New(), actor
	sealed, err := s.cipher.Seal(ctx, []byte(secrets.DKIMPrivateKeyPEM))
	if err != nil {
		return domain.Domain{}, err
	}
	if err := s.repo.Create(ctx, Stored{Domain: *d, Sealed: sealed}); err != nil {
		return domain.Domain{}, err
	}
	if err := s.audit.Change(ctx, "sending_domain", d.ID, "sending_domain.created", nil, viewOf(*d), nil); err != nil {
		return domain.Domain{}, err
	}
	return *d, nil
}

// Get returns one domain.
func (s *Service) Get(ctx context.Context, tenantID, id string) (domain.Domain, error) {
	st, err := s.repo.Get(ctx, tenantID, id)
	return st.Domain, err
}

// List returns a page of domains.
func (s *Service) List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Domain, int, error) {
	return s.repo.List(ctx, tenantID, limit, offset)
}

// Verify looks up the domain's records and records the outcome. A lookup
// that fails (SERVFAIL, timeout) is 503: the records were not checked.
func (s *Service) Verify(ctx context.Context, tenantID, id string) (domain.Domain, error) {
	st, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return domain.Domain{}, err
	}
	d := st.Domain
	before := viewOf(d)
	var txt [3][]string
	for i, name := range []string{d.DKIMRecordName(), d.Name, d.DMARCRecordName()} {
		if txt[i], err = s.resolver.LookupTXT(ctx, name); err != nil {
			return domain.Domain{}, apperrors.Unavailable("the DNS lookup failed; try again shortly")
		}
	}
	check := d.Evaluate(txt[0], txt[1], txt[2])
	d.ApplyCheck(check, s.now())
	if err := s.repo.Update(ctx, d, nil); err != nil {
		return domain.Domain{}, err
	}
	if err := s.audit.Change(ctx, "sending_domain", d.ID, "sending_domain.verified", before, viewOf(d),
		map[string]any{"dkim": check.DKIM, "spf": check.SPF, "dmarc": check.DMARC}); err != nil {
		return domain.Domain{}, err
	}
	return d, nil
}

// Delete removes a domain.
func (s *Service) Delete(ctx context.Context, tenantID, id, actor string) error {
	st, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tenantID, id, s.now()); err != nil {
		return err
	}
	return s.audit.Change(ctx, "sending_domain", id, "sending_domain.deleted", viewOf(st.Domain), nil, map[string]any{"by": actor})
}

// aligned finds the verified domain fromEmail is sent from: the domain or
// a parent of it (DMARC relaxed alignment), the most specific first.
func (s *Service) aligned(ctx context.Context, tenantID, fromEmail string) (Stored, bool, error) {
	from := domain.FromDomain(fromEmail)
	if from == "" {
		return Stored{}, false, nil
	}
	list, err := s.repo.Verified(ctx, tenantID)
	if err != nil {
		return Stored{}, false, err
	}
	var best Stored
	found := false
	for _, st := range list {
		n := st.Domain.Name
		if (from == n || strings.HasSuffix(from, "."+n)) && (!found || len(n) > len(best.Domain.Name)) {
			best, found = st, true
		}
	}
	return best, found, nil
}

// VerifiedFrom reports whether fromEmail is on one of the tenant's
// verified domains.
func (s *Service) VerifiedFrom(ctx context.Context, tenantID, fromEmail string) (bool, error) {
	_, ok, err := s.aligned(ctx, tenantID, fromEmail)
	return ok, err
}

// SigningKey returns the DKIM key for mail from fromEmail, or nil when the
// sender is on no verified domain.
func (s *Service) SigningKey(ctx context.Context, tenantID, fromEmail string) (*domain.SigningKey, error) {
	st, ok, err := s.aligned(ctx, tenantID, fromEmail)
	if err != nil || !ok || st.Sealed == "" {
		return nil, err
	}
	pemKey, err := s.cipher.Open(ctx, st.Sealed)
	if err != nil {
		return nil, err
	}
	k, ok := st.Domain.SigningKey(domain.Secrets{DKIMPrivateKeyPEM: string(pemKey)})
	if !ok {
		return nil, nil
	}
	return &k, nil
}

// Bootstrap seals DKIM keys still in the plaintext column and empties it,
// once, under an advisory lock.
func (s *Service) Bootstrap(ctx context.Context) (int, error) {
	n := 0
	_, err := s.repo.WithLock(ctx, func(ctx context.Context) error {
		rows, err := s.repo.Legacy(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			sealed, err := s.cipher.Seal(ctx, []byte(r.PrivateKeyPEM))
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
