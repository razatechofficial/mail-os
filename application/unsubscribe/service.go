// Package unsubscribe is one-click unsubscribe for broadcast mail (RFC
// 8058, RFC 2369): the signed link each marketing message carries in its
// List-Unsubscribe header and as the {{unsubscribe_url}} variable, and the
// recording of the recipient's choice as an unsubscribe suppression.
//
// The link names the tenant, the recipient, the sending application (for
// its mail) and the campaign; it needs no session or cookie, and a GET
// never unsubscribes (mail scanners follow links): only the RFC 8058 POST
// or the confirmation page's form does.
package unsubscribe

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	domain "github.com/razatechofficial/mail-os/domain/suppression"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
)

// Suppressions records the unsubscribe (application/suppression.Service).
type Suppressions interface {
	Blocks(ctx context.Context, tenantID, applicationID, email string, mt message.Type) (*domain.Suppression, error)
	Add(ctx context.Context, in domain.Suppression) (domain.Suppression, error)
}

// Config are the links' settings.
type Config struct {
	// BaseURL is MailOS's public origin; links are BaseURL/unsubscribe/<token>.
	BaseURL string
	// TTL is how long a link works.
	TTL time.Duration
	// Mailto, when set, is a mailbox also offered in List-Unsubscribe.
	Mailto string
}

// Service issues links and records unsubscribes.
type Service struct {
	signer *Signer
	sup    Suppressions
	cfg    Config
}

// NewService builds the service.
func NewService(signer *Signer, sup Suppressions, cfg Config) (*Service, error) {
	if signer == nil || sup == nil {
		return nil, errors.New("unsubscribe: signer and suppressions are required")
	}
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("unsubscribe: base URL must be an absolute http(s) URL")
	}
	cfg.BaseURL = u.String()
	if cfg.TTL <= 0 {
		cfg.TTL = 180 * 24 * time.Hour
	}
	return &Service{signer: signer, sup: sup, cfg: cfg}, nil
}

// Link is one message's unsubscribe link.
type Link struct {
	TenantID      string
	ApplicationID string
	Email         string
	CampaignID    string
	MessageID     string
}

// URL is the link's https address.
func (s *Service) URL(l Link) (string, error) {
	tok, err := s.signer.Issue(Claims{TenantID: l.TenantID, ApplicationID: l.ApplicationID,
		Email: domain.NormalizeEmail(l.Email), CampaignID: l.CampaignID, MessageID: l.MessageID}, s.cfg.TTL)
	if err != nil {
		return "", err
	}
	return s.cfg.BaseURL + "/unsubscribe/" + tok, nil
}

// Headers are the List-Unsubscribe (RFC 2369) and List-Unsubscribe-Post
// (RFC 8058) headers for the link at u.
func (s *Service) Headers(u string) map[string]string {
	v := "<" + u + ">"
	if s.cfg.Mailto != "" {
		v += ", <mailto:" + s.cfg.Mailto + "?subject=unsubscribe>"
	}
	return map[string]string{"List-Unsubscribe": v, "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}
}

// Verify reads a link's token without acting on it (the confirmation
// page).
func (s *Service) Verify(token string) (Claims, error) { return s.signer.Verify(token) }

// Ways a recipient unsubscribes, for the suppression's reason.
const (
	ViaOneClick = "one-click"
	ViaPage     = "page"
)

// Result is the outcome: Already when the address was suppressed for
// broadcast mail before.
type Result struct {
	Claims  Claims
	Already bool
}

// Unsubscribe verifies token and suppresses its recipient for broadcast
// mail in the link's scope (the application's, or tenant-wide for the
// tenant's own campaigns). It is idempotent: an address already
// suppressed is not written or audited again.
func (s *Service) Unsubscribe(ctx context.Context, token, via string) (Result, error) {
	c, err := s.signer.Verify(token)
	if err != nil {
		return Result{}, err
	}
	ctx = audit.WithTenant(ctx, c.TenantID)
	prior, err := s.sup.Blocks(ctx, c.TenantID, c.ApplicationID, c.Email, message.TypeMarketing)
	if err != nil {
		return Result{}, err
	}
	if prior != nil {
		return Result{Claims: c, Already: true}, nil
	}
	reason := "one-click unsubscribe (RFC 8058)"
	if via == ViaPage {
		reason = "unsubscribed from the unsubscribe page"
	}
	if c.CampaignID != "" {
		reason += "; campaign " + c.CampaignID
	}
	if _, err := s.sup.Add(ctx, domain.Suppression{OrgID: c.TenantID, ApplicationID: c.ApplicationID, Email: c.Email,
		Type: domain.TypeUnsubscribe, Reason: reason, Source: domain.SourceUnsubscribe, CreatedBy: "recipient"}); err != nil {
		return Result{}, err
	}
	return Result{Claims: c}, nil
}
