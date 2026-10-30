package access

import (
	"errors"
	"strings"
)

// ServiceGrant is one allow-listed service client (contract §4).
type ServiceGrant struct {
	ClientID string
	// TopicPatterns are exact topics or prefixes written "iam.*".
	TopicPatterns []string
	// Tenant is the tenant the client acts for when its token carries none.
	Tenant string
}

// Allows reports whether topic matches one of the grant's patterns. "iam.*"
// matches "iam.auth.login" but not "iam" or "iamx.login".
func (g ServiceGrant) Allows(topic string) bool {
	for _, p := range g.TopicPatterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(topic, prefix) && len(topic) > len(prefix) {
				return true
			}
			continue
		}
		if topic == p {
			return true
		}
	}
	return false
}

// Service-caller refusals. Each is audited by the caller with its reason.
var (
	ErrUnknownClient    = errors.New("the service client is not allow-listed")
	ErrTopicNotAllowed  = errors.New("the service client may not publish this topic")
	ErrTenantMismatch   = errors.New("the event names a tenant the service may not act for")
	ErrNoTenant         = errors.New("the service token carries no tenant and none is configured for the client")
	ErrNotServiceCaller = errors.New("only service clients publish events")
)

// ServiceGrants is the allow-list by client_id.
type ServiceGrants map[string]ServiceGrant

// NewServiceGrants indexes grants by client.
func NewServiceGrants(grants []ServiceGrant) ServiceGrants {
	out := make(ServiceGrants, len(grants))
	for _, g := range grants {
		out[g.ClientID] = g
	}
	return out
}

// Authorize decides whether p may publish topic for the tenant the event
// names (requested, possibly empty), and returns the tenant it acts for:
//
//   - an unknown client, or a topic outside its patterns, is refused;
//   - the tenant is the token's tid, else the client's configured tenant;
//     when both exist they must agree;
//   - an event naming another tenant is refused (tenant scoping).
func (g ServiceGrants) Authorize(p Principal, topic, requested string) (string, error) {
	if !p.IsService() {
		return "", ErrNotServiceCaller
	}
	grant, ok := g[p.ClientID]
	if !ok {
		return "", ErrUnknownClient
	}
	if !grant.Allows(topic) {
		return "", ErrTopicNotAllowed
	}
	tenant := p.TenantID
	if grant.Tenant != "" {
		if tenant != "" && !strings.EqualFold(tenant, grant.Tenant) {
			return "", ErrTenantMismatch
		}
		tenant = grant.Tenant
	}
	if tenant == "" {
		return "", ErrNoTenant
	}
	if requested != "" && !strings.EqualFold(requested, tenant) {
		return "", ErrTenantMismatch
	}
	return strings.ToLower(tenant), nil
}

// Reason is the short machine-readable reason audited for a refusal.
func Reason(err error) string {
	switch {
	case errors.Is(err, ErrUnknownClient):
		return "unknown_client"
	case errors.Is(err, ErrTopicNotAllowed):
		return "topic_not_allowed"
	case errors.Is(err, ErrTenantMismatch):
		return "tenant_mismatch"
	case errors.Is(err, ErrNoTenant):
		return "no_tenant"
	case errors.Is(err, ErrNotServiceCaller):
		return "not_service_caller"
	default:
		return "refused"
	}
}
