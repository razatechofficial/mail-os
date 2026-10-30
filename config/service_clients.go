package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// ServiceClient is one entry of the contract §4 allow-list: an IAM OAuth
// client allowed to publish events whose topics match TopicPatterns, for
// Tenant when its token carries none.
type ServiceClient struct {
	ClientID      string
	TopicPatterns []string // "iam.*" (a prefix) or an exact topic
	Tenant        string   // optional tenant UUID
}

var topicPattern = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?$`)

// ParseServiceClients reads MAILOS_SERVICE_CLIENTS:
//
//	client_id=pattern|pattern[@tenant_uuid];client_id=...
//
// for example "mailos-iam=iam.*;core-banking=bank.otp.*@6f1c…". A client
// listed twice, an empty pattern list or a malformed tenant is refused, so
// a typo cannot widen or silently drop a grant.
func ParseServiceClients(raw string) ([]ServiceClient, error) {
	var out []ServiceClient
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, rest, ok := strings.Cut(entry, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			return nil, fmt.Errorf("entry %q must be client_id=pattern|pattern[@tenant]", entry)
		}
		if seen[id] {
			return nil, fmt.Errorf("client %q is listed twice", id)
		}
		seen[id] = true
		patterns, tenant, _ := strings.Cut(rest, "@")
		sc := ServiceClient{ClientID: id, Tenant: strings.TrimSpace(tenant)}
		if sc.Tenant != "" {
			if _, err := uuid.Parse(sc.Tenant); err != nil {
				return nil, fmt.Errorf("client %q: tenant %q is not a UUID", id, sc.Tenant)
			}
		}
		for _, p := range strings.Split(patterns, "|") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if p == "*" || !topicPattern.MatchString(p) {
				return nil, fmt.Errorf("client %q: topic pattern %q must be a topic or a prefix ending in .*", id, p)
			}
			sc.TopicPatterns = append(sc.TopicPatterns, p)
		}
		if len(sc.TopicPatterns) == 0 {
			return nil, fmt.Errorf("client %q has no topic patterns", id)
		}
		out = append(out, sc)
	}
	return out, nil
}
