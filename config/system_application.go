package config

import (
	"fmt"
	"strings"

	"github.com/google/uuid"

	domainapp "github.com/razatechofficial/mail-os/domain/application"
)

// validateSystemApplication checks IAM's own client, which MailOS seeds as
// its system application at startup (IAM_SERVICE_CLIENT_ID): required
// outside local, test and e2e, with the tenant it acts for and topic
// patterns that are topics or prefixes (never "*").
func (i IAM) validateSystemApplication(plaintext bool) error {
	id, tenant := strings.TrimSpace(i.ServiceClientID), strings.TrimSpace(i.ServiceTenantID)
	if id == "" && tenant == "" {
		if !plaintext {
			return fmt.Errorf("IAM_SERVICE_CLIENT_ID and IAM_SERVICE_TENANT_ID are required outside local and test (IAM's own client, contract §1)")
		}
		return nil
	}
	if id == "" || tenant == "" {
		return fmt.Errorf("IAM_SERVICE_CLIENT_ID and IAM_SERVICE_TENANT_ID are set together")
	}
	if _, err := uuid.Parse(tenant); err != nil {
		return fmt.Errorf("IAM_SERVICE_TENANT_ID %q is not a UUID", tenant)
	}
	if len(i.ServiceTopics) == 0 {
		return fmt.Errorf("IAM_SERVICE_TOPICS needs at least one topic pattern")
	}
	for _, p := range i.ServiceTopics {
		p = strings.TrimSpace(p)
		if p == domainapp.RawType || !domainapp.ValidPattern(p) {
			return fmt.Errorf("IAM_SERVICE_TOPICS: topic pattern %q must be a topic or a prefix ending in .*", p)
		}
	}
	return nil
}
