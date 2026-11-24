package config

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Platform is the platform plane's sign-in rule (ADR 0001 D2, contract
// C2). Every /api/platform/v1 request's token must name one of ClientIDs
// as azp, carry the IAM's phishing-resistant acr (a fixed floor, not a
// setting) and an auth_time no older than MaxAge. It applies whenever the
// platform API is on, that is whenever ACS_ENDPOINT is set.
type Platform struct {
	// ClientIDs are the platform console's OAuth clients at the IAM (its
	// platform_web client UUIDs): only a token issued to one of them is
	// accepted. Required with ACS_ENDPOINT.
	ClientIDs []string `yaml:"client_ids" env:"PLATFORM_CLIENT_IDS" env-separator:","`
	// MaxAge is how old the sign-in behind a platform token may be: the
	// platform session's 8 hours by default, at most that.
	MaxAge time.Duration `yaml:"auth_max_age" env:"PLATFORM_AUTH_MAX_AGE" env-default:"8h"`
}

// maxPlatformAuthAge is the platform session's total length (ADR 0001
// §3.4); a longer PLATFORM_AUTH_MAX_AGE would outlive it.
const maxPlatformAuthAge = 8 * time.Hour

// AllowedClients are ClientIDs without blanks.
func (p Platform) AllowedClients() []string {
	var out []string
	for _, id := range p.ClientIDs {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}

func (p Platform) validate(acs ACS, consoleAudiences []string) error {
	if p.MaxAge < time.Minute || p.MaxAge > maxPlatformAuthAge {
		return fmt.Errorf("PLATFORM_AUTH_MAX_AGE must be between 1m and 8h (the platform session)")
	}
	if !acs.Enabled() {
		return nil
	}
	clients := p.AllowedClients()
	if len(clients) == 0 {
		return fmt.Errorf("PLATFORM_CLIENT_IDS (the platform console's OAuth client) is required when ACS_ENDPOINT is set")
	}
	for _, id := range clients {
		if slices.ContainsFunc(consoleAudiences, func(a string) bool { return strings.EqualFold(strings.TrimSpace(a), id) }) {
			return fmt.Errorf("PLATFORM_CLIENT_IDS names %q, which IAM_CONSOLE_AUDIENCES names as a workspace console client", id)
		}
	}
	return nil
}
