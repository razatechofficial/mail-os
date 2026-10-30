package config

import (
	"fmt"
	"strings"
)

// E2EHooks are the black-box test hooks (server/e2e): mail is captured by an
// in-memory provider instead of being sent, and served under /e2e/v1 to
// callers holding Token. Off by default and refused outside the test
// environments: anyone holding the token could read every message,
// one-time codes included.
type E2EHooks struct {
	Enabled bool `yaml:"enabled" env:"MAILOS_E2E_HOOKS" env-default:"false"`
	// Token is the bearer token the hook routes require (at least 32 characters).
	Token string `yaml:"token" env:"MAILOS_E2E_HOOKS_TOKEN" env-default:""`
}

// e2eHookEnvironments are the only APP_ENV values the hooks may run in.
var e2eHookEnvironments = map[string]bool{"e2e": true, "test": true, "local": true, "development": true}

// minE2EHookTokenLen keeps the hook token out of guessing range.
const minE2EHookTokenLen = 32

// validate refuses the hooks in production, staging and any environment not
// named for tests or development, and without a strong token.
func (h E2EHooks) validate(env string) error {
	if !h.Enabled {
		return nil
	}
	if !e2eHookEnvironments[strings.ToLower(strings.TrimSpace(env))] {
		return fmt.Errorf("MAILOS_E2E_HOOKS is a test-only hook and is refused in APP_ENV %q", env)
	}
	if len(strings.TrimSpace(h.Token)) < minE2EHookTokenLen {
		return fmt.Errorf("MAILOS_E2E_HOOKS_TOKEN must be at least %d characters", minE2EHookTokenLen)
	}
	return nil
}
