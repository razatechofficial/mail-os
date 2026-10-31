//go:build e2e

// Package harness drives the MailOS binaries from outside, as the e2e
// suite's only way in (the same pattern as IAM's e2e harness). e2e/run.sh
// starts the server and worker against the test stack and a fake IAM
// (e2e/cmd/fakeiam); tests mint tokens through the fake IAM, call the API
// over HTTP, and read the mail the server would have sent through the
// test-only hooks (MAILOS_E2E_HOOKS). Each test package gets its own tenant
// from Main.
package harness

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Env is where the processes run and how to reach the test-only routes.
type Env struct {
	// BaseURL is the MailOS server's HTTP origin.
	BaseURL string
	// GRPCAddr is the MailOS server's gRPC host:port (plaintext in e2e).
	GRPCAddr string
	// HookToken authorizes the server's /e2e/v1 hook routes.
	HookToken string
	// IAMURL is the fake IAM's origin: the issuer MailOS trusts.
	IAMURL string
	// IAMMintToken authorizes the fake IAM's /test mint routes.
	IAMMintToken string
}

// LoadEnv reads MAILOS_E2E_BASE_URL, MAILOS_E2E_GRPC_ADDR,
// MAILOS_E2E_HOOK_TOKEN, MAILOS_E2E_IAM_URL and MAILOS_E2E_IAM_TOKEN
// (e2e/run.sh env prints them). A missing value is an error, never a skip:
// the gate fails rather than passing with nothing run.
func LoadEnv() (*Env, error) {
	e := &Env{
		BaseURL:      strings.TrimRight(os.Getenv("MAILOS_E2E_BASE_URL"), "/"),
		GRPCAddr:     os.Getenv("MAILOS_E2E_GRPC_ADDR"),
		HookToken:    os.Getenv("MAILOS_E2E_HOOK_TOKEN"),
		IAMURL:       strings.TrimRight(os.Getenv("MAILOS_E2E_IAM_URL"), "/"),
		IAMMintToken: os.Getenv("MAILOS_E2E_IAM_TOKEN"),
	}
	var missing []string
	for name, v := range map[string]string{
		"MAILOS_E2E_BASE_URL": e.BaseURL, "MAILOS_E2E_GRPC_ADDR": e.GRPCAddr, "MAILOS_E2E_HOOK_TOKEN": e.HookToken,
		"MAILOS_E2E_IAM_URL": e.IAMURL, "MAILOS_E2E_IAM_TOKEN": e.IAMMintToken,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s must be set: start the stack with e2e/run.sh up (or run e2e/run.sh test)", strings.Join(missing, ", "))
	}
	return e, nil
}
