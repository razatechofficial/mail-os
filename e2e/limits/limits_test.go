//go:build e2e

// Package limits starts its own server process from the run's binary
// (MAILOS_E2E_SERVER_BIN, MAILOS_E2E_SERVER_ENV) with the rate limits on,
// which the shared server turns off.
package limits

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "limits", &fx) }

// port is the e2e port this package's own server listens on.
const port = "19885"

// serverEnv is the run's server.env with overrides applied.
func serverEnv(t *testing.T, overrides map[string]string) []string {
	t.Helper()
	path, bin := os.Getenv("MAILOS_E2E_SERVER_ENV"), os.Getenv("MAILOS_E2E_SERVER_BIN")
	if path == "" || bin == "" {
		t.Fatal("MAILOS_E2E_SERVER_ENV and MAILOS_E2E_SERVER_BIN must be set (e2e/run.sh test sets them)")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	env := map[string]string{"PATH": os.Getenv("PATH"), "HOME": os.Getenv("HOME")}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		env[k] = strings.Trim(v, `'"`)
	}
	for k, v := range overrides {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func start(t *testing.T, overrides map[string]string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, os.Getenv("MAILOS_E2E_SERVER_BIN"))
	cmd.Env = serverEnv(t, overrides)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	return cmd
}

func TestRateLimits(t *testing.T) {
	start(t, map[string]string{"HTTP_PORT": port, "GRPC_PORT": "0", "METRICS_ENABLED": "false", "RATE_LIMIT_ENABLED": "true",
		"RATE_LIMIT_PER_TENANT": "3", "RATE_LIMIT_BURST": "1", "RATE_LIMIT_PREVIEW_PER_MINUTE": "2", "RATE_LIMIT_TEST_SEND_PER_HOUR": "1"})
	base := "http://127.0.0.1:" + port
	harness.Eventually(t, "the rate-limited server", 150*time.Second, func() bool {
		r, err := http.Get(base + "/ready")
		if err == nil {
			r.Body.Close()
		}
		return err == nil && r.StatusCode == http.StatusOK
	})
	tok, _ := fx.Env.UserToken(t, harness.User{Tenant: fx.TenantID, Roles: []string{harness.RoleAdmin}})
	c := fx.Env.NewClient().WithBearer(tok)
	c.Base = base

	var limited *harness.Response
	for i := 0; i < 20 && limited == nil; i++ {
		if r := c.Do(t, http.MethodGet, "/api/v1/templates", nil); r.Status == http.StatusTooManyRequests {
			limited = r
		}
	}
	if limited == nil {
		t.Fatal("20 calls in a burst were never limited")
	}
	if limited.ErrorCode() != "RATE_LIMITED" || limited.Header.Get("Retry-After") == "" {
		t.Fatalf("429 = %s (Retry-After %q)", limited, limited.Header.Get("Retry-After"))
	}

	// Another tenant has its own budget.
	otherTok, _ := fx.Env.UserToken(t, harness.User{Tenant: harness.NewID(), Roles: []string{harness.RoleAdmin}})
	other := fx.Env.NewClient().WithBearer(otherTok)
	other.Base = base
	other.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/templates", nil)
}
