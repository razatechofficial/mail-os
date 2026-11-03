// Command bootstrap prepares the tenant IAM sends from (IAM_SERVICE_TENANT_ID)
// so a new deployment mails invitations, verification links, email codes
// and password resets before any console user exists. Run it once the
// migrations ran and the worker is up; run it again at any time:
//
//   - template branding: MAILOS_BRAND_NAME as the company name, while the
//     tenant has the default branding;
//   - a published default template for every IAM topic that has none;
//   - the sending domain MAILOS_SENDING_DOMAIN with a new DKIM key, or a DNS
//     check of the existing one, and the DKIM, SPF and DMARC records to
//     publish (MAILOS_DKIM_SELECTOR, MAILOS_SPF_INCLUDES,
//     MAILOS_DMARC_POLICY, MAILOS_DMARC_REPORT_TO);
//   - a test message to MAILOS_TEST_RECIPIENT through the tenant's provider
//     or the platform relay (SMTP_*), waiting MAILOS_TEST_TIMEOUT for the
//     worker's outcome.
//
// It uses the server's configuration (the same environment as
// mailos-server) and changes nothing an administrator set. It exits 1 when
// a template could not be published or the test message was not sent.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	appsendingdomain "github.com/razatechofficial/mail-os/application/sendingdomain"
	"github.com/razatechofficial/mail-os/config"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/dnscheck"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/internal/container"
	"github.com/razatechofficial/mail-os/internal/provision"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Version and Commit are set by the build (-ldflags -X).
var (
	Version = "dev"
	Commit  = ""
)

func env(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func list(name string) []string {
	var out []string
	for _, v := range strings.Split(env(name), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func main() {
	_ = logger.InitSimple("warn", "json")
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mailos-bootstrap:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	tenant := env("MAILOS_BOOTSTRAP_TENANT")
	if tenant == "" {
		tenant = cfg.IAM.ServiceTenantID
	}
	if _, err := uuid.Parse(tenant); err != nil {
		return fmt.Errorf("the tenant to prepare must be a UUID (IAM_SERVICE_TENANT_ID or MAILOS_BOOTSTRAP_TENANT), got %q", tenant)
	}
	timeout := 90 * time.Second
	if v := env("MAILOS_TEST_TIMEOUT"); v != "" {
		if timeout, err = time.ParseDuration(v); err != nil || timeout < time.Second {
			return fmt.Errorf("MAILOS_TEST_TIMEOUT must be a duration such as 90s")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Minute)
	defer cancel()
	c, err := container.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx = audit.WithTenant(ctx, tenant)
	if err := c.Tenants.Ensure(ctx, tenant); err != nil {
		return fmt.Errorf("tenant %s: %w", tenant, err)
	}
	out := os.Stdout
	fmt.Fprintf(out, "MailOS %s bootstrap of tenant %s\n", Version, tenant)

	if err := provision.EnsureBranding(ctx, c.Templates, tenant, env("MAILOS_BRAND_NAME"), out); err != nil {
		return err
	}
	fmt.Fprintln(out, "templates:")
	rep, err := provision.SeedTemplates(ctx, c.Templates, tenant, out)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "templates: %d published, %d kept, %d left for the console\n", rep.Published, rep.Kept, rep.Failed)

	domains := appsendingdomain.NewService(postgres.NewSendingDomainRepository(c.DB), c.Keys.Cipher(domainkm.PurposeDKIM),
		dnscheck.New("", 5*time.Second), nil, c.Audit,
		appsendingdomain.Config{SPFIncludes: list("MAILOS_SPF_INCLUDES"), DMARCPolicy: env("MAILOS_DMARC_POLICY")})
	if _, err := provision.EnsureDomain(ctx, domains, tenant, provision.DomainSpec{Name: env("MAILOS_SENDING_DOMAIN"),
		Selector: env("MAILOS_DKIM_SELECTOR"), DMARCReportTo: env("MAILOS_DMARC_REPORT_TO"), FromEmail: cfg.SMTP.FromAddr}, out); err != nil {
		return err
	}

	sendErr := provision.TestSend(ctx, c.Messages, tenant, env("MAILOS_TEST_RECIPIENT"), cfg.SMTP.FromAddr, timeout, out)
	switch {
	case sendErr != nil:
		return sendErr
	case rep.Failed > 0:
		return fmt.Errorf("%d template(s) were not published", rep.Failed)
	}
	fmt.Fprintln(out, "bootstrap complete")
	return nil
}
