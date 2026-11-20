package container

import (
	"context"
	"fmt"
	"time"

	grpclib "google.golang.org/grpc"

	v1 "github.com/razatechofficial/mail-os/api/proto/v1"
	"github.com/razatechofficial/mail-os/application/analytics"
	appmessage "github.com/razatechofficial/mail-os/application/message"
	appprovider "github.com/razatechofficial/mail-os/application/provider"
	"github.com/razatechofficial/mail-os/application/providerevents"
	appsendingdomain "github.com/razatechofficial/mail-os/application/sendingdomain"
	appsuppression "github.com/razatechofficial/mail-os/application/suppression"
	appunsubscribe "github.com/razatechofficial/mail-os/application/unsubscribe"
	appwebhook "github.com/razatechofficial/mail-os/application/webhook"
	"github.com/razatechofficial/mail-os/config"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/infrastructure/clamav"
	"github.com/razatechofficial/mail-os/infrastructure/dnscheck"
	"github.com/razatechofficial/mail-os/infrastructure/mailer"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/infrastructure/providerhooks"
	"github.com/razatechofficial/mail-os/infrastructure/render"
	"github.com/razatechofficial/mail-os/infrastructure/webhookclient"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	"github.com/razatechofficial/mail-os/internal/bootstrap"
	"github.com/razatechofficial/mail-os/pkg/logger"
	grpchandler "github.com/razatechofficial/mail-os/transport/grpc/handler"
	"github.com/razatechofficial/mail-os/transport/http/handler"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

// The messaging structures the migrations 20261031110000-110300 add. The
// probes run in buildCore, before buildMessaging, so they register here.
func init() {
	bootstrap.Register("messages v2 columns",
		"SELECT template_version_id, template_data, secret_keys, body_purged_at, actor_type FROM messages LIMIT 0", true,
		"templated sends, masking and the retention purge cannot work")
	bootstrap.Register("sealed provider, DKIM and webhook columns",
		"SELECT p.credentials_sealed, d.dkim_private_key_sealed, d.dkim_selector, w.secret FROM providers p, sending_domains d, webhooks w LIMIT 0",
		true, "provider credentials, DKIM keys and webhook secrets cannot be sealed")
	bootstrap.Register("message attachments (20261121010000)",
		"SELECT message_id, position, content_id, inline, sha256, data FROM message_attachments LIMIT 0", true,
		"messages with attachments cannot be stored or sent")
	bootstrap.Register("message secrets (20261124090000)",
		"SELECT message_id, org_id, sealed, expires_at, created_at FROM message_secrets LIMIT 0", true,
		"authentication mail cannot be stored redacted or retried")
	bootstrap.Register("provider last test (20261104110000)", "SELECT last_test FROM providers LIMIT 0", true,
		"providers cannot be listed or tested")
	bootstrap.Register("applications and their scope (20261031150000-150200)",
		"SELECT a.client_id, m.application_id, m.sandbox, m.stream, e.application_id, w.application_id, s.application_id, k.scope "+
			"FROM applications a, messages m, inbound_events e, webhooks w, suppressions s, idempotency_keys k LIMIT 0",
		true, "service callers cannot be authorised, and Idempotency-Key cannot be honoured")
}

// providerSource serves the router the tenant's providers.
type providerSource struct{ svc *appprovider.Service }

func (p providerSource) ActiveProviders(ctx context.Context, tenantID string) ([]mailer.Configured, error) {
	list, err := p.svc.Active(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]mailer.Configured, len(list))
	for i, o := range list {
		out[i] = mailer.Configured{Provider: o.Provider, Credentials: o.Credentials}
	}
	return out, nil
}

// routerSender adapts the mailer router to the message use case.
type routerSender struct{ r *mailer.Router }

func (s routerSender) Send(ctx context.Context, out domainmsg.Outgoing) (appmessage.SendResult, error) {
	res, err := s.r.Send(ctx, out)
	return appmessage.SendResult{ProviderID: res.ProviderID, ProviderMessageID: res.ProviderMessageID}, err
}

func renderContent(c appmessage.Content, data map[string]any) (appmessage.Content, error) {
	out, err := render.Render(render.Content{Subject: c.Subject, HTML: c.HTML, Text: c.Text}, data, render.Options{})
	return appmessage.Content{Subject: out.Subject, HTML: out.HTML, Text: out.Text}, err
}

// buildUnsubscribe makes the one-click unsubscribe links (RFC 8058).
func buildUnsubscribe(cfg config.Unsubscribe, sup *appsuppression.Service) (*appunsubscribe.Service, error) {
	key, err := cfg.Key()
	if err != nil {
		return nil, err
	}
	signer, err := appunsubscribe.NewSigner(key)
	if err != nil {
		return nil, err
	}
	return appunsubscribe.NewService(signer, sup, appunsubscribe.Config{BaseURL: cfg.BaseURL, TTL: cfg.TokenTTL, Mailto: cfg.Mailto})
}

// buildMessaging runs before buildEvents and buildMarketing: it sets
// EventDispatcher and CampaignSender for them. It wires providers, sending domains, suppressions, webhooks,
// stats and messages: their routes, worker tasks, the gRPC MailService,
// the sealed columns, and the one-time sealing of legacy plaintext
// secrets.
func (c *Container) buildMessaging(ctx context.Context) error {
	cfg := c.Cfg
	plaintext := cfg.App.AllowsPlaintext()

	providerRepo := postgres.NewProviderRepository(c.DB)
	domainRepo := postgres.NewSendingDomainRepository(c.DB)
	webhookRepo := postgres.NewWebhookRepository(c.DB)
	secretRepo := postgres.NewMessageSecretRepository(c.DB)
	c.Keys.Register(providerRepo.SealedColumn(), domainRepo.SealedColumn(), webhookRepo.SealedColumn(), secretRepo.SealedColumn())

	queue := worker.NewMessageQueue(c.Enqueuer, cfg.Worker.MaxRetry, cfg.Worker.SendTimeout)
	providers := appprovider.NewService(providerRepo, c.Keys.Cipher(domainkm.PurposeProvider), c.Audit,
		appprovider.Config{AllowPlaintext: plaintext})
	var resolver appsendingdomain.Resolver = dnscheck.New("", 5*time.Second)
	if c.E2EZone != nil {
		resolver = c.E2EZone
	}
	c.SendingDomains = appsendingdomain.NewService(domainRepo, c.Keys.Cipher(domainkm.PurposeDKIM), resolver,
		providers, c.Audit, appsendingdomain.Config{})
	if err := c.buildApplications(ctx, c.SendingDomains); err != nil {
		return err
	}
	suppressions := appsuppression.NewService(postgres.NewSuppressionRepository(c.DB), c.Audit)
	// Tenant webhooks reach only public addresses, except in local and
	// test, where receivers run on loopback.
	webhooks := appwebhook.NewService(webhookRepo, c.Keys.Cipher(domainkm.PurposeWebhook), queue,
		webhookclient.New(webhookclient.Options{AllowPrivateNetworks: plaintext, AllowLoopback: plaintext}), c.Audit,
		appwebhook.Config{AllowPlaintext: plaintext})
	stats := analytics.NewService(postgres.NewStatsRepository(c.DB))

	for name, convert := range map[string]func(context.Context) (int, error){
		"provider credentials": providers.Bootstrap, "DKIM keys": c.SendingDomains.Bootstrap, "webhook secrets": webhooks.Bootstrap,
	} {
		n, err := convert(ctx)
		if err != nil {
			return fmt.Errorf("sealing legacy %s: %w", name, err)
		}
		if n > 0 {
			logger.Info("sealed legacy plaintext secrets", logger.String("kind", name), logger.Int("count", n))
		}
	}

	sendOpts := mailer.Options{Timeout: cfg.Worker.SendTimeout,
		AllowPlaintext: plaintext, AllowPrivateNetworks: plaintext, AllowLoopback: plaintext}
	router := mailer.NewRouter(providerSource{providers}, c.Platform, sendOpts)
	router.SetFailureRecorder(providers)
	deps := appmessage.Deps{Applications: c.Apps, Repo: postgres.NewMessageRepository(c.DB), Queue: queue, Suppressions: suppressions, Tenants: c.Tenants,
		Render: renderContent, Sender: routerSender{router}, Signer: c.SendingDomains, Webhooks: webhooks, Stats: stats, Audit: c.Audit,
		Events: postgres.NewMessageEventRepository(c.DB), Feedback: suppressions,
		Secrets: secretRepo, SecretCipher: c.Keys.Cipher(domainkm.PurposeMessageSecret)}
	if c.Templates != nil {
		deps.Templates, deps.Versions, deps.Branding = c.Templates, c.Templates, c.Templates
	}
	if av := cfg.ClamAV; av.Enabled {
		deps.Scanner = clamav.New(clamav.Config{Addr: av.Addr(), Timeout: av.Timeout, ChunkBytes: av.ChunkBytes, FailClosed: av.FailClosed})
		logger.Info("attachment virus scan on", logger.String("clamd", av.Addr()), logger.Bool("fail_closed", av.FailClosed))
	}
	if cfg.Unsubscribe.Enabled() {
		unsub, err := buildUnsubscribe(cfg.Unsubscribe, suppressions)
		if err != nil {
			return err
		}
		deps.Unsubscribe = unsub
		c.PublicRoutes = append(c.PublicRoutes, handler.NewUnsubscribeHandler(unsub, c.Redis, cfg.Unsubscribe.RatePerMinute))
	}
	c.Messages = appmessage.NewService(deps, appmessage.Config{MaxAttempts: cfg.Worker.MaxRetry + 1,
		RetentionDays: cfg.Retention.MessageDays, PurgeBatch: cfg.Retention.PurgeBatch, DefaultFrom: cfg.SMTP.FromAddr,
		StaleSending: 3*cfg.Worker.SendTimeout + time.Minute,
		Attachments: domainmsg.AttachmentLimits{MaxBytes: cfg.Attachments.MaxBytes, MaxTotalBytes: cfg.Attachments.MaxTotalBytes,
			MaxCount: cfg.Attachments.MaxCount, AllowedTypes: cfg.Attachments.AllowedTypes, BlockedTypes: cfg.Attachments.BlockedTypes,
			BlockedExtensions: cfg.Attachments.BlockedExtensions}})

	if c.Templates != nil {
		c.Templates.SetTestSend(c.Messages, c.SendingDomains, c.Apps)
	}
	providers.SetTesting(mailer.Tester{Options: sendOpts}, c.Messages)
	// Events (buildEvents) and campaigns (buildMarketing) send through the
	// message use case; both builders run after this one.
	c.EventDispatcher = c.Messages
	c.CampaignSender = c.Messages

	// The sending APIs post delivery events to a public route, each
	// authenticated by the provider's webhook secret; SNS certificates and
	// subscription confirmations are fetched over HTTPS from SNS only.
	sns := &providerhooks.HTTPSFetcher{}
	c.PublicRoutes = append(c.PublicRoutes, handler.NewProviderEventHandler(providerevents.NewService(providers,
		&providerhooks.Verifier{Certs: sns}, sns, c.Messages, c.Audit)))

	idempotent := postgres.NewIdempotencyRepository(c.DB)
	c.Routes = append(c.Routes,
		handler.NewMessageHandler(c.Messages, c.Apps, middleware.Idempotency(idempotent, cfg.Idempotency.TTL)),
		handler.NewProviderHandler(providers),
		handler.NewSendingDomainHandler(c.SendingDomains),
		handler.NewSuppressionHandler(suppressions, c.Apps),
		handler.NewWebhookHandler(webhooks, c.Apps),
		handler.NewAnalyticsHandler(stats),
	)
	c.GRPCServices = append(c.GRPCServices, func(s *grpclib.Server) {
		ms := &grpchandler.MailService{Messages: c.Messages, Tenants: c.Tenants}
		if c.GRPCEvents != nil { // set by buildEvents, which runs later
			ms.Events = c.GRPCEvents
		}
		v1.RegisterMailServiceServer(s, ms)
	})
	c.Tasks = append(c.Tasks, func(s *worker.Server) error {
		s.HandleFunc(worker.TypeMessageSend, worker.MessageSend(c.Messages))
		s.HandleFunc(worker.TypeWebhookDeliver, worker.WebhookDeliver(webhooks))
		s.HandleFunc(worker.TypeMessageRelease, worker.MessageRelease(c.Messages))
		s.HandleFunc(worker.TypeMessageRetention, worker.MessageRetention(c.Messages))
		s.HandleFunc(worker.TypeIdempotencyPurge, worker.IdempotencyPurge(idempotent))
		if err := s.Every("@every 1h", worker.TypeIdempotencyPurge, 50*time.Minute); err != nil {
			return err
		}
		release := max(cfg.Worker.SchedulerInterval, 5*time.Second)
		if err := s.Every("@every "+release.String(), worker.TypeMessageRelease, release-time.Second); err != nil {
			return err
		}
		purge := max(cfg.Retention.PurgeInterval, time.Minute)
		return s.Every("@every "+purge.String(), worker.TypeMessageRetention, purge-time.Second)
	})
	return nil
}
