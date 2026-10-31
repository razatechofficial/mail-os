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
	appsendingdomain "github.com/razatechofficial/mail-os/application/sendingdomain"
	appsuppression "github.com/razatechofficial/mail-os/application/suppression"
	appwebhook "github.com/razatechofficial/mail-os/application/webhook"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/infrastructure/dnscheck"
	"github.com/razatechofficial/mail-os/infrastructure/mailer"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/infrastructure/render"
	"github.com/razatechofficial/mail-os/infrastructure/webhookclient"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	"github.com/razatechofficial/mail-os/pkg/logger"
	grpchandler "github.com/razatechofficial/mail-os/transport/grpc/handler"
	"github.com/razatechofficial/mail-os/transport/http/handler"
)

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

// buildMessaging wires providers, sending domains, suppressions, webhooks,
// stats and messages: their routes, worker tasks, the gRPC MailService,
// the sealed columns, and the one-time sealing of legacy plaintext
// secrets.
func (c *Container) buildMessaging(ctx context.Context) error {
	cfg := c.Cfg
	plaintext := cfg.App.AllowsPlaintext()

	providerRepo := postgres.NewProviderRepository(c.DB)
	domainRepo := postgres.NewSendingDomainRepository(c.DB)
	webhookRepo := postgres.NewWebhookRepository(c.DB)
	c.Keys.Register(providerRepo.SealedColumn(), domainRepo.SealedColumn(), webhookRepo.SealedColumn())

	queue := worker.NewMessageQueue(c.Enqueuer, cfg.Worker.MaxRetry, cfg.Worker.SendTimeout)
	providers := appprovider.NewService(providerRepo, c.Keys.Cipher(domainkm.PurposeProvider), c.Audit,
		appprovider.Config{AllowPlaintext: plaintext})
	c.SendingDomains = appsendingdomain.NewService(domainRepo, c.Keys.Cipher(domainkm.PurposeDKIM), dnscheck.New("", 5*time.Second),
		providers, c.Audit, appsendingdomain.Config{})
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

	router := mailer.NewRouter(providerSource{providers}, c.Platform, mailer.Options{Timeout: cfg.Worker.SendTimeout,
		AllowPlaintext: plaintext, AllowPrivateNetworks: plaintext, AllowLoopback: plaintext})
	deps := appmessage.Deps{Repo: postgres.NewMessageRepository(c.DB), Queue: queue, Suppressions: suppressions, Tenants: c.Tenants,
		Render: renderContent, Sender: routerSender{router}, Signer: c.SendingDomains, Webhooks: webhooks, Stats: stats, Audit: c.Audit}
	if c.Templates != nil {
		deps.Templates = c.Templates
	}
	if c.TemplateVersions != nil {
		deps.Versions = c.TemplateVersions
	}
	if c.Branding != nil {
		deps.Branding = c.Branding
	}
	c.Messages = appmessage.NewService(deps, appmessage.Config{MaxAttempts: cfg.Worker.MaxRetry + 1,
		RetentionDays: cfg.Retention.MessageDays, PurgeBatch: cfg.Retention.PurgeBatch, DefaultFrom: cfg.SMTP.FromAddr,
		StaleSending: 3*cfg.Worker.SendTimeout + time.Minute})

	c.Routes = append(c.Routes,
		handler.NewMessageHandler(c.Messages),
		handler.NewProviderHandler(providers),
		handler.NewSendingDomainHandler(c.SendingDomains),
		handler.NewSuppressionHandler(suppressions),
		handler.NewWebhookHandler(webhooks),
		handler.NewAnalyticsHandler(stats),
	)
	c.GRPCServices = append(c.GRPCServices, func(s *grpclib.Server) {
		v1.RegisterMailServiceServer(s, &grpchandler.MailService{Messages: c.Messages, Tenants: c.Tenants, Events: c.MailEvents})
	})
	c.Tasks = append(c.Tasks, func(s *worker.Server) error {
		s.HandleFunc(worker.TypeMessageSend, worker.MessageSend(c.Messages))
		s.HandleFunc(worker.TypeWebhookDeliver, worker.WebhookDeliver(webhooks))
		s.HandleFunc(worker.TypeMessageRelease, worker.MessageRelease(c.Messages))
		s.HandleFunc(worker.TypeMessageRetention, worker.MessageRetention(c.Messages))
		release := max(cfg.Worker.SchedulerInterval, 5*time.Second)
		if err := s.Every("@every "+release.String(), worker.TypeMessageRelease, release-time.Second); err != nil {
			return err
		}
		purge := max(cfg.Retention.PurgeInterval, time.Minute)
		return s.Every("@every "+purge.String(), worker.TypeMessageRetention, purge-time.Second)
	})
	return nil
}
