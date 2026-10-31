package container

import (
	"context"

	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/transport/http/handler"
)

// buildTemplates wires the template designer: its repository, the use
// case (four-eyes from the tenant settings, raw HTML blocks behind
// FEATURE_RAW_HTML_BLOCKS) and its routes. Test sends stay unavailable
// (503) until messaging calls Templates.SetTestSend.
func (c *Container) buildTemplates(context.Context) error {
	cfg := c.Cfg
	c.Templates = apptemplate.New(apptemplate.Deps{
		Repo:          postgres.NewTemplateRepository(c.DB),
		Settings:      c.Tenants,
		Audit:         c.Audit,
		RawHTMLBlocks: cfg.FeatureFlags.RawHTMLBlocks,
	})
	limits := handler.TemplateLimits{}
	if cfg.RateLimit.Enabled {
		limits = handler.TemplateLimits{PreviewPerMinute: cfg.RateLimit.PreviewPerMinute, TestSendPerHour: cfg.RateLimit.TestSendPerHour}
	}
	c.Routes = append(c.Routes, handler.NewTemplateHandler(c.Templates, c.Redis, limits))
	return nil
}
