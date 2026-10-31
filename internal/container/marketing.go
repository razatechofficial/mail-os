package container

import (
	"context"
	"time"

	"github.com/razatechofficial/mail-os/application/campaign"
	"github.com/razatechofficial/mail-os/application/contact"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	"github.com/razatechofficial/mail-os/internal/bootstrap"
	"github.com/razatechofficial/mail-os/transport/http/handler"
)

// buildMarketing wires contacts, contact lists and campaigns: their routes,
// the campaign fan-out task and the release schedule. Campaigns send
// through c.CampaignSender, which the messaging builder sets.
func (c *Container) buildMarketing(_ context.Context) error {
	bootstrap.Register("campaign_recipients message_id and claimed_at",
		"SELECT campaign_id, contact_id, status, message_id, claimed_at FROM campaign_recipients LIMIT 0", true,
		"campaign fan-out cannot record its recipients")

	contacts := contact.NewService(postgres.NewContactRepository(c.DB), postgres.NewContactListRepository(c.DB), c.DB, c.Audit)
	repo := postgres.NewCampaignRepository(c.DB)
	campaigns := campaign.NewService(campaign.Deps{
		Campaigns: repo, Targets: repo, Recipients: postgres.NewCampaignRecipientRepository(c.DB),
		Queue: worker.CampaignQueue{Enqueuer: c.Enqueuer}, Sender: c.CampaignSender,
		Tx: c.DB, Audit: c.Audit, ScopeTenant: audit.WithTenant,
	}, campaign.Config{})

	c.Routes = append(c.Routes,
		handler.NewContactHandler(contacts),
		handler.NewContactListHandler(contacts),
		handler.NewCampaignHandler(campaigns),
	)
	c.Tasks = append(c.Tasks, func(s *worker.Server) error {
		s.HandleFunc(worker.TypeCampaignFanout, worker.CampaignFanout(campaigns))
		s.HandleFunc(worker.TypeCampaignRelease, worker.CampaignRelease(campaigns))
		return s.Every("@every 30s", worker.TypeCampaignRelease, 25*time.Second)
	})
	return nil
}
