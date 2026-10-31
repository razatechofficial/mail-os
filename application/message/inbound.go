package message

import (
	"context"
	"maps"

	"github.com/razatechofficial/mail-os/application/campaign"
	"github.com/razatechofficial/mail-os/application/inbound"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
)

var (
	_ inbound.Dispatcher      = (*Service)(nil)
	_ campaign.CampaignSender = (*Service)(nil)
)

// Dispatch turns an accepted event into a templated message to data.email
// (inbound.Dispatcher). It runs inside the inbound transaction: the
// message row commits with the event record, and the send task, queued
// before the commit, retries until the row is visible.
func (s *Service) Dispatch(ctx context.Context, d inbound.Delivery) (string, error) {
	to, _ := d.Data["email"].(string)
	in := TemplatedSend{TenantID: d.TenantID, Topic: d.Topic, To: to, EventID: d.EventID, Source: d.Source, Data: d.Data}
	if d.ClientID != "" {
		in.actor = &domainmsg.Actor{Type: domainmsg.ActorService, ID: d.ClientID}
	}
	if d.OrgID != "" {
		in.metadata = map[string]any{"iam_org_id": d.OrgID}
	}
	m, err := s.SendTemplated(ctx, in)
	return m.ID, err
}

// SendCampaignMessage queues one campaign message as marketing mail on
// the mailos.campaign topic (campaign.CampaignSender).
func (s *Service) SendCampaignMessage(ctx context.Context, cm campaign.CampaignMessage) (string, error) {
	m, err := s.SendTemplated(ctx, TemplatedSend{TenantID: cm.TenantID, Topic: domaintemplate.TopicCampaign, TemplateID: cm.TemplateID,
		To: cm.To, ToName: cm.ToName, FromName: cm.FromName, FromEmail: cm.FromEmail, Data: maps.Clone(cm.Data),
		Type: domainmsg.TypeMarketing, CampaignID: cm.CampaignID, actor: &domainmsg.Actor{Type: domainmsg.ActorSystem}})
	return m.ID, err
}
