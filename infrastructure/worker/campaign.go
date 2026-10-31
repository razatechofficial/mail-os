package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
)

// Campaign tasks, on the low queue.
const (
	// TypeCampaignFanout sends one campaign to the next pages of its list.
	TypeCampaignFanout = "campaign:fanout"
	// TypeCampaignRelease starts due scheduled campaigns and restarts
	// stalled fan-outs (@every 30s).
	TypeCampaignRelease = "campaign:release"
)

// CampaignFanoutPayload names the campaign a fan-out task sends.
type CampaignFanoutPayload struct {
	TenantID   string `json:"tenant_id"`
	CampaignID string `json:"campaign_id"`
}

// CampaignRunner is the campaign use case's worker side.
type CampaignRunner interface {
	Fanout(ctx context.Context, tenant, campaignID string) error
	Release(ctx context.Context) error
}

// CampaignFanout runs one fan-out task. A malformed payload is dropped.
func CampaignFanout(r CampaignRunner) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, t *asynq.Task) error {
		var p CampaignFanoutPayload
		if err := json.Unmarshal(t.Payload(), &p); err != nil || p.TenantID == "" || p.CampaignID == "" {
			return fmt.Errorf("campaign fan-out payload: %w", asynq.SkipRetry)
		}
		return r.Fanout(ctx, p.TenantID, p.CampaignID)
	}
}

// CampaignRelease runs the release task.
func CampaignRelease(r CampaignRunner) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, _ *asynq.Task) error { return r.Release(ctx) }
}

// CampaignQueue enqueues fan-out tasks for the campaign use case.
type CampaignQueue struct {
	Enqueuer *Enqueuer
}

// EnqueueFanout queues a fan-out on the low queue. Fan-outs of one
// campaign may overlap (a resume, a stalled restart): the recipient claim
// keeps them from sending anyone twice.
func (q CampaignQueue) EnqueueFanout(ctx context.Context, tenant, campaignID string) error {
	payload, err := json.Marshal(CampaignFanoutPayload{TenantID: tenant, CampaignID: campaignID})
	if err != nil {
		return err
	}
	return q.Enqueuer.Enqueue(ctx, TypeCampaignFanout, payload,
		asynq.Queue(QueueLow), asynq.MaxRetry(10), asynq.Timeout(15*time.Minute))
}
