package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/hibiken/asynq"
)

type runner struct {
	tenant, campaign string
	released         bool
}

func (r *runner) Fanout(_ context.Context, tenant, campaignID string) error {
	r.tenant, r.campaign = tenant, campaignID
	return nil
}

func (r *runner) Release(context.Context) error {
	r.released = true
	return nil
}

func TestCampaignFanoutPayload(t *testing.T) {
	r := &runner{}
	h := CampaignFanout(r)
	if err := h(context.Background(), asynq.NewTask(TypeCampaignFanout, []byte(`{"tenant_id":"t1","campaign_id":"c1"}`))); err != nil {
		t.Fatal(err)
	}
	if r.tenant != "t1" || r.campaign != "c1" {
		t.Fatalf("runner got %q %q", r.tenant, r.campaign)
	}
	for _, p := range []string{`{`, `{"tenant_id":"t1"}`} {
		if err := h(context.Background(), asynq.NewTask(TypeCampaignFanout, []byte(p))); !errors.Is(err, asynq.SkipRetry) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if err := CampaignRelease(r)(context.Background(), asynq.NewTask(TypeCampaignRelease, nil)); err != nil || !r.released {
		t.Fatal("release not run")
	}
}
