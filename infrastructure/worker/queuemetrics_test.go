package worker

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hibiken/asynq"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type fakeQueues map[string]*asynq.QueueInfo

func (f fakeQueues) GetQueueInfo(q string) (*asynq.QueueInfo, error) {
	if info, ok := f[q]; ok {
		return info, nil
	}
	return nil, errors.New("queue not found")
}

func TestQueueCollectorReportsBacklogAndLatency(t *testing.T) {
	c := NewQueueCollector(fakeQueues{QueueCritical: {Pending: 7, Retry: 2, Latency: 90 * time.Second}})
	want := `
# HELP mailos_queue_latency_seconds Age of the oldest pending task in each worker queue.
# TYPE mailos_queue_latency_seconds gauge
mailos_queue_latency_seconds{queue="critical"} 90
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "mailos_queue_latency_seconds"); err != nil {
		t.Fatal(err)
	}
	// Five states for the one readable queue; unreadable queues report nothing.
	if n := testutil.CollectAndCount(c, "mailos_queue_tasks"); n != 5 {
		t.Fatalf("%d task series, want 5", n)
	}
}
