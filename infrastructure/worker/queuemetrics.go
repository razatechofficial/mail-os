package worker

import (
	"github.com/hibiken/asynq"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/razatechofficial/mail-os/pkg/logger"
)

// QueueInfoer reads one queue's state (asynq.Inspector).
type QueueInfoer interface {
	GetQueueInfo(queue string) (*asynq.QueueInfo, error)
}

// QueueCollector reports the send and maintenance queues at each scrape:
// mailos_queue_tasks by queue and state, and mailos_queue_latency_seconds,
// the age of the oldest pending task. A backlog or a growing latency is
// mail waiting, the first sign of a provider outage or a stuck worker.
type QueueCollector struct {
	q       QueueInfoer
	tasks   *prometheus.Desc
	latency *prometheus.Desc
}

// NewQueueCollector builds the collector.
func NewQueueCollector(q QueueInfoer) *QueueCollector {
	return &QueueCollector{
		q: q,
		tasks: prometheus.NewDesc("mailos_queue_tasks", "Tasks in each worker queue by state (pending, active, scheduled, retry, archived).",
			[]string{"queue", "state"}, nil),
		latency: prometheus.NewDesc("mailos_queue_latency_seconds", "Age of the oldest pending task in each worker queue.",
			[]string{"queue"}, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *QueueCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tasks
	ch <- c.latency
}

// Collect implements prometheus.Collector. A queue that cannot be read
// (Redis down, or never used) reports nothing rather than zeros.
func (c *QueueCollector) Collect(ch chan<- prometheus.Metric) {
	for _, q := range []string{QueueCritical, QueueDefault, QueueLow} {
		info, err := c.q.GetQueueInfo(q)
		if err != nil {
			logger.Debug("queue metrics", logger.String("queue", q), logger.Err(err))
			continue
		}
		for state, n := range map[string]int{"pending": info.Pending, "active": info.Active, "scheduled": info.Scheduled,
			"retry": info.Retry, "archived": info.Archived} {
			ch <- prometheus.MustNewConstMetric(c.tasks, prometheus.GaugeValue, float64(n), q, state)
		}
		ch <- prometheus.MustNewConstMetric(c.latency, prometheus.GaugeValue, info.Latency.Seconds(), q)
	}
}
