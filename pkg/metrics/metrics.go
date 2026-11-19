// Package metrics holds MailOS's Prometheus metrics. They are served on
// their own listener (METRICS_ADDR), reachable only by the scraper.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "http_requests_total", Help: "HTTP requests by route, method and status.",
	}, []string{"route", "method", "status"})
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mailos", Name: "http_request_duration_seconds", Help: "HTTP request latency.",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"route", "method"})
	grpcRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "grpc_requests_total", Help: "gRPC requests by method and code.",
	}, []string{"method", "code"})
	events = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "events_total", Help: "Inbound events by transport and outcome (accepted, duplicate, rejected reason).",
	}, []string{"transport", "outcome"})
	sends = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "sends_total", Help: "Provider send attempts by provider kind and result.",
	}, []string{"provider", "result"})
	messages = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "messages_total", Help: "Message outcomes by status (sent, delivered, bounced, complained, failed).",
	}, []string{"status"})
	deliverySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "mailos", Name: "delivery_seconds", Help: "Time from a message being accepted to the provider accepting it.",
		Buckets: []float64{.25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900, 3600},
	})
	tasks = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "worker_tasks_total", Help: "Worker tasks by type and result.",
	}, []string{"type", "result"})
	smtpConnections = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "smtp_connections_total", Help: "SMTP submission connections by listener and outcome (accepted, limit).",
	}, []string{"listener", "outcome"})
	smtpActive = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "mailos", Name: "smtp_active_connections", Help: "Open SMTP submission connections.",
	})
	smtpAuth = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "smtp_auth_total", Help: "SMTP AUTH attempts by mechanism and result (ok, failed, throttled, error).",
	}, []string{"mechanism", "result"})
	smtpMessages = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mailos", Name: "smtp_messages_total", Help: "SMTP transactions by outcome (queued, or the refusal reason).",
	}, []string{"outcome"})
	smtpRecipients = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mailos", Name: "smtp_recipients_queued_total", Help: "Messages queued from SMTP submissions (one per recipient).",
	})
)

// ObserveHTTP records one HTTP request.
func ObserveHTTP(route, method, status string, d time.Duration) {
	httpRequests.WithLabelValues(route, method, status).Inc()
	httpDuration.WithLabelValues(route, method).Observe(d.Seconds())
}

// ObserveGRPC records one RPC.
func ObserveGRPC(method, code string) { grpcRequests.WithLabelValues(method, code).Inc() }

// Event records an inbound event outcome.
func Event(transport, outcome string) { events.WithLabelValues(transport, outcome).Inc() }

// Send records a provider send attempt.
func Send(provider, result string) { sends.WithLabelValues(provider, result).Inc() }

// Message records a message outcome.
func Message(status string) { messages.WithLabelValues(status).Inc() }

// Delivered records how long a sent message waited from acceptance.
func Delivered(d time.Duration) { deliverySeconds.Observe(d.Seconds()) }

// Task records a worker task result.
func Task(typ, result string) { tasks.WithLabelValues(typ, result).Inc() }

// SMTPConnection records an SMTP connection accepted or refused at a limit.
func SMTPConnection(listener, outcome string) {
	smtpConnections.WithLabelValues(listener, outcome).Inc()
}

// SMTPActive moves the open SMTP connections gauge by delta.
func SMTPActive(delta float64) { smtpActive.Add(delta) }

// SMTPAuth records an SMTP AUTH attempt.
func SMTPAuth(mechanism, result string) { smtpAuth.WithLabelValues(mechanism, result).Inc() }

// SMTPMessage records an SMTP transaction's outcome and, when queued, its
// recipients.
func SMTPMessage(outcome string, recipients int) {
	smtpMessages.WithLabelValues(outcome).Inc()
	if recipients > 0 {
		smtpRecipients.Add(float64(recipients))
	}
}

// Handler serves the registry.
func Handler() http.Handler { return promhttp.Handler() }
