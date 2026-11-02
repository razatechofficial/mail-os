package container

import (
	"context"
	"fmt"
	"strings"

	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/kafka"
	"github.com/razatechofficial/mail-os/infrastructure/msgsig"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	grpchandler "github.com/razatechofficial/mail-os/transport/grpc/handler"
	"github.com/razatechofficial/mail-os/transport/http/handler"
	"github.com/razatechofficial/mail-os/transport/pubsub"
)

// buildEvents wires event ingestion: the inbound use case, POST /events,
// the gRPC DispatchEvent handler and, with FEATURE_PUBSUB_INGEST, the
// Kafka consumer of signed IAM events. EventDispatcher is set by the
// messaging builder, which runs first; without it events are answered 503
// (and redelivered over Kafka), never dropped.
func (c *Container) buildEvents(_ context.Context) error {
	cfg := c.Cfg
	dispatcher := c.EventDispatcher
	if dispatcher == nil {
		dispatcher = inbound.Unconfigured{}
	}
	c.Inbound = inbound.NewService(c.Apps, c.Tenants, postgres.NewInboundEventRepository(c.DB), c.DB, dispatcher, c.Audit)
	c.Routes = append(c.Routes, handler.NewEventHandler(c.Inbound))
	c.GRPCEvents = grpchandler.NewEventHandler(c.Inbound)

	if !cfg.FeatureFlags.PubSubIngest {
		return nil
	}
	verifier, err := msgsig.NewVerifier(c.Verifier, msgsig.NewStoreReplayGuard(c.Redis))
	if err != nil {
		return err
	}
	ingest := pubsub.NewHandler(verifier, c.Inbound, c.Audit)
	topics := cfg.Kafka.Topics
	if len(topics) == 0 {
		topics = iamTopics()
	}
	consumer, err := kafka.NewConsumer(cfg.Kafka, topics, ingest.Handle)
	if err != nil {
		return fmt.Errorf("event consumer: %w", err)
	}
	c.closers = append(c.closers, consumer.Close)
	c.Consumers = append(c.Consumers, consumer.Run)
	return nil
}

// iamTopics are the catalogue's topics IAM publishes.
func iamTopics() []string {
	var out []string
	for _, t := range template.Topics() {
		if t.Source == template.SourceIAM && strings.HasPrefix(t.Key, "iam.") {
			out = append(out, t.Key)
		}
	}
	return out
}
