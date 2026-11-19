package telemetry

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/razatechofficial/mail-os/config"
)

func TestSetupInstallsTheOTLPProvider(t *testing.T) {
	off, err := Setup(context.Background(), config.Telemetry{}, "mailos", "test")
	if err != nil || off(context.Background()) != nil {
		t.Fatal("telemetry off:", err)
	}
	if _, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		t.Fatal("a provider was installed with telemetry off")
	}
	// The exporter connects lazily, so no collector is needed here.
	shutdown, err := Setup(context.Background(), config.Telemetry{Enabled: true, OTLPEndpoint: "127.0.0.1:4317", Insecure: true,
		SampleRatio: 1}, "mailos", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); !ok {
		t.Fatal("the OTLP provider is not the global one")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = shutdown(ctx)
}
