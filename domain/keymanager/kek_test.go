package keymanager

import (
	"testing"
	"time"
)

func TestKEKID(t *testing.T) {
	id := KEKID(ProviderPKCS11, "mailos-kek")
	if id != "pkcs11:mailos-kek" || KEKProvider(id) != ProviderPKCS11 {
		t.Fatalf("%q %q", id, KEKProvider(id))
	}
	arn := KEKID(ProviderKMS, "arn:aws:kms:me-central-1:1:key/k")
	if KEKProvider(arn) != ProviderKMS {
		t.Fatalf("provider of %q", arn)
	}
}

func TestKEKRotationDone(t *testing.T) {
	start := time.Now()
	r := KEKRotation{State: RotationRewrapping, StartedAt: start}
	if !r.Done(start.Add(time.Minute), time.Minute) {
		t.Fatal("drained rotation past the settle time not done")
	}
	if r.Done(start, time.Minute) {
		t.Fatal("completed before the settle time")
	}
	r.Remaining = 1
	if r.Done(start.Add(time.Hour), 0) {
		t.Fatal("completed with keys left")
	}
	r.Remaining, r.Failed = 0, 1
	if r.Done(start.Add(time.Hour), 0) {
		t.Fatal("completed with failures")
	}
	r.Failed = 0
	r.Complete(start.Add(time.Hour))
	if r.State != RotationCompleted || r.CompletedAt == nil || r.Done(start.Add(time.Hour), 0) {
		t.Fatalf("complete: %+v", r)
	}
}
