package message

import (
	"strings"
	"testing"
	"time"
)

func TestProviderEventStatusAndKey(t *testing.T) {
	cases := map[EventType]Status{EventDelivered: StatusDelivered, EventBounced: StatusBounced,
		EventComplained: StatusComplained, EventSoftBounced: "", EventDeferred: ""}
	for typ, want := range cases {
		if !typ.Valid() || typ.Status() != want {
			t.Fatalf("%s: valid %v status %q, want %q", typ, typ.Valid(), typ.Status(), want)
		}
	}
	if EventType("open").Valid() {
		t.Fatal("open is not a delivery event")
	}

	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	e := ProviderEvent{Type: EventBounced, ProviderMessageID: " <abc@x> ", Recipient: " A@B.example ",
		Reason: "550  5.1.1\n user unknown" + strings.Repeat("x", 600), OccurredAt: at}
	e.Normalize()
	if e.ProviderMessageID != "abc@x" || e.Recipient != "a@b.example" || len(e.Reason) != maxReason ||
		strings.Contains(e.Reason, "\n") {
		t.Fatalf("normalised %+v", e)
	}
	k := e.Key()
	if !strings.HasPrefix(k, "h:") || k != e.Key() {
		t.Fatalf("derived key %q", k)
	}
	other := e
	other.Type = EventDelivered
	if other.Key() == k {
		t.Fatal("another event type must have another key")
	}
	e.ProviderEventID = "evt-1"
	if e.Key() != "evt-1" {
		t.Fatalf("provider key %q", e.Key())
	}
}

func TestComplaintTransitions(t *testing.T) {
	for _, from := range []Status{StatusSent, StatusDelivered} {
		if !CanTransition(from, StatusComplained) {
			t.Fatalf("%s must allow complained", from)
		}
	}
	if CanTransition(StatusQueued, StatusComplained) || CanTransition(StatusComplained, StatusDelivered) {
		t.Fatal("complained is reached only after sending, and is final")
	}
	if !StatusComplained.Final() || !StatusComplained.Valid() {
		t.Fatal("complained is a final, known status")
	}
}
