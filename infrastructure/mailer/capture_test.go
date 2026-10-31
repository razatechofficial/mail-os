package mailer

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/razatechofficial/mail-os/domain/message"
)

func TestCaptureRingListsByRecipientNewestFirst(t *testing.T) {
	c := NewCapture(3)
	ctx := context.Background()
	for i := range 5 {
		out := sampleOutgoing()
		out.Subject = fmt.Sprintf("code %d", i)
		if i%2 == 1 {
			out.To.Email = "other@example.com"
		}
		if _, err := c.Send(ctx, out); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 3 {
		t.Fatalf("len %d", c.Len())
	}
	all := c.List("")
	if len(all) != 3 || all[0].Subject != "code 4" || all[2].Subject != "code 2" {
		t.Fatalf("ring kept %v", subjects(all))
	}
	zoe := c.List("ZOE@example.com")
	if len(zoe) != 2 || zoe[0].Subject != "code 4" || zoe[1].Subject != "code 2" {
		t.Fatalf("zoe %v", subjects(zoe))
	}
	if last, ok := c.Last("other@example.com"); !ok || last.Subject != "code 3" || last.ProviderMessageID != "capture-4" {
		t.Fatalf("last %+v", last)
	}
	c.Reset()
	if c.Len() != 0 || len(c.List("")) != 0 {
		t.Fatal("reset kept messages")
	}
}

func TestCaptureCopiesAndDropsKeys(t *testing.T) {
	c := NewCapture(0)
	key, _ := signingKey(t, "bank.example")
	out := sampleOutgoing()
	out.DKIM = key
	if _, err := c.Send(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	out.Headers["X-Campaign"] = "changed"
	got, _ := c.Last("zoe@example.com")
	if got.DKIM != nil || got.Headers["X-Campaign"] != "otp" {
		t.Fatalf("capture shares caller state or keeps keys: %+v", got.Headers)
	}
	out.To.Email = "nobody"
	if _, err := c.Send(context.Background(), out); !message.IsPermanent(err) {
		t.Fatal("invalid message captured")
	}
}

func TestCaptureConcurrent(t *testing.T) {
	c := NewCapture(50)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				_, _ = c.Send(context.Background(), sampleOutgoing())
				_ = c.List("zoe@example.com")
			}
		})
	}
	wg.Wait()
	if c.Len() != 50 {
		t.Fatalf("len %d", c.Len())
	}
}

func subjects(l []Captured) []string {
	var s []string
	for _, m := range l {
		s = append(s, m.Subject)
	}
	return s
}
