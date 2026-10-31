package worker

import (
	"errors"
	"testing"
	"time"
)

type retryAfter time.Duration

func (r retryAfter) Error() string             { return "rate limited" }
func (r retryAfter) RetryAfter() time.Duration { return time.Duration(r) }

func TestBackoffGrowsWithJitterAndCap(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		d := Backoff(10*time.Second, 1, time.Hour)
		if d < 8*time.Second || d > 12*time.Second {
			t.Fatalf("first delay %v outside ±20%%", d)
		}
		seen[d] = true
	}
	if len(seen) < 10 {
		t.Fatal("no jitter")
	}
	if d := Backoff(10*time.Second, 30, time.Hour); d > 72*time.Minute || d < 48*time.Minute {
		t.Fatalf("cap: %v", d)
	}
	if d := RetryDelay(0, retryAfter(5*time.Minute), nil); d != 5*time.Minute {
		t.Fatalf("Retry-After ignored: %v", d)
	}
	if d := RetryDelay(0, errors.New("x"), nil); d > 12*time.Second {
		t.Fatalf("first retry %v", d)
	}
}
