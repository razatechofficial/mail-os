package mailer

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
)

// DefaultCaptureSize is the capture ring's size when none is given.
const DefaultCaptureSize = 1000

// Captured is one message the Capture sender kept.
type Captured struct {
	message.Outgoing
	ProviderMessageID string
	CapturedAt        time.Time
}

// Capture is a sender that keeps messages in memory instead of sending
// them, for the e2e test hooks (config.E2EHooks, refused outside test
// environments). It holds the newest messages in a bounded ring, so a long
// run cannot exhaust memory, and never keeps DKIM keys.
type Capture struct {
	mu   sync.Mutex
	ring []Captured
	next int // index the next message is written to
	full bool
	seq  uint64
}

// NewCapture returns a capture sender holding at most size messages.
func NewCapture(size int) *Capture {
	if size <= 0 {
		size = DefaultCaptureSize
	}
	return &Capture{ring: make([]Captured, size)}
}

var _ Sender = (*Capture)(nil)

// Send validates out like a real sender and keeps a copy.
func (c *Capture) Send(_ context.Context, out message.Outgoing) (Result, error) {
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, "capture")
	}
	out.Headers = maps.Clone(out.Headers)
	out.Tags = slices.Clone(out.Tags)
	out.DKIM = nil
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	id := "capture-" + strconv.FormatUint(c.seq, 10)
	c.ring[c.next] = Captured{Outgoing: out, ProviderMessageID: id, CapturedAt: time.Now()}
	c.next = (c.next + 1) % len(c.ring)
	if c.next == 0 {
		c.full = true
	}
	return Result{ProviderMessageID: id}, nil
}

// List returns the kept messages to recipient (case-insensitive; all when
// empty), newest first.
func (c *Capture) List(recipient string) []Captured {
	recipient = strings.TrimSpace(recipient)
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.next
	if c.full {
		n = len(c.ring)
	}
	var out []Captured
	for i := 1; i <= n; i++ {
		m := c.ring[(c.next-i+len(c.ring))%len(c.ring)]
		if recipient == "" || strings.EqualFold(m.To.Email, recipient) {
			out = append(out, m)
		}
	}
	return out
}

// Last returns the newest message to recipient.
func (c *Capture) Last(recipient string) (Captured, bool) {
	l := c.List(recipient)
	if len(l) == 0 {
		return Captured{}, false
	}
	return l[0], true
}

// Len is the number of messages kept.
func (c *Capture) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.full {
		return len(c.ring)
	}
	return c.next
}

// Reset drops every kept message.
func (c *Capture) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.ring)
	c.next, c.full = 0, false
}
