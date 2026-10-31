package mailer

import (
	"context"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// New builds the sender for a tenant provider and its opened credentials.
func New(p provider.Provider, c provider.Credentials, opts Options) (Sender, error) {
	s := p.Settings
	switch p.Kind {
	case provider.KindSMTP:
		return NewSMTP(SMTPConfig{
			Host: s.Host, Port: s.Port, TLSMode: s.TLSMode, Username: s.Username, Password: c.Password,
			From: message.Address{Name: s.FromName, Email: s.FromEmail},
		}, opts)
	case provider.KindSES:
		return NewSES(s, c, opts)
	case provider.KindSendGrid:
		return NewSendGrid(s, c, opts)
	case provider.KindMailgun:
		return NewMailgun(s, c, opts)
	case provider.KindPostmark:
		return NewPostmark(s, c, opts)
	}
	return nil, message.NewSendError(string(p.Kind), message.ReasonConfig, 0, "unknown provider kind")
}

// Configured is a tenant provider with its opened credentials.
type Configured struct {
	Provider    provider.Provider
	Credentials provider.Credentials
}

// ProviderSource lists a tenant's providers that may send now: active and
// under their daily limit. The repository opens the credentials.
type ProviderSource interface {
	ActiveProviders(ctx context.Context, tenantID string) ([]Configured, error)
}

// Builder builds a provider's sender (New, or a fake in tests).
type Builder func(p provider.Provider, c provider.Credentials) (Sender, error)

// Router sends a tenant's mail through its providers: highest priority
// first, spreading load by weight among providers of equal priority, and
// trying the next provider when one fails for its own reasons (auth,
// configuration, outage). A failure that is the message's (invalid
// recipient, rejected content) stops at once: another provider would
// refuse it too. A tenant without providers sends through the platform
// relay; one whose providers all fail does not, as the relay may not be
// authorised for the tenant's domain.
type Router struct {
	src      ProviderSource
	build    Builder
	platform Sender

	mu      sync.Mutex
	senders map[string]cachedSender
}

type cachedSender struct {
	version time.Time
	sender  Sender
}

// NewRouter returns a router. platform may be nil (no relay configured).
func NewRouter(src ProviderSource, platform Sender, opts Options) *Router {
	return NewRouterWithBuilder(src, platform, func(p provider.Provider, c provider.Credentials) (Sender, error) {
		return New(p, c, opts)
	})
}

// NewRouterWithBuilder returns a router that builds senders with build.
func NewRouterWithBuilder(src ProviderSource, platform Sender, build Builder) *Router {
	if platform != nil {
		if s, ok := platform.(*SMTP); ok && s == nil {
			platform = nil // a disabled relay from NewPlatformSMTP
		}
	}
	return &Router{src: src, build: build, platform: platform, senders: map[string]cachedSender{}}
}

var _ Sender = (*Router)(nil)

// Send routes out by its TenantID.
func (r *Router) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	list, err := r.src.ActiveProviders(ctx, out.TenantID)
	if err != nil {
		// The provider list could not be read (database, key manager):
		// transient, never a reason to fall back to the relay.
		return Result{}, &message.SendError{Reason: message.ReasonUnavailable, Err: err, Detail: "the tenant's providers could not be loaded"}
	}
	if len(list) == 0 {
		if r.platform == nil {
			return Result{}, message.NewSendError("", message.ReasonConfig, 0, "no mail provider is configured")
		}
		res, err := r.platform.Send(ctx, out)
		if err == nil {
			res.Kind = provider.KindSMTP
		}
		return res, err
	}

	var transient, permanent error
	for _, c := range order(list) {
		s, err := r.sender(c)
		if err == nil {
			var res Result
			if res, err = s.Send(ctx, out); err == nil {
				res.ProviderID, res.Kind = c.Provider.ID, c.Provider.Kind
				return res, nil
			}
		}
		if ctx.Err() != nil {
			return Result{}, err
		}
		se, ok := message.AsSendError(err)
		if ok && !se.Reason.ProviderFault() {
			return Result{}, err
		}
		if ok && se.Permanent() {
			permanent = err
		} else {
			transient = err
		}
	}
	// Prefer a transient error: the queue retries, and the provider that
	// was down may be back.
	if transient != nil {
		return Result{}, transient
	}
	return Result{}, permanent
}

// sender returns the cached sender for c, rebuilding it when the provider
// changed (UpdatedAt) and releasing the old one's connections.
func (r *Router) sender(c Configured) (Sender, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cs, ok := r.senders[c.Provider.ID]; ok && cs.version.Equal(c.Provider.UpdatedAt) {
		return cs.sender, nil
	}
	s, err := r.build(c.Provider, c.Credentials)
	if err != nil {
		return nil, err
	}
	if old, ok := r.senders[c.Provider.ID]; ok {
		if ci, ok := old.sender.(interface{ CloseIdleConnections() }); ok {
			ci.CloseIdleConnections()
		}
	}
	r.senders[c.Provider.ID] = cachedSender{version: c.Provider.UpdatedAt, sender: s}
	return s, nil
}

// order sorts active providers by priority (highest first) and, within a
// priority, by a weighted random draw (Efraimidis–Spirakis: key u^(1/w)),
// so a provider of weight 2w goes first about twice as often as one of w.
// Weight 0 is a standby, after its weighted peers.
func order(list []Configured) []Configured {
	type keyed struct {
		c   Configured
		key float64
	}
	ks := make([]keyed, 0, len(list))
	for _, c := range list {
		if !c.Provider.Active {
			continue
		}
		key := -1.0
		if w := c.Provider.Weight; w > 0 {
			key = math.Pow(unitRandom(), 1/float64(w))
		}
		ks = append(ks, keyed{c, key})
	}
	slices.SortStableFunc(ks, func(a, b keyed) int {
		if a.c.Provider.Priority != b.c.Provider.Priority {
			return b.c.Provider.Priority - a.c.Provider.Priority
		}
		switch {
		case a.key > b.key:
			return -1
		case a.key < b.key:
			return 1
		}
		return strings.Compare(a.c.Provider.ID, b.c.Provider.ID)
	})
	out := make([]Configured, len(ks))
	for i, k := range ks {
		out[i] = k.c
	}
	return out
}

