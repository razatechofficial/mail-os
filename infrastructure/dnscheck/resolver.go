// Package dnscheck reads the TXT records sending domain verification
// compares: through the system resolver, or a configured DNS server.
package dnscheck

import (
	"context"
	"errors"
	"net"
	"time"
)

// Resolver looks up TXT records.
type Resolver struct {
	r       *net.Resolver
	timeout time.Duration
}

// New returns a resolver. server ("host:port") replaces the system
// resolver when set, e.g. a validating resolver the bank runs.
func New(server string, timeout time.Duration) *Resolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	r := &net.Resolver{PreferGo: true}
	if server != "" {
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		}
	}
	return &Resolver{r: r, timeout: timeout}
}

// LookupTXT returns the TXT strings at name; a name that does not exist,
// or has no TXT records, returns none and no error.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	txt, err := r.r.LookupTXT(ctx, name)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return nil, nil
	}
	return txt, err
}
