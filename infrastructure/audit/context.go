package audit

import "context"

type ctxKey int

const (
	ctxRequestMeta ctxKey = iota + 1
	ctxTenant
)

// RequestMeta is the request an event happened in.
type RequestMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

// WithRequestMeta attaches client IP, user-agent and request id for audit enrichment.
func WithRequestMeta(ctx context.Context, m RequestMeta) context.Context {
	return context.WithValue(ctx, ctxRequestMeta, m)
}

func requestMetaFromContext(ctx context.Context) (RequestMeta, bool) {
	if ctx == nil {
		return RequestMeta{}, false
	}
	m, ok := ctx.Value(ctxRequestMeta).(RequestMeta)
	return m, ok
}

// WithTenant scopes events to a tenant the principal does not carry: a
// service event accepted for its configured tenant, or a worker acting for
// a tenant's message.
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, ctxTenant, tenant)
}

func tenantFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	t, _ := ctx.Value(ctxTenant).(string)
	return t
}
