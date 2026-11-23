// Package acs is MailOS's client of ACS, the central authorization service
// (ACS ADR 0001 §10; MailOS ADR 0001 §3.4): Check and CheckBulk, reading
// relationships, and writing and deleting them with an optional expiry.
// It dials ACS's app gateway over gRPC with MailOS's client certificate and
// an access token for api://acs the IAM issues to that certificate (OAuth
// client credentials, tls_client_auth, RFC 8705), as ACS's own SDK does;
// the SDK is not imported (the ACS module is private), the wire contract is
// copied in api/proto/acs/v1.
//
// Every call names its scope: PlatformTenant, the reserved selector of
// MailOS's platform binding, or a tenant MailOS is bound in.
package acs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	acsv1 "github.com/razatechofficial/mail-os/api/proto/acs/v1"
	"github.com/razatechofficial/mail-os/pkg/tlsconfig"
)

// PlatformTenant is the reserved tenant selector of the platform scope
// (contract C3): tenant IDs are UUIDs, so it never names a tenant.
const PlatformTenant = "platform"

// Config locates ACS and MailOS's credentials there.
type Config struct {
	// Endpoint is ACS's app gateway (host:port); ServerName its
	// certificate name (the endpoint's host when empty).
	Endpoint, ServerName string
	// CAFile verifies ACS's and the IAM token endpoint's certificates;
	// CertFile and KeyFile are MailOS's client certificate.
	CAFile, CertFile, KeyFile string
	// TokenURL is the IAM's token endpoint; ClientID MailOS's OAuth client
	// for ACS.
	TokenURL, ClientID string
	// Insecure dials ACS in plaintext and asks for tokens without a client
	// certificate: local, test and e2e only (configuration refuses it
	// elsewhere).
	Insecure bool
	// Timeout bounds each call (default 3s).
	Timeout time.Duration
}

// Client calls ACS.
type Client struct {
	authz   acsv1.AuthorizationServiceClient
	rel     acsv1.RelationshipServiceClient
	timeout time.Duration
	close   func() error
}

// Dial connects to ACS. The connection is lazy: MailOS starts while ACS is
// unreachable, and calls answer ErrUnavailable meanwhile.
func Dial(cfg Config, opts ...grpc.DialOption) (*Client, error) {
	if cfg.Endpoint == "" || cfg.TokenURL == "" || cfg.ClientID == "" {
		return nil, errors.New("acs: Endpoint, TokenURL and ClientID are required")
	}
	name := cfg.ServerName
	if name == "" {
		host, _, err := net.SplitHostPort(cfg.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("acs: endpoint: %w", err)
		}
		name = host
	}
	var creds credentials.TransportCredentials
	tokens := &TokenSource{URL: cfg.TokenURL, ClientID: cfg.ClientID, Insecure: cfg.Insecure}
	if cfg.Insecure {
		creds = insecure.NewCredentials()
	} else {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, errors.New("acs: a client certificate is required")
		}
		grpcTLS, err := tlsconfig.NewClient(tlsconfig.Client{CAFile: cfg.CAFile, CertFile: cfg.CertFile, KeyFile: cfg.KeyFile, ServerName: name})
		if err != nil {
			return nil, fmt.Errorf("acs: %w", err)
		}
		tokenTLS, err := tlsconfig.NewClient(tlsconfig.Client{CAFile: cfg.CAFile, CertFile: cfg.CertFile, KeyFile: cfg.KeyFile})
		if err != nil {
			return nil, fmt.Errorf("acs: %w", err)
		}
		creds = credentials.NewTLS(grpcTLS)
		tokens.TLS = tokenTLS
	}
	opts = append([]grpc.DialOption{grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(tokens)}, opts...)
	conn, err := grpc.NewClient(cfg.Endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("acs: %w", err)
	}
	c := New(conn, cfg.Timeout)
	c.close = conn.Close
	return c, nil
}

// New wraps an existing connection (tests dial a fake ACS).
func New(conn grpc.ClientConnInterface, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Client{authz: acsv1.NewAuthorizationServiceClient(conn), rel: acsv1.NewRelationshipServiceClient(conn),
		timeout: timeout, close: func() error { return nil }}
}

// Close closes the connection.
func (c *Client) Close() error { return c.close() }

// Object is a resource; Subject a subject (a userset when Relation is set).
type Object struct{ Type, ID string }

type Subject struct {
	Type, ID, Relation string
}

// User is the core user subject.
func User(id string) Subject { return Subject{Type: "user", ID: id} }

// Relationship is one stored relationship; ExpiresAt is zero when it does
// not expire.
type Relationship struct {
	Resource  Object
	Relation  string
	Subject   Subject
	ExpiresAt time.Time
}

// Update is a write (touch) or a delete of one relationship.
type Update struct {
	Delete bool
	Relationship
}

// Touch writes a relationship (idempotent), expiring at expiresAt unless it
// is zero; Delete removes one (idempotent).
func Touch(res Object, rel string, sub Subject, expiresAt time.Time) Update {
	return Update{Relationship: Relationship{Resource: res, Relation: rel, Subject: sub, ExpiresAt: expiresAt}}
}

func Delete(res Object, rel string, sub Subject) Update {
	return Update{Delete: true, Relationship: Relationship{Resource: res, Relation: rel, Subject: sub}}
}

// Filter selects relationships of one resource type.
type Filter struct {
	ResourceType, ResourceID, Relation string
	// Subject narrows to one subject when its Type is set.
	Subject Subject
}

// ErrUnavailable means ACS did not answer (down, timed out, over quota, or
// refusing MailOS's own credentials). Nothing was decided: callers answer
// 503 and fail closed.
var ErrUnavailable = errors.New("the authorization service is unavailable")

// RefusedError is ACS refusing the request itself (its grant, its
// validation): retrying the same request does not help.
type RefusedError struct {
	Code    codes.Code
	Reason  string // ACS's ErrorInfo reason, e.g. SUBJECT_NOT_PLATFORM
	Message string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("acs refused (%s %s): %s", e.Code, e.Reason, e.Message)
}

// Reason is ACS's refusal reason of err, "" when err is no refusal.
func Reason(err error) string {
	var r *RefusedError
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

func mapError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	st := status.Convert(err)
	switch st.Code() {
	case codes.InvalidArgument, codes.PermissionDenied, codes.FailedPrecondition, codes.NotFound, codes.AlreadyExists, codes.OutOfRange:
		r := &RefusedError{Code: st.Code(), Message: st.Message()}
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == "acs" {
				r.Reason = info.GetReason()
			}
		}
		return r
	default:
		// Unavailable, DeadlineExceeded, ResourceExhausted, Aborted,
		// Internal, Unknown, Unauthenticated (MailOS's own credentials).
		return fmt.Errorf("%w: %s: %s", ErrUnavailable, st.Code(), st.Message())
	}
}

func tenant(id string) *acsv1.TenantSelector { return &acsv1.TenantSelector{TenantId: id} }

func (o Object) ref() *acsv1.ObjectRef { return &acsv1.ObjectRef{ObjectType: o.Type, ObjectId: o.ID} }

func (s Subject) ref() *acsv1.SubjectRef {
	return &acsv1.SubjectRef{Object: &acsv1.ObjectRef{ObjectType: s.Type, ObjectId: s.ID}, OptionalRelation: s.Relation}
}

func (c *Client) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

// Check answers whether sub has perm on res in scope. Only ALLOWED is an
// allow; a caveat that lacks context is a deny.
func (c *Client) Check(ctx context.Context, scope string, res Object, perm string, sub Subject) (bool, error) {
	cctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.authz.Check(cctx, &acsv1.CheckRequest{Tenant: tenant(scope), Resource: res.ref(), Permission: perm, Subject: sub.ref(),
		Consistency: consistencyOf(ctx)})
	if err != nil {
		return false, mapError(ctx, err)
	}
	return resp.GetDecision() == acsv1.Decision_DECISION_ALLOWED, nil
}

// maxBulk is ACS's CheckBulk limit.
const maxBulk = 100

// CheckEach answers Check for each permission, in one CheckBulk call per
// 100. A per-item refusal is an error for the whole call.
func (c *Client) CheckEach(ctx context.Context, scope string, res Object, perms []string, sub Subject) ([]bool, error) {
	out := make([]bool, 0, len(perms))
	for start := 0; start < len(perms); start += maxBulk {
		end := min(start+maxBulk, len(perms))
		req := &acsv1.CheckBulkRequest{Tenant: tenant(scope), Consistency: consistencyOf(ctx)}
		for _, p := range perms[start:end] {
			req.Items = append(req.Items, &acsv1.CheckRequest{Resource: res.ref(), Permission: p, Subject: sub.ref()})
		}
		cctx, cancel := c.ctx(ctx)
		resp, err := c.authz.CheckBulk(cctx, req)
		cancel()
		if err != nil {
			return nil, mapError(ctx, err)
		}
		if len(resp.GetItems()) != end-start {
			return nil, fmt.Errorf("%w: CheckBulk answered %d of %d items", ErrUnavailable, len(resp.GetItems()), end-start)
		}
		for i, it := range resp.GetItems() {
			if e := it.GetError(); e != nil {
				return nil, &RefusedError{Code: codes.PermissionDenied, Reason: e.GetReason(), Message: perms[start+i] + ": " + e.GetMessage()}
			}
			out = append(out, it.GetResponse().GetDecision() == acsv1.Decision_DECISION_ALLOWED)
		}
	}
	return out, nil
}

// maxReadPages bounds one Read (100 relationships a page).
const maxReadPages = 100

// Read lists the relationships f selects in scope, following the cursor.
func (c *Client) Read(ctx context.Context, scope string, f Filter) ([]Relationship, error) {
	filter := &acsv1.RelationshipFilter{ResourceType: f.ResourceType, OptionalResourceId: f.ResourceID, OptionalRelation: f.Relation}
	if f.Subject.Type != "" {
		filter.OptionalSubject = &acsv1.SubjectFilter{SubjectType: f.Subject.Type, OptionalSubjectId: f.Subject.ID, OptionalRelation: f.Subject.Relation}
	}
	var out []Relationship
	cursor := ""
	for range maxReadPages {
		cctx, cancel := c.ctx(ctx)
		resp, err := c.rel.ReadRelationships(cctx, &acsv1.ReadRelationshipsRequest{Tenant: tenant(scope), Filter: filter, PageSize: 100, Cursor: cursor,
			Consistency: consistencyOf(ctx)})
		cancel()
		if err != nil {
			return nil, mapError(ctx, err)
		}
		for _, r := range resp.GetRelationships() {
			rel := Relationship{
				Resource: Object{r.GetResource().GetObjectType(), r.GetResource().GetObjectId()},
				Relation: r.GetRelation(),
				Subject: Subject{Type: r.GetSubject().GetObject().GetObjectType(), ID: r.GetSubject().GetObject().GetObjectId(),
					Relation: r.GetSubject().GetOptionalRelation()},
			}
			if ts := r.GetOptionalExpiresAt(); ts != nil {
				rel.ExpiresAt = ts.AsTime()
			}
			out = append(out, rel)
		}
		if cursor = resp.GetNextCursor(); cursor == "" {
			return out, nil
		}
	}
	return nil, fmt.Errorf("acs: read of %s returned more than %d pages", f.ResourceType, maxReadPages)
}

// Write applies updates atomically in scope and returns ACS's ZedToken of
// the write, for later reads at least as fresh (AtLeastAsFresh).
// idempotencyKey, when set, makes a retry within 24 h return the first
// result.
func (c *Client) Write(ctx context.Context, scope string, updates []Update, idempotencyKey string) (string, error) {
	req := &acsv1.WriteRelationshipsRequest{Tenant: tenant(scope), IdempotencyKey: idempotencyKey}
	for _, u := range updates {
		op := acsv1.RelationshipUpdate_OPERATION_TOUCH
		if u.Delete {
			op = acsv1.RelationshipUpdate_OPERATION_DELETE
		}
		r := &acsv1.Relationship{Resource: u.Resource.ref(), Relation: u.Relation, Subject: u.Subject.ref()}
		if !u.Delete && !u.ExpiresAt.IsZero() {
			r.OptionalExpiresAt = timestamppb.New(u.ExpiresAt)
		}
		req.Updates = append(req.Updates, &acsv1.RelationshipUpdate{Operation: op, Relationship: r})
	}
	cctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.rel.WriteRelationships(cctx, req)
	if err != nil {
		return "", mapError(ctx, err)
	}
	return resp.GetWrittenAt().GetToken(), nil
}

type freshKey struct{}

// AtLeastAsFresh makes the Check, CheckEach and Read calls made with ctx
// answer from data at least as fresh as token (a ZedToken from Write), so
// a role ended or granted a moment ago is seen at once. An empty token
// leaves ACS's default (minimize_latency).
func AtLeastAsFresh(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, freshKey{}, token)
}

func consistencyOf(ctx context.Context) *acsv1.Consistency {
	tok, _ := ctx.Value(freshKey{}).(string)
	if tok == "" {
		return nil
	}
	return &acsv1.Consistency{Requirement: &acsv1.Consistency_AtLeastAsFresh{AtLeastAsFresh: &acsv1.ZedToken{Token: tok}}}
}
