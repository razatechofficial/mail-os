// Package fakeacs is a stand-in for ACS in tests: an in-memory
// implementation of the acs.v1 calls MailOS makes (Check, CheckBulk,
// ReadRelationships, WriteRelationships) for MailOS's module, with what
// ACS enforces that MailOS relies on: the platform scope (tenant selector
// "platform"), user subjects only, a required expiry no more than 8 h
// ahead on the activation relations, and expired relationships reaching
// nothing. Permissions follow domain/platformrole's table (the same as
// authz/module.zed). The e2e harness runs it as a binary (e2e/cmd/fakeacs).
package fakeacs

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	acsv1 "github.com/razatechofficial/mail-os/api/proto/acs/v1"
	"github.com/razatechofficial/mail-os/domain/platformrole"
)

// MaxExpiry is the module's expiry horizon on activation relations.
const MaxExpiry = platformrole.MaxActivationCeiling

type rel struct {
	resource, relation, subjectType, subjectID string
	expires                                    time.Time
}

func (r rel) key() string {
	return r.resource + "#" + r.relation + "@" + r.subjectType + ":" + r.subjectID
}

// ACS is the fake. Its zero value is not usable; call New.
type ACS struct {
	acsv1.UnimplementedAuthorizationServiceServer
	acsv1.UnimplementedRelationshipServiceServer

	// Now is the clock expiry is judged by.
	Now func() time.Time
	// Authenticate, when set, checks each call's bearer token.
	Authenticate func(ctx context.Context, token string) error

	mu          sync.Mutex
	rels        map[string]rel
	unavailable bool
	calls       []string
	fresh       []string
}

// note records the ZedToken a read asked to be at least as fresh as ("" for
// minimize_latency). The fake always answers from its newest data.
func (a *ACS) note(c *acsv1.Consistency) {
	a.mu.Lock()
	a.fresh = append(a.fresh, c.GetAtLeastAsFresh().GetToken())
	a.mu.Unlock()
}

// Freshness lists, per Check, CheckBulk and ReadRelationships call, the
// token it asked to be at least as fresh as ("" when none).
func (a *ACS) Freshness() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.fresh...)
}

// New returns an empty fake.
func New() *ACS { return &ACS{Now: time.Now, rels: map[string]rel{}} }

// SetUnavailable makes every call answer UNAVAILABLE (ACS down).
func (a *ACS) SetUnavailable(down bool) {
	a.mu.Lock()
	a.unavailable = down
	a.mu.Unlock()
}

// Calls lists the calls made, as "Method tenant".
func (a *ACS) Calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

// Relationships lists the stored relationships as
// "resource#relation@type:id[expiration:RFC3339]", sorted.
func (a *ACS) Relationships() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, r := range a.rels {
		s := r.key()
		if !r.expires.IsZero() {
			s += "[expiration:" + r.expires.UTC().Format(time.RFC3339) + "]"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Register serves the fake on s.
func (a *ACS) Register(s *grpc.Server) {
	acsv1.RegisterAuthorizationServiceServer(s, a)
	acsv1.RegisterRelationshipServiceServer(s, a)
}

// Dial serves the fake in memory for the test and returns a connection.
func Dial(t testing.TB) (*ACS, *grpc.ClientConn) {
	t.Helper()
	a := New()
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	a.Register(s)
	go func() { _ = s.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///fakeacs",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); s.Stop() })
	return a, conn
}

func refuse(code codes.Code, reason, format string, args ...any) error {
	st, _ := status.New(code, fmt.Sprintf(format, args...)).WithDetails(&errdetails.ErrorInfo{Domain: "acs", Reason: reason})
	return st.Err()
}

// enter records the call and applies authentication, availability and the
// scope: MailOS's module types are reachable only in the platform scope.
func (a *ACS) enter(ctx context.Context, method string, tenant *acsv1.TenantSelector, resourceType string) error {
	a.mu.Lock()
	a.calls = append(a.calls, method+" "+tenant.GetTenantId())
	down := a.unavailable
	a.mu.Unlock()
	if down {
		return status.Error(codes.Unavailable, "fake ACS is down")
	}
	if a.Authenticate != nil {
		md, _ := metadata.FromIncomingContext(ctx)
		var tok string
		if v := md.Get("authorization"); len(v) == 1 {
			tok, _ = strings.CutPrefix(v[0], "Bearer ")
		}
		if err := a.Authenticate(ctx, tok); err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}
	}
	if !strings.HasPrefix(resourceType, "mailos/") {
		return refuse(codes.PermissionDenied, "TYPE_NOT_OWNED", "%s is not the app's own type", resourceType)
	}
	if tenant.GetTenantId() != "platform" {
		return refuse(codes.PermissionDenied, "TENANT_NOT_BOUND", "the app is not bound in tenant %q", tenant.GetTenantId())
	}
	return nil
}

// holds reports whether subject holds relation on resource now.
func (a *ACS) holds(resource, relation, subjectType, subjectID string, now time.Time) bool {
	r, ok := a.rels[rel{resource: resource, relation: relation, subjectType: subjectType, subjectID: subjectID}.key()]
	return ok && (r.expires.IsZero() || now.Before(r.expires))
}

func (a *ACS) decide(req *acsv1.CheckRequest) acsv1.Decision {
	res := req.GetResource().GetObjectType() + ":" + req.GetResource().GetObjectId()
	st, sid := req.GetSubject().GetObject().GetObjectType(), req.GetSubject().GetObject().GetObjectId()
	now := a.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	relations := []string{req.GetPermission()}
	if req.GetResource().GetObjectType() == platformrole.ObjectType {
		for _, p := range platformrole.Permissions {
			if string(p.Permission) == req.GetPermission() {
				relations = relations[:0]
				for _, r := range p.Roles {
					relations = append(relations, r.Relation())
				}
			}
		}
	}
	for _, r := range relations {
		if a.holds(res, r, st, sid, now) {
			return acsv1.Decision_DECISION_ALLOWED
		}
	}
	return acsv1.Decision_DECISION_DENIED
}

func (a *ACS) Check(ctx context.Context, req *acsv1.CheckRequest) (*acsv1.CheckResponse, error) {
	if err := a.enter(ctx, "Check", req.GetTenant(), req.GetResource().GetObjectType()); err != nil {
		return nil, err
	}
	a.note(req.GetConsistency())
	return &acsv1.CheckResponse{Decision: a.decide(req)}, nil
}

func (a *ACS) CheckBulk(ctx context.Context, req *acsv1.CheckBulkRequest) (*acsv1.CheckBulkResponse, error) {
	if len(req.GetItems()) == 0 || len(req.GetItems()) > 100 {
		return nil, refuse(codes.InvalidArgument, "TOO_MANY_ITEMS", "1 to 100 items")
	}
	if err := a.enter(ctx, "CheckBulk", req.GetTenant(), req.GetItems()[0].GetResource().GetObjectType()); err != nil {
		return nil, err
	}
	a.note(req.GetConsistency())
	out := &acsv1.CheckBulkResponse{}
	for _, it := range req.GetItems() {
		out.Items = append(out.Items, &acsv1.CheckBulkResponse_Item{Result: &acsv1.CheckBulkResponse_Item_Response{
			Response: &acsv1.CheckResponse{Decision: a.decide(it)}}})
	}
	return out, nil
}

func (a *ACS) ReadRelationships(ctx context.Context, req *acsv1.ReadRelationshipsRequest) (*acsv1.ReadRelationshipsResponse, error) {
	f := req.GetFilter()
	if err := a.enter(ctx, "ReadRelationships", req.GetTenant(), f.GetResourceType()); err != nil {
		return nil, err
	}
	a.note(req.GetConsistency())
	now := a.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	out := &acsv1.ReadRelationshipsResponse{}
	var keys []string
	for k := range a.rels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := a.rels[k]
		typ, id, _ := strings.Cut(r.resource, ":")
		sf := f.GetOptionalSubject()
		switch {
		case typ != f.GetResourceType(),
			f.GetOptionalResourceId() != "" && id != f.GetOptionalResourceId(),
			f.GetOptionalRelation() != "" && r.relation != f.GetOptionalRelation(),
			sf != nil && (sf.GetSubjectType() != r.subjectType || (sf.GetOptionalSubjectId() != "" && sf.GetOptionalSubjectId() != r.subjectID)),
			!r.expires.IsZero() && !now.Before(r.expires):
			continue
		}
		pb := &acsv1.Relationship{Resource: &acsv1.ObjectRef{ObjectType: typ, ObjectId: id}, Relation: r.relation,
			Subject: &acsv1.SubjectRef{Object: &acsv1.ObjectRef{ObjectType: r.subjectType, ObjectId: r.subjectID}}}
		if !r.expires.IsZero() {
			pb.OptionalExpiresAt = timestamppb.New(r.expires)
		}
		out.Relationships = append(out.Relationships, pb)
	}
	return out, nil
}

// expiring reports the module's "user with expiration" relations: the
// activations.
func expiring(resourceType, relation string) bool {
	if resourceType != platformrole.ObjectType {
		return false
	}
	r, eligible, ok := platformrole.RoleOfRelation(relation)
	return ok && !eligible && r != ""
}

func known(resourceType, relation string) bool {
	if resourceType != platformrole.ObjectType {
		return false
	}
	_, _, ok := platformrole.RoleOfRelation(relation)
	return ok
}

func (a *ACS) WriteRelationships(ctx context.Context, req *acsv1.WriteRelationshipsRequest) (*acsv1.WriteRelationshipsResponse, error) {
	if len(req.GetUpdates()) == 0 || len(req.GetUpdates()) > 100 {
		return nil, refuse(codes.InvalidArgument, "TOO_MANY_UPDATES", "1 to 100 updates")
	}
	if err := a.enter(ctx, "WriteRelationships", req.GetTenant(), req.GetUpdates()[0].GetRelationship().GetResource().GetObjectType()); err != nil {
		return nil, err
	}
	now := a.Now()
	var touch, del []rel
	for _, u := range req.GetUpdates() {
		r := u.GetRelationship()
		typ := r.GetResource().GetObjectType()
		x := rel{resource: typ + ":" + r.GetResource().GetObjectId(), relation: r.GetRelation(),
			subjectType: r.GetSubject().GetObject().GetObjectType(), subjectID: r.GetSubject().GetObject().GetObjectId()}
		if !strings.HasPrefix(typ, "mailos/") {
			return nil, refuse(codes.PermissionDenied, "TYPE_NOT_OWNED", "%s is not the app's own type", typ)
		}
		if !known(typ, x.relation) {
			return nil, refuse(codes.InvalidArgument, "UNKNOWN_RELATION", "%s#%s is not in the schema", typ, x.relation)
		}
		if x.subjectType != "user" || r.GetSubject().GetOptionalRelation() != "" || x.subjectID == "" {
			return nil, refuse(codes.PermissionDenied, "SUBJECT_NOT_PLATFORM", "only platform users are subjects in the platform scope")
		}
		switch u.GetOperation() {
		case acsv1.RelationshipUpdate_OPERATION_TOUCH:
			if ts := r.GetOptionalExpiresAt(); ts != nil {
				x.expires = ts.AsTime()
			}
			if expiring(typ, x.relation) {
				if x.expires.IsZero() {
					return nil, refuse(codes.InvalidArgument, "EXPIRY_REQUIRED", "%s#%s needs an expiry", typ, x.relation)
				}
				if !x.expires.After(now) || x.expires.After(now.Add(MaxExpiry)) {
					return nil, refuse(codes.InvalidArgument, "EXPIRY_OUT_OF_RANGE", "expires_at must be in the future and within %s", MaxExpiry)
				}
			} else if !x.expires.IsZero() {
				return nil, refuse(codes.InvalidArgument, "EXPIRY_NOT_ALLOWED", "%s#%s does not expire", typ, x.relation)
			}
			touch = append(touch, x)
		case acsv1.RelationshipUpdate_OPERATION_DELETE:
			del = append(del, x)
		default:
			return nil, refuse(codes.InvalidArgument, "BAD_OPERATION", "touch or delete")
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range touch {
		a.rels[x.key()] = x
	}
	for _, x := range del {
		delete(a.rels, x.key())
	}
	return &acsv1.WriteRelationshipsResponse{WrittenAt: &acsv1.ZedToken{Token: fmt.Sprint(now.UnixNano())}}, nil
}
