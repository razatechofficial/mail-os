//go:build e2e

package harness

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// MainT is a T for code that runs outside a test (TestMain): Fatalf prints
// and exits.
type MainT struct {
	name     string
	mu       sync.Mutex
	cleanups []func()
}

// NewMainT returns a T that reports under name.
func NewMainT(name string) *MainT { return &MainT{name: name} }

func (m *MainT) Helper() {}

func (m *MainT) Logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, m.name+": "+format+"\n", args...)
}

func (m *MainT) Fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, m.name+": FATAL: "+format+"\n", args...)
	m.runCleanups()
	os.Exit(1)
}

func (m *MainT) Cleanup(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanups = append(m.cleanups, f)
}

func (m *MainT) runCleanups() {
	m.mu.Lock()
	fs := m.cleanups
	m.cleanups = nil
	m.mu.Unlock()
	for i := len(fs) - 1; i >= 0; i-- {
		fs[i]()
	}
}

// Role names MailOS reads from the token's roles claim (domain/access).
const (
	RoleAdmin             = "mailos_admin"
	RoleTemplateEditor    = "mailos_template_editor"
	RoleTemplatePublisher = "mailos_template_publisher"
	RoleOperator          = "mailos_operator"
	RoleAuditor           = "mailos_auditor"
	RoleViewer            = "mailos_viewer"
)

// Fixture is a test package's own world. MailOS has no tenant table to
// provision: a tenant exists for MailOS as the tid claim IAM puts in tokens,
// so a fresh UUID is a fresh, empty tenant.
type Fixture struct {
	Env  *Env
	Name string
	// TenantID and OrgID are the package's tenant and organization.
	TenantID, OrgID string
	// AdminSubject is the tenant administrator Admin signs in as.
	AdminSubject string
}

// NewFixture creates the package's tenant and its administrator.
func NewFixture(t T, env *Env, name string) *Fixture {
	t.Helper()
	f := &Fixture{Env: env, Name: name, TenantID: uuid.NewString(), OrgID: uuid.NewString(), AdminSubject: uuid.NewString()}
	t.Logf("tenant %s, organization %s", f.TenantID, f.OrgID)
	return f
}

// As returns a client signed in as u. Tenant and Org default to the
// package's. Each call mints a new token (the fake IAM's live 10 minutes),
// so take a client per test rather than keeping one for the package.
func (f *Fixture) As(t T, u User) *Client {
	t.Helper()
	if u.Tenant == "" {
		u.Tenant = f.TenantID
	}
	if u.Org == "" {
		u.Org = f.OrgID
	}
	tok, _ := f.Env.UserToken(t, u)
	return f.Env.NewClient().WithBearer(tok)
}

// Admin is the package's tenant administrator (mailos_admin, fresh MFA).
func (f *Fixture) Admin(t T) *Client {
	t.Helper()
	return f.As(t, User{Subject: f.AdminSubject, Roles: []string{RoleAdmin}})
}

// NewUser returns a client for a new user of the package's tenant holding
// roles, and the user's subject.
func (f *Fixture) NewUser(t T, roles ...string) (*Client, string) {
	t.Helper()
	sub := uuid.NewString()
	return f.As(t, User{Subject: sub, Roles: roles}), sub
}

// Service returns a client calling as the IAM service client clientID,
// scoped to the package's tenant.
func (f *Fixture) Service(t T, clientID string) *Client {
	t.Helper()
	return f.Env.NewClient().WithBearer(f.Env.ServiceToken(t, clientID, f.TenantID))
}

// Main is a test package's TestMain: it loads the environment, builds the
// package's fixture (a fresh tenant), runs the tests and exits. Packages
// never share a tenant, so they run in parallel against one server without
// seeing each other's data.
func Main(m *testing.M, name string, fx **Fixture) {
	t := NewMainT(name)
	env, err := LoadEnv()
	if err != nil {
		t.Fatalf("%v", err)
	}
	*fx = NewFixture(t, env, name)
	code := m.Run()
	t.runCleanups()
	os.Exit(code)
}

// MainAsIAM is Main for a package that plays IAM: its tenant is the one
// IAM's system application belongs to (MAILOS_E2E_IAM_TENANT), so events
// sent with Env.IAMClient's token are that tenant's. The package's other
// users are of the same tenant.
func MainAsIAM(m *testing.M, name string, fx **Fixture) {
	t := NewMainT(name)
	env, err := LoadEnv()
	if err != nil {
		t.Fatalf("%v", err)
	}
	*fx = NewFixture(t, env, name)
	(*fx).TenantID = env.IAMTenant
	code := m.Run()
	t.runCleanups()
	os.Exit(code)
}

// NewID returns a new UUID string.
func NewID() string { return uuid.NewString() }
