package contact

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	domain "github.com/razatechofficial/mail-os/domain/contact"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

const tenant, other = "tenant-a", "tenant-b"

// store is an in-memory Repository and ListRepository.
type store struct {
	contacts map[string]domain.Contact
	lists    map[string]domain.List
	members  map[string][]string
	inUse    map[string]bool
}

func newStore() *store {
	return &store{contacts: map[string]domain.Contact{}, lists: map[string]domain.List{}, members: map[string][]string{}, inUse: map[string]bool{}}
}

func (s *store) Get(_ context.Context, t, id string) (domain.Contact, error) {
	c, ok := s.contacts[id]
	if !ok || c.OrgID != t {
		return domain.Contact{}, domain.ErrNotFound
	}
	return c, nil
}

func (s *store) List(_ context.Context, t string, f Filter) ([]domain.Contact, int, error) {
	var out []domain.Contact
	for _, c := range s.contacts {
		if c.OrgID == t && (f.Status == "" || c.Status == f.Status) {
			out = append(out, c)
		}
	}
	return out, len(out), nil
}

func (s *store) taken(c domain.Contact) bool {
	for _, x := range s.contacts {
		if x.OrgID == c.OrgID && x.Email == c.Email && x.ID != c.ID {
			return true
		}
	}
	return false
}

func (s *store) Create(_ context.Context, c domain.Contact) error {
	if s.taken(c) {
		return domain.ErrDuplicateEmail
	}
	s.contacts[c.ID] = c
	return nil
}

func (s *store) CreateMany(_ context.Context, cs []domain.Contact) (int, error) {
	n := 0
	for _, c := range cs {
		if !s.taken(c) {
			s.contacts[c.ID] = c
			n++
		}
	}
	return n, nil
}

func (s *store) Update(_ context.Context, c domain.Contact) error {
	if s.taken(c) {
		return domain.ErrDuplicateEmail
	}
	s.contacts[c.ID] = c
	return nil
}

func (s *store) Delete(_ context.Context, _, id string) error {
	delete(s.contacts, id)
	return nil
}

func (s *store) GetList(_ context.Context, t, id string) (domain.List, error) {
	l, ok := s.lists[id]
	if !ok || l.OrgID != t {
		return domain.List{}, domain.ErrListNotFound
	}
	return l, nil
}

func (s *store) Lists(_ context.Context, t string, _, _ int) ([]domain.List, int, error) {
	var out []domain.List
	for _, l := range s.lists {
		if l.OrgID == t {
			out = append(out, l)
		}
	}
	return out, len(out), nil
}

func (s *store) CreateList(_ context.Context, l domain.List) error { s.lists[l.ID] = l; return nil }
func (s *store) UpdateList(_ context.Context, l domain.List) error { s.lists[l.ID] = l; return nil }
func (s *store) DeleteList(_ context.Context, _, id string) error {
	delete(s.lists, id)
	delete(s.members, id)
	return nil
}
func (s *store) InUse(_ context.Context, _, id string) (bool, error) { return s.inUse[id], nil }

func (s *store) MissingContacts(ctx context.Context, t string, ids []string) ([]string, error) {
	var out []string
	for _, id := range ids {
		if _, err := s.Get(ctx, t, id); err != nil {
			out = append(out, id)
		}
	}
	return out, nil
}

func (s *store) AddMembers(_ context.Context, _, listID string, ids []string) (int, error) {
	n := 0
	for _, id := range ids {
		if !slices.Contains(s.members[listID], id) {
			s.members[listID] = append(s.members[listID], id)
			n++
		}
	}
	return n, nil
}

func (s *store) RemoveMembers(_ context.Context, _, listID string, ids []string) (int, error) {
	before := len(s.members[listID])
	s.members[listID] = slices.DeleteFunc(s.members[listID], func(id string) bool { return slices.Contains(ids, id) })
	return before - len(s.members[listID]), nil
}

func (s *store) Members(_ context.Context, _, listID string, _ Filter) ([]domain.Contact, int, error) {
	var out []domain.Contact
	for _, id := range s.members[listID] {
		out = append(out, s.contacts[id])
	}
	return out, len(out), nil
}

type event struct {
	action string
	meta   map[string]any
}

type auditLog struct {
	events []event
	fail   bool
}

func (a *auditLog) Append(_ context.Context, _, _, action string, meta map[string]any) error {
	if a.fail {
		return errors.New("audit down")
	}
	a.events = append(a.events, event{action, meta})
	return nil
}

func (a *auditLog) Change(ctx context.Context, rt, id, action string, _, _ any, _ map[string]any) error {
	return a.Append(ctx, rt, id, action, nil)
}

func (a *auditLog) actions() []string {
	var out []string
	for _, e := range a.events {
		out = append(out, e.action)
	}
	return out
}

type tx struct{}

func (tx) InTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

func newService() (*Service, *store, *auditLog) {
	st, log := newStore(), &auditLog{}
	return NewService(st, st, tx{}, log), st, log
}

func TestContactLifecycle(t *testing.T) {
	svc, _, log := newService()
	ctx := context.Background()
	c, err := svc.Create(ctx, tenant, domain.Contact{Email: " Amna@Example.com", FirstName: "Amna"})
	if err != nil || c.ID == "" || c.Email != "amna@example.com" || c.Status != domain.StatusActive {
		t.Fatalf("create %+v %v", c, err)
	}
	if _, err := svc.Create(ctx, tenant, domain.Contact{Email: "AMNA@example.com"}); apperrors.KindOf(err) != apperrors.KindAlreadyExists {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := svc.Create(ctx, other, domain.Contact{Email: "amna@example.com"}); err != nil {
		t.Fatalf("same address, other tenant: %v", err)
	}
	if _, err := svc.Get(ctx, other, c.ID); !apperrors.IsNotFound(err) {
		t.Fatal("other tenant reads the contact")
	}
	unsub := domain.StatusUnsubscribed
	last := "Khan"
	u, err := svc.Update(ctx, tenant, c.ID, Update{LastName: &last, Status: &unsub})
	if err != nil || u.LastName != "Khan" || u.Status != unsub || u.FirstName != "Amna" {
		t.Fatalf("update %+v %v", u, err)
	}
	bad := "not-an-address"
	if _, err := svc.Update(ctx, tenant, c.ID, Update{Email: &bad}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("invalid update: %v", err)
	}
	if _, err := svc.Update(ctx, other, c.ID, Update{LastName: &last}); !apperrors.IsNotFound(err) {
		t.Fatal("other tenant updates the contact")
	}
	if err := svc.Delete(ctx, other, c.ID); !apperrors.IsNotFound(err) {
		t.Fatal("other tenant deletes the contact")
	}
	if err := svc.Delete(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log.actions(), ","); got != "contact.created,contact.created,contact.updated,contact.deleted" {
		t.Fatalf("audit %s", got)
	}
	for _, e := range log.events {
		if strings.Contains(fmt.Sprint(e.meta), "amna@example.com") {
			t.Fatalf("address in the audit record: %v", e.meta)
		}
	}
	upd := log.events[2].meta
	if fmt.Sprint(upd["changed"]) != "[last_name status]" || upd["status_after"] != "unsubscribed" {
		t.Fatalf("update audit %v", upd)
	}
}

func TestNoChangeIsNotAudited(t *testing.T) {
	svc, _, log := newService()
	ctx := context.Background()
	c, _ := svc.Create(ctx, tenant, domain.Contact{Email: "a@example.com", FirstName: "A"})
	same := " A "
	if _, err := svc.Update(ctx, tenant, c.ID, Update{FirstName: &same}); err != nil {
		t.Fatal(err)
	}
	if len(log.events) != 1 {
		t.Fatalf("audit %v", log.actions())
	}
}

func TestAuditFailureFailsTheChange(t *testing.T) {
	svc, _, log := newService()
	log.fail = true
	if _, err := svc.Create(context.Background(), tenant, domain.Contact{Email: "a@example.com"}); err == nil {
		t.Fatal("change reported done without its audit record")
	}
}

func TestImport(t *testing.T) {
	svc, st, log := newService()
	ctx := context.Background()
	_, _ = svc.Create(ctx, tenant, domain.Contact{Email: "old@example.com"})
	res, err := svc.Import(ctx, tenant, []domain.Contact{{Email: "old@example.com"}, {Email: "new@example.com"}, {Email: "NEW@example.com"}})
	if err != nil || res.Created != 1 || res.Skipped != 2 {
		t.Fatalf("import %+v %v", res, err)
	}
	if len(st.contacts) != 2 || log.actions()[1] != "contact.imported" {
		t.Fatalf("contacts %d audit %v", len(st.contacts), log.actions())
	}
	if _, err := svc.Import(ctx, tenant, []domain.Contact{{Email: "x@example.com"}, {Email: "bad"}}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("invalid batch: %v", err)
	}
	if len(st.contacts) != 2 {
		t.Fatal("part of an invalid batch was created")
	}
}

func TestLists(t *testing.T) {
	svc, st, log := newService()
	ctx := context.Background()
	a, _ := svc.Create(ctx, tenant, domain.Contact{Email: "a@example.com"})
	b, _ := svc.Create(ctx, tenant, domain.Contact{Email: "b@example.com"})
	foreign, _ := svc.Create(ctx, other, domain.Contact{Email: "f@example.com"})
	l, err := svc.CreateList(ctx, tenant, domain.List{Name: "VIP"})
	if err != nil || l.Type != domain.ListStatic {
		t.Fatalf("create list %+v %v", l, err)
	}
	if _, err := svc.CreateList(ctx, tenant, domain.List{Name: "Seg", Type: domain.ListDynamic, Query: "x"}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatal("dynamic list accepted")
	}
	if _, err := svc.AddMembers(ctx, tenant, l.ID, []string{a.ID, foreign.ID}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("other tenant's contact added: %v", err)
	}
	if len(st.members[l.ID]) != 0 {
		t.Fatal("partial add")
	}
	if n, err := svc.AddMembers(ctx, tenant, l.ID, []string{a.ID, b.ID, a.ID}); err != nil || n != 2 {
		t.Fatalf("add %d %v", n, err)
	}
	if _, err := svc.AddMembers(ctx, other, l.ID, []string{foreign.ID}); !apperrors.IsNotFound(err) {
		t.Fatal("other tenant adds to the list")
	}
	if _, _, err := svc.Members(ctx, other, l.ID, Filter{}); !apperrors.IsNotFound(err) {
		t.Fatal("other tenant reads the members")
	}
	if ms, n, err := svc.Members(ctx, tenant, l.ID, Filter{}); err != nil || n != 2 || len(ms) != 2 {
		t.Fatalf("members %d %v", n, err)
	}
	if n, err := svc.RemoveMembers(ctx, tenant, l.ID, []string{b.ID, "nope"}); err != nil || n != 1 {
		t.Fatalf("remove %d %v", n, err)
	}
	name := "VIPs"
	if u, err := svc.UpdateList(ctx, tenant, l.ID, ListUpdate{Name: &name}); err != nil || u.Name != "VIPs" {
		t.Fatalf("update list %+v %v", u, err)
	}
	st.inUse[l.ID] = true
	if err := svc.DeleteList(ctx, tenant, l.ID); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("deleted a list in use: %v", err)
	}
	st.inUse[l.ID] = false
	if err := svc.DeleteList(ctx, tenant, l.ID); err != nil {
		t.Fatal(err)
	}
	want := "contact_list.created,contact_list.members_added,contact_list.members_removed,contact_list.updated,contact_list.deleted"
	var got []string
	for _, a := range log.actions() {
		if strings.HasPrefix(a, "contact_list.") {
			got = append(got, a)
		}
	}
	if strings.Join(got, ",") != want {
		t.Fatalf("audit %v", got)
	}
}
