package sendingdomain

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/domain/provider"
	domain "github.com/razatechofficial/mail-os/domain/sendingdomain"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type fakeCipher struct{}

func (fakeCipher) Seal(_ context.Context, p []byte) (string, error) {
	return "km1.testkid0.x" + string(p), nil
}
func (fakeCipher) Open(_ context.Context, c string) ([]byte, error) {
	return []byte(strings.TrimPrefix(c, "km1.testkid0.x")), nil
}

type memRepo struct {
	rows   map[string]Stored
	legacy []LegacyRow
}

func (r *memRepo) Create(_ context.Context, s Stored) error {
	for _, o := range r.rows {
		if o.Domain.OrgID == s.Domain.OrgID && o.Domain.Name == s.Domain.Name {
			return apperrors.Conflict("exists")
		}
	}
	r.rows[s.Domain.ID] = s
	return nil
}
func (r *memRepo) Update(_ context.Context, d domain.Domain, sealed *string) error {
	s := r.rows[d.ID]
	s.Domain = d
	if sealed != nil {
		s.Sealed = *sealed
	}
	r.rows[d.ID] = s
	return nil
}
func (r *memRepo) Delete(_ context.Context, _, id string, _ time.Time) error {
	delete(r.rows, id)
	return nil
}
func (r *memRepo) Get(_ context.Context, t, id string) (Stored, error) {
	s, ok := r.rows[id]
	if !ok || s.Domain.OrgID != t {
		return Stored{}, apperrors.NotFound("domain not found")
	}
	return s, nil
}
func (r *memRepo) List(context.Context, string, int, int) ([]domain.Domain, int, error) {
	return nil, 0, nil
}
func (r *memRepo) Verified(_ context.Context, t string) ([]Stored, error) {
	var out []Stored
	for _, s := range r.rows {
		if s.Domain.OrgID == t && s.Domain.Status == domain.StatusVerified {
			out = append(out, s)
		}
	}
	return out, nil
}
func (r *memRepo) Legacy(context.Context) ([]LegacyRow, error) { return r.legacy, nil }
func (r *memRepo) ReplaceLegacy(_ context.Context, id, sealed string) error {
	r.rows[id] = Stored{Sealed: sealed}
	r.legacy = nil
	return nil
}
func (r *memRepo) WithLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

type dns map[string][]string

func (d dns) LookupTXT(_ context.Context, name string) ([]string, error) {
	if name == "fail.example" {
		return nil, errors.New("servfail")
	}
	return d[name], nil
}

type kinds []provider.Kind

func (k kinds) Kinds(context.Context, string) ([]provider.Kind, error) { return k, nil }

type nopAudit struct{}

func (nopAudit) Change(context.Context, string, string, string, any, any, map[string]any) error {
	return nil
}

const tenant = "t1"

func TestCreateVerifySign(t *testing.T) {
	repo := &memRepo{rows: map[string]Stored{}}
	records := dns{}
	svc := NewService(repo, fakeCipher{}, records, kinds{provider.KindSES}, nopAudit{}, Config{})
	d, err := svc.Create(context.Background(), tenant, Input{Name: "Bank.Example"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	st := repo.rows[d.ID]
	if !strings.HasPrefix(st.Sealed, "km1.") || !strings.Contains(st.Sealed, "PRIVATE KEY") || !strings.Contains(d.SPFRecord, "include:amazonses.com") {
		t.Fatalf("%+v", d)
	}
	if _, err := svc.Create(context.Background(), tenant, Input{Name: "bank.example"}, "admin"); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatal("duplicate domain accepted")
	}
	if k, _ := svc.SigningKey(context.Background(), tenant, "noreply@bank.example"); k != nil {
		t.Fatal("a pending domain signs")
	}
	records[d.DKIMRecordName()] = []string{d.DKIMRecordValue()}
	records[d.Name] = []string{d.SPFRecord}
	v, err := svc.Verify(context.Background(), tenant, d.ID)
	if err != nil || v.Status != domain.StatusVerified {
		t.Fatal(v.Status, err)
	}
	k, err := svc.SigningKey(context.Background(), tenant, "noreply@mail.bank.example")
	if err != nil || k == nil || k.Domain != "bank.example" || !strings.Contains(k.PrivateKeyPEM, "PRIVATE KEY") {
		t.Fatal(k, err)
	}
	if ok, _ := svc.VerifiedFrom(context.Background(), tenant, "a@evilbank.example"); ok {
		t.Fatal("a look-alike domain counted as verified")
	}
	if ok, _ := svc.VerifiedFrom(context.Background(), "other", "a@bank.example"); ok {
		t.Fatal("another tenant's domain counted")
	}
}

func TestVerifyLookupFailureIs503(t *testing.T) {
	repo := &memRepo{rows: map[string]Stored{"d1": {Domain: domain.Domain{ID: "d1", OrgID: tenant, Name: "fail.example", DKIMSelector: "s"}}}}
	svc := NewService(repo, fakeCipher{}, dns{}, nil, nopAudit{}, Config{})
	if _, err := svc.Verify(context.Background(), tenant, "d1"); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatal(err)
	}
}

func TestLegacyKeySealed(t *testing.T) {
	repo := &memRepo{rows: map[string]Stored{}, legacy: []LegacyRow{{ID: "d1", PrivateKeyPEM: "-----BEGIN RSA PRIVATE KEY-----"}}}
	svc := NewService(repo, fakeCipher{}, dns{}, nil, nopAudit{}, Config{})
	if n, err := svc.Bootstrap(context.Background()); n != 1 || err != nil || !strings.HasPrefix(repo.rows["d1"].Sealed, "km1.") {
		t.Fatal(n, err)
	}
}
