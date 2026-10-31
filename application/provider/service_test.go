package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// fakeCipher "seals" by prefixing, so tests can see the plaintext never
// reaches the repository unsealed.
type fakeCipher struct{}

func (fakeCipher) Seal(_ context.Context, p []byte) (string, error) {
	return "km1.testkid0.x" + string(p), nil
}
func (fakeCipher) Open(_ context.Context, c string) ([]byte, error) {
	return []byte(strings.TrimPrefix(c, "km1.testkid0.x")), nil
}

type memRepo struct {
	rows   map[string]Stored
	sent   map[string]int
	legacy []LegacyRow
}

func (r *memRepo) Create(_ context.Context, s Stored) error { r.rows[s.Provider.ID] = s; return nil }
func (r *memRepo) Update(_ context.Context, p domain.Provider, sealed *string) error {
	s := r.rows[p.ID]
	s.Provider = p
	if sealed != nil {
		s.Sealed = *sealed
	}
	r.rows[p.ID] = s
	return nil
}
func (r *memRepo) Delete(_ context.Context, _, id string, _ time.Time) error {
	delete(r.rows, id)
	return nil
}
func (r *memRepo) Get(_ context.Context, t, id string) (Stored, error) {
	s, ok := r.rows[id]
	if !ok || s.Provider.OrgID != t {
		return Stored{}, apperrors.NotFound("provider not found")
	}
	return s, nil
}
func (r *memRepo) List(context.Context, string, int, int) ([]domain.Provider, int, error) {
	return nil, 0, nil
}
func (r *memRepo) ListActive(_ context.Context, t string) ([]Stored, error) {
	var out []Stored
	for _, s := range r.rows {
		if s.Provider.OrgID == t && s.Provider.Active {
			out = append(out, s)
		}
	}
	return out, nil
}
func (r *memRepo) SentSince(context.Context, []string, time.Time) (map[string]int, error) {
	return r.sent, nil
}
func (r *memRepo) Legacy(context.Context) ([]LegacyRow, error) { return r.legacy, nil }
func (r *memRepo) ReplaceLegacy(_ context.Context, id string, s domain.Settings, sealed string, h domain.Hints) error {
	r.rows[id] = Stored{Provider: domain.Provider{ID: id, Settings: s, CredentialHints: h}, Sealed: sealed}
	r.legacy = nil
	return nil
}
func (r *memRepo) WithLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

type storeFunc func(audit.Event)

func (f storeFunc) Insert(_ context.Context, ev audit.Event, _ bool) error { f(ev); return nil }

func newSvc() (*Service, *memRepo, *[]audit.Event) {
	repo := &memRepo{rows: map[string]Stored{}, sent: map[string]int{}}
	var events []audit.Event
	w := audit.NewWriter(storeFunc(func(ev audit.Event) { events = append(events, ev) }), false)
	return NewService(repo, fakeCipher{}, w, Config{}), repo, &events
}

const tenant = "0192f0c4-0000-7000-8000-000000000001"

func TestCreateSealsAndAuditsWithoutSecrets(t *testing.T) {
	svc, repo, events := newSvc()
	p, err := svc.Create(context.Background(), tenant, Input{Name: "SendGrid", Kind: domain.KindSendGrid,
		Credentials: domain.Credentials{APIKey: "SG.super-secret-key-1234"}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	st := repo.rows[p.ID]
	if !strings.HasPrefix(st.Sealed, "km1.") || !p.HasCredentials || p.CredentialHints["api_key"] != "…1234" || p.Weight != domain.DefaultWeight {
		t.Fatalf("stored %+v", st)
	}
	raw, _ := json.Marshal(*events)
	if strings.Contains(string(raw), "super-secret") || !strings.Contains(string(raw), audit.RedactedValue) {
		t.Fatalf("audit leaks or lacks redaction: %s", raw)
	}
}

func TestCreateValidates(t *testing.T) {
	svc, _, _ := newSvc()
	_, err := svc.Create(context.Background(), tenant, Input{Name: "x", Kind: domain.KindSMTP,
		Settings: domain.Settings{Host: "smtp.bank.example", Port: 587}, Credentials: domain.Credentials{Password: "pw"}}, "a")
	if got := apperrors.DetailsOf(err); len(got) != 1 || got[0].Field != "settings.username" {
		t.Fatalf("%v", got)
	}
	_, err = svc.Create(context.Background(), tenant, Input{Name: "x", Kind: domain.KindSES, Settings: domain.Settings{Region: "eu-west-1"}}, "a")
	if apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatal("SES without keys accepted")
	}
}

func TestUpdateMergesCredentials(t *testing.T) {
	svc, repo, events := newSvc()
	p, _ := svc.Create(context.Background(), tenant, Input{Name: "SES", Kind: domain.KindSES, Settings: domain.Settings{Region: "eu-west-1"},
		Credentials: domain.Credentials{AccessKeyID: "AKIAOLDOLDOLDOLD1111", SecretAccessKey: "old-secret"}}, "a")
	name := "SES EU"
	p2, err := svc.Update(context.Background(), tenant, p.ID, Patch{Name: &name, Credentials: &domain.Credentials{SecretAccessKey: "new-secret"}}, "b")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := svc.open(context.Background(), repo.rows[p.ID].Sealed)
	if c.AccessKeyID != "AKIAOLDOLDOLDOLD1111" || c.SecretAccessKey != "new-secret" || p2.Name != "SES EU" {
		t.Fatalf("merge %v", c)
	}
	last := (*events)[len(*events)-1]
	changed := last.Metadata["changed"].([]string)
	if !strings.Contains(strings.Join(changed, ","), "credentials") {
		t.Fatalf("credential change not recorded: %v", changed)
	}
	if _, err := svc.Update(context.Background(), "other", p.ID, Patch{Name: &name}, "b"); apperrors.KindOf(err) != apperrors.KindNotFound {
		t.Fatal("another tenant updated the provider")
	}
}

func TestActiveSkipsProvidersAtTheirDailyLimit(t *testing.T) {
	svc, repo, _ := newSvc()
	a, _ := svc.Create(context.Background(), tenant, Input{Name: "A", Kind: domain.KindPostmark, DailyLimit: 10,
		Credentials: domain.Credentials{ServerToken: "tok-a"}}, "a")
	_, _ = svc.Create(context.Background(), tenant, Input{Name: "B", Kind: domain.KindPostmark, Credentials: domain.Credentials{ServerToken: "tok-b"}}, "a")
	repo.sent[a.ID] = 10
	list, err := svc.Active(context.Background(), tenant)
	if err != nil || len(list) != 1 || list[0].Credentials.ServerToken != "tok-b" {
		t.Fatal(list, err)
	}
}

func TestLegacyConversion(t *testing.T) {
	svc, repo, _ := newSvc()
	repo.legacy = []LegacyRow{{ID: "p1", Kind: domain.KindSMTP, Configuration: map[string]any{
		"host": "smtp.bank.example", "port": 587.0, "username": "u", "password": "plain-pw", "from_addr": "a@bank.example"}}}
	n, err := svc.Bootstrap(context.Background())
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	st := repo.rows["p1"]
	c, _ := svc.open(context.Background(), st.Sealed)
	if c.Password != "plain-pw" || st.Provider.Settings.Host != "smtp.bank.example" || st.Provider.Settings.FromEmail != "a@bank.example" {
		t.Fatalf("%+v %v", st, c)
	}
	if n, _ := svc.Bootstrap(context.Background()); n != 0 {
		t.Fatal("conversion not idempotent")
	}
	s, c := SplitLegacy(domain.KindPostmark, map[string]any{"api_key": "pm"})
	if c.ServerToken != "pm" || c.APIKey != "" || s.Host != "" {
		t.Fatal("postmark token")
	}
}

func TestSplitConfiguration(t *testing.T) {
	s, c, err := SplitConfiguration(map[string]any{"region": "eu-west-1", "access_key_id": "AK", "secret_access_key": "SK"})
	if err != nil || s.Region != "eu-west-1" || c.AccessKeyID != "AK" || c.SecretAccessKey != "SK" {
		t.Fatal(s, c, err)
	}
	if _, _, err := SplitConfiguration(map[string]any{"port": "x"}); err == nil {
		t.Fatal("bad port type accepted")
	}
}
