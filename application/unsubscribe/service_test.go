package unsubscribe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	domain "github.com/razatechofficial/mail-os/domain/suppression"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newSigner(t *testing.T, now time.Time) *Signer {
	t.Helper()
	s, err := NewSigner(testKey)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }
	return s
}

func TestSignerRoundTripAndTamper(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	s := newSigner(t, now)
	tok, err := s.Issue(Claims{TenantID: "t1", ApplicationID: "a1", Email: "x@example.com", CampaignID: "c1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Verify(tok)
	if err != nil || c.TenantID != "t1" || c.ApplicationID != "a1" || c.Email != "x@example.com" || c.CampaignID != "c1" {
		t.Fatalf("verify = %+v, %v", c, err)
	}
	payload, sig, _ := strings.Cut(tok, ".")
	other := newSigner(t, now)
	other.key = []byte("another key that is long enough!!")
	forged, _ := other.Issue(Claims{TenantID: "t1", Email: "x@example.com"}, time.Hour)
	for name, bad := range map[string]string{
		"empty": "", "no dot": payload, "bad sig": payload + ".AAAA", "other key": forged,
		"swapped payload": strings.Split(forged, ".")[0] + "." + sig, "long": strings.Repeat("a", 3000),
	} {
		if _, err := s.Verify(bad); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err = %v, want ErrInvalidToken", name, err)
		}
	}
	later := newSigner(t, now.Add(2*time.Hour))
	if _, err := later.Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired token accepted: %v", err)
	}
	if _, err := NewSigner([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

type fakeSup struct {
	list  []domain.Suppression
	added int
}

func (f *fakeSup) Blocks(_ context.Context, tenantID, applicationID, email string, mt message.Type) (*domain.Suppression, error) {
	for _, s := range f.list {
		if s.OrgID == tenantID && s.Email == email && (s.ApplicationID == "" || s.ApplicationID == applicationID) && s.Type.Blocks(mt) {
			return &s, nil
		}
	}
	return nil, nil
}

func (f *fakeSup) Add(_ context.Context, in domain.Suppression) (domain.Suppression, error) {
	f.added++
	f.list = append(f.list, in)
	return in, nil
}

func TestServiceLinksAndUnsubscribe(t *testing.T) {
	sup := &fakeSup{}
	svc, err := NewService(newSigner(t, time.Now()), sup, Config{BaseURL: "https://mail.example.com/", TTL: time.Hour, Mailto: "unsub@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := svc.URL(Link{TenantID: "t1", ApplicationID: "a1", Email: " X@Example.com ", CampaignID: "c9"})
	if err != nil || !strings.HasPrefix(u, "https://mail.example.com/unsubscribe/") {
		t.Fatalf("url = %q, %v", u, err)
	}
	h := svc.Headers(u)
	if h["List-Unsubscribe"] != "<"+u+">, <mailto:unsub@example.com?subject=unsubscribe>" || h["List-Unsubscribe-Post"] != "List-Unsubscribe=One-Click" {
		t.Fatalf("headers = %v", h)
	}
	tok := strings.TrimPrefix(u, "https://mail.example.com/unsubscribe/")
	res, err := svc.Unsubscribe(context.Background(), tok, ViaOneClick)
	if err != nil || res.Already {
		t.Fatalf("unsubscribe = %+v, %v", res, err)
	}
	got := sup.list[0]
	if got.Email != "x@example.com" || got.ApplicationID != "a1" || got.Type != domain.TypeUnsubscribe ||
		got.Source != domain.SourceUnsubscribe || !strings.Contains(got.Reason, "RFC 8058") || !strings.Contains(got.Reason, "c9") {
		t.Fatalf("suppression = %+v", got)
	}
	// Idempotent: the second click writes nothing.
	res, err = svc.Unsubscribe(context.Background(), tok, ViaPage)
	if err != nil || !res.Already || sup.added != 1 {
		t.Fatalf("second = %+v, %v, added %d", res, err, sup.added)
	}
	if _, err := svc.Unsubscribe(context.Background(), tok+"x", ViaOneClick); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered token: %v", err)
	}
}

func TestNewServiceRefusesBadBaseURL(t *testing.T) {
	for _, u := range []string{"", "mail.example.com", "ftp://x"} {
		if _, err := NewService(newSigner(t, time.Now()), &fakeSup{}, Config{BaseURL: u}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}
