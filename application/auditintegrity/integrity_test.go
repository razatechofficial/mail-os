package auditintegrity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

type memStore struct {
	rows    []Record
	digests []Digest
}

func (m *memStore) LastDigest(context.Context) (*Digest, error) {
	if len(m.digests) == 0 {
		return nil, nil
	}
	d := m.digests[len(m.digests)-1]
	return &d, nil
}

func (m *memStore) RecordsAfter(_ context.Context, after int64, before time.Time, limit int) ([]Record, error) {
	var out []Record
	for _, r := range m.rows {
		if r.Seq <= after {
			continue
		}
		if !r.CreatedAt.Before(before) || len(out) == limit {
			break
		}
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) InsertDigest(_ context.Context, d *Digest) error {
	d.Seq = int64(len(m.digests) + 1)
	m.digests = append(m.digests, *d)
	return nil
}

func (m *memStore) Digests(_ context.Context, after int64, limit int) ([]Digest, error) {
	var out []Digest
	for _, d := range m.digests {
		if d.Seq > after && len(out) < limit {
			out = append(out, d)
		}
	}
	return out, nil
}

func (m *memStore) RecordsInRange(_ context.Context, from, to int64) ([]Record, error) {
	var out []Record
	for _, r := range m.rows {
		if r.Seq >= from && r.Seq <= to {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) MinSeq(context.Context) (int64, error) {
	if len(m.rows) == 0 {
		return 0, nil
	}
	return m.rows[0].Seq, nil
}

func (m *memStore) add(n int, at time.Time) {
	for range n {
		seq := int64(1)
		if len(m.rows) > 0 {
			seq = m.rows[len(m.rows)-1].Seq + 1
		}
		m.rows = append(m.rows, Record{Seq: seq, EventID: fmt.Sprintf("ev-%d", seq), Service: "mailos", Tier: "critical",
			Severity: 5, ActorType: "user", TenantUUID: "t1", ResourceType: "template", ResourceID: "x",
			Action: "template.published", Metadata: `{"version": 1}`, CreatedAt: at})
	}
}

func seed(t *testing.T) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(seed)
}

func newSvc(t *testing.T, store Store, previous ...VerificationKey) *Service {
	t.Helper()
	signer, err := NewSigner(seed(t))
	if err != nil {
		t.Fatal(err)
	}
	return NewService(store, signer, previous...)
}

func TestSealChainsAndVerifies(t *testing.T) {
	store := &memStore{}
	svc := newSvc(t, store)
	old := time.Now().Add(-time.Hour)
	store.add(3, old)
	d1, err := svc.Seal(context.Background())
	if err != nil || d1 == nil || d1.FromSeq != 1 || d1.ToSeq != 3 || d1.PreviousDigest != "" {
		t.Fatalf("first digest %+v %v", d1, err)
	}
	if d, _ := svc.Seal(context.Background()); d != nil {
		t.Fatal("sealed with nothing new")
	}
	store.add(2, old)
	store.add(1, time.Now()) // inside the lag: left for the next digest
	d2, _ := svc.Seal(context.Background())
	if d2 == nil || d2.FromSeq != 4 || d2.ToSeq != 5 || d2.PreviousDigest != d1.DigestHash {
		t.Fatalf("second digest %+v", d2)
	}
	rep, err := svc.Verify(context.Background())
	if err != nil || !rep.Intact || rep.Digests != 2 || rep.Records != 5 {
		t.Fatalf("verify %+v %v", rep, err)
	}
}

func TestVerifyFindsTampering(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	for name, tamper := range map[string]func(*memStore){
		"row altered":     func(s *memStore) { s.rows[1].Action = "template.deleted" },
		"metadata edited": func(s *memStore) { s.rows[0].Metadata = `{"version": 2}` },
		"row removed":     func(s *memStore) { s.rows = append(s.rows[:1], s.rows[2:]...) },
		"row inserted": func(s *memStore) {
			s.rows = append(s.rows[:2], append([]Record{{Seq: 2, EventID: "forged", CreatedAt: old}}, s.rows[2:]...)...)
		},
		"digest altered": func(s *memStore) { s.digests[0].RecordCount = 2 },
		"digest resigned elsewhere": func(s *memStore) {
			s.digests[1].PreviousDigest = "x"
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &memStore{}
			svc := newSvc(t, store)
			store.add(3, old)
			_, _ = svc.Seal(context.Background())
			store.add(3, old)
			_, _ = svc.Seal(context.Background())
			tamper(store)
			rep, err := svc.Verify(context.Background())
			if err != nil || rep.Intact || len(rep.Problems) == 0 {
				t.Fatalf("tampering not found: %+v %v", rep, err)
			}
		})
	}
}

func TestRotatedKeyStillVerifies(t *testing.T) {
	store := &memStore{}
	first := newSvc(t, store)
	store.add(2, time.Now().Add(-time.Hour))
	if _, err := first.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Without the old key the digest is from an unknown key.
	if rep, _ := newSvc(t, store).Verify(context.Background()); rep.Intact || rep.Problems[0].Kind != "unknown_key" {
		t.Fatalf("old key accepted unconfigured: %+v", rep)
	}
	prev, err := ParsePublicKeys([]string{first.PublicKey().PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	second := newSvc(t, store, prev...)
	store.add(2, time.Now().Add(-time.Hour))
	if _, err := second.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rep, _ := second.Verify(context.Background()); !rep.Intact || rep.Digests != 2 {
		t.Fatalf("rotated chain: %+v", rep)
	}
}

func TestRetentionLeavesTheChainVerifiable(t *testing.T) {
	store := &memStore{}
	svc := newSvc(t, store)
	old := time.Now().Add(-time.Hour)
	store.add(3, old)
	_, _ = svc.Seal(context.Background())
	store.add(3, old)
	_, _ = svc.Seal(context.Background())
	store.rows = store.rows[3:] // the first digest's rows passed retention
	rep, err := svc.Verify(context.Background())
	if err != nil || !rep.Intact || rep.Purged != 1 || rep.Records != 3 {
		t.Fatalf("after retention: %+v %v", rep, err)
	}
}

func TestKeysMustBeEd25519(t *testing.T) {
	if _, err := NewSigner("c2hvcnQ="); err == nil {
		t.Fatal("short seed accepted")
	}
	if _, err := ParsePublicKeys([]string{"bm90LWEta2V5"}); err == nil {
		t.Fatal("bad public key accepted")
	}
}
