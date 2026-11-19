// Package auditintegrity makes the audit log tamper-evident (PCI DSS v4.0
// 10.3.2–10.3.4, NIST SP 800-53 AU-9(3), AU-10), as IAM's auditintegrity
// does: every audit row is hashed, and a periodic digest covers the rows
// written since the previous one, chains to it, and is signed with an
// Ed25519 key. Anyone holding the public key can check that no row was
// changed, removed or inserted after the fact, and that no digest was.
//
// Each digest names the key that signed it. A rotated signing key's public
// key stays configured (AUDIT_DIGEST_PREVIOUS_KEYS), so every digest still
// verifies against the key that signed it.
package auditintegrity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Record is an audit row as stored, in the fields its hash covers.
type Record struct {
	Seq          int64
	EventID      string
	Service      string
	Tier         string
	Severity     int
	ActorUUID    string
	ActorType    string
	TenantUUID   string
	OrgUUID      string
	ResourceType string
	ResourceID   string
	Action       string
	IP           string
	UserAgent    string
	// Metadata is the jsonb text as Postgres outputs it (canonical order).
	Metadata  string
	CreatedAt time.Time
}

// field appends a length-prefixed field, so no two field lists hash alike.
func field(h []byte, v string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(v)))
	return append(append(h, n[:]...), v...)
}

func stamp(t time.Time) string { return t.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano) }

// Hash is the record's SHA-256.
func (r Record) Hash() [32]byte {
	b := []byte("mailos-audit-record/1")
	for _, v := range []string{
		strconv.FormatInt(r.Seq, 10), r.EventID, r.Service, r.Tier, strconv.Itoa(r.Severity), r.ActorUUID,
		r.ActorType, r.TenantUUID, r.OrgUUID, r.ResourceType, r.ResourceID, r.Action, r.IP, r.UserAgent,
		r.Metadata, stamp(r.CreatedAt),
	} {
		b = field(b, v)
	}
	return sha256.Sum256(b)
}

// RecordsHash is the SHA-256 over the records' hashes in seq order.
func RecordsHash(records []Record) string {
	h := sha256.New()
	for _, r := range records {
		sum := r.Hash()
		h.Write(sum[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Digest seals a run of audit rows.
type Digest struct {
	Seq            int64     `json:"seq"`
	FromSeq        int64     `json:"from_seq"`
	ToSeq          int64     `json:"to_seq"`
	RecordCount    int       `json:"record_count"`
	RecordsHash    string    `json:"records_hash"`
	PreviousDigest string    `json:"previous_digest"`
	DigestHash     string    `json:"digest_hash"`
	Signature      string    `json:"signature"`
	KeyID          string    `json:"key_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// ComputeHash is the digest's SHA-256 over its fields; the signature signs it.
func (d Digest) ComputeHash() string {
	b := []byte("mailos-audit-digest/1")
	for _, v := range []string{
		strconv.FormatInt(d.FromSeq, 10), strconv.FormatInt(d.ToSeq, 10), strconv.Itoa(d.RecordCount),
		d.RecordsHash, d.PreviousDigest, d.KeyID, stamp(d.CreatedAt),
	} {
		b = field(b, v)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Signer signs digests.
type Signer struct {
	key ed25519.PrivateKey
	id  string
}

// NewSigner reads a base64 Ed25519 seed (32 bytes).
func NewSigner(seedB64 string) (*Signer, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("AUDIT_DIGEST_SIGNING_KEY must be a base64 32-byte Ed25519 seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	return &Signer{key: key, id: KeyID(key.Public().(ed25519.PublicKey))}, nil
}

// KeyID names a public key: the first 16 hex characters of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// PublicKey is the verification key, base64.
func (s *Signer) PublicKey() string {
	return base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))
}

// VerificationKey is a public key digests are checked with.
type VerificationKey struct {
	ID        string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// ParsePublicKeys reads base64 Ed25519 public keys (32 bytes), the keys of
// earlier signing keys.
func ParsePublicKeys(b64 []string) ([]VerificationKey, error) {
	out := make([]VerificationKey, 0, len(b64))
	for _, k := range b64 {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("AUDIT_DIGEST_PREVIOUS_KEYS: %q is not a base64 32-byte Ed25519 public key", k)
		}
		out = append(out, VerificationKey{ID: KeyID(raw), PublicKey: k})
	}
	return out, nil
}

// Store reads audit rows and keeps digests.
type Store interface {
	LastDigest(ctx context.Context) (*Digest, error)
	// RecordsAfter returns rows with seq > afterSeq written before `before`,
	// in seq order.
	RecordsAfter(ctx context.Context, afterSeq int64, before time.Time, limit int) ([]Record, error)
	InsertDigest(ctx context.Context, d *Digest) error
	// Digests returns digests with seq > after, in order.
	Digests(ctx context.Context, after int64, limit int) ([]Digest, error)
	// RecordsInRange returns rows with from <= seq <= to, in seq order.
	RecordsInRange(ctx context.Context, from, to int64) ([]Record, error)
	// MinSeq is the oldest audit row still kept (retention), 0 when none.
	MinSeq(ctx context.Context) (int64, error)
}

// Service seals and verifies the audit log.
type Service struct {
	store  Store
	signer *Signer
	// previous are earlier signing keys' public keys, by key id.
	previous map[string]ed25519.PublicKey
	// lag keeps the newest rows out of a digest so transactions still
	// writing them have committed (seq is taken at insert, not commit).
	lag      time.Duration
	maxBatch int
	now      func() time.Time
}

// NewService returns the integrity service. previous are the public keys
// of earlier signing keys (ParsePublicKeys); digests they signed verify.
func NewService(store Store, signer *Signer, previous ...VerificationKey) *Service {
	s := &Service{store: store, signer: signer, previous: map[string]ed25519.PublicKey{},
		lag: 5 * time.Minute, maxBatch: 50000, now: func() time.Time { return time.Now().UTC() }}
	for _, k := range previous {
		raw, _ := base64.StdEncoding.DecodeString(k.PublicKey)
		s.previous[k.ID] = ed25519.PublicKey(raw)
	}
	return s
}

// SetLag changes how recent a row may be and still be sealed.
func (s *Service) SetLag(d time.Duration) { s.lag = d }

// PublicKey is the digest verification key and its id.
func (s *Service) PublicKey() VerificationKey {
	return VerificationKey{ID: s.signer.id, PublicKey: s.signer.PublicKey()}
}

// PreviousKeys are the earlier signing keys digests are still verified
// with, in key id order.
func (s *Service) PreviousKeys() []VerificationKey {
	out := make([]VerificationKey, 0, len(s.previous))
	for id, k := range s.previous {
		out = append(out, VerificationKey{ID: id, PublicKey: base64.StdEncoding.EncodeToString(k)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Service) verificationKey(id string) (ed25519.PublicKey, bool) {
	if id == s.signer.id {
		return s.signer.key.Public().(ed25519.PublicKey), true
	}
	k, ok := s.previous[id]
	return k, ok
}

// Seal writes one digest over the rows recorded since the last one, and
// returns it; nil when there was nothing new.
func (s *Service) Seal(ctx context.Context) (*Digest, error) {
	last, err := s.store.LastDigest(ctx)
	if err != nil {
		return nil, err
	}
	after, prev := int64(0), ""
	if last != nil {
		after, prev = last.ToSeq, last.DigestHash
	}
	records, err := s.store.RecordsAfter(ctx, after, s.now().Add(-s.lag), s.maxBatch)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	d := &Digest{
		FromSeq:        after + 1,
		ToSeq:          records[len(records)-1].Seq,
		RecordCount:    len(records),
		RecordsHash:    RecordsHash(records),
		PreviousDigest: prev,
		KeyID:          s.signer.id,
		CreatedAt:      s.now().Truncate(time.Microsecond),
	}
	d.DigestHash = d.ComputeHash()
	d.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.signer.key, []byte(d.DigestHash)))
	if err := s.store.InsertDigest(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

// Problem is one integrity failure.
type Problem struct {
	DigestSeq int64  `json:"digest_seq"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
}

// Report is the result of a verification.
type Report struct {
	Digests  int       `json:"digests_checked"`
	Records  int       `json:"records_checked"`
	FromSeq  int64     `json:"from_seq"`
	ToSeq    int64     `json:"to_seq"`
	Purged   int       `json:"digests_past_retention"`
	Problems []Problem `json:"problems"`
	Intact   bool      `json:"intact"`
}

// Verify checks every digest: its chain link, its hash and signature, and
// the rows it covers. Digests whose rows retention removed are checked as a
// chain only.
func (s *Service) Verify(ctx context.Context) (*Report, error) {
	minSeq, err := s.store.MinSeq(ctx)
	if err != nil {
		return nil, err
	}
	rep := &Report{Problems: []Problem{}}
	prev := ""
	var after, expectFrom int64 = 0, 1
	for {
		batch, err := s.store.Digests(ctx, after, 500)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		for _, d := range batch {
			after = d.Seq
			rep.Digests++
			if rep.FromSeq == 0 {
				rep.FromSeq = d.FromSeq
			}
			rep.ToSeq = d.ToSeq
			bad := func(kind, detail string) {
				rep.Problems = append(rep.Problems, Problem{DigestSeq: d.Seq, Kind: kind, Detail: detail})
			}
			if d.PreviousDigest != prev {
				bad("chain_broken", "previous_digest does not match the digest before it")
			}
			if d.FromSeq != expectFrom {
				bad("gap", fmt.Sprintf("covers from seq %d, expected %d", d.FromSeq, expectFrom))
			}
			if d.ComputeHash() != d.DigestHash {
				bad("digest_altered", "digest fields do not match its hash")
			}
			sig, err := base64.StdEncoding.DecodeString(d.Signature)
			if pub, ok := s.verificationKey(d.KeyID); !ok {
				bad("unknown_key", "signed with key "+d.KeyID+", neither the signing key nor one of AUDIT_DIGEST_PREVIOUS_KEYS")
			} else if err != nil || !ed25519.Verify(pub, []byte(d.DigestHash), sig) {
				bad("bad_signature", "signature does not verify")
			}
			prev, expectFrom = d.DigestHash, d.ToSeq+1
			if minSeq == 0 || d.ToSeq < minSeq {
				rep.Purged++
				continue
			}
			if d.FromSeq < minSeq {
				// Retention cut into this digest: its rows cannot be recomputed.
				rep.Purged++
				continue
			}
			records, err := s.store.RecordsInRange(ctx, d.FromSeq, d.ToSeq)
			if err != nil {
				return nil, err
			}
			rep.Records += len(records)
			if len(records) != d.RecordCount {
				bad("records_changed", fmt.Sprintf("%d rows present, digest sealed %d", len(records), d.RecordCount))
			} else if RecordsHash(records) != d.RecordsHash {
				bad("records_changed", "a row covered by this digest was altered")
			}
		}
	}
	rep.Intact = len(rep.Problems) == 0
	return rep, nil
}
