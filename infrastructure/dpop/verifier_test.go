package dpop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type memReplay struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func (m *memReplay) ClaimOnce(_ context.Context, key string, _ time.Duration) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[key] {
		return false, nil
	}
	m.seen[key] = true
	return true, nil
}

type holder struct {
	key *ecdsa.PrivateKey
	jkt string
}

func newHolder(t *testing.T) holder {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tp, _ := (&jose.JSONWebKey{Key: k.Public()}).Thumbprint(crypto.SHA256)
	return holder{key: k, jkt: base64.RawURLEncoding.EncodeToString(tp)}
}

func (h holder) proof(t *testing.T, claims map[string]any) string {
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt")
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: h.key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	jws, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := jws.CompactSerialize()
	return out
}

func ath(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const htu = "https://mailos.internal/api/v1/templates"

func TestCheck(t *testing.T) {
	h := newHolder(t)
	other := newHolder(t)
	v := NewVerifier(&memReplay{seen: map[string]bool{}}, time.Minute)
	token := "access.token.value"
	good := func(jti string) map[string]any {
		return map[string]any{"jti": jti, "htm": "POST", "htu": htu + "?page=2", "iat": time.Now().Unix(), "ath": ath(token)}
	}
	check := func(proof string, method string) error {
		r := httptest.NewRequest(method, htu, nil)
		if proof != "" {
			r.Header.Set("DPoP", proof)
		}
		return v.Check(context.Background(), r, "DPoP", token, h.jkt, htu)
	}

	if err := check(h.proof(t, good("a")), "POST"); err != nil {
		t.Fatalf("good proof refused: %v", err)
	}
	if err := check(h.proof(t, good("a")), "POST"); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay: %v", err)
	}
	if err := check("", "POST"); !errors.Is(err, ErrProofRequired) {
		t.Fatalf("missing proof: %v", err)
	}
	bad := map[string]map[string]any{
		"other method": func() map[string]any { c := good("b"); c["htm"] = "GET"; return c }(),
		"other uri":    func() map[string]any { c := good("c"); c["htu"] = "https://mailos.internal/api/v1/providers"; return c }(),
		"stale":        func() map[string]any { c := good("d"); c["iat"] = time.Now().Add(-5 * time.Minute).Unix(); return c }(),
		"other token":  func() map[string]any { c := good("e"); c["ath"] = ath("another"); return c }(),
		"no jti":       func() map[string]any { c := good(""); return c }(),
	}
	for name, claims := range bad {
		if err := check(h.proof(t, claims), "POST"); !errors.Is(err, ErrInvalidProof) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := check(other.proof(t, good("f")), "POST"); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("proof by another key: %v", err)
	}
}

func TestUnboundTokens(t *testing.T) {
	v := NewVerifier(&memReplay{seen: map[string]bool{}}, time.Minute)
	r := httptest.NewRequest("GET", htu, nil)
	if err := v.Check(context.Background(), r, "Bearer", "t", "", htu); err != nil {
		t.Fatalf("unbound bearer token: %v", err)
	}
	if err := v.Check(context.Background(), r, "DPoP", "t", "", htu); !errors.Is(err, ErrUnboundDPoP) {
		t.Fatalf("DPoP scheme with unbound token: %v", err)
	}
}

func TestReplayCacheDownFailsClosed(t *testing.T) {
	h := newHolder(t)
	v := NewVerifier(&memReplay{err: errors.New("redis down")}, time.Minute)
	r := httptest.NewRequest("GET", htu, nil)
	r.Header.Set("DPoP", h.proof(t, map[string]any{"jti": "x", "htm": "GET", "htu": htu, "iat": time.Now().Unix(), "ath": ath("t")}))
	if err := v.Check(context.Background(), r, "DPoP", "t", h.jkt, htu); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("replay cache down: %v", err)
	}
}

func TestRequestURI(t *testing.T) {
	r := httptest.NewRequest("GET", "http://mailos:8080/api/v1/messages?x=1", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := RequestURI(r, false); got != "http://mailos:8080/api/v1/messages" {
		t.Fatalf("untrusted forwarded header used: %s", got)
	}
	if got := RequestURI(r, true); got != "https://mailos:8080/api/v1/messages" {
		t.Fatalf("trusted proxy: %s", got)
	}
}
