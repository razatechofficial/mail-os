package msgsig

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/domain/event"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
)

// testdata/v1.json is IAM's api/mailos/testvectors/v1.json (IAM branch
// feature/mailos-s2s, commit 6b2fecb6), the contract §2 vectors IAM's own
// reference verifier passes. Copy it again when IAM changes it.
type vectorFile struct {
	Issuer  string          `json:"issuer"`
	Subject string          `json:"subject"`
	JWKS    json.RawMessage `json:"jwks"`
	Signing []struct {
		Name     string `json:"name"`
		Topic    string `json:"topic"`
		Body     string `json:"body"`
		JTI      string `json:"jti"`
		Iat      int64  `json:"iat"`
		JWS      string `json:"jws"`
		BodyHash string `json:"body_sha256"`
	} `json:"signing"`
	Verify []struct {
		Name     string   `json:"name"`
		JWS      string   `json:"jws"`
		Topic    string   `json:"topic"`
		Body     string   `json:"body"`
		Now      int64    `json:"now"`
		SeenJTIs []string `json:"seen_jtis"`
		Valid    bool     `json:"valid"`
		Reason   string   `json:"reason"`
	} `json:"verify"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Verify) == 0 || len(v.Signing) == 0 {
		t.Fatal("the vector file has no vectors")
	}
	return v
}

// vectorIAM serves the vectors' discovery document and JWKS for their
// issuer (https://iam.local): every request the verifier makes is routed to
// a local server, so the real discovery and kid lookup run.
func vectorIAM(t *testing.T, v vectorFile) *http.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": v.Issuer, "jwks_uri": v.Issuer + "/.well-known/jwks.json"})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(v.JWKS)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = "http", srv.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVectors(t *testing.T) {
	v := loadVectors(t)
	client := vectorIAM(t, v)
	for _, vec := range v.Verify {
		t.Run(vec.Name, func(t *testing.T) {
			now := time.Unix(vec.Now, 0)
			keys := jwt.NewVerifier(jwt.Config{Issuer: v.Issuer, Audience: "mailos", ClockSkew: 60 * time.Second,
				HTTPClient: client, Now: func() time.Time { return now }})
			store := newMemStore()
			for _, jti := range vec.SeenJTIs {
				store.keys[ReplayKeyPrefix+jti] = time.Minute
			}
			verifier, err := NewVerifier(keys, NewStoreReplayGuard(store))
			if err != nil {
				t.Fatal(err)
			}
			c, err := verifier.Verify(context.Background(), vec.JWS, vec.Topic, []byte(vec.Body))
			if vec.Valid {
				if err != nil {
					t.Fatalf("valid vector refused: %v", err)
				}
				if c.ClientID != v.Subject || c.Topic != vec.Topic || c.Issuer != v.Issuer {
					t.Fatalf("claims = %+v", c)
				}
				return
			}
			got, ok := event.ReasonOf(err)
			if !ok || string(got) != vec.Reason {
				t.Fatalf("err = %v, want reason %q", err, vec.Reason)
			}
		})
	}
}

// The signing vectors verify, their jti is the event id, and body_sha256
// is the unpadded base64url SHA-256 of the exact body bytes.
func TestSigningVectorsVerify(t *testing.T) {
	v := loadVectors(t)
	client := vectorIAM(t, v)
	for _, s := range v.Signing {
		t.Run(s.Name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(s.Body))
			if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != s.BodyHash {
				t.Fatalf("body_sha256 = %s, vector has %s", got, s.BodyHash)
			}
			now := time.Unix(s.Iat, 0)
			keys := jwt.NewVerifier(jwt.Config{Issuer: v.Issuer, Audience: "mailos", HTTPClient: client,
				Now: func() time.Time { return now }})
			verifier, _ := NewVerifier(keys, NewStoreReplayGuard(newMemStore()))
			c, err := verifier.Verify(context.Background(), s.JWS, s.Topic, []byte(s.Body))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			ev, err := event.Parse([]byte(s.Body))
			if err != nil {
				t.Fatalf("the vector body is not an event: %v", err)
			}
			if c.JTI != s.JTI || ev.ID != c.JTI || ev.Type != s.Topic || !c.IssuedAt.Equal(now) {
				t.Fatalf("claims %+v, event id %q", c, ev.ID)
			}
		})
	}
}
