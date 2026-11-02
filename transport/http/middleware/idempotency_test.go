package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/idempotency"
	"github.com/razatechofficial/mail-os/domain/access"
)

type memIdem struct {
	mu   sync.Mutex
	rows map[string]idempotency.Record
	fail bool
}

func (m *memIdem) Claim(_ context.Context, scope, key, hash string, _ time.Time) (idempotency.Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return idempotency.Record{}, false, errors.New("down")
	}
	if r, ok := m.rows[scope+"/"+key]; ok {
		return r, false, nil
	}
	m.rows[scope+"/"+key] = idempotency.Record{RequestSHA256: hash}
	return idempotency.Record{}, true, nil
}

func (m *memIdem) Complete(_ context.Context, scope, key string, status int, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rows[scope+"/"+key]
	r.Status, r.Body = status, append([]byte(nil), body...)
	m.rows[scope+"/"+key] = r
	return nil
}

func (m *memIdem) Release(_ context.Context, scope, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, scope+"/"+key)
	return nil
}

func idemRouter(store idempotency.Store, app string, status *int, calls *int) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/messages/send", func(c *gin.Context) {
		p := access.Principal{Kind: access.KindService, TenantID: "t1", ApplicationID: app}
		c.Request = c.Request.WithContext(access.WithPrincipal(c.Request.Context(), p))
	}, Idempotency(store, time.Hour), func(c *gin.Context) {
		*calls++
		c.JSON(*status, gin.H{"message_id": "m" + string(rune('0'+*calls))})
	})
	return r
}

func post(r *gin.Engine, key, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/messages/send", strings.NewReader(body))
	if key != "" {
		req.Header.Set(IdempotencyHeader, key)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestIdempotencyReplaysAndRefusesReuse(t *testing.T) {
	store := &memIdem{rows: map[string]idempotency.Record{}}
	status, calls := http.StatusCreated, 0
	r := idemRouter(store, "app-1", &status, &calls)

	first := post(r, "order-1", `{"to":"a@example.com"}`)
	again := post(r, "order-1", `{"to":"a@example.com"}`)
	if calls != 1 || first.Code != 201 || again.Code != 201 || again.Body.String() != first.Body.String() ||
		again.Header().Get(ReplayedHeader) != "true" {
		t.Fatalf("replay: calls=%d %d %s / %d %s", calls, first.Code, first.Body, again.Code, again.Body)
	}
	if w := post(r, "order-1", `{"to":"b@example.com"}`); w.Code != 409 || calls != 1 {
		t.Fatalf("same key, other body: %d", w.Code)
	}
	if w := post(r, "", `{"to":"a@example.com"}`); w.Code != 201 || calls != 2 {
		t.Fatal("a request without the header ran idempotently")
	}
	if w := post(r, "bad\nkey", `{}`); w.Code != 422 {
		t.Fatalf("control characters in the key: %d", w.Code)
	}
	if w := post(r, strings.Repeat("k", 256), `{}`); w.Code != 422 {
		t.Fatalf("a 256-character key: %d", w.Code)
	}

	// Another application's identical key is its own.
	other := idemRouter(store, "app-2", &status, &calls)
	if w := post(other, "order-1", `{"to":"b@example.com"}`); w.Code != 201 || calls != 3 {
		t.Fatalf("keys are per application: %d", w.Code)
	}
}

func TestIdempotencyFailuresAreNotStored(t *testing.T) {
	store := &memIdem{rows: map[string]idempotency.Record{}}
	status, calls := http.StatusCreated, 0
	r := idemRouter(store, "app-1", &status, &calls)
	status = http.StatusTooManyRequests
	if w := post(r, "limited", `{}`); w.Code != 429 {
		t.Fatal(w.Code)
	}
	status = http.StatusCreated
	if w := post(r, "limited", `{}`); w.Code != 201 || w.Header().Get(ReplayedHeader) != "" {
		t.Fatalf("a 429 was stored: %d", w.Code)
	}
	status = http.StatusServiceUnavailable
	_ = post(r, "down", `{}`)
	if _, ok := store.rows["app-1/down"]; ok {
		t.Fatal("a 5xx was stored")
	}
	status = http.StatusUnprocessableEntity
	_ = post(r, "invalid", `{}`)
	if w := post(r, "invalid", `{}`); w.Code != 422 || w.Header().Get(ReplayedHeader) != "true" {
		t.Fatalf("a 4xx outcome is replayed: %d", w.Code)
	}
	store.fail = true
	if w := post(r, "any", `{}`); w.Code != 503 {
		t.Fatalf("store down: %d", w.Code)
	}
}

func TestIdempotencyInProgressExactRequest(t *testing.T) {
	store := &memIdem{rows: map[string]idempotency.Record{}}
	release := make(chan struct{})
	started := make(chan struct{})
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/messages/send", Idempotency(store, time.Hour), func(c *gin.Context) {
		close(started)
		<-release
		c.JSON(201, gin.H{"ok": true})
	})
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- post(r, "k", `{}`) }()
	<-started
	if w := post(r, "k", `{}`); w.Code != 409 || !strings.Contains(w.Body.String(), "still being processed") {
		t.Fatalf("concurrent retry: %d %s", w.Code, w.Body)
	}
	close(release)
	if w := <-done; w.Code != 201 {
		t.Fatal(w.Code)
	}
}
