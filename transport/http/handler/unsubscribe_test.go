package handler

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/unsubscribe"
	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/suppression"
)

type unsubSup struct{ added []suppression.Suppression }

func (s *unsubSup) Blocks(_ context.Context, tenantID, appID, email string, mt message.Type) (*suppression.Suppression, error) {
	for _, x := range s.added {
		if x.OrgID == tenantID && x.Email == email && x.ApplicationID == appID && x.Type.Blocks(mt) {
			return &x, nil
		}
	}
	return nil, nil
}

func (s *unsubSup) Add(_ context.Context, in suppression.Suppression) (suppression.Suppression, error) {
	s.added = append(s.added, in)
	return in, nil
}

type countAll struct{ n int64 }

func (c *countAll) CountWindow(context.Context, string, time.Duration) (int64, error) {
	c.n++
	return c.n, nil
}

func unsubEngine(t *testing.T, limiter *countAll, rate int) (*gin.Engine, *unsubSup, string) {
	t.Helper()
	signer, err := unsubscribe.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	sup := &unsubSup{}
	svc, err := unsubscribe.NewService(signer, sup, unsubscribe.Config{BaseURL: "https://mail.example.com", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := svc.URL(unsubscribe.Link{TenantID: "t1", Email: "ana@example.com", CampaignID: "c1"})
	r := gin.New()
	var lim interface {
		CountWindow(context.Context, string, time.Duration) (int64, error)
	}
	if limiter != nil {
		lim = limiter
	}
	NewUnsubscribeHandler(svc, lim, rate).MountPublic(r)
	return r, sup, strings.TrimPrefix(u, "https://mail.example.com")
}

func doUnsub(r *gin.Engine, method, path, ctype string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestUnsubscribePageNeverUnsubscribes(t *testing.T) {
	r, sup, path := unsubEngine(t, nil, 0)
	w := doUnsub(r, http.MethodGet, path, "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="confirm"`) || len(sup.added) != 0 {
		t.Fatalf("GET = %d %s, added %d", w.Code, w.Body.String(), len(sup.added))
	}
	if strings.Contains(w.Body.String(), "ana@example.com") {
		t.Fatal("the page shows the whole address")
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("csp = %q", csp)
	}
	if w := doUnsub(r, http.MethodGet, path+"x", "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("tampered GET = %d", w.Code)
	}
}

func TestOneClickUnsubscribe(t *testing.T) {
	r, sup, path := unsubEngine(t, nil, 0)
	form := "application/x-www-form-urlencoded"
	w := doUnsub(r, http.MethodPost, path, form, []byte("List-Unsubscribe=One-Click"))
	if w.Code != http.StatusOK || len(sup.added) != 1 {
		t.Fatalf("one-click = %d, added %d", w.Code, len(sup.added))
	}
	got := sup.added[0]
	if got.OrgID != "t1" || got.Email != "ana@example.com" || got.Type != suppression.TypeUnsubscribe || got.Source != suppression.SourceUnsubscribe {
		t.Fatalf("suppression %+v", got)
	}
	// The page's form, and a repeat, answer the same without a second entry.
	if w := doUnsub(r, http.MethodPost, path, form, []byte("confirm=yes")); w.Code != http.StatusOK || len(sup.added) != 1 {
		t.Fatalf("repeat = %d, added %d", w.Code, len(sup.added))
	}
	// RFC 8058 also allows multipart/form-data.
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	_ = mw.WriteField("List-Unsubscribe", "One-Click")
	_ = mw.Close()
	if w := doUnsub(r, http.MethodPost, path, mw.FormDataContentType(), b.Bytes()); w.Code != http.StatusOK {
		t.Fatalf("multipart = %d", w.Code)
	}
	if w := doUnsub(r, http.MethodPost, path, form, []byte("something=else")); w.Code != http.StatusBadRequest {
		t.Fatalf("other body = %d", w.Code)
	}
	if w := doUnsub(r, http.MethodPost, path+"x", form, []byte("List-Unsubscribe=One-Click")); w.Code != http.StatusBadRequest {
		t.Fatalf("tampered = %d", w.Code)
	}
}

func TestUnsubscribeRateLimit(t *testing.T) {
	r, _, path := unsubEngine(t, &countAll{}, 2)
	for i := 0; i < 2; i++ {
		if w := doUnsub(r, http.MethodGet, path, "", nil); w.Code != http.StatusOK {
			t.Fatalf("request %d = %d", i, w.Code)
		}
	}
	if w := doUnsub(r, http.MethodGet, path, "", nil); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("over the limit = %d", w.Code)
	}
}
