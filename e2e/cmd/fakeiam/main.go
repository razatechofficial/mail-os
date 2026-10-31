//go:build e2e

// Command fakeiam is the IAM the e2e suite runs MailOS against: it wraps
// internal/testutil/fakeiam in a process, so the server verifies tokens
// against a real discovery document and JWKS over HTTP, and no running IAM
// is needed. Its keys live only in memory for the life of the process.
//
// With -mint-token-file it also serves test-only routes that sign tokens and
// message signatures with those keys, for the harness. Every mint route needs
// `Authorization: Bearer <the file's token>`; without the flag they are not
// served at all.
//
//	fakeiam -addr 127.0.0.1:18090 -mint-token-file e2e/.work/keys/iam-mint.token
//
//	GET  /.well-known/openid-configuration   discovery (issuer, jwks_uri)
//	GET  /.well-known/jwks.json              the published signing keys
//	POST /test/tokens/user                   {"sub","tid","org_id","roles","acr","auth_age_seconds","aud","client_id","jkt","extra"} -> {"access_token","sub"}
//	POST /test/tokens/service                {"client_id","tid"} -> {"access_token"}
//	POST /test/signatures                    {"client_id","topic","value"(base64)} -> {"signature"}
//
// With -oidc-client-id (and the mint routes) it is also an OIDC provider for
// the console's Playwright suite: see oidc.go.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

// minMintTokenLen keeps the mint token out of guessing range.
const minMintTokenLen = 32

func main() {
	addr := flag.String("addr", "127.0.0.1:18090", "listen address")
	issuer := flag.String("issuer", "", "issuer origin (default http://<addr>)")
	mintFile := flag.String("mint-token-file", "", "file holding the bearer token for the /test mint routes; unset disables them")
	allowRemote := flag.Bool("allow-remote", false, "listen on a non-loopback address")
	oidcClient := flag.String("oidc-client-id", "", "serve the OIDC provider routes for this confidential client (needs -mint-token-file)")
	oidcSecretFile := flag.String("oidc-client-secret-file", "", "file holding the OIDC client's secret")
	oidcRedirects := flag.String("oidc-redirect-uris", "", "comma-separated redirect URIs registered for the OIDC client")
	oidcLogout := flag.String("oidc-post-logout-uris", "", "comma-separated post-logout redirect URIs")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("fakeiam: -addr: %v", err)
	}
	if ip := net.ParseIP(host); !*allowRemote && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Fatalf("fakeiam: refusing to listen on %s: it mints tokens; pass -allow-remote to override", *addr)
	}
	iss := *issuer
	if iss == "" {
		iss = "http://" + *addr
	}

	f := fakeiam.New(iss)
	mux := http.NewServeMux()
	mux.Handle("/.well-known/", f.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	if *mintFile != "" {
		raw, err := os.ReadFile(*mintFile)
		if err != nil {
			log.Fatalf("fakeiam: read mint token: %v", err)
		}
		token := strings.TrimSpace(string(raw))
		if len(token) < minMintTokenLen {
			log.Fatalf("fakeiam: the mint token must be at least %d characters", minMintTokenLen)
		}
		m := &minter{iam: f, token: []byte(token)}
		mux.HandleFunc("POST /test/tokens/user", m.guard(m.user))
		mux.HandleFunc("POST /test/tokens/service", m.guard(m.service))
		mux.HandleFunc("POST /test/signatures", m.guard(m.signature))
		if *oidcClient != "" {
			secret, err := os.ReadFile(*oidcSecretFile)
			if err != nil || len(strings.TrimSpace(string(secret))) < minMintTokenLen {
				log.Fatalf("fakeiam: -oidc-client-secret-file must hold at least %d characters: %v", minMintTokenLen, err)
			}
			newProvider(f, *oidcClient, []byte(strings.TrimSpace(string(secret))), splitList(*oidcRedirects), splitList(*oidcLogout)).mount(mux, m)
		}
	} else if *oidcClient != "" {
		log.Fatalf("fakeiam: -oidc-client-id needs -mint-token-file (personas are registered through it)")
	}

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	log.Printf("fakeiam: issuer %s listening on %s (mint routes: %t)", iss, *addr, *mintFile != "")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("fakeiam: %v", err)
	}
}

type minter struct {
	iam   *fakeiam.IAM
	token []byte
}

// guard requires the mint token and a JSON body of at most 1 MiB.
func (m *minter) guard(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), m.token) != 1 {
			writeError(w, http.StatusUnauthorized, "mint token required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next(w, r)
	}
}

type userRequest struct {
	Subject        string         `json:"sub"`
	Tenant         string         `json:"tid"`
	Org            string         `json:"org_id"`
	Roles          []string       `json:"roles"`
	ACR            string         `json:"acr"`
	AuthAgeSeconds int64          `json:"auth_age_seconds"`
	Audience       any            `json:"aud"`
	ClientID       string         `json:"client_id"`
	JKT            string         `json:"jkt"`
	Extra          map[string]any `json:"extra"`
}

func (m *minter) user(w http.ResponseWriter, r *http.Request) {
	var req userRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Subject == "" {
		req.Subject = uuid.NewString()
	}
	tok := m.iam.UserToken(fakeiam.User{
		Subject: req.Subject, Tenant: req.Tenant, Org: req.Org, Roles: req.Roles, ACR: req.ACR,
		AuthAge: time.Duration(req.AuthAgeSeconds) * time.Second, Audience: req.Audience,
		ClientID: req.ClientID, JKT: req.JKT, Extra: req.Extra,
	})
	writeJSON(w, http.StatusOK, map[string]string{"access_token": tok, "sub": req.Subject})
}

func (m *minter) service(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		Tenant   string `json:"tid"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.ClientID == "" {
		writeError(w, http.StatusBadRequest, "client_id is required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"access_token": m.iam.ServiceToken(req.ClientID, req.Tenant)})
}

func (m *minter) signature(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		Topic    string `json:"topic"`
		Value    string `json:"value"` // base64 (standard) of the exact message bytes
	}
	if !decode(w, r, &req) {
		return
	}
	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil || req.ClientID == "" || req.Topic == "" {
		writeError(w, http.StatusBadRequest, "client_id, topic and a base64 value are required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"signature": m.iam.MessageSignature(req.ClientID, req.Topic, value)})
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("bad request body: %v", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
