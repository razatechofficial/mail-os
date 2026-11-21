//go:build e2e

package main

// The platform plane's test routes (contract C2, C5): platform tokens, role
// attestations signed with the ACS approval key and their delivery to
// MailOS as the IAM's PIM does it, and ACS client-credentials tokens.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

type platformRequest struct {
	Subject        string         `json:"sub"`
	ACR            string         `json:"acr"`
	AuthAgeSeconds int64          `json:"auth_age_seconds"`
	ClientID       string         `json:"client_id"`
	Email          string         `json:"email"`
	JKT            string         `json:"jkt"`
	Extra          map[string]any `json:"extra"`
}

func (m *minter) platformToken(w http.ResponseWriter, r *http.Request) {
	var req platformRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Subject == "" {
		req.Subject = uuid.NewString()
	}
	tok := m.iam.PlatformToken(fakeiam.PlatformUser{Subject: req.Subject, ACR: req.ACR, AuthAge: time.Duration(req.AuthAgeSeconds) * time.Second,
		ClientID: req.ClientID, Email: req.Email, JKT: req.JKT, Extra: req.Extra})
	writeJSON(w, http.StatusOK, map[string]string{"access_token": tok, "sub": req.Subject})
}

// attestation signs the claims given (any shape, for refusal tests).
func (m *minter) attestation(w http.ResponseWriter, r *http.Request) {
	var claims map[string]any
	if !decode(w, r, &claims) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"attestation": m.iam.Attestation(claims)})
}

// pim plays the IAM's PIM for MailOS platform roles: it keeps the record
// id of each person's eligibility and activation per role, signs the
// attestation and delivers it.
type pim struct {
	iam     *fakeiam.IAM
	mailos  string
	client  http.Client
	mu      sync.Mutex
	records map[string]string // "eligibility|sub|role" or "activation|sub|role" -> record id
}

type roleRequest struct {
	Subject       string `json:"sub"`
	Role          string `json:"role"`
	Action        string `json:"action"` // add, remove, activate, end
	ActiveSeconds int64  `json:"active_seconds"`
	ApprovedBy    string `json:"approved_by"`
}

func (p *pim) record(kind, sub, role string, fresh bool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := kind + "|" + sub + "|" + role
	if id, ok := p.records[k]; ok && !fresh {
		return id
	}
	id := uuid.NewString()
	p.records[k] = id
	return id
}

func (p *pim) deliver(w http.ResponseWriter, r *http.Request) {
	var req roleRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Subject == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "sub and role are required")
		return
	}
	claims := map[string]any{"sub": req.Subject, "role": req.Role, "action": req.Action, "requested_by": req.Subject}
	var recordID string
	switch req.Action {
	case "add", "remove":
		recordID = p.record("eligibility", req.Subject, req.Role, req.Action == "add")
		claims["op"], claims["eligibility_id"] = "mailos.role_eligibility", recordID
	case "activate", "end":
		recordID = p.record("activation", req.Subject, req.Role, req.Action == "activate")
		claims["op"], claims["activation_id"] = "mailos.role_activation", recordID
		if req.Action == "activate" {
			if req.ActiveSeconds <= 0 {
				req.ActiveSeconds = 3600
			}
			claims["active_until"] = time.Now().Add(time.Duration(req.ActiveSeconds) * time.Second).Unix()
			approver := req.ApprovedBy
			if approver == "" {
				approver = uuid.NewString() // a second platform owner
			}
			claims["approved_by"] = approver
		}
	default:
		writeError(w, http.StatusBadRequest, "action is add, remove, activate or end")
		return
	}
	att := p.iam.Attestation(claims)
	body, _ := json.Marshal(map[string]string{"attestation": att})
	resp, err := p.client.Post(p.mailos+"/api/platform/v1/role-attestations", "application/json", bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "deliver to MailOS: "+err.Error())
		return
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	writeJSON(w, http.StatusOK, map[string]any{"status": resp.StatusCode, "body": string(answer), "attestation": att, "record_id": recordID})
}

// acsToken issues the ACS client an access token for api://acs, as the
// IAM's client credentials grant does (sub "client:<id>").
func acsToken(w http.ResponseWriter, r *http.Request, f *fakeiam.IAM, clientID string) {
	if r.PostForm.Get("client_id") != clientID || r.PostForm.Get("resource") != "api://acs" {
		oauthError(w, http.StatusBadRequest, "invalid_client", "only the ACS client gets client-credentials tokens for api://acs")
		return
	}
	now := time.Now()
	tok := f.Sign(f.Keys[0], "at+jwt", map[string]any{"iss": f.Issuer, "sub": "client:" + clientID, "client_id": clientID,
		"aud": "api://acs", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": uuid.NewString()})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 600})
}
