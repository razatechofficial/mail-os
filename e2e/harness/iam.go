//go:build e2e

package harness

import (
	"encoding/base64"
	"net/http"
	"time"
)

// User describes the console user an access token is minted for. Zero
// fields take the fake IAM's defaults: a new subject, acr urn:iam:acr:mfa,
// signed in a minute ago, aud "mailos", client_id "mailos-console".
type User struct {
	Subject string
	Tenant  string
	Org     string
	Roles   []string
	ACR     string
	// AuthAge is how long ago the user signed in (step-up freshness).
	AuthAge  time.Duration
	Audience any
	ClientID string
	// JKT is cnf.jkt for a DPoP-bound token.
	JKT string
	// Extra claims override the defaults (for example an "exp" in the past).
	Extra map[string]any
}

func (e *Env) iamClient() *Client {
	return newClient(e.IAMURL).WithBearer(e.IAMMintToken)
}

// UserToken mints a console user's access token signed by the fake IAM's
// published key, and returns it with the token's subject.
func (e *Env) UserToken(t T, u User) (token, subject string) {
	t.Helper()
	body := map[string]any{
		"sub": u.Subject, "tid": u.Tenant, "org_id": u.Org, "roles": u.Roles, "acr": u.ACR,
		"auth_age_seconds": int64(u.AuthAge / time.Second), "client_id": u.ClientID, "jkt": u.JKT, "extra": u.Extra,
	}
	if u.Audience != nil {
		body["aud"] = u.Audience
	}
	out := e.iamClient().Expect(t, http.StatusOK, http.MethodPost, "/test/tokens/user", body).JSON()
	token, subject = Str(out, "access_token"), Str(out, "sub")
	if token == "" {
		t.Fatalf("fake IAM minted no user token: %v", out)
	}
	return token, subject
}

// ServiceToken mints a client-credentials token for an IAM service client
// (contract §1), scoped to tenant when it is not "".
func (e *Env) ServiceToken(t T, clientID, tenant string) string {
	t.Helper()
	out := e.iamClient().Expect(t, http.StatusOK, http.MethodPost, "/test/tokens/service",
		map[string]any{"client_id": clientID, "tid": tenant}).JSON()
	tok := Str(out, "access_token")
	if tok == "" {
		t.Fatalf("fake IAM minted no service token: %v", out)
	}
	return tok
}

// MessageSignature signs a pub/sub message value as IAM would (contract §2:
// the iam-msg-sig header) for clientID and topic.
func (e *Env) MessageSignature(t T, clientID, topic string, value []byte) string {
	t.Helper()
	out := e.iamClient().Expect(t, http.StatusOK, http.MethodPost, "/test/signatures", map[string]any{
		"client_id": clientID, "topic": topic, "value": base64.StdEncoding.EncodeToString(value),
	}).JSON()
	sig := Str(out, "signature")
	if sig == "" {
		t.Fatalf("fake IAM minted no signature: %v", out)
	}
	return sig
}
