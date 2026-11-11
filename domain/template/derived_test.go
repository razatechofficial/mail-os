package template

import (
	"encoding/json"
	"strings"
	"testing"
)

func derive(t *testing.T, topic string, data map[string]any, key string) string {
	t.Helper()
	got, ok := WithDerived(topic, data)[key].(string)
	if !ok {
		t.Fatalf("%s: %s not derived", topic, key)
	}
	return got
}

func TestWithDerivedLeavesDataAlone(t *testing.T) {
	data := map[string]any{"kind": "mfa_reset", "kind_text": "forged by the publisher"}
	out := WithDerived(TopicSecurityNotice, data)
	if out["kind_text"] != "Your multi-factor authentication was reset" {
		t.Fatalf("kind_text = %v", out["kind_text"])
	}
	if data["kind_text"] != "forged by the publisher" {
		t.Fatal("WithDerived changed its input")
	}
	plain := map[string]any{"link": "https://iam.example.com/m"}
	if got := WithDerived(TopicMagicLink, plain); len(got) != 1 {
		t.Fatalf("a topic without derived variables got %v", got)
	}
	if got := WithDerived(TopicSecurityNotice, nil); got["kind_text"] == nil {
		t.Fatal("nil data not derived")
	}
}

// Every security notice kind IAM sends has its own wording.
func TestSecurityNoticeKinds(t *testing.T) {
	seen := map[string]string{}
	for _, kind := range []string{"factor_added", "factor_removed", "password_changed", "account_locked",
		"new_device_sign_in", "authenticator_invitation", "push_fraud_reported", "mfa_reset",
		"temporary_access_pass_issued"} {
		got := derive(t, TopicSecurityNotice, map[string]any{"kind": kind}, "kind_text")
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s share %q", kind, prev, got)
		}
		seen[got] = kind
	}
	if got := derive(t, TopicSecurityNotice, map[string]any{"kind": "new_kind"}, "kind_text"); !strings.Contains(got, "security change") {
		t.Errorf("unknown kind = %q", got)
	}

	full := map[string]any{"kind": "new_device_sign_in", "credential": "app", "occurred_at": "2026-11-10T09:30:00Z",
		"ip": "203.0.113.10", "user_agent": "Firefox on Windows"}
	if got := derive(t, TopicSecurityNotice, full, "detail_text"); got !=
		"Method: authenticator app. When: 10 Nov 2026 09:30 UTC. IP address: 203.0.113.10. Device: Firefox on Windows." {
		t.Errorf("detail_text = %q", got)
	}
	if got := derive(t, TopicSecurityNotice, map[string]any{"kind": "password_changed"}, "detail_text"); got != "" {
		t.Errorf("detail_text without details = %q", got)
	}
	invite := map[string]any{"kind": "authenticator_invitation", "link": "https://iam.example.com/account/authenticator"}
	if got := derive(t, TopicSecurityNotice, invite, "advice_text"); !strings.HasSuffix(got, "https://iam.example.com/account/authenticator") {
		t.Errorf("invitation advice = %q", got)
	}
	if got := derive(t, TopicSecurityNotice, map[string]any{"kind": "factor_added"}, "advice_text"); !strings.Contains(got, "not you") {
		t.Errorf("default advice = %q", got)
	}
}

// A platform approval has no scope name: the mail says "the platform",
// never "in ".
func TestApprovalScope(t *testing.T) {
	cases := []struct {
		data map[string]any
		want string
	}{
		{map[string]any{"tenant_id": "platform", "scope_name": ""}, "the platform"},
		{map[string]any{"tenant_id": "t1", "scope_name": "Averox"}, "Averox"},
		{map[string]any{"tenant_id": "t1"}, "your workspace"},
	}
	for _, c := range cases {
		if got := derive(t, TopicApprovalRequested, c.data, "scope_text"); got != c.want {
			t.Errorf("%v: scope_text = %q, want %q", c.data, got, c.want)
		}
	}
	if got := derive(t, TopicApprovalRequested, map[string]any{"requester_email": ""}, "requester_text"); got != "An administrator" {
		t.Errorf("requester_text = %q", got)
	}
}

func TestAccessRequestWording(t *testing.T) {
	data := map[string]any{"application_name": "T24 Transact", "role_key": "teller", "role_name": "Teller",
		"duration_days": json.Number("7"), "justification": " "}
	if got := derive(t, TopicAccessRequestSubmitted, data, "access_text"); got != "access to T24 Transact with the role Teller" {
		t.Errorf("access_text = %q", got)
	}
	if got := derive(t, TopicAccessRequestSubmitted, data, "duration_text"); got != "for 7 days" {
		t.Errorf("duration_text = %q", got)
	}
	if got := derive(t, TopicAccessRequestSubmitted, data, "justification_text"); got != "none given" {
		t.Errorf("justification_text = %q", got)
	}
	plain := map[string]any{"application_name": "T24 Transact", "role_key": "", "role_name": ""}
	if got := derive(t, TopicAccessRequestExpired, plain, "access_text"); got != "access to T24 Transact" {
		t.Errorf("plain access_text = %q", got)
	}
	if got := derive(t, TopicAccessRequestSubmitted, plain, "duration_text"); got != "with no end date" {
		t.Errorf("duration_text = %q", got)
	}
	if got := derive(t, TopicAccessRequestDecided, map[string]any{"decision": "denied"}, "outcome_text"); !strings.Contains(got, "ask again") {
		t.Errorf("denied outcome = %q", got)
	}
	approved := map[string]any{"decision": "approved", "access_expires_at": "2026-11-17T09:00:00Z"}
	if got := derive(t, TopicAccessRequestDecided, approved, "outcome_text"); got != "You can sign in now. The access ends 17 Nov 2026 09:00 UTC." {
		t.Errorf("approved outcome = %q", got)
	}
}

func TestPrivilegedAndStatusWording(t *testing.T) {
	if got := derive(t, TopicPrivilegedAccessRequested, map[string]any{"role_name": ""}, "role_text"); got != "a privileged role" {
		t.Errorf("role_text = %q", got)
	}
	if got := derive(t, TopicPrivilegedAccessDenied, map[string]any{"note": ""}, "note_text"); got != "none" {
		t.Errorf("note_text = %q", got)
	}
	if got := derive(t, TopicBreakGlassUsed, map[string]any{"ip": "203.0.113.10"}, "ip_text"); got != "203.0.113.10" {
		t.Errorf("ip_text = %q", got)
	}
	for action, want := range map[string]string{"suspended": "Until it is reactivated", "reactivated": "sign in again",
		"cancelled": "8 Feb 2027 09:00 UTC"} {
		data := map[string]any{"action": action, "purge_after": "2027-02-08T09:00:00Z"}
		if got := derive(t, TopicTenantStatusChanged, data, "status_text"); !strings.Contains(got, want) {
			t.Errorf("%s: status_text = %q", action, got)
		}
	}
}

// Derived variables are offered in the designer with a worded sample, and
// an event is never checked for one.
func TestDerivedVariablesInCatalogue(t *testing.T) {
	tp, _ := TopicByKey(TopicSecurityNotice)
	v, ok := tp.Variable("kind_text")
	if !ok || !v.Derived || v.Required || v.Sample != "A sign-in method was added" {
		t.Fatalf("kind_text = %+v", v)
	}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), `"derived":true`) {
		t.Fatalf("json = %s", b)
	}
	data := map[string]any{"email": "a@example.com", "user_uuid": "u", "kind": "factor_added",
		"occurred_at": "2026-10-31T09:30:00Z", "kind_text": 42}
	if errs := ValidateData(TopicSecurityNotice, data); errs != nil {
		t.Fatalf("derived key checked: %+v", errs)
	}
}
