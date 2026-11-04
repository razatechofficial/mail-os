package template

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func TestTopicsCatalogue(t *testing.T) {
	ts := Topics()
	want := []string{TopicSecurityNotice, TopicApprovalRequested, TopicInvite, TopicMagicLink, TopicPasswordReset,
		TopicEmailVerification, TopicMFAEmailCode, TopicPasskeyEnrolment, TopicDeletionRequested, TopicAccessReview,
		TopicLifecycleEmail, TopicDomainVerified, TopicDomainClaimExpiring, TopicDomainClaimReleased,
		TopicDomainVerificationLapsed, TopicDomainTransferRequested, TopicDomainTransferred, TopicDomainRevoked,
		TopicTenantSignupEmailVerification, TopicTenantSignupApproved, TopicTenantSignupRejected,
		TopicTenantSignupReviewRequested, TopicCampaign}
	var keys []string
	for _, tp := range ts {
		keys = append(keys, tp.Key)
		seen := map[string]bool{}
		for _, v := range tp.Variables {
			if seen[v.Key] {
				t.Errorf("%s: %s twice", tp.Key, v.Key)
			}
			seen[v.Key] = true
			if !ValidKey(v.Key) || v.Label == "" || v.Sample == "" {
				t.Errorf("%s: bad variable %+v", tp.Key, v)
			}
		}
		for _, common := range []string{"user.name", "user.email", "brand.company_name", "unsubscribe_url"} {
			if !seen[common] {
				t.Errorf("%s lacks %s", tp.Key, common)
			}
		}
		if tp.Source != SourceIAM && tp.Source != SourceMailOS {
			t.Errorf("%s: source %q", tp.Key, tp.Source)
		}
	}
	if !slices.Equal(keys, want) {
		t.Fatalf("topics = %v", keys)
	}
	// Topics hands out copies.
	ts[0].Variables[0].Key = "changed"
	if again, _ := TopicByKey(ts[0].Key); again.Variables[0].Key == "changed" {
		t.Fatal("catalogue mutated through Topics")
	}
}

func TestTopicVariables(t *testing.T) {
	notice, ok := TopicByKey(TopicSecurityNotice)
	if !ok {
		t.Fatal("security notice missing")
	}
	for _, k := range []string{"email", "user_uuid", "kind", "credential", "ip", "user_agent", "occurred_at", "link", "brand.name", "brand.support_text"} {
		if _, ok := notice.Variable(k); !ok {
			t.Errorf("security notice lacks %s", k)
		}
	}
	for _, gone := range []string{"brand.locale", "brand.dir"} {
		if _, ok := notice.Variable(gone); ok {
			t.Errorf("%s offered; IAM no longer sends it", gone)
		}
	}
	code, _ := TopicByKey(TopicMFAEmailCode)
	if _, ok := code.Variable("brand.name"); ok {
		t.Error("brand offered on a topic IAM does not brand")
	}
	life, _ := TopicByKey(TopicLifecycleEmail)
	for _, k := range []string{"email", "user_uuid", "tenant_uuid", "subject", "body", "occurred_at"} {
		if v, ok := life.Variable(k); !ok || !v.Required {
			t.Errorf("lifecycle lacks required %s", k)
		}
	}
	if _, ok := TopicByKey("iam.unknown"); ok {
		t.Fatal("unknown topic found")
	}
}

func TestTopicJSON(t *testing.T) {
	tp, _ := TopicByKey(TopicMFAEmailCode)
	b, err := json.Marshal(tp)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if got["topic"] != TopicMFAEmailCode || got["source"] != "iam" {
		t.Fatalf("json = %s", b)
	}
	v := got["variables"].([]any)[1].(map[string]any)
	if v["key"] != "code" || v["kind"] != "secret" || v["required"] != nil {
		t.Fatalf("variable json = %v", v)
	}
}

func TestSecretKeys(t *testing.T) {
	if got := SecretKeys(TopicMFAEmailCode); !slices.Equal(got, []string{"code"}) {
		t.Fatalf("secrets = %v", got)
	}
	if got := SecretKeys(TopicMagicLink); got != nil {
		t.Fatalf("secrets = %v", got)
	}
}

func TestSampleDataPassesValidation(t *testing.T) {
	for _, tp := range Topics() {
		data := SampleData(tp.Key)
		if errs := ValidateData(tp.Key, data); len(errs) > 0 {
			t.Errorf("%s: sample data refused: %+v", tp.Key, errs)
		}
	}
	data := SampleData(TopicMFAEmailCode)
	if data["expires_in_minutes"] != float64(10) {
		t.Fatalf("number sample = %#v", data["expires_in_minutes"])
	}
	if name, _ := Lookup(data, "user.name"); name != "Amna Khan" {
		t.Fatalf("nested sample = %v", name)
	}
	if common := SampleData(""); common["unsubscribe_url"] == nil || common["email"] != nil {
		t.Fatalf("common samples = %v", common)
	}
}

func TestValidateData(t *testing.T) {
	ok := map[string]any{
		"email": "amna@example.com", "code": "123456", "purpose": "sign_in", "expires_in_minutes": 10,
		"extra": map[string]any{"ignored": true},
	}
	if errs := ValidateData(TopicMFAEmailCode, ok); errs != nil {
		t.Fatalf("valid data refused: %+v", errs)
	}
	bad := map[string]any{
		"email": "not an email", "code": 123456, "purpose": "", "expires_in_minutes": "ten",
		"user": map[string]any{"email": "x"},
	}
	errs := ValidateData(TopicMFAEmailCode, bad)
	want := map[string]string{
		"data.email": CodeInvalidEmail, "data.code": CodeInvalidType, "data.purpose": CodeRequired,
		"data.expires_in_minutes": CodeInvalidNumber, "data.user.email": CodeInvalidEmail,
	}
	assertCodes(t, errs, want)
	for _, e := range errs {
		if e.Field == "data.code" && strings.Contains(e.Message, "123456") {
			t.Fatal("secret value in message")
		}
	}

	notice := map[string]any{
		"email": "a@example.com", "user_uuid": "u", "kind": "factor_added", "occurred_at": "yesterday",
		"link": "javascript:alert(1)",
	}
	assertCodes(t, ValidateData(TopicSecurityNotice, notice), map[string]string{
		"data.occurred_at": CodeInvalidDatetime, "data.link": CodeInvalidURL,
	})

	review := map[string]any{"email": "a@example.com", "pending_count": json.Number("3"), "review_link": "https://iam.example.com/r"}
	if errs := ValidateData(TopicAccessReview, review); errs != nil {
		t.Fatalf("json.Number refused: %+v", errs)
	}
	campaign := map[string]any{"contact": map[string]any{"email": "c@example.com"}}
	if errs := ValidateData(TopicCampaign, campaign); errs != nil {
		t.Fatalf("campaign refused: %+v", errs)
	}
	assertCodes(t, ValidateData("iam.nope", nil), map[string]string{"topic": CodeUnknownTopic})
	assertCodes(t, ValidateData(TopicMagicLink, nil), map[string]string{"data.email": CodeRequired, "data.link": CodeRequired})
}

func assertCodes(t *testing.T, errs []apperrors.FieldError, want map[string]string) {
	t.Helper()
	got := map[string]string{}
	for _, e := range errs {
		got[e.Field] = e.Code
	}
	if len(got) != len(want) {
		t.Fatalf("errors = %+v, want %v", errs, want)
	}
	for f, c := range want {
		if got[f] != c {
			t.Fatalf("%s = %q, want %q (all: %+v)", f, got[f], c, errs)
		}
	}
}

// The §7 domain topics take IAM's DomainNotice as it is sent: every topic
// its own fields, the tenant name optional.
func TestDomainTopics(t *testing.T) {
	base := map[string]any{"email": "admin@example.com", "user_id": "u1", "tenant_id": "t1", "domain": "example.com",
		"occurred_at": "2026-10-31T09:30:00Z", "link": "https://iam.example.com/settings/domains"}
	extra := map[string]map[string]any{
		TopicDomainVerified:           {"domain_id": "d1"},
		TopicDomainClaimExpiring:      {"domain_id": "d1", "expires_at": "2026-11-01T09:30:00Z"},
		TopicDomainClaimReleased:      {"domain_id": "d1", "reason": "verified_elsewhere"},
		TopicDomainVerificationLapsed: {"domain_id": "d1", "reason": "parent_lapsed", "expires_at": "2026-11-07T09:30:00Z"},
		TopicDomainTransferRequested:  {"reason": "merger", "dns_name": "_iam.example.com", "dns_value": "abc", "expires_at": "2026-11-07T09:30:00Z"},
		TopicDomainTransferred:        {"domain_id": "d1", "reason": "merger", "direction": "from"},
		TopicDomainRevoked:            {"domain_id": "d1", "reason": "dispute"},
	}
	for topic, fields := range extra {
		data := map[string]any{}
		for k, v := range base {
			data[k] = v
		}
		for k, v := range fields {
			data[k] = v
		}
		if errs := ValidateData(topic, data); len(errs) != 0 {
			t.Errorf("%s: %v", topic, errs)
		}
		delete(data, "domain")
		if errs := ValidateData(topic, data); len(errs) != 1 || errs[0].Field != "data.domain" {
			t.Errorf("%s without domain: %v", topic, errs)
		}
	}
}

// The workspace request topics take IAM's TenantSignupNotice as each is
// sent: the common fields, then each topic's own (omitempty ones optional).
func TestTenantSignupTopics(t *testing.T) {
	base := map[string]any{"email": "founder@averox-labs.example", "user": map[string]any{"name": "Sara Ahmed"},
		"request_id": "r1", "organization_name": "Averox Labs", "occurred_at": "2026-10-31T09:30:00Z"}
	cases := map[string]struct {
		extra    map[string]any
		required string
	}{
		TopicTenantSignupEmailVerification: {map[string]any{"verify_link": "https://iam.example.com/signup/workspace/verify#token=t",
			"expires_at": "2026-11-01T09:30:00Z"}, "verify_link"},
		TopicTenantSignupApproved: {map[string]any{"workspace_name": "Averox Labs", "workspace_slug": "averox-labs",
			"link": "https://iam.example.com/login"}, "link"},
		TopicTenantSignupRejected: {map[string]any{}, "request_id"},
		TopicTenantSignupReviewRequested: {map[string]any{"email": "platform-admin@example.com",
			"user": map[string]any{"name": "Platform administrator"}, "workspace_name": "Averox Labs", "workspace_slug": "averox-labs",
			"requester_email": "founder@averox-labs.example", "requester_name": "Sara Ahmed", "domain": "averox-labs.example",
			"expires_at": "2026-11-07T09:30:00Z", "link": "https://iam.example.com/platform/workspace-requests?request=r1"}, "requester_email"},
	}
	for topic, c := range cases {
		data := map[string]any{}
		for k, v := range base {
			data[k] = v
		}
		for k, v := range c.extra {
			data[k] = v
		}
		if errs := ValidateData(topic, data); len(errs) != 0 {
			t.Errorf("%s: valid notice refused: %v", topic, errs)
		}
		if tp, ok := TopicByKey(topic); !ok || tp.Source != SourceIAM {
			t.Errorf("%s: %+v", topic, tp)
		}
		delete(data, c.required)
		if errs := ValidateData(topic, data); len(errs) != 1 || errs[0].Field != "data."+c.required {
			t.Errorf("%s without %s: %v", topic, c.required, errs)
		}
	}
	// A rejection without a reason is still sent; a bad optional value is not.
	bad := map[string]any{"email": "a@example.com", "request_id": "r1", "organization_name": "o", "occurred_at": "2026-10-31T09:30:00Z",
		"expires_at": "tomorrow", "verify_link": "https://iam.example.com/v"}
	if errs := ValidateData(TopicTenantSignupEmailVerification, bad); len(errs) != 1 || errs[0].Field != "data.expires_at" {
		t.Errorf("bad expiry: %v", errs)
	}
}
