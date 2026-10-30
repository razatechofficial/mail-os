package provider

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func fields(err error) []string {
	var out []string
	for _, d := range apperrors.DetailsOf(err) {
		out = append(out, d.Field+":"+d.Code)
	}
	return out
}

func smtpProvider() Provider {
	p := Provider{Name: "Relay", Kind: KindSMTP, Weight: DefaultWeight, Settings: Settings{
		Host: " SMTP.Example.com ", Port: 587, Username: "mailer", FromEmail: "noreply@example.com",
	}}
	p.Normalize()
	return p
}

func TestValidateAcceptsEachKind(t *testing.T) {
	cases := []Provider{
		smtpProvider(),
		{Name: "SES", Kind: KindSES, Settings: Settings{Region: "eu-west-1", ConfigurationSet: "events"}},
		{Name: "SG", Kind: KindSendGrid, Settings: Settings{Region: "eu"}},
		{Name: "MG", Kind: KindMailgun, Settings: Settings{Domain: "mg.example.com", BaseURL: MailgunEU}},
		{Name: "PM", Kind: KindPostmark, Settings: Settings{MessageStream: "otp-stream"}},
	}
	for _, p := range cases {
		if err := p.Validate(false); err != nil {
			t.Errorf("%s: %v %v", p.Kind, err, fields(err))
		}
	}
	if got := cases[0].Settings; got.Host != "smtp.example.com" || got.TLSMode != TLSStartTLS {
		t.Fatalf("normalize: %+v", got)
	}
}

func TestValidateRefusesBadSettings(t *testing.T) {
	cases := []struct {
		p    Provider
		want []string
	}{
		{Provider{Kind: "fax"}, []string{"name:required", "kind:invalid"}},
		{Provider{Name: "x", Kind: KindSMTP, Settings: Settings{Host: "bad host", Port: 0, TLSMode: "ssl"}},
			[]string{"settings.host:invalid", "settings.port:out_of_range", "settings.tls_mode:invalid"}},
		{Provider{Name: "x", Kind: KindSMTP, Settings: Settings{Host: "h.example", Port: 25, TLSMode: TLSNone}},
			[]string{"settings.tls_mode:plaintext_refused"}},
		{Provider{Name: "x", Kind: KindSES, Settings: Settings{Region: "europe", Host: "h.example"}},
			[]string{"settings.host:not_allowed", "settings.region:invalid"}},
		{Provider{Name: "x", Kind: KindMailgun, Settings: Settings{Domain: "mg.example.com", BaseURL: "https://attacker.example"}},
			[]string{"settings.base_url:invalid"}},
		{Provider{Name: "x", Kind: KindPostmark, Priority: 101, Weight: -1, DailyLimit: -1, Settings: Settings{FromEmail: "Bob <b@example.com>"}},
			[]string{"priority:out_of_range", "weight:out_of_range", "daily_limit:out_of_range", "settings.from_email:invalid"}},
		{Provider{Name: "x", Kind: KindSendGrid, Settings: Settings{Region: "us", Domain: "x.example"}},
			[]string{"settings.domain:not_allowed", "settings.region:invalid"}},
	}
	for i, c := range cases {
		err := c.p.Validate(false)
		if apperrors.KindOf(err) != apperrors.KindInvalidInput {
			t.Fatalf("case %d: kind %v (%v)", i, apperrors.KindOf(err), err)
		}
		got := fields(err)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("case %d: missing %s in %v", i, w, got)
			}
		}
	}
}

func TestPlaintextSMTPOnlyWhenAllowed(t *testing.T) {
	p := Provider{Name: "MailHog", Kind: KindSMTP, Settings: Settings{Host: "127.0.0.1", Port: 1025, TLSMode: TLSNone}}
	if err := p.Validate(true); err != nil {
		t.Fatalf("plaintext refused where allowed: %v", fields(err))
	}
	if err := p.Validate(false); err == nil {
		t.Fatal("plaintext accepted where refused")
	}
}

func TestValidateCredentialsPerKind(t *testing.T) {
	ok := map[Kind]Credentials{
		KindSMTP:     {},
		KindSES:      {AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"},
		KindSendGrid: {APIKey: "SG.key"},
		KindMailgun:  {APIKey: "key-1"},
		KindPostmark: {ServerToken: "tok"},
	}
	for k, c := range ok {
		if err := ValidateCredentials(k, c); err != nil {
			t.Errorf("%s: %v", k, fields(err))
		}
	}
	err := ValidateCredentials(KindSES, Credentials{AccessKeyID: "AKIA", APIKey: "x"})
	got := fields(err)
	for _, w := range []string{"credentials.secret_access_key:required", "credentials.api_key:not_allowed"} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	if err := ValidateCredentials(KindPostmark, Credentials{ServerToken: "a\r\nb"}); err == nil {
		t.Fatal("a token with a line break was accepted")
	}
}

func TestCredentialsNeverPrinted(t *testing.T) {
	c := Credentials{Password: "hunter2-password", APIKey: "SG.abcdefghijklmnop1234"}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s", c, c, c, c)} {
		if strings.Contains(s, "hunter2") || strings.Contains(s, "SG.abc") {
			t.Fatalf("credentials printed: %s", s)
		}
	}
}

func TestViewIsRedacted(t *testing.T) {
	p := smtpProvider()
	p.Kind = KindSendGrid
	c := Credentials{APIKey: "SG.abcdefghijklmnop1234", Password: "longpassword-should-not-hint"}
	p.SetCredentials(c)
	b, err := json.Marshal(p.View())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "SG.abc") || strings.Contains(s, "longpassword") {
		t.Fatalf("secret in view: %s", s)
	}
	if !strings.Contains(s, `"has_credentials":true`) || !strings.Contains(s, `"api_key":"…1234"`) {
		t.Fatalf("view lacks hints: %s", s)
	}
	if h := (Credentials{APIKey: "short-key"}).Hints(); h != nil {
		t.Fatalf("short key hinted: %v", h)
	}
}

func TestMergeKeepsStoredSecrets(t *testing.T) {
	stored := Credentials{AccessKeyID: "AKIA1", SecretAccessKey: "s1"}
	got := stored.Merge(Credentials{AccessKeyID: "AKIA2"})
	if got.AccessKeyID != "AKIA2" || got.SecretAccessKey != "s1" {
		t.Fatalf("merge: %#v", got.AccessKeyID+"/"+got.SecretAccessKey)
	}
}

func TestDailyLimit(t *testing.T) {
	p := Provider{DailyLimit: 2}
	if !p.UnderDailyLimit(1) || p.UnderDailyLimit(2) {
		t.Fatal("daily limit")
	}
	if !(&Provider{}).UnderDailyLimit(1 << 30) {
		t.Fatal("0 is unlimited")
	}
}

func TestSPFIncludes(t *testing.T) {
	if KindSES.SPFInclude() != "amazonses.com" || KindSMTP.SPFInclude() != "" {
		t.Fatal("spf includes")
	}
}
