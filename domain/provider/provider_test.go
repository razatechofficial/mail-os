package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

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

func testKeyPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mailos"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

func TestValidateAcceptsEachKind(t *testing.T) {
	cases := []Provider{
		smtpProvider(),
		{Name: "SES", Kind: KindSES, Settings: Settings{Region: "eu-west-1", ConfigurationSet: "events"}},
		{Name: "SG", Kind: KindSendGrid, Settings: Settings{Region: "eu"}},
		{Name: "MG", Kind: KindMailgun, Settings: Settings{Domain: "mg.example.com", Region: RegionEU}},
		{Name: "PM", Kind: KindPostmark, Settings: Settings{MessageStream: "otp-stream"}},
		{Name: "Graph", Kind: KindMSGraph, Settings: Settings{TenantID: "contoso.onmicrosoft.com",
			ClientID: "11111111-2222-3333-4444-555555555555", Sender: "noreply@bank.example"}},
		{Name: "Gmail", Kind: KindGmail, Settings: Settings{Sender: "noreply@bank.example"}},
		{Name: "ACS", Kind: KindACS, Settings: Settings{Endpoint: "https://bank.unitedstates.communication.azure.com/"}},
		{Name: "SP", Kind: KindSparkPost},
		{Name: "Brevo", Kind: KindBrevo},
		{Name: "MJ", Kind: KindMailjet},
		{Name: "Mandrill", Kind: KindMandrill, Settings: Settings{Subaccount: "otp"}},
		{Name: "Resend", Kind: KindResend},
	}
	for i := range cases {
		p := &cases[i]
		p.Normalize()
		if err := p.Validate(false); err != nil {
			t.Errorf("%s: %v %v", p.Kind, err, fields(err))
		}
	}
	if got := cases[0].Settings; got.Host != "smtp.example.com" || got.TLSMode != TLSStartTLS || got.AuthMechanism != AuthPlain {
		t.Fatalf("normalize: %+v", got)
	}
	if got := cases[7].Settings.Endpoint; got != "https://bank.unitedstates.communication.azure.com" {
		t.Fatalf("endpoint not normalised: %s", got)
	}
	if len(cases) != len(Kinds) {
		t.Fatalf("a kind is not covered: %d of %d", len(cases), len(Kinds))
	}
}

func TestValidateRefusesBadSettings(t *testing.T) {
	cases := []struct {
		p    Provider
		want []string
	}{
		{Provider{Kind: "fax"}, []string{"name:required", "kind:invalid"}},
		{Provider{Name: "x", Kind: KindSMTP, Settings: Settings{Host: "bad host", Port: 0, TLSMode: "ssl"}},
			[]string{"settings.host:invalid", "settings.port:required", "settings.tls_mode:invalid"}},
		{Provider{Name: "x", Kind: KindSMTP, Settings: Settings{Host: "h.example", Port: 70000, TLSMode: TLSNone, Preset: "nope"}},
			[]string{"settings.tls_mode:plaintext_refused", "settings.port:out_of_range", "settings.preset:invalid"}},
		{Provider{Name: "x", Kind: KindSES, Settings: Settings{Region: "europe", Host: "h.example"}},
			[]string{"settings.host:not_allowed", "settings.region:invalid"}},
		{Provider{Name: "x", Kind: KindMailgun, Settings: Settings{Domain: "mg.example.com", Region: "attacker"}},
			[]string{"settings.region:invalid"}},
		{Provider{Name: "x", Kind: KindPostmark, Priority: 101, Weight: -1, DailyLimit: -1, Settings: Settings{FromEmail: "Bob <b@example.com>"}},
			[]string{"priority:out_of_range", "weight:out_of_range", "daily_limit:out_of_range", "settings.from_email:invalid"}},
		{Provider{Name: "x", Kind: KindSendGrid, Settings: Settings{Region: "us", Domain: "x.example"}},
			[]string{"settings.domain:not_allowed", "settings.region:invalid"}},
		{Provider{Name: "x", Kind: KindMSGraph, Settings: Settings{ClientID: "not-a-guid", AuthMethod: MicrosoftCertificate, ClientCertificate: "junk"}},
			[]string{"settings.tenant_id:required", "settings.client_id:invalid", "settings.sender:required", "settings.client_certificate:invalid"}},
		{Provider{Name: "x", Kind: KindACS, Settings: Settings{Endpoint: "https://attacker.example"}},
			[]string{"settings.endpoint:invalid"}},
		{Provider{Name: "x", Kind: KindSMTP, Settings: Settings{Host: "h.example", Port: 587, HELOName: "two\nlines"}},
			[]string{"settings.helo_name:invalid"}},
	}
	for i, c := range cases {
		c.p.Normalize()
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

func TestNormalizeDropsSettingsThatNoLongerApply(t *testing.T) {
	p := Provider{Name: "x", Kind: KindSMTP, Settings: Settings{Host: "h.example", Port: 587, AuthMechanism: AuthNone,
		Username: "stale", OAuthProvider: OAuthMicrosoft, TenantID: "contoso.example"}}
	p.Normalize()
	if s := p.Settings; s.Username != "" || s.OAuthProvider != "" || s.TenantID != "" {
		t.Fatalf("stale settings kept: %+v", s)
	}
	p.Settings.AuthMechanism = AuthXOAUTH2
	p.Settings.Username = "Box@Bank.example"
	p.Normalize()
	if s := p.Settings; s.OAuthProvider != OAuthMicrosoft || s.AuthMethod != MicrosoftSecret {
		t.Fatalf("select defaults not filled: %+v", s)
	}
	if err := p.Validate(false); !slices.Contains(fields(err), "settings.tenant_id:required") {
		t.Fatalf("xoauth2 without tenant: %v", fields(err))
	}
}

func TestPlaintextSMTPOnlyWhenAllowed(t *testing.T) {
	p := Provider{Name: "MailHog", Kind: KindSMTP, Settings: Settings{Host: "127.0.0.1", Port: 1025, TLSMode: TLSNone, AuthMechanism: AuthNone}}
	if err := p.Validate(true); err != nil {
		t.Fatalf("plaintext refused where allowed: %v", fields(err))
	}
	if err := p.Validate(false); err == nil {
		t.Fatal("plaintext accepted where refused")
	}
}

func TestValidateCredentialsPerKind(t *testing.T) {
	cert, key := testKeyPEM(t)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "svc@proj.iam.gserviceaccount.com",
		"private_key": key, "private_key_id": "k1", "token_uri": GoogleTokenURI})
	ok := []struct {
		kind Kind
		s    Settings
		c    Credentials
	}{
		{KindSMTP, Settings{AuthMechanism: AuthNone}, Credentials{}},
		{KindSMTP, Settings{AuthMechanism: AuthPlain, ClientCert: cert}, Credentials{Password: "p", ClientKey: key}},
		{KindSMTP, Settings{AuthMechanism: AuthXOAUTH2, OAuthProvider: OAuthGoogle}, Credentials{ServiceAccountJSON: string(sa)}},
		{KindSES, Settings{}, Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}},
		{KindSendGrid, Settings{}, Credentials{APIKey: "SG.key"}},
		{KindMailgun, Settings{}, Credentials{APIKey: "key-1"}},
		{KindPostmark, Settings{}, Credentials{ServerToken: "tok"}},
		{KindMSGraph, Settings{AuthMethod: MicrosoftSecret}, Credentials{ClientSecret: "s"}},
		{KindMSGraph, Settings{AuthMethod: MicrosoftCertificate}, Credentials{CertificateKey: key}},
		{KindGmail, Settings{}, Credentials{ServiceAccountJSON: string(sa)}},
		{KindACS, Settings{}, Credentials{AccessKey: "a2V5"}},
		{KindMailjet, Settings{}, Credentials{APIKey: "k", APISecret: "s"}},
	}
	for _, c := range ok {
		if err := ValidateCredentials(c.kind, c.s, c.c); err != nil {
			t.Errorf("%s: %v", c.kind, fields(err))
		}
	}
	bad := []struct {
		kind Kind
		s    Settings
		c    Credentials
		want []string
	}{
		{KindSES, Settings{}, Credentials{AccessKeyID: "AKIA", APIKey: "x"}, []string{"credentials.secret_access_key:required", "credentials.api_key:not_allowed"}},
		{KindPostmark, Settings{}, Credentials{ServerToken: "a\r\nb"}, []string{"credentials.server_token:invalid"}},
		{KindSMTP, Settings{AuthMechanism: AuthNone}, Credentials{Password: "p"}, []string{"credentials.password:not_allowed"}},
		{KindSMTP, Settings{AuthMechanism: AuthPlain, ClientCert: cert}, Credentials{Password: "p"}, []string{"credentials.client_key:required"}},
		{KindGmail, Settings{}, Credentials{ServiceAccountJSON: `{"type":"user"}`}, []string{"credentials.service_account_json:invalid"}},
		{KindMSGraph, Settings{AuthMethod: MicrosoftCertificate}, Credentials{CertificateKey: "nope"}, []string{"credentials.certificate_key:invalid"}},
	}
	for i, c := range bad {
		got := fields(ValidateCredentials(c.kind, c.s, c.c))
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("case %d: missing %s in %v", i, w, got)
			}
		}
	}
}

func TestPruneCredentials(t *testing.T) {
	c := PruneCredentials(KindSMTP, Settings{AuthMechanism: AuthXOAUTH2, OAuthProvider: OAuthMicrosoft, AuthMethod: MicrosoftSecret},
		Credentials{Password: "old", ClientSecret: "new", APIKey: "foreign"})
	if c.Password != "" || c.APIKey != "" || c.ClientSecret != "new" {
		t.Fatal("prune kept secrets that no longer apply")
	}
}

func TestDecode(t *testing.T) {
	s, err := DecodeSettings(map[string]any{"host": "h.example", "port": float64(587), "preset": "postfix"})
	if err != nil || s.Port != 587 || s.Preset != "postfix" {
		t.Fatalf("%+v %v", s, err)
	}
	_, err = DecodeSettings(map[string]any{"port": "587", "password": "x", "bogus": 1})
	got := fields(err)
	for _, w := range []string{"settings.port:invalid", "settings.password:unknown", "settings.bogus:unknown"} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	if _, err := DecodeCredentials(map[string]any{"host": "x", "api_key": 3}); len(fields(err)) != 2 {
		t.Fatalf("credentials decode: %v", fields(err))
	}
}

// credentialKeys are every key of Credentials.
var credentialKeys = []string{"password", "access_key_id", "secret_access_key", "api_key", "api_secret", "server_token",
	"client_secret", "certificate_key", "client_key", "service_account_json", "access_key", "webhook_secret"}

func TestSchemaIsConsistent(t *testing.T) {
	all := map[string]string{}
	for _, k := range credentialKeys {
		all[k] = "x"
	}
	if len(CredentialsFrom(all).Map()) != len(credentialKeys) {
		t.Fatal("credentialKeys out of step with Credentials")
	}
	for _, plain := range []bool{false, true} {
		cat := Schema(plain)
		if len(cat.Types) != len(Kinds) {
			t.Fatal("schema misses a kind")
		}
		for _, ts := range cat.Types {
			keys := map[string]bool{}
			for _, f := range ts.Fields {
				if keys[f.Key] {
					t.Errorf("%s: duplicate field %s", ts.Type, f.Key)
				}
				keys[f.Key] = true
				if f.Label == "" || !slices.ContainsFunc(ts.Groups, func(g Group) bool { return g.Key == f.Group }) {
					t.Errorf("%s.%s: label or group missing", ts.Type, f.Key)
				}
				if f.Type == FieldSelect && (len(f.Options) == 0 || f.Default != nil && !slices.ContainsFunc(f.Options, func(o Option) bool { return o.Value == f.Default })) {
					t.Errorf("%s.%s: select default is not an option", ts.Type, f.Key)
				}
				for _, c := range f.VisibleWhen {
					if !keys[c.Field] {
						t.Errorf("%s.%s: condition on a later or unknown field %s", ts.Type, f.Key, c.Field)
					}
				}
				if v := f.Validation; v != nil && v.Pattern != "" {
					regexp.MustCompile(v.Pattern)
				}
				// The secret flag must agree with the struct the value lands in.
				if f.Secret != slices.Contains(credentialKeys, f.Key) {
					t.Errorf("%s.%s: secret flag does not match Credentials", ts.Type, f.Key)
				}
				if !f.Secret {
					if _, err := DecodeSettings(map[string]any{f.Key: nil}); err != nil {
						t.Errorf("%s.%s: not a Settings key", ts.Type, f.Key)
					}
				}
			}
			for _, p := range ts.Presets {
				if p.Label == "" || p.Description == "" {
					t.Errorf("%s preset %s: label", ts.Type, p.ID)
				}
				for k := range p.Values {
					if !keys[k] {
						t.Errorf("%s preset %s: unknown key %s", ts.Type, p.ID, k)
					}
				}
			}
		}
		smtp := cat.Types[0]
		f, _ := smtp.Field("tls_mode")
		if hasNone := slices.ContainsFunc(f.Options, func(o Option) bool { return o.Value == TLSNone }); hasNone != plain {
			t.Errorf("plaintext option offered=%v with allowPlaintext=%v", hasNone, plain)
		}
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
	if !strings.Contains(s, `"has_credentials":true`) || !strings.Contains(s, `"api_key":"…1234"`) || !strings.Contains(s, `"password":""`) {
		t.Fatalf("view lacks hints: %s", s)
	}
	if h := (Credentials{APIKey: "short-key"}).Hints(); h["api_key"] != "" {
		t.Fatalf("short key hinted: %v", h)
	}
	if h := (Credentials{ServiceAccountJSON: `{"client_email":"svc@p.iam.gserviceaccount.com","private_key":"x"}`}).Hints(); h["service_account_json"] != "svc@p.iam.gserviceaccount.com" {
		t.Fatalf("service account hint: %v", h)
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
	if KindSES.SPFInclude() != "amazonses.com" || KindSMTP.SPFInclude() != "" || KindMSGraph.SPFInclude() != "spf.protection.outlook.com" {
		t.Fatal("spf includes")
	}
}
