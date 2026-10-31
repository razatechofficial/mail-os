package application

import (
	"errors"
	"fmt"
	"testing"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func validServer() Application {
	return Application{Name: "Core banking", Kind: KindServer, ClientID: "core-banking", Status: StatusActive,
		Environment: EnvLive, Stream: StreamTransactional, MessageTypes: []string{"bank.otp.*", "welcome"},
		Senders: []string{"otp@bank.example", "*@alerts.bank.example"}, DefaultFromEmail: "otp@bank.example",
		RatePerMinute: 60, DailyQuota: 1000}
}

func validSPA() Application {
	a := validServer()
	a.Kind, a.ClientID = KindSPA, "portal-web"
	a.MessageTypes = []string{"verify-email", "bank.otp.*"}
	a.BrowserTemplates = []string{"verify-email"}
	a.UserRatePerHour = 5
	a.AllowedOrigins = []string{"https://portal.bank.example"}
	return a
}

func fields(err error) map[string]string {
	out := map[string]string{}
	for _, d := range apperrors.DetailsOf(err) {
		out[d.Field] = d.Code
	}
	return out
}

func TestMatches(t *testing.T) {
	for _, c := range []struct {
		pattern, key string
		want         bool
	}{
		{"bank.otp.*", "bank.otp.login", true},
		{"bank.otp.*", "bank.otp", false},
		{"bank.otp.*", "bank.otpx.login", false},
		{"welcome", "welcome", true},
		{"welcome", "welcome-2", false},
		{"raw", "raw", true},
		{"iam.*", "", false},
	} {
		if got := Matches(c.pattern, c.key); got != c.want {
			t.Errorf("Matches(%q, %q) = %v", c.pattern, c.key, got)
		}
	}
	a := validServer()
	if !a.AllowsType("", "welcome") || !a.AllowsType("bank.otp.reset") || a.AllowsType("iam.auth.login", "other") {
		t.Fatal("AllowsType")
	}
	if a.AllowsRaw() {
		t.Fatal("raw is allowed only when listed")
	}
	a.MessageTypes = append(a.MessageTypes, "raw")
	if !a.AllowsRaw() {
		t.Fatal("raw listed")
	}
}

func TestValidPatternRefusesWildcards(t *testing.T) {
	for _, p := range []string{"*", ".*", "bank.*.otp", "Bank.OTP", "bank otp", ""} {
		if ValidPattern(p) {
			t.Errorf("%q accepted", p)
		}
	}
	for _, p := range []string{"raw", "iam.*", "welcome-email", "bank.otp.login"} {
		if !ValidPattern(p) {
			t.Errorf("%q refused", p)
		}
	}
}

func TestAllowsSender(t *testing.T) {
	a := validServer()
	for from, want := range map[string]bool{
		"otp@bank.example":          true,
		"OTP@Bank.Example":          true,
		"news@alerts.bank.example":  true,
		"x@sub.alerts.bank.example": false,
		"other@bank.example":        false,
		"otp@bank.example.evil":     false,
		"no-at-sign":                false,
	} {
		if got := a.AllowsSender(from); got != want {
			t.Errorf("AllowsSender(%q) = %v", from, got)
		}
	}
}

func TestValidateServer(t *testing.T) {
	a := validServer()
	a.Normalize()
	if err := a.Validate(false); err != nil {
		t.Fatal(err)
	}
	bad := Application{Kind: "worker", Status: "on", Environment: "prod", Stream: "bulk", MessageTypes: []string{"*"},
		Senders: []string{"not an address"}, DefaultFromEmail: "x@y.example", RatePerMinute: 0, DailyQuota: MaxDailyQuota + 1,
		BrowserTemplates: []string{"verify"}}
	got := fields(bad.Validate(false))
	for _, f := range []string{"name", "kind", "client_id", "status", "environment", "stream", "message_types", "senders",
		"default_from_email", "rate_limit_per_minute", "daily_quota", "browser_templates"} {
		if got[f] == "" {
			t.Errorf("no error for %s: %v", f, got)
		}
	}
}

func TestValidateZeroLimitsOnlyForSystem(t *testing.T) {
	a := validServer()
	a.RatePerMinute, a.DailyQuota = 0, 0
	if err := a.Validate(false); err == nil {
		t.Fatal("unlimited tenant application accepted")
	}
	a.System = true
	if err := a.Validate(false); err != nil {
		t.Fatalf("system application: %v", err)
	}
	a.Kind = KindSPA
	if fields(a.Validate(false))["kind"] == "" {
		t.Fatal("a system spa accepted")
	}
}

func TestValidateSPA(t *testing.T) {
	a := validSPA()
	if err := a.Validate(false); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Application){
		"browser_templates": func(a *Application) { a.BrowserTemplates = []string{"not-allowed-type"} },
		"message_types":     func(a *Application) { a.MessageTypes = append(a.MessageTypes, RawType) },
		"default_from_email": func(a *Application) {
			a.DefaultFromEmail = ""
		},
		"user_rate_limit_per_hour": func(a *Application) { a.UserRatePerHour = 0 },
		"allowed_origins":          func(a *Application) { a.AllowedOrigins = []string{"http://portal.bank.example"} },
	} {
		b := validSPA()
		mutate(&b)
		if fields(b.Validate(false))[name] == "" {
			t.Errorf("%s: no error", name)
		}
	}
	b := validSPA()
	b.AllowedOrigins = []string{"http://localhost:3000"}
	if err := b.Validate(true); err != nil {
		t.Fatalf("plaintext origin in local: %v", err)
	}
	b.AllowedOrigins = []string{"https://portal.bank.example/path"}
	if fields(b.Validate(true))["allowed_origins"] == "" {
		t.Fatal("origin with a path accepted")
	}
	if !validSPA().AllowsBrowserTemplate("verify-email") || validSPA().AllowsBrowserTemplate("bank-otp") {
		t.Fatal("AllowsBrowserTemplate")
	}
	if !validSPA().AllowsOrigin("https://Portal.bank.example/") || validSPA().AllowsOrigin("https://evil.example") {
		t.Fatal("AllowsOrigin")
	}
}

func TestNormalize(t *testing.T) {
	a := Application{Name: " App ", MessageTypes: []string{" Welcome ", "welcome", ""}, Senders: []string{"A@B.example"},
		AllowedOrigins: []string{"https://X.example/"}}
	a.Normalize()
	if a.Name != "App" || len(a.MessageTypes) != 1 || a.MessageTypes[0] != "welcome" || a.Senders[0] != "a@b.example" ||
		a.AllowedOrigins[0] != "https://x.example" {
		t.Fatalf("%+v", a)
	}
}

func TestReasons(t *testing.T) {
	for e, want := range reasons {
		if got := Reason(fmt.Errorf("wrapped: %w", e)); got != want {
			t.Errorf("Reason(%v) = %q, want %q", e, got, want)
		}
	}
	if Reason(errors.New("other")) != "" {
		t.Fatal("unknown error has a reason")
	}
	if !IsLimit(ErrQuotaExceeded) || IsLimit(ErrSuspended) || !Identity(ErrUnknownClient) || Identity(ErrTypeNotAllowed) {
		t.Fatal("classification")
	}
}
