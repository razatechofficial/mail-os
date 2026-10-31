package sendingdomain

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func newDomain(t *testing.T) (*Domain, Secrets) {
	t.Helper()
	d, s, err := New("org-1", " Mail.Example.COM. ", Options{SPFIncludes: []string{"amazonses.com", "", "amazonses.com"}, DMARCReportTo: "dmarc@example.com"}, now)
	if err != nil {
		t.Fatal(err)
	}
	return d, s
}

func TestNewGeneratesMatchingRSA2048Key(t *testing.T) {
	d, s := newDomain(t)
	if d.Name != "mail.example.com" || d.Status != StatusPending || d.DKIMSelector != DefaultSelector {
		t.Fatalf("domain: %+v", d)
	}
	key, err := ParsePrivateKey(s.DKIMPrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 2048 {
		t.Fatalf("bits %d", key.N.BitLen())
	}
	der, _ := base64.StdEncoding.DecodeString(d.DKIMPublicKey)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil || !pub.(*rsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("published key does not match the private key")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", s, s), "PRIVATE") {
		t.Fatal("secrets printed")
	}
}

func TestRecords(t *testing.T) {
	d, _ := newDomain(t)
	r := d.Records()
	if r[0].Name != "mailos._domainkey.mail.example.com" || !strings.HasPrefix(r[0].Value, "v=DKIM1; k=rsa; p=MII") {
		t.Fatalf("dkim %+v", r[0])
	}
	if r[1].Value != "v=spf1 include:amazonses.com ~all" {
		t.Fatalf("spf %q", r[1].Value)
	}
	if r[2].Name != "_dmarc.mail.example.com" || r[2].Value != "v=DMARC1; p=none; adkim=r; aspf=r; rua=mailto:dmarc@example.com" {
		t.Fatalf("dmarc %+v", r[2])
	}
}

func TestNewRefusesBadInput(t *testing.T) {
	_, _, err := New("o", "localhost", Options{Selector: "bad selector", DMARCPolicy: "block", DMARCReportTo: "a@b;c", SPFIncludes: []string{"-x"}}, now)
	if got := len(apperrors.DetailsOf(err)); got != 5 {
		t.Fatalf("want 5 field errors, got %d: %v", got, apperrors.DetailsOf(err))
	}
}

func TestEvaluateAndApplyCheck(t *testing.T) {
	d, s := newDomain(t)
	if _, ok := d.SigningKey(s); ok {
		t.Fatal("a pending domain signs")
	}
	// The key split into several strings with spaces, as DNS UIs do.
	half := len(d.DKIMPublicKey) / 2
	dkim := []string{"v=DKIM1; k=rsa; p=" + d.DKIMPublicKey[:half] + " " + d.DKIMPublicKey[half:]}
	c := d.Evaluate(dkim, []string{"google-site-verification=x", "v=spf1 include:_spf.google.com include:amazonses.com -all"}, nil)
	if !c.Verified() || c.DMARC {
		t.Fatalf("check %+v", c)
	}
	d.ApplyCheck(c, now)
	if d.Status != StatusVerified || d.VerifiedAt == nil {
		t.Fatalf("status %s", d.Status)
	}
	if k, ok := d.SigningKey(s); !ok || k.Domain != "mail.example.com" || k.Selector != "mailos" || strings.Contains(k.String(), "PRIVATE") {
		t.Fatalf("signing key %v %v", k, ok)
	}

	c = d.Evaluate(dkim, []string{"v=spf1 include:_spf.google.com ~all"}, nil)
	if c.SPF || c.Reason == "" {
		t.Fatalf("spf without the include passed: %+v", c)
	}
	d.ApplyCheck(c, now.Add(time.Hour))
	if d.Status != StatusFailed || d.FailureReason == "" {
		t.Fatalf("a verified domain whose records broke is %s", d.Status)
	}
	if _, ok := d.SigningKey(s); ok {
		t.Fatal("a failed domain signs")
	}
}

func TestPendingStaysPendingOnFailedCheck(t *testing.T) {
	d, _ := newDomain(t)
	d.ApplyCheck(d.Evaluate(nil, nil, nil), now)
	if d.Status != StatusPending || d.LastCheckedAt == nil {
		t.Fatalf("status %s", d.Status)
	}
}

func TestRotateDKIM(t *testing.T) {
	d, s := newDomain(t)
	d.ApplyCheck(Check{DKIM: true, SPF: true}, now)
	old := d.DKIMPublicKey
	if _, err := d.RotateDKIM("mailos", now); err == nil {
		t.Fatal("rotation to the same selector accepted")
	}
	s2, err := d.RotateDKIM("mailos2", now)
	if err != nil {
		t.Fatal(err)
	}
	if d.DKIMPublicKey == old || s2.DKIMPrivateKeyPEM == s.DKIMPrivateKeyPEM || d.Status != StatusPending || d.VerifiedAt != nil {
		t.Fatal("rotation did not replace the key and reset verification")
	}
}

func TestParsePrivateKeyRefusesWeakOrJunk(t *testing.T) {
	if _, err := ParsePrivateKey("junk"); err != ErrInvalidKey {
		t.Fatal(err)
	}
}

func TestFromDomain(t *testing.T) {
	if FromDomain("Bob@Mail.Example.com") != "mail.example.com" || FromDomain("nobody") != "" {
		t.Fatal("from domain")
	}
}
