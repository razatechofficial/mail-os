package keymanager

import (
	"context"
	"errors"
	"testing"

	"github.com/razatechofficial/mail-os/config"
)

func testOpener(t *testing.T, dev *fakeDevice, f *fakeKMS) *Opener {
	return &Opener{
		OpenDevice: func(c config.KeyManagerPKCS11) (Device, error) {
			if err := c.Validate(); err != nil {
				return nil, err
			}
			return dev, nil
		},
		OpenKMS: func(context.Context, config.KeyManagerKMS) (RemoteKEKService, error) {
			if f == nil {
				return nil, errors.New("kms: no AWS region")
			}
			return NewAWSKMS(f.client()), nil
		},
	}
}

var testHSM = config.KeyManagerPKCS11{ModulePath: "/usr/lib/softhsm/libsofthsm2.so", TokenLabel: "mailos", PIN: "1234", KEKLabel: "mailos-kek"}

func TestOpenBuildsTheConfiguredKEKs(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS(t)
	arn := f.addKEK("mailos-kek")
	newARN := f.addKEK("mailos-kek-2027")
	sw, _ := NewSoftwareKEK("KEY_MANAGER_MASTER_KEY", masterKeyB64(1))
	hsm := testHSM
	hsm.NewKEKLabel = "mailos-kek-2027"
	cases := []struct {
		name          string
		cfg           config.KeyManager
		current, next string
	}{
		{"software", config.KeyManager{Provider: "software", MasterKey: masterKeyB64(1)}, sw.ID(), ""},
		{"software into the HSM", config.KeyManager{Provider: "software", MasterKey: masterKeyB64(1), PKCS11: hsm}, sw.ID(), "pkcs11:mailos-kek-2027"},
		{"pkcs11", config.KeyManager{Provider: "pkcs11", PKCS11: testHSM}, "pkcs11:mailos-kek", ""},
		{"new HSM key", config.KeyManager{Provider: "pkcs11", PKCS11: hsm}, "pkcs11:mailos-kek", "pkcs11:mailos-kek-2027"},
		{"kms", config.KeyManager{Provider: "kms", KMS: config.KeyManagerKMS{KEKKeyID: "alias/mailos-kek"}}, "kms:" + arn, ""},
		{"new KMS key", config.KeyManager{Provider: "kms", KMS: config.KeyManagerKMS{KEKKeyID: "alias/mailos-kek", NewKEKKeyID: "alias/mailos-kek-2027"}},
			"kms:" + arn, "kms:" + newARN},
		{"kms back to software", config.KeyManager{Provider: "kms", NewMasterKey: masterKeyB64(1), KMS: config.KeyManagerKMS{KEKKeyID: "alias/mailos-kek"}},
			"kms:" + arn, sw.ID()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dev := newFakeDevice()
			keks, closeKEKs, err := testOpener(t, dev, f).Open(ctx, c.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if keks.Current().ID() != c.current || keks.Wrapping().ID() != c.current {
				t.Fatalf("current %q", keks.Current().ID())
			}
			next := ""
			if keks.Next() != nil {
				next = keks.Next().ID()
			}
			if next != c.next {
				t.Fatalf("next %q, want %q", next, c.next)
			}
			closeKEKs()
			if c.cfg.Provider == "pkcs11" && !dev.closed {
				t.Fatal("HSM session not closed")
			}
		})
	}
}

// A provider that cannot be reached stops the server: no fallback.
func TestOpenRefuses(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS(t)
	cases := map[string]config.KeyManager{
		"bad master key":      {Provider: "software", MasterKey: "c2hvcnQ="},
		"unknown provider":    {Provider: "vault"},
		"HSM without PIN":     {Provider: "pkcs11", PKCS11: config.KeyManagerPKCS11{ModulePath: "/lib/x.so", TokenLabel: "t"}},
		"KMS unreachable":     {Provider: "kms", KMS: config.KeyManagerKMS{KEKKeyID: "alias/x"}},
		"KMS key not found":   {Provider: "kms", KMS: config.KeyManagerKMS{KEKKeyID: "alias/missing"}},
		"new KEK not working": {Provider: "software", MasterKey: masterKeyB64(1), KMS: config.KeyManagerKMS{NewKEKKeyID: "alias/missing"}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			kms := f
			if name == "KMS unreachable" {
				kms = nil
			}
			dev := newFakeDevice()
			if _, _, err := testOpener(t, dev, kms).Open(ctx, cfg); err == nil {
				t.Fatal("opened")
			}
		})
	}
}
