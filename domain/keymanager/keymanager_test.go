package keymanager

import (
	"testing"
	"time"
)

func TestCiphertextFormat(t *testing.T) {
	kid, _ := NewKID()
	s := FormatCiphertext(kid, []byte{1, 2, 3})
	gotKID, sealed, err := ParseCiphertext(s)
	if err != nil || gotKID != kid || len(sealed) != 3 {
		t.Fatalf("round trip: %q %v %v", gotKID, sealed, err)
	}
	for _, bad := range []string{"", "plain secret", "km0." + kid + ".AQID", "km1..AQID", "km1.a b c d e f.AQID", "km1." + kid + ".", "km1." + kid + ".!!"} {
		if IsCiphertext(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if string(AdditionalData(PurposeDKIM, kid)) == string(AdditionalData(PurposeProvider, kid)) {
		t.Fatal("additional data does not bind the purpose")
	}
}

func TestDue(t *testing.T) {
	now := time.Now()
	k := EncryptionKey{State: StateActive, CreatedAt: now.Add(-48 * time.Hour)}
	if !k.Due(now, 24*time.Hour) || k.Due(now, 0) || k.Due(now, 72*time.Hour) {
		t.Fatal("cryptoperiod")
	}
	k.State = StateRetired
	if k.Due(now, time.Hour) {
		t.Fatal("a retired key is never due")
	}
}
