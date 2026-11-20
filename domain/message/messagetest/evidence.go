// Package messagetest holds test doubles for the message domain's ports.
package messagetest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// Evidence is an in-memory evidence key (message.Evidence): HMAC-SHA-256
// under one fixed key, named KeyID.
type Evidence struct{}

// KeyID names the test evidence key.
const KeyID = "test-evidence"

var key = []byte("messagetest evidence key 0123456789")

func mac(in []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(in)
	return m.Sum(nil)
}

// MAC implements message.Evidence.
func (Evidence) MAC(_ context.Context, inputs ...[]byte) (string, [][]byte, error) {
	out := make([][]byte, len(inputs))
	for i, in := range inputs {
		out[i] = mac(in)
	}
	return KeyID, out, nil
}

// VerifyMAC implements message.Evidence.
func (Evidence) VerifyMAC(_ context.Context, kid string, input, m []byte) (bool, error) {
	if kid != KeyID {
		return false, fmt.Errorf("unknown evidence key %q", kid)
	}
	return hmac.Equal(mac(input), m), nil
}
