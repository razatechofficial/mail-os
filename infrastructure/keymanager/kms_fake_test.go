package keymanager

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// fakeKMS is an AWS KMS endpoint speaking the awsJson1_1 protocol over
// in-memory symmetric keys, so AWSKMS is tested through the real SDK
// client: request signing, serialization and error mapping (after IAM's
// kms_fake_test.go). A ciphertext blob names its key, as KMS's does.
type fakeKMS struct {
	srv *httptest.Server

	mu       sync.Mutex
	keys     map[string]*fakeKMSKey // by ARN
	aliases  map[string]string
	requests []fakeKMSRequest
}

type fakeKMSKey struct {
	arn, spec, usage, state string
	aead                    cipher.AEAD
}

type fakeKMSRequest struct {
	Op   string
	Body map[string]any
}

const fakeKMSAccount = "arn:aws:kms:me-central-1:000000000000:key/"

func newFakeKMS(t *testing.T) *fakeKMS {
	f := &fakeKMS{keys: map[string]*fakeKMSKey{}, aliases: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// client is a real KMS client pointed at the fake with test credentials.
func (f *fakeKMS) client() *kms.Client {
	return kms.New(kms.Options{
		Region:           "me-central-1",
		BaseEndpoint:     aws.String(f.srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("AKIDTEST", "test-secret", ""),
		RetryMaxAttempts: 1,
	})
}

// addKey creates a symmetric key and an alias/<id> alias for it.
func (f *fakeKMS) addKey(id, spec, usage string) string {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, _ := aes.NewCipher(k)
	a, _ := cipher.NewGCM(b)
	arn := fakeKMSAccount + id
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[arn] = &fakeKMSKey{arn: arn, spec: spec, usage: usage, state: "Enabled", aead: a}
	f.aliases["alias/"+id] = arn
	return arn
}

func (f *fakeKMS) addKEK(id string) string {
	return f.addKey(id, "SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT")
}

func (f *fakeKMS) setState(arn, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[arn].state = state
}

func (f *fakeKMS) calls(op string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, r := range f.requests {
		if r.Op == op {
			out = append(out, r.Body)
		}
	}
	return out
}

func (f *fakeKMS) serve(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		f.writeErr(w, "MissingAuthenticationTokenException", "request not signed")
		return
	}
	if r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
		f.writeErr(w, "SerializationException", "content type "+r.Header.Get("Content-Type"))
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.writeErr(w, "SerializationException", err.Error())
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, fakeKMSRequest{Op: op, Body: body})
	f.mu.Unlock()
	out, code, err := f.handle(op, body)
	if err != nil {
		f.writeErr(w, code, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeKMS) writeErr(w http.ResponseWriter, code, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": msg})
}

func fakeStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// fakeBlob decodes a JSON base64 blob the way the protocol encodes []byte.
func fakeBlob(m map[string]any, k string) []byte {
	var b []byte
	raw, _ := json.Marshal(m[k])
	_ = json.Unmarshal(raw, &b)
	return b
}

func (f *fakeKMS) find(id string) (*fakeKMSKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if arn, ok := f.aliases[id]; ok {
		id = arn
	}
	if !strings.HasPrefix(id, "arn:") {
		id = fakeKMSAccount + id
	}
	k, ok := f.keys[id]
	if !ok {
		return nil, fmt.Errorf("key %s does not exist", id)
	}
	return k, nil
}

// encryptionContext is the canonical form of the request's context, the
// additional data the fake binds ciphertexts to.
func encryptionContext(m map[string]any) []byte {
	ec, _ := m["EncryptionContext"].(map[string]any)
	b, _ := json.Marshal(ec) // keys sorted
	return b
}

func (f *fakeKMS) usable(k *fakeKMSKey) (string, error) {
	if k.state != "Enabled" {
		return "DisabledException", fmt.Errorf("%s is %s", k.arn, k.state)
	}
	if k.usage != "ENCRYPT_DECRYPT" {
		return "InvalidKeyUsageException", fmt.Errorf("%s is not for encryption", k.arn)
	}
	return "", nil
}

func (f *fakeKMS) handle(op string, b map[string]any) (any, string, error) {
	switch op {
	case "DescribeKey":
		k, err := f.find(fakeStr(b, "KeyId"))
		if err != nil {
			return nil, "NotFoundException", err
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		return map[string]any{"KeyMetadata": map[string]any{"KeyId": strings.TrimPrefix(k.arn, fakeKMSAccount), "Arn": k.arn,
			"KeySpec": k.spec, "KeyUsage": k.usage, "KeyState": k.state, "Enabled": k.state == "Enabled", "KeyManager": "CUSTOMER"}}, "", nil
	case "Encrypt":
		k, err := f.find(fakeStr(b, "KeyId"))
		if err != nil {
			return nil, "NotFoundException", err
		}
		if code, err := f.usable(k); err != nil {
			return nil, code, err
		}
		nonce := make([]byte, k.aead.NonceSize())
		_, _ = rand.Read(nonce)
		blob := append([]byte(k.arn+"\x00"), k.aead.Seal(nonce, nonce, fakeBlob(b, "Plaintext"), encryptionContext(b))...)
		return map[string]any{"KeyId": k.arn, "CiphertextBlob": blob, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}, "", nil
	case "Decrypt":
		blob := fakeBlob(b, "CiphertextBlob")
		arn, ct, ok := bytes.Cut(blob, []byte{0})
		if !ok {
			return nil, "InvalidCiphertextException", fmt.Errorf("not a ciphertext blob")
		}
		k, err := f.find(fakeStr(b, "KeyId"))
		if err != nil {
			return nil, "NotFoundException", err
		}
		if k.arn != string(arn) {
			return nil, "IncorrectKeyException", fmt.Errorf("the ciphertext was not encrypted under %s", k.arn)
		}
		if code, err := f.usable(k); err != nil {
			return nil, code, err
		}
		n := k.aead.NonceSize()
		if len(ct) < n {
			return nil, "InvalidCiphertextException", fmt.Errorf("short")
		}
		plain, err := k.aead.Open(nil, ct[:n], ct[n:], encryptionContext(b))
		if err != nil {
			return nil, "InvalidCiphertextException", fmt.Errorf("the ciphertext or encryption context is wrong")
		}
		return map[string]any{"KeyId": k.arn, "Plaintext": plain, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}, "", nil
	}
	return nil, "UnknownOperationException", fmt.Errorf("operation %q", op)
}
