package keymanager

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// In-process fakes of the GCP KMS, Azure Key Vault and Vault Transit HTTPS
// APIs: real AEAD and RSA-OAEP, bearer tokens checked on every call.

func aeadSeal(t *testing.T, key, plain, aad []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nonce, nonce, plain, aad)
}

func aeadOpen(key, ct, aad []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if len(ct) < gcm.NonceSize() {
		return nil, fmt.Errorf("short")
	}
	return gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], aad)
}

func randKey() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request) map[string]string {
	var m map[string]string
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

func b64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// fakeTokens is a token service: it issues tokens and the fake API
// accepts only the latest.
type fakeTokens struct {
	mu      sync.Mutex
	n       int
	current string
	issued  int
	refuse  bool
}

func (f *fakeTokens) issue() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	f.issued++
	f.current = fmt.Sprintf("tok-%d", f.n)
	return f.current
}

func (f *fakeTokens) valid(tok string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return tok != "" && tok == f.current
}

// revoke makes the issued token invalid, as an expiry or revocation would.
func (f *fakeTokens) revoke() {
	f.mu.Lock()
	f.current = "revoked"
	f.mu.Unlock()
}

// --- Google Cloud KMS ---

type fakeGCP struct {
	t      *testing.T
	srv    *httptest.Server
	tokens fakeTokens
	sa     *rsa.PrivateKey
	mu     sync.Mutex
	keys   map[string]*gcpFakeKey
	broken bool // answer encrypt with non-base64
}

type gcpFakeKey struct {
	purpose, state string
	material       []byte
}

const gcpTestKey = "projects/p/locations/global/keyRings/mailos/cryptoKeys/kek"

func newFakeGCP(t *testing.T) *fakeGCP {
	f := &fakeGCP{t: t, keys: map[string]*gcpFakeKey{}}
	f.sa, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGCP) addKey(name, purpose, state string) {
	f.mu.Lock()
	f.keys[name] = &gcpFakeKey{purpose: purpose, state: state, material: randKey()}
	f.mu.Unlock()
}

// credentials is a service-account JSON key whose token_uri is the fake.
func (f *fakeGCP) credentials() []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(f.sa)
	raw, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "mailos@p.iam.gserviceaccount.com", "private_key_id": "k1",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":   f.srv.URL + "/token",
	})
	return raw
}

func (f *fakeGCP) checkAssertion(assertion string) bool {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&f.sa.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	return claims["scope"] == gcpKMSScope && claims["aud"] == f.srv.URL+"/token"
}

func (f *fakeGCP) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/token":
		_ = r.ParseForm()
		if f.tokens.refuse || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || !f.checkAssertion(r.PostForm.Get("assertion")) {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": f.tokens.issue(), "expires_in": 3600})
		return
	case r.URL.Path == "/meta":
		if r.Header.Get("Metadata-Flavor") != "Google" {
			writeJSON(w, 403, map[string]string{"error": "missing Metadata-Flavor"})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": f.tokens.issue(), "expires_in": 3599})
		return
	}
	if !f.tokens.valid(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		writeJSON(w, 401, map[string]any{"error": map[string]any{"code": 401, "message": "Request had invalid authentication credentials."}})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	name, verb, _ := strings.Cut(path, ":")
	f.mu.Lock()
	key := f.keys[name]
	f.mu.Unlock()
	if key == nil {
		writeJSON(w, 404, map[string]any{"error": map[string]any{"code": 404, "message": "CryptoKey " + name + " not found."}})
		return
	}
	switch verb {
	case "":
		writeJSON(w, 200, map[string]any{"name": name, "purpose": key.purpose, "primary": map[string]string{"state": key.state}})
	case "encrypt":
		in := decodeJSON(r)
		if f.broken {
			writeJSON(w, 200, map[string]string{"ciphertext": "%%%"})
			return
		}
		ct := aeadSeal(f.t, key.material, b64(in["plaintext"]), b64(in["additionalAuthenticatedData"]))
		writeJSON(w, 200, map[string]string{"name": name + "/cryptoKeyVersions/1", "ciphertext": base64.StdEncoding.EncodeToString(ct)})
	case "decrypt":
		in := decodeJSON(r)
		pt, err := aeadOpen(key.material, b64(in["ciphertext"]), b64(in["additionalAuthenticatedData"]))
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": map[string]any{"code": 400, "message": "Decryption failed: the ciphertext is invalid."}})
			return
		}
		writeJSON(w, 200, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)})
	default:
		writeJSON(w, 404, nil)
	}
}

// --- Azure Key Vault ---

type fakeAzure struct {
	t      *testing.T
	srv    *httptest.Server
	tokens fakeTokens
	mu     sync.Mutex
	// keys: name → versions (the last is current).
	keys map[string][]*azureFakeKey
}

type azureFakeKey struct {
	version string
	kty     string
	ops     []string
	enabled bool
	priv    *rsa.PrivateKey
}

func newFakeAzure(t *testing.T) *fakeAzure {
	f := &fakeAzure{t: t, keys: map[string][]*azureFakeKey{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAzure) addVersion(name, kty string, enabled bool, ops ...string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(ops) == 0 {
		ops = []string{"wrapKey", "unwrapKey"}
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := fmt.Sprintf("%032x", len(f.keys[name])+1)
	f.keys[name] = append(f.keys[name], &azureFakeKey{version: v, kty: kty, ops: ops, enabled: enabled, priv: priv})
	return v
}

func (f *fakeAzure) find(name, version string) *azureFakeKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	vs := f.keys[name]
	if len(vs) == 0 {
		return nil
	}
	if version == "" {
		return vs[len(vs)-1]
	}
	for _, k := range vs {
		if k.version == version {
			return k
		}
	}
	return nil
}

func (f *fakeAzure) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		_ = r.ParseForm()
		if f.tokens.refuse || r.PostForm.Get("client_secret") != "s3cret" || r.PostForm.Get("scope") != azureVaultScope+"/.default" ||
			r.URL.Path != "/tenant-1/oauth2/v2.0/token" {
			writeJSON(w, 401, map[string]string{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": f.tokens.issue(), "expires_in": 3599, "token_type": "Bearer"})
		return
	}
	if r.URL.Path == "/imds" {
		if r.Header.Get("Metadata") != "true" || r.URL.Query().Get("resource") != azureVaultScope {
			writeJSON(w, 400, map[string]string{"error": "invalid_request"})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": f.tokens.issue(), "expires_in": "86399"})
		return
	}
	if r.URL.Query().Get("api-version") != azureAPIVersion {
		writeJSON(w, 400, map[string]any{"error": map[string]string{"message": "api-version"}})
		return
	}
	if !f.tokens.valid(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		writeJSON(w, 401, map[string]any{"error": map[string]string{"code": "Unauthorized", "message": "AKV10000: Request is missing a Bearer or PoP token."}})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/keys/"), "/")
	op := ""
	if n := len(parts); n > 1 && (parts[n-1] == "wrapkey" || parts[n-1] == "unwrapkey") {
		op, parts = parts[n-1], parts[:n-1]
	}
	version := ""
	if len(parts) == 2 {
		version = parts[1]
	}
	key := f.find(parts[0], version)
	if key == nil {
		writeJSON(w, 404, map[string]any{"error": map[string]string{"code": "KeyNotFound", "message": "A key with (name/id) " + parts[0] + " was not found in this key vault."}})
		return
	}
	kid := f.srv.URL + "/keys/" + parts[0] + "/" + key.version
	switch op {
	case "":
		writeJSON(w, 200, map[string]any{"key": map[string]any{"kid": kid, "kty": key.kty, "key_ops": key.ops},
			"attributes": map[string]any{"enabled": key.enabled}})
	case "wrapkey", "unwrapkey":
		in := decodeJSON(r)
		val, err := base64.RawURLEncoding.DecodeString(in["value"])
		if in["alg"] != azureWrapAlg || err != nil {
			writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "BadParameter", "message": "bad alg or value"}})
			return
		}
		var out []byte
		if op == "wrapkey" {
			out, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.priv.PublicKey, val, nil)
		} else {
			out, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, key.priv, val, nil)
		}
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "BadParameter", "message": "Unwrap failed"}})
			return
		}
		writeJSON(w, 200, map[string]string{"kid": kid, "value": base64.RawURLEncoding.EncodeToString(out)})
	}
}

// --- Vault Transit ---

type fakeVault struct {
	t      *testing.T
	srv    *httptest.Server
	tokens fakeTokens
	mu     sync.Mutex
	keys   map[string]*vaultFakeKey
	logins int
}

type vaultFakeKey struct {
	typ      string
	versions [][]byte
}

func newFakeVault(t *testing.T) *fakeVault {
	f := &fakeVault{t: t, keys: map[string]*vaultFakeKey{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVault) addKey(name, typ string) {
	f.mu.Lock()
	f.keys[name] = &vaultFakeKey{typ: typ, versions: [][]byte{randKey()}}
	f.mu.Unlock()
}

func (f *fakeVault) rotate(name string) {
	f.mu.Lock()
	f.keys[name].versions = append(f.keys[name].versions, randKey())
	f.mu.Unlock()
}

func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Namespace") != "mailos" {
		writeJSON(w, 403, map[string]any{"errors": []string{"permission denied (namespace)"}})
		return
	}
	if r.URL.Path == "/v1/auth/approle/login" {
		in := decodeJSON(r)
		f.mu.Lock()
		f.logins++
		f.mu.Unlock()
		if f.tokens.refuse || in["role_id"] != "role-1" || in["secret_id"] != "secret-1" {
			writeJSON(w, 400, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": f.tokens.issue(), "lease_duration": 3600}})
		return
	}
	if !f.tokens.valid(r.Header.Get("X-Vault-Token")) {
		writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/transit/")
	op, name, _ := strings.Cut(rest, "/")
	f.mu.Lock()
	key := f.keys[name]
	f.mu.Unlock()
	if !ok || key == nil {
		writeJSON(w, 404, map[string]any{"errors": []string{}})
		return
	}
	switch op {
	case "keys":
		writeJSON(w, 200, map[string]any{"data": map[string]any{"type": key.typ, "supports_encryption": key.typ != "ed25519",
			"supports_decryption": key.typ != "ed25519"}})
	case "encrypt":
		in := decodeJSON(r)
		v := len(key.versions)
		ct := aeadSeal(f.t, key.versions[v-1], b64(in["plaintext"]), b64(in["associated_data"]))
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ciphertext": fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(ct)), "key_version": v}})
	case "decrypt":
		in := decodeJSON(r)
		var v int
		var body string
		if _, err := fmt.Sscanf(in["ciphertext"], "vault:v%d:", &v); err == nil {
			_, body, _ = strings.Cut(strings.TrimPrefix(in["ciphertext"], "vault:"), ":")
		}
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil || v < 1 || v > len(key.versions) {
			writeJSON(w, 400, map[string]any{"errors": []string{"invalid ciphertext"}})
			return
		}
		pt, err := aeadOpen(key.versions[v-1], raw, b64(in["associated_data"]))
		if err != nil {
			writeJSON(w, 400, map[string]any{"errors": []string{"cipher: message authentication failed"}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
	default:
		writeJSON(w, 404, map[string]any{"errors": []string{}})
	}
}
