// Package tlstest writes a throwaway CA, a server certificate for 127.0.0.1
// and localhost, and a client certificate into a test's temporary
// directory, for TLS and mutual-TLS tests of the listeners.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Files are the PEM files of one test PKI.
type Files struct {
	CA         string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// New writes a CA, a server pair and a client pair under t.TempDir().
func New(t testing.TB) Files {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mailos test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	f := Files{CA: filepath.Join(dir, "ca.crt")}
	write(t, f.CA, "CERTIFICATE", caDER)
	f.ServerCert, f.ServerKey = leaf(t, dir, "server", caCert, caKey, x509.ExtKeyUsageServerAuth)
	f.ClientCert, f.ClientKey = leaf(t, dir, "client", caCert, caKey, x509.ExtKeyUsageClientAuth)
	return f
}

func leaf(t testing.TB, dir, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "mailos test " + name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, keyFile := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	write(t, cert, "CERTIFICATE", der)
	write(t, keyFile, "EC PRIVATE KEY", keyDER)
	return cert, keyFile
}

func write(t testing.TB, path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
