package webhookclient

import (
	"testing"

	"github.com/razatechofficial/mail-os/infrastructure/mailer"
)

// A tenant's webhook URL must not reach into the deployment: the dial guard
// refuses every internal address the client could be pointed at, whatever
// the DNS answer was.
func TestDialGuardRefusesInternalAddresses(t *testing.T) {
	strict := mailer.DialGuard(false, false)
	for _, addr := range []string{
		"127.0.0.1:443", "[::1]:443", "10.0.0.5:443", "172.16.3.4:443", "192.168.1.1:443", "100.64.0.1:443",
		"169.254.169.254:80", "[fe80::1]:443", "[fd00::1]:443", "0.0.0.0:443", "[::]:443", "224.0.0.1:443",
		"[::ffff:127.0.0.1]:443", "[::ffff:169.254.169.254]:80",
	} {
		if err := strict(network(addr), addr, nil); err == nil {
			t.Errorf("dial to %s allowed", addr)
		}
	}
	if err := strict("tcp4", "93.184.216.34:443", nil); err != nil {
		t.Errorf("public address refused: %v", err)
	}

	// Allowing private networks (local and test) still keeps link-local and
	// the cloud metadata address out.
	private := mailer.DialGuard(true, false)
	for _, addr := range []string{"10.0.0.5:443", "192.168.1.1:443"} {
		if err := private("tcp4", addr, nil); err != nil {
			t.Errorf("private network refused when allowed: %s: %v", addr, err)
		}
	}
	for _, addr := range []string{"169.254.169.254:80", "127.0.0.1:443", "[fe80::1]:443"} {
		if err := private(network(addr), addr, nil); err == nil {
			t.Errorf("dial to %s allowed with private networks on", addr)
		}
	}
}

func network(addr string) string {
	if addr[0] == '[' {
		return "tcp6"
	}
	return "tcp4"
}
