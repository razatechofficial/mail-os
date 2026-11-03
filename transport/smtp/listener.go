package smtp

import (
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/mail-os/pkg/metrics"
)

// limitListener bounds the connections open at once, in all and per
// client address, and how long any one stays open. A connection over a
// limit is answered 421 (on the STARTTLS port, where the client reads
// plaintext first) and closed before the SMTP server sees it.
type limitListener struct {
	net.Listener
	name    string
	max     int
	perIP   int
	session time.Duration
	// greet is whether a refused connection gets a plaintext 421.
	greet bool

	mu    sync.Mutex
	total int
	byIP  map[string]int
}

func newLimitListener(l net.Listener, name string, max, perIP int, session time.Duration, greet bool) *limitListener {
	return &limitListener{Listener: l, name: name, max: max, perIP: perIP, session: session, greet: greet, byIP: map[string]int{}}
}

// Accept returns the next connection within the limits.
func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := hostOf(c.RemoteAddr())
		if !l.acquire(ip) {
			metrics.SMTPConnection(l.name, "limit")
			go l.refuse(c)
			continue
		}
		metrics.SMTPConnection(l.name, "accepted")
		metrics.SMTPActive(1)
		lc := &limitConn{Conn: c}
		lc.release = func() {
			l.releaseIP(ip)
			metrics.SMTPActive(-1)
		}
		// However busy, a session ends: the server then sees a closed
		// connection and frees it.
		lc.timer = time.AfterFunc(l.session, func() { _ = c.Close() })
		return lc, nil
	}
}

func (l *limitListener) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.max || l.byIP[ip] >= l.perIP {
		return false
	}
	l.total++
	l.byIP[ip]++
	return true
}

func (l *limitListener) releaseIP(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.byIP[ip]--; l.byIP[ip] <= 0 {
		delete(l.byIP, ip)
	}
}

func (l *limitListener) refuse(c net.Conn) {
	defer func() { _ = c.Close() }()
	if !l.greet {
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("421 4.7.0 Too many connections, try again later\r\n"))
}

// limitConn gives its slot back when closed, once.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
	timer   *time.Timer
	// closing closes the connection once the next reply is written.
	closing atomic.Bool
}

func (c *limitConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.closing.Load() {
		_ = c.Close()
	}
	return n, err
}

// closeAfterWrite ends conn (a limitConn, or TLS over one) once the reply
// being written has gone out.
func closeAfterWrite(conn net.Conn) {
	if t, ok := conn.(*tls.Conn); ok {
		conn = t.NetConn()
	}
	if lc, ok := conn.(*limitConn); ok {
		lc.closing.Store(true)
		return
	}
	time.AfterFunc(time.Second, func() { _ = conn.Close() })
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.timer.Stop()
		c.release()
	})
	return err
}

// hostOf is the IP of a remote address.
func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return host
	}
	return a.String()
}
