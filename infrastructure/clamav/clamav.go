// Package clamav scans attachments with a ClamAV daemon (clamd) over TCP:
// the virus-scan hook of the message use case (message.Scanner).
//
// Each file is streamed with the INSTREAM command: "zINSTREAM\0", then the
// content in chunks, each prefixed with its length as a 4-byte big-endian
// integer, then a zero-length chunk. clamd answers one NUL-terminated
// line: "stream: OK", "stream: <signature> FOUND", or "<reason> ERROR".
package clamav

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Config is how the scanner reaches clamd.
type Config struct {
	// Addr is clamd's host:port (TCPSocket in clamd.conf).
	Addr string
	// Timeout bounds one scan: connecting, streaming and the verdict.
	Timeout time.Duration
	// ChunkBytes is the largest INSTREAM chunk; it must not exceed clamd's
	// StreamMaxLength.
	ChunkBytes int
	// FailClosed refuses the message when clamd cannot answer (unreachable,
	// timed out, an ERROR reply); otherwise the file is let through and
	// the failure logged.
	FailClosed bool
}

// Scanner is a message.Scanner backed by clamd.
type Scanner struct {
	cfg  Config
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

var _ appmsg.Scanner = (*Scanner)(nil)

// maxReply bounds clamd's answer.
const maxReply = 4 << 10

// New returns the scanner.
func New(cfg Config) *Scanner {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.ChunkBytes <= 0 {
		cfg.ChunkBytes = 64 << 10
	}
	d := &net.Dialer{}
	return &Scanner{cfg: cfg, dial: d.DialContext}
}

// Scan implements message.Scanner. A FOUND reply is a rejection naming the
// signature; a failure is an error when FailClosed, a clean verdict
// otherwise.
func (s *Scanner) Scan(ctx context.Context, name, contentType string, data []byte) (appmsg.Verdict, error) {
	v, err := s.instream(ctx, data)
	if err == nil {
		return v, nil
	}
	if s.cfg.FailClosed {
		return appmsg.Verdict{}, err
	}
	logger.FromContext(ctx).Warn("clamd scan failed; attachment allowed unscanned (CLAMAV_FAIL_CLOSED=false)",
		logger.String("filename", name), logger.String("content_type", contentType), logger.Err(err))
	return appmsg.Verdict{Clean: true}, nil
}

// instream streams data to clamd and reads its verdict.
func (s *Scanner) instream(ctx context.Context, data []byte) (appmsg.Verdict, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	conn, err := s.dial(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return appmsg.Verdict{}, fmt.Errorf("clamd: connect: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// A cancelled request stops the scan at once.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if werr := s.send(conn, data); werr != nil {
		// clamd may refuse mid-stream (a stream over StreamMaxLength) and
		// close: its reply says why.
		if v, rerr := readVerdict(conn); rerr == nil || !errors.Is(rerr, errNoReply) {
			return v, rerr
		}
		return appmsg.Verdict{}, fmt.Errorf("clamd: send: %w", werr)
	}
	return readVerdict(conn)
}

// send writes the command, the chunks and the terminator.
func (s *Scanner) send(w io.Writer, data []byte) error {
	if _, err := io.WriteString(w, "zINSTREAM\x00"); err != nil {
		return err
	}
	var size [4]byte
	for len(data) > 0 {
		n := min(len(data), s.cfg.ChunkBytes)
		binary.BigEndian.PutUint32(size[:], uint32(n))
		if _, err := w.Write(size[:]); err != nil {
			return err
		}
		if _, err := w.Write(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	binary.BigEndian.PutUint32(size[:], 0)
	_, err := w.Write(size[:])
	return err
}

var errNoReply = errors.New("clamd: no reply")

// readVerdict reads the NUL-terminated reply and parses it.
func readVerdict(r io.Reader) (appmsg.Verdict, error) {
	buf := make([]byte, 0, 128)
	one := make([]byte, 256)
	for len(buf) < maxReply {
		n, err := r.Read(one)
		buf = append(buf, one[:n]...)
		if i := bytes.IndexByte(buf, 0); i >= 0 {
			return parse(string(buf[:i]))
		}
		if err != nil {
			if len(buf) > 0 && errors.Is(err, io.EOF) {
				return parse(string(buf))
			}
			if len(buf) == 0 {
				return appmsg.Verdict{}, fmt.Errorf("%w: %w", errNoReply, err)
			}
			return appmsg.Verdict{}, fmt.Errorf("clamd: read: %w", err)
		}
	}
	return appmsg.Verdict{}, errors.New("clamd: reply too long")
}

// parse reads "stream: OK", "stream: <name> FOUND" or "<reason> ERROR".
func parse(reply string) (appmsg.Verdict, error) {
	reply = strings.TrimSpace(reply)
	switch {
	case reply == "stream: OK":
		return appmsg.Verdict{Clean: true}, nil
	case strings.HasPrefix(reply, "stream: ") && strings.HasSuffix(reply, " FOUND"):
		name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(reply, "stream: "), " FOUND"))
		return appmsg.Verdict{Reason: name}, nil
	case strings.HasSuffix(reply, " ERROR"):
		return appmsg.Verdict{}, fmt.Errorf("clamd: %s", reply)
	}
	return appmsg.Verdict{}, fmt.Errorf("clamd: unexpected reply %q", reply)
}
