package clamav

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClamd is a clamd speaking INSTREAM on loopback: it records each
// stream's chunks and answers with reply (nothing when hang is set).
type fakeClamd struct {
	addr  string
	reply func(data []byte) string
	hang  bool

	mu       sync.Mutex
	commands []string
	chunks   [][]int
	streams  [][]byte
}

func newFakeClamd(t *testing.T, reply func(data []byte) string) *fakeClamd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeClamd{addr: ln.Addr().String(), reply: reply}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, done)
		}
	}()
	return f
}

func (f *fakeClamd) serve(conn net.Conn, done <-chan struct{}) {
	defer func() { _ = conn.Close() }()
	cmd := make([]byte, len("zINSTREAM\x00"))
	if _, err := io.ReadFull(conn, cmd); err != nil {
		return
	}
	var sizes []int
	var data []byte
	for {
		var size [4]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(size[:])
		if n == 0 {
			break
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(conn, chunk); err != nil {
			return
		}
		sizes = append(sizes, int(n))
		data = append(data, chunk...)
	}
	f.mu.Lock()
	f.commands = append(f.commands, string(cmd))
	f.chunks = append(f.chunks, sizes)
	f.streams = append(f.streams, data)
	f.mu.Unlock()
	if f.hang {
		<-done
		return
	}
	_, _ = io.WriteString(conn, f.reply(data)+"\x00")
}

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// answer is clamd: EICAR is found, "BROKEN" is an error, anything else OK.
func answer(data []byte) string {
	switch {
	case bytes.Contains(data, []byte("EICAR-STANDARD")):
		return "stream: Eicar-Test-Signature FOUND"
	case bytes.Equal(data, []byte("BROKEN")):
		return "INSTREAM size limit exceeded. ERROR"
	}
	return "stream: OK"
}

func scanner(addr string, failClosed bool) *Scanner {
	return New(Config{Addr: addr, Timeout: 2 * time.Second, ChunkBytes: 1024, FailClosed: failClosed})
}

func TestScanCleanAndInfected(t *testing.T) {
	f := newFakeClamd(t, answer)
	s := scanner(f.addr, true)
	v, err := s.Scan(context.Background(), "invoice.pdf", "application/pdf", []byte("%PDF-1.7"))
	if err != nil || !v.Clean {
		t.Fatalf("clean: %+v %v", v, err)
	}
	v, err = s.Scan(context.Background(), "eicar.txt", "text/plain", []byte(eicar))
	if err != nil || v.Clean || v.Reason != "Eicar-Test-Signature" {
		t.Fatalf("infected: %+v %v", v, err)
	}
	// Infected is a verdict, not a failure: fail-open still rejects it.
	if v, err := scanner(f.addr, false).Scan(context.Background(), "eicar.txt", "text/plain", []byte(eicar)); err != nil || v.Clean {
		t.Fatalf("infected, fail-open: %+v %v", v, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.commands[0] != "zINSTREAM\x00" || string(f.streams[0]) != "%PDF-1.7" {
		t.Fatalf("command %q stream %q", f.commands[0], f.streams[0])
	}
}

func TestScanStreamsInChunks(t *testing.T) {
	f := newFakeClamd(t, answer)
	s := New(Config{Addr: f.addr, Timeout: 2 * time.Second, ChunkBytes: 4, FailClosed: true})
	data := []byte("0123456789")
	if v, err := s.Scan(context.Background(), "a.txt", "text/plain", data); err != nil || !v.Clean {
		t.Fatalf("%+v %v", v, err)
	}
	big := bytes.Repeat([]byte("abcdefgh"), 40<<10) // 320 KiB, default chunk size
	if v, err := New(Config{Addr: f.addr, FailClosed: true}).Scan(context.Background(), "big.bin", "application/octet-stream", big); err != nil || !v.Clean {
		t.Fatalf("big: %+v %v", v, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.chunks[0]; len(got) != 3 || got[0] != 4 || got[1] != 4 || got[2] != 2 || string(f.streams[0]) != string(data) {
		t.Fatalf("chunks %v stream %q", got, f.streams[0])
	}
	if got := f.chunks[1]; len(got) != 5 || got[0] != 64<<10 || !bytes.Equal(f.streams[1], big) {
		t.Fatalf("big chunks %v (%d bytes)", got, len(f.streams[1]))
	}
}

func TestScanErrorReply(t *testing.T) {
	f := newFakeClamd(t, answer)
	if _, err := scanner(f.addr, true).Scan(context.Background(), "a.bin", "", []byte("BROKEN")); err == nil ||
		!strings.Contains(err.Error(), "size limit exceeded") {
		t.Fatalf("fail-closed: %v", err)
	}
	if v, err := scanner(f.addr, false).Scan(context.Background(), "a.bin", "", []byte("BROKEN")); err != nil || !v.Clean {
		t.Fatalf("fail-open: %+v %v", v, err)
	}
	g := newFakeClamd(t, func([]byte) string { return "UNKNOWN COMMAND" })
	if _, err := scanner(g.addr, true).Scan(context.Background(), "a.bin", "", []byte("x")); err == nil ||
		!strings.Contains(err.Error(), "unexpected reply") {
		t.Fatalf("unexpected reply: %v", err)
	}
}

func TestScanTimeout(t *testing.T) {
	f := newFakeClamd(t, answer)
	f.hang = true
	s := New(Config{Addr: f.addr, Timeout: 200 * time.Millisecond, ChunkBytes: 1024, FailClosed: true})
	start := time.Now()
	if _, err := s.Scan(context.Background(), "a.txt", "text/plain", []byte("x")); err == nil {
		t.Fatal("a hung clamd answered")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("timeout took %v", d)
	}
	s.cfg.FailClosed = false
	if v, err := s.Scan(context.Background(), "a.txt", "text/plain", []byte("x")); err != nil || !v.Clean {
		t.Fatalf("fail-open: %+v %v", v, err)
	}
	// A cancelled request stops the scan too.
	s.cfg.FailClosed, s.cfg.Timeout = true, time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Scan(ctx, "a.txt", "text/plain", []byte("x")); err == nil || time.Since(start) > 4*time.Second {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestScanUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens there now
	if _, err := scanner(addr, true).Scan(context.Background(), "a.txt", "text/plain", []byte("x")); err == nil ||
		!strings.Contains(err.Error(), "connect") {
		t.Fatalf("fail-closed: %v", err)
	}
	if v, err := scanner(addr, false).Scan(context.Background(), "a.txt", "text/plain", []byte("x")); err != nil || !v.Clean {
		t.Fatalf("fail-open: %+v %v", v, err)
	}
}

// clamd refuses a stream over StreamMaxLength mid-way and hangs up.
func TestScanRefusedMidStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.ReadFull(conn, make([]byte, len("zINSTREAM\x00")+4))
		_, _ = io.WriteString(conn, "INSTREAM size limit exceeded. ERROR\x00")
		_ = conn.Close()
	}()
	s := New(Config{Addr: ln.Addr().String(), Timeout: 2 * time.Second, ChunkBytes: 1024, FailClosed: true})
	if _, err := s.Scan(context.Background(), "big.bin", "", bytes.Repeat([]byte("x"), 8<<20)); err == nil {
		t.Fatal("a refused stream passed")
	}
}
