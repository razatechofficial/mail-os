package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ClamAV scans attachments with a clamd daemon over TCP (INSTREAM) before
// a message or campaign is accepted. It is off by default; then files are
// checked against the attachment limits only.
type ClamAV struct {
	Enabled bool   `yaml:"enabled" env:"CLAMAV_ENABLED" env-default:"false"`
	Host    string `yaml:"host" env:"CLAMAV_HOST" env-default:"127.0.0.1"`
	Port    int    `yaml:"port" env:"CLAMAV_PORT" env-default:"3310"`
	// Timeout bounds one file's scan: connecting, streaming, the verdict.
	Timeout time.Duration `yaml:"timeout" env:"CLAMAV_TIMEOUT" env-default:"30s"`
	// ChunkBytes is the largest INSTREAM chunk (at most clamd's
	// StreamMaxLength).
	ChunkBytes int `yaml:"chunk_bytes" env:"CLAMAV_CHUNK_BYTES" env-default:"65536"`
	// FailClosed refuses the send (503) when clamd cannot answer;
	// false lets the file through unscanned and logs it.
	FailClosed bool `yaml:"fail_closed" env:"CLAMAV_FAIL_CLOSED" env-default:"true"`
}

// Addr is host:port.
func (c ClamAV) Addr() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

func (c ClamAV) validate() error {
	if !c.Enabled {
		return nil
	}
	switch {
	case strings.TrimSpace(c.Host) == "":
		return fmt.Errorf("CLAMAV_HOST is required when CLAMAV_ENABLED is true")
	case c.Port < 1 || c.Port > 65535:
		return fmt.Errorf("CLAMAV_PORT must be 1 to 65535")
	case c.Timeout < 100*time.Millisecond || c.Timeout > 10*time.Minute:
		return fmt.Errorf("CLAMAV_TIMEOUT must be 100ms to 10m")
	case c.ChunkBytes < 1<<10 || c.ChunkBytes > 16<<20:
		return fmt.Errorf("CLAMAV_CHUNK_BYTES must be 1 KiB to 16 MiB")
	}
	return nil
}
