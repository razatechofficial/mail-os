package logger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// captured is a sanitising JSON logger writing to buf.
func captured(buf *bytes.Buffer) *zap.Logger {
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(buf), zapcore.DebugLevel)
	return zap.New(wrapSanitize(core))
}

// A message's live secrets are replaced in every part of a log line it
// writes, whatever their length, and the captured output never holds them.
func TestScrubbingReplacesValuesEverywhere(t *testing.T) {
	const code = "482913"
	const link = "https://iam.example.com/reset-password?token=tok-9f2&x=1"
	const short = "q7"
	var buf bytes.Buffer
	l := Scrubbing(captured(&buf), []string{code, link, short, ""})
	l.Info("sending code "+code, zap.String("detail", "provider said: "+link))
	l.Warn("send failed", zap.Error(fmt.Errorf("smtp 550: rejected body containing %s", code)),
		zap.Any("data", map[string]any{"nested": []any{link}}), zap.Stringer("s", stringer("pin "+short)))
	l.With(zap.String("ctx", "child "+code)).Error("child", zap.ByteString("raw", []byte(link)))
	out := buf.String()
	for _, leak := range []string{code, "tok-9f2", "pin q7"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log holds %q:\n%s", leak, out)
		}
	}
	if strings.Count(out, Scrubbed) < 6 {
		t.Fatalf("expected replacements:\n%s", out)
	}
	if !strings.Contains(out, `"msg":"sending code [redacted]"`) {
		t.Fatalf("message not scrubbed in place:\n%s", out)
	}
}

func TestScrubContextAndString(t *testing.T) {
	var buf bytes.Buffer
	prev := Log
	Log = captured(&buf)
	defer func() { Log = prev }()
	ctx := ScrubContext(context.Background(), []string{"731904"})
	FromContext(ctx).Info("code 731904", Err(errors.New("echo 731904")))
	if strings.Contains(buf.String(), "731904") {
		t.Fatalf("context logger leaks: %s", buf.String())
	}
	if got := ScrubString("a 731904 b", []string{"731904"}); got != "a [redacted] b" {
		t.Fatalf("ScrubString = %q", got)
	}
	if got := ScrubString("unchanged", nil); got != "unchanged" {
		t.Fatalf("no values changed %q", got)
	}
	// No values: the logger is returned as it is.
	l := captured(&buf)
	if Scrubbing(l, nil) != l {
		t.Fatal("empty scrubber wrapped the logger")
	}
}

type stringer string

func (s stringer) String() string { return string(s) }
