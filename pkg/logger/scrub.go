package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Scrubbed replaces a scrubbed value.
const Scrubbed = "[redacted]"

// Scrubbing returns l replacing each of values, whatever its length,
// wherever it appears: in the message, in any field (strings, errors,
// stringers, objects, arrays) and in a child logger's fields. It is how
// the delivery path keeps a message's live one-time code and links out of
// its log lines (ADR 0001 §3.6), on top of the key-based sanitiser.
func Scrubbing(l *zap.Logger, values []string) *zap.Logger {
	r := newScrubber(values)
	if l == nil || r == nil {
		return l
	}
	return l.WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core { return scrubCore{Core: c, s: r} }))
}

// ScrubContext stores in ctx a logger that scrubs values (Scrubbing), for
// FromContext.
func ScrubContext(ctx context.Context, values []string) context.Context {
	base, _ := ctx.Value(loggerContextKey).(*zap.Logger)
	if base == nil {
		base = Log
	}
	if base == nil {
		return ctx
	}
	return WithLogger(ctx, Scrubbing(base, values))
}

// ScrubString replaces each of values in s.
func ScrubString(s string, values []string) string {
	if r := newScrubber(values); r != nil {
		return r.replace(s)
	}
	return s
}

type scrubber struct {
	values []string
	r      *strings.Replacer
}

func newScrubber(values []string) *scrubber {
	var vs []string
	for _, v := range values {
		if v != "" && !slices.Contains(vs, v) {
			vs = append(vs, v)
		}
	}
	if len(vs) == 0 {
		return nil
	}
	// Longest first, so a value containing another is replaced whole.
	slices.SortFunc(vs, func(a, b string) int { return len(b) - len(a) })
	pairs := make([]string, 0, 2*len(vs))
	for _, v := range vs {
		pairs = append(pairs, v, Scrubbed)
	}
	return &scrubber{values: vs, r: strings.NewReplacer(pairs...)}
}

func (s *scrubber) holds(text string) bool {
	for _, v := range s.values {
		if strings.Contains(text, v) {
			return true
		}
	}
	return false
}

func (s *scrubber) replace(text string) string { return s.r.Replace(text) }

// field returns f with the values replaced. A field that is not a string
// is encoded (unescaped JSON) and, when it holds a value, logged as its
// scrubbed text.
func (s *scrubber) field(f zapcore.Field) zapcore.Field {
	switch f.Type {
	case zapcore.SkipType:
		return f
	case zapcore.StringType:
		if s.holds(f.String) {
			return zap.String(f.Key, s.replace(f.String))
		}
		return f
	}
	enc := zapcore.NewMapObjectEncoder()
	f.AddTo(enc)
	var buf bytes.Buffer
	je := json.NewEncoder(&buf)
	je.SetEscapeHTML(false)
	if err := je.Encode(enc.Fields); err != nil {
		return zap.String(f.Key, Scrubbed)
	}
	text := strings.TrimSpace(buf.String())
	if !s.holds(text) {
		return f
	}
	return zap.String(f.Key, s.replace(text))
}

func (s *scrubber) fields(fs []zapcore.Field) []zapcore.Field {
	out := make([]zapcore.Field, len(fs))
	for i, f := range fs {
		out[i] = s.field(f)
	}
	return out
}

// scrubCore replaces the values in every entry it writes.
type scrubCore struct {
	zapcore.Core
	s *scrubber
}

func (c scrubCore) With(fields []zapcore.Field) zapcore.Core {
	return scrubCore{Core: c.Core.With(c.s.fields(fields)), s: c.s}
}

// Check adds this core, so Write runs (see sanitizeCore.Check).
func (c scrubCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c scrubCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	ent.Message = c.s.replace(ent.Message)
	ent.Stack = c.s.replace(ent.Stack)
	return c.Core.Write(ent, c.s.fields(fields))
}
