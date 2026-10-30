// Package logger provides structured, high-performance logging via zap.
//
// Production: JSON to stdout, caller disabled. Development: console + caller.
// Secret field keys (passwords, tokens, one-time codes, message bodies) are
// redacted automatically on every write.
package logger

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type contextKey string

const (
	requestIDContextKey contextKey = "request_id"
	loggerContextKey    contextKey = "logger"
)

// RequestIDContextKey is the key used to store request_id in context.
const RequestIDContextKey = requestIDContextKey

// Log is the global logger instance.
var Log *zap.Logger

var stdLogUndo func()

// Field wraps zap.Field so callers never import zap.
type Field = zap.Field

// Options configure Init.
type Options struct {
	Level      string // debug, info, warn, error
	Format     string // json or console
	Production bool   // forces JSON and drops the caller
	Service    string // service.name
	Version    string // service.version
	Env        string // deployment.environment.name
}

// Init initializes Zap with stdout output.
func Init(o Options) error {
	format := o.Format
	if o.Production {
		format = "json"
	}
	core, err := buildStdoutCore(o.Level, format, o.Production)
	if err != nil {
		return err
	}
	opts := []zap.Option{zap.AddCallerSkip(1)}
	if !o.Production {
		opts = append(opts, zap.AddCaller(), zap.Development())
	}
	Log = zap.New(wrapSanitize(core), opts...)
	var fields []Field
	if o.Service != "" {
		fields = append(fields, String("service.name", o.Service))
	}
	if o.Version != "" {
		fields = append(fields, String("service.version", o.Version))
	}
	if o.Env != "" {
		fields = append(fields, String("deployment.environment.name", o.Env))
	}
	if len(fields) > 0 {
		Log = Log.With(fields...)
	}
	redirectStdLog()
	return nil
}

// InitSimple initializes Zap for tests and CLI tools.
func InitSimple(level, format string) error {
	core, err := buildStdoutCore(level, format, false)
	if err != nil {
		return err
	}
	Log = zap.New(wrapSanitize(core), zap.AddCallerSkip(1), zap.AddCaller(), zap.Development())
	redirectStdLog()
	return nil
}

func redirectStdLog() {
	if stdLogUndo != nil {
		stdLogUndo()
	}
	stdLogUndo = zap.RedirectStdLog(Log)
	refreshAsynqLogger()
}

func buildStdoutCore(level, format string, production bool) (zapcore.Core, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}
	var cfg zap.Config
	if format == "json" || production {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "timestamp"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		cfg.DisableCaller = true
		cfg.EncoderConfig.CallerKey = zapcore.OmitKey
		cfg.Sampling = nil
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	l, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	return l.Core(), nil
}

// Sync flushes buffered log entries.
func Sync() {
	if Log == nil {
		return
	}
	_ = Log.Sync()
}

func criticalLog() *zap.Logger {
	if Log != nil {
		return Log
	}
	return zap.NewNop()
}

func Debug(msg string, fields ...Field) {
	if Log != nil {
		Log.Debug(msg, sanitizeFields(fields)...)
	}
}

func Info(msg string, fields ...Field) {
	if Log != nil {
		Log.Info(msg, sanitizeFields(fields)...)
	}
}

func Warn(msg string, fields ...Field) {
	if Log != nil {
		Log.Warn(msg, sanitizeFields(fields)...)
	}
}

func Error(msg string, fields ...Field) {
	if Log != nil {
		Log.Error(msg, sanitizeFields(fields)...)
	}
}

// Fatal logs at error level, flushes, then exits.
func Fatal(msg string, fields ...Field) {
	if Log != nil {
		Log.Error(msg, sanitizeFields(fields)...)
	}
	Sync()
	os.Exit(1)
}

// With creates a child logger with additional fields (sanitized).
func With(fields ...Field) *zap.Logger {
	if Log == nil {
		return zap.NewNop()
	}
	return Log.With(sanitizeFields(fields)...)
}

// WithLogger stores a logger in context.
func WithLogger(ctx context.Context, l *zap.Logger) context.Context {
	if ctx == nil || l == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerContextKey, l)
}

// WithRequestIDContext stores the request ID for FromContext.
func WithRequestIDContext(ctx context.Context, requestID string) context.Context {
	if requestID == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDContextKey, requestID)
}

// RequestIDFromContext returns the request ID stored by WithRequestIDContext.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	rid, _ := ctx.Value(requestIDContextKey).(string)
	return rid
}

// FromContext returns a request-scoped logger with trace_id and request_id when present.
func FromContext(ctx context.Context) *zap.Logger {
	base := Log
	if base == nil {
		base = zap.NewNop()
	}
	if ctx == nil {
		return base
	}
	if l, ok := ctx.Value(loggerContextKey).(*zap.Logger); ok && l != nil {
		base = l
	}
	var fields []Field
	if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
		fields = append(fields, String("trace_id", sc.TraceID().String()))
		if sc.HasSpanID() {
			fields = append(fields, String("span_id", sc.SpanID().String()))
		}
	}
	if rid := RequestIDFromContext(ctx); rid != "" {
		fields = append(fields, String("request_id", rid))
	}
	if len(fields) == 0 {
		return base
	}
	return base.With(fields...)
}

func String(key, val string) Field                 { return zap.String(key, val) }
func Strings(key string, val []string) Field       { return zap.Strings(key, val) }
func Int(key string, val int) Field                { return zap.Int(key, val) }
func Int64(key string, val int64) Field            { return zap.Int64(key, val) }
func Float64(key string, val float64) Field        { return zap.Float64(key, val) }
func Bool(key string, val bool) Field              { return zap.Bool(key, val) }
func Duration(key string, val time.Duration) Field { return zap.Duration(key, val) }
func Err(err error) Field                          { return zap.Error(err) }
func Any(key string, val interface{}) Field        { return zap.Any(key, val) }
