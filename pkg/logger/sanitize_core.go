package logger

import "go.uber.org/zap/zapcore"

// sanitizeCore redacts denylisted field keys on every write, including
// direct Log.Info / FromContext().Info calls.
type sanitizeCore struct {
	zapcore.Core
}

func (c sanitizeCore) With(fields []zapcore.Field) zapcore.Core {
	return sanitizeCore{Core: c.Core.With(sanitizeFields(fields))}
}

func (c sanitizeCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	return c.Core.Write(ent, sanitizeFields(fields))
}

func wrapSanitize(core zapcore.Core) zapcore.Core {
	return sanitizeCore{Core: core}
}
