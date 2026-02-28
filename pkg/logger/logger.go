// Package logger provides a thin wrapper around zap for structured,
// leveled logging with a package-level singleton.
package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var log *zap.Logger

func Init(level string) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.DebugLevel
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.AddSync(os.Stdout),
		zapLevel,
	)

	log = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
}

func Sync() {
	if log != nil {
		_ = log.Sync()
	}
}

func get() *zap.Logger {
	if log == nil {
		log, _ = zap.NewDevelopment()
	}
	return log
}

func Info(msg string, fields ...zap.Field)  { get().Info(msg, fields...) }
func Error(msg string, fields ...zap.Field) { get().Error(msg, fields...) }
func Warn(msg string, fields ...zap.Field)  { get().Warn(msg, fields...) }
func Debug(msg string, fields ...zap.Field) { get().Debug(msg, fields...) }
func Fatal(msg string, fields ...zap.Field) { get().Fatal(msg, fields...) }

func String(key, val string) zap.Field   { return zap.String(key, val) }
func Int(key string, val int) zap.Field   { return zap.Int(key, val) }
func Err(err error) zap.Field             { return zap.Error(err) }
func Any(key string, val any) zap.Field   { return zap.Any(key, val) }
