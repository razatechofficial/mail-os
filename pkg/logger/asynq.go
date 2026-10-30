package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// AsynqLogger adapts pkg/logger to hibiken/asynq.Logger.
type AsynqLogger struct{}

var asynqLogger *zap.Logger

func refreshAsynqLogger() {
	if Log == nil {
		asynqLogger = nil
		return
	}
	// component tags framework logs; extra caller skip attributes hibiken/asynq frames in dev.
	asynqLogger = Log.With(String("component", "asynq")).WithOptions(zap.AddCallerSkip(1))
}

func (AsynqLogger) Debug(args ...interface{}) { asynqLog(zap.DebugLevel, args...) }
func (AsynqLogger) Info(args ...interface{})  { asynqLog(zap.InfoLevel, args...) }
func (AsynqLogger) Warn(args ...interface{})  { asynqLog(zap.WarnLevel, args...) }
func (AsynqLogger) Error(args ...interface{}) { asynqLog(zap.ErrorLevel, args...) }
func (AsynqLogger) Fatal(args ...interface{}) {
	asynqLog(zap.ErrorLevel, args...)
	Sync()
}

func asynqLog(level zapcore.Level, args ...interface{}) {
	if asynqLogger == nil {
		return
	}
	msg := fmt.Sprint(args...)
	switch level {
	case zap.DebugLevel:
		asynqLogger.Debug(msg)
	case zap.WarnLevel:
		asynqLogger.Warn(msg)
	case zap.ErrorLevel:
		asynqLogger.Error(msg)
	default:
		asynqLogger.Info(msg)
	}
}

// Asynq returns an asynq-compatible logger backed by zap.
func Asynq() AsynqLogger { return AsynqLogger{} }
