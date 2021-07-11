package logger

import (
	"io"
	"log"

	"github.com/hashicorp/go-hclog"
	"github.com/rs/zerolog"
)

type HCLogAdapter struct {
	hclog.Logger
}

func (l *HCLogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	var ev *zerolog.Event
	switch level {
	case hclog.Info:
		ev = logger.Info()
	case hclog.Warn:
		ev = logger.Warn()
	case hclog.Error:
		ev = logger.Error()
	default:
		ev = logger.Debug()
	}
	ev.Timestamp().Str("sender", l.Name())
	addKeysAndValues(ev, args...)
	ev.Msg(msg)
}

func (l *HCLogAdapter) Trace(msg string, args ...interface{}) {
	l.Log(hclog.Debug, msg, args...)
}

func (l *HCLogAdapter) Debug(msg string, args ...interface{}) {
	l.Log(hclog.Debug, msg, args...)
}

func (l *HCLogAdapter) Info(msg string, args ...interface{}) {
	l.Log(hclog.Info, msg, args...)
}

func (l *HCLogAdapter) Warn(msg string, args ...interface{}) {
	l.Log(hclog.Warn, msg, args...)
}

func (l *HCLogAdapter) Error(msg string, args ...interface{}) {
	l.Log(hclog.Error, msg, args...)
}

func (l *HCLogAdapter) With(args ...interface{}) hclog.Logger {
	return &HCLogAdapter{Logger: l.Logger.With(args...)}
}

func (l *HCLogAdapter) Named(name string) hclog.Logger {
	return &HCLogAdapter{Logger: l.Logger.Named(name)}
}

func (l *HCLogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	return log.New(&StdLoggerWrapper{Sender: l.Name()}, "", 0)
}

func (l *HCLogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return &StdLoggerWrapper{Sender: l.Name()}
}
