package logger

import (
	"io"
	"log"

	"github.com/hashicorp/go-hclog"
)

// HCLogAdapter is an adapter for hclog.Logger
type HCLogAdapter struct {
	hclog.Logger
}

// Log emits a message and key/value pairs at a provided log level
func (l *HCLogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	logger.LogWithKeyVals(level, l.Name(), msg, args...)
}

// Trace emits a message and key/value pairs at the TRACE level
func (l *HCLogAdapter) Trace(msg string, args ...interface{}) {
	l.Log(hclog.Debug, msg, args...)
}

// Debug emits a message and key/value pairs at the DEBUG level
func (l *HCLogAdapter) Debug(msg string, args ...interface{}) {
	l.Log(hclog.Debug, msg, args...)
}

// Info emits a message and key/value pairs at the INFO level
func (l *HCLogAdapter) Info(msg string, args ...interface{}) {
	l.Log(hclog.Info, msg, args...)
}

// Warn emits a message and key/value pairs at the WARN level
func (l *HCLogAdapter) Warn(msg string, args ...interface{}) {
	l.Log(hclog.Warn, msg, args...)
}

// Error emits a message and key/value pairs at the ERROR level
func (l *HCLogAdapter) Error(msg string, args ...interface{}) {
	l.Log(hclog.Error, msg, args...)
}

// With creates a sub-logger
func (l *HCLogAdapter) With(args ...interface{}) hclog.Logger {
	return &HCLogAdapter{Logger: l.Logger.With(args...)}
}

// Named creates a logger that will prepend the name string on the front of all messages
func (l *HCLogAdapter) Named(name string) hclog.Logger {
	return &HCLogAdapter{Logger: l.Logger.Named(name)}
}

// StandardLogger returns a value that conforms to the stdlib log.Logger interface
func (l *HCLogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	return log.New(&StdLoggerWrapper{Sender: l.Name()}, "", 0)
}

// StandardWriter returns a value that conforms to io.Writer, which can be passed into log.SetOutput()
func (l *HCLogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return &StdLoggerWrapper{Sender: l.Name()}
}

// StdLoggerWrapper is a wrapper for standard logger compatibility
type StdLoggerWrapper struct {
	Sender string
}

// Write implements the io.Writer interface. This is useful to set as a writer
// for the standard library log.
func (l *StdLoggerWrapper) Write(p []byte) (n int, err error) {
	n = len(p)
	if n > 0 && p[n-1] == '\n' {
		// Trim CR added by stdlog.
		p = p[0 : n-1]
	}

	logger.Log(hclog.Error, l.Sender, "", string(p))
	return
}
