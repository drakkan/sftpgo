// Package logger provides logging capabilities.
package logger

import "github.com/hashicorp/go-hclog"

var (
	logger Logger
)

func init() {
	DisableLogger()
}

// Logger interface
type Logger interface {
	// LogWithKeyVals logs at the specified level for the specified sender adding the specified key vals
	LogWithKeyVals(level hclog.Level, sender, msg string, args ...interface{})
	// Log logs at the specified level for the specified sender
	Log(level hclog.Level, sender, format string, v ...interface{})
}

// SetLogger sets the specified logger
func SetLogger(l Logger) {
	logger = l
}

// DisableLogger disables logging
func DisableLogger() {
	logger = &noLogger{}
}

type noLogger struct{}

func (*noLogger) LogWithKeyVals(level hclog.Level, sender, msg string, args ...interface{}) {}

func (*noLogger) Log(level hclog.Level, sender, format string, v ...interface{}) {}

// Debug logs at debug level for the specified sender
func Debug(sender, format string, v ...interface{}) {
	logger.Log(hclog.Debug, sender, format, v...)
}

// Info logs at info level for the specified sender
func Info(sender, format string, v ...interface{}) {
	logger.Log(hclog.Info, sender, format, v...)
}

// Warn logs at warn level for the specified sender
func Warn(sender, format string, v ...interface{}) {
	logger.Log(hclog.Warn, sender, format, v...)
}

// Error logs at error level for the specified sender
func Error(sender, format string, v ...interface{}) {
	logger.Log(hclog.Error, sender, format, v...)
}
