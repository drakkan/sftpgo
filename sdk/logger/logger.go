// Package logger provides logging capabilities.
package logger

const (
	levelDebug = iota
	levelInfo
	levelWarn
	levelError
)

var (
	logger Logger
)

func init() {
	DisableLogger()
}

// Logger interface
type Logger interface {
	// Log logs at the specified level for the specified sender
	Log(level int, sender, format string, v ...interface{})
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

func (*noLogger) Log(level int, sender, format string, v ...interface{}) {}

// Debug logs at debug level for the specified sender
func Debug(sender, format string, v ...interface{}) {
	logger.Log(levelDebug, sender, format, v...)
}

// Info logs at info level for the specified sender
func Info(sender, format string, v ...interface{}) {
	logger.Log(levelInfo, sender, format, v...)
}

// Warn logs at warn level for the specified sender
func Warn(sender, format string, v ...interface{}) {
	logger.Log(levelWarn, sender, format, v...)
}

// Error logs at error level for the specified sender
func Error(sender, format string, v ...interface{}) {
	logger.Log(levelError, sender, format, v...)
}
