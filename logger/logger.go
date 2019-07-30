// Package logger provides logging capabilities.
// It is a wrapper around zerolog for logging and lumberjack for log rotation.
// It provides a request logger to log the HTTP requests for REST API too.
// The request logger uses chi.middleware.RequestLogger,
// chi.middleware.LogFormatter and chi.middleware.LogEntry to build a structured
// logger using zerlog
package logger

import (
	"fmt"

	"github.com/rs/zerolog"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

const (
	dateFormat = "2006-01-02T15:04.05.000" // YYYY-MM-DDTHH:MM.SS.ZZZ
)

var (
	logger zerolog.Logger
)

// GetLogger get the configured logger instance
func GetLogger() *zerolog.Logger {
	return &logger
}

// InitLogger configures the logger.
// It sets the log file path and the log level
func InitLogger(logFilePath string, level zerolog.Level) {
	logMaxSize := 10 // MB
	logMaxBackups := 5
	logMaxAge := 28 // days

	zerolog.TimeFieldFormat = dateFormat
	logger = zerolog.New(&lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   false,
	}).With().Timestamp().Logger().Level(level)
}

// Debug logs at debug level for the specified sender
func Debug(sender string, format string, v ...interface{}) {
	logger.Debug().Str("sender", sender).Msg(fmt.Sprintf(format, v...))
}

// Info logs at info level for the specified sender
func Info(sender string, format string, v ...interface{}) {
	logger.Info().Str("sender", sender).Msg(fmt.Sprintf(format, v...))
}

// Warn logs at warn level for the specified sender
func Warn(sender string, format string, v ...interface{}) {
	logger.Warn().Str("sender", sender).Msg(fmt.Sprintf(format, v...))
}

// Error logs at error level for the specified sender
func Error(sender string, format string, v ...interface{}) {
	logger.Error().Str("sender", sender).Msg(fmt.Sprintf(format, v...))
}

// TransferLog logs an SFTP upload or download
func TransferLog(operation string, path string, elapsed int64, size int64, user string, connectionID string) {
	logger.Info().
		Str("sender", operation).
		Int64("elapsed_ms", elapsed).
		Int64("size_bytes", size).
		Str("username", user).
		Str("file_path", path).
		Str("connection_id", connectionID).
		Msg("")
}

// CommandLog logs an SFTP command
func CommandLog(command string, path string, target string, user string, connectionID string) {
	logger.Info().
		Str("sender", command).
		Str("username", user).
		Str("file_path", path).
		Str("target_path", target).
		Str("connection_id", connectionID).
		Msg("")
}
