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

// GetLogger get the logger instance
func GetLogger() *zerolog.Logger {
	return &logger
}

// InitLogger initialize loggers
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

// Debug log at debug level for sender
func Debug(sender string, format string, v ...interface{}) {
	logger.Debug().Str("sender", sender).Msg(fmt.Sprintf(format, v...))
}

// Info log at info level for sender
func Info(sender string, format string, v ...interface{}) {
	logger.Info().Str("sender", sender).Msg(fmt.Sprintf(format, v...))
}

// Warn log at warn level for sender
func Warn(sender string, format string, v ...interface{}) {
	logger.Warn().Str("sender", sender).Msg(fmt.Sprintf(format, v...))
}

// Error log at error level for sender
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

// CommandLog log an SFTP command
func CommandLog(command string, path string, target string, user string, connectionID string) {
	logger.Info().
		Str("sender", command).
		Str("username", user).
		Str("file_path", path).
		Str("target_path", target).
		Str("connection_id", connectionID).
		Msg("")
}
