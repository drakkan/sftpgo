// Package logger provides logging capabilities.
// It is a wrapper around zerolog for logging and lumberjack for log rotation.
// Logs are written to the specified log file.
// Logging on the console is provided to print initialization info, errors and warnings.
// The package provides a request logger to log the HTTP requests for REST API too.
// The request logger uses chi.middleware.RequestLogger,
// chi.middleware.LogFormatter and chi.middleware.LogEntry to build a structured
// logger using zerlog
package logger

import (
	"fmt"
	"os"
	"runtime"

	"github.com/rs/zerolog"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

const (
	dateFormat = "2006-01-02T15:04.05.000" // YYYY-MM-DDTHH:MM.SS.ZZZ
)

var (
	logger        zerolog.Logger
	consoleLogger zerolog.Logger
)

// GetLogger get the configured logger instance
func GetLogger() *zerolog.Logger {
	return &logger
}

// InitLogger configures the logger using the given parameters
func InitLogger(logFilePath string, logMaxSize int, logMaxBackups int, logMaxAge int, logCompress bool, level zerolog.Level) {
	zerolog.TimeFieldFormat = dateFormat
	logger = zerolog.New(&lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   logCompress,
	}).With().Timestamp().Logger().Level(level)

	consoleOutput := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: dateFormat,
		NoColor:    runtime.GOOS == "windows",
	}
	consoleLogger = zerolog.New(consoleOutput).With().Timestamp().Logger().Level(level)
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

// DebugToConsole logs at debug level to stdout
func DebugToConsole(format string, v ...interface{}) {
	consoleLogger.Debug().Msg(fmt.Sprintf(format, v...))
}

// InfoToConsole logs at info level to stdout
func InfoToConsole(format string, v ...interface{}) {
	consoleLogger.Info().Msg(fmt.Sprintf(format, v...))
}

// WarnToConsole logs at info level to stdout
func WarnToConsole(format string, v ...interface{}) {
	consoleLogger.Warn().Msg(fmt.Sprintf(format, v...))
}

// ErrorToConsole logs at error level to stdout
func ErrorToConsole(format string, v ...interface{}) {
	consoleLogger.Error().Msg(fmt.Sprintf(format, v...))
}

// TransferLog logs an SFTP/SCP upload or download
func TransferLog(operation string, path string, elapsed int64, size int64, user string, connectionID string, protocol string) {
	logger.Info().
		Str("sender", operation).
		Int64("elapsed_ms", elapsed).
		Int64("size_bytes", size).
		Str("username", user).
		Str("file_path", path).
		Str("connection_id", connectionID).
		Str("protocol", protocol).
		Msg("")
}

// CommandLog logs an SFTP/SCP command
func CommandLog(command string, path string, target string, user string, connectionID string, protocol string) {
	logger.Info().
		Str("sender", command).
		Str("username", user).
		Str("file_path", path).
		Str("target_path", target).
		Str("connection_id", connectionID).
		Str("protocol", protocol).
		Msg("")
}
