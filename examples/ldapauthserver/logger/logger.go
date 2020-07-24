package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

const (
	dateFormat = "2006-01-02T15:04:05.000" // YYYY-MM-DDTHH:MM:SS.ZZZ
)

var (
	logger        zerolog.Logger
	consoleLogger zerolog.Logger
)

// GetLogger get the configured logger instance
func GetLogger() *zerolog.Logger {
	return &logger
}

// InitLogger initialize loggers
func InitLogger(logFilePath string, logMaxSize, logMaxBackups, logMaxAge int, logCompress bool, level zerolog.Level) {
	zerolog.TimeFieldFormat = dateFormat
	if isLogFilePathValid(logFilePath) {
		logger = zerolog.New(&lumberjack.Logger{
			Filename:   logFilePath,
			MaxSize:    logMaxSize,
			MaxBackups: logMaxBackups,
			MaxAge:     logMaxAge,
			Compress:   logCompress,
		})
		EnableConsoleLogger(level)
	} else {
		logger = zerolog.New(&logSyncWrapper{
			output: os.Stdout,
		})
		consoleLogger = zerolog.Nop()
	}
	logger.Level(level)
}

// DisableLogger disable the main logger.
// ConsoleLogger will not be affected
func DisableLogger() {
	logger = zerolog.Nop()
}

// EnableConsoleLogger enables the console logger
func EnableConsoleLogger(level zerolog.Level) {
	consoleOutput := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: dateFormat,
		NoColor:    runtime.GOOS == "windows",
	}
	consoleLogger = zerolog.New(consoleOutput).With().Timestamp().Logger().Level(level)
}

// Debug logs at debug level for the specified sender
func Debug(prefix, requestID string, format string, v ...interface{}) {
	logger.Debug().
		Timestamp().
		Str("sender", prefix).
		Str("request_id", requestID).
		Msg(fmt.Sprintf(format, v...))
}

// Info logs at info level for the specified sender
func Info(prefix, requestID string, format string, v ...interface{}) {
	logger.Info().
		Timestamp().
		Str("sender", prefix).
		Str("request_id", requestID).
		Msg(fmt.Sprintf(format, v...))
}

// Warn logs at warn level for the specified sender
func Warn(prefix, requestID string, format string, v ...interface{}) {
	logger.Warn().
		Timestamp().
		Str("sender", prefix).
		Str("request_id", requestID).
		Msg(fmt.Sprintf(format, v...))
}

// Error logs at error level for the specified sender
func Error(prefix, requestID string, format string, v ...interface{}) {
	logger.Error().
		Timestamp().
		Str("sender", prefix).
		Str("request_id", requestID).
		Msg(fmt.Sprintf(format, v...))
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

func isLogFilePathValid(logFilePath string) bool {
	cleanInput := filepath.Clean(logFilePath)
	if cleanInput == "." || cleanInput == ".." {
		return false
	}
	return true
}
