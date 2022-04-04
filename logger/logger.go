// Package logger provides logging capabilities.
// It is a wrapper around zerolog for logging and lumberjack for log rotation.
// Logs are written to the specified log file.
// Logging on the console is provided to print initialization info, errors and warnings.
// The package provides a request logger to log the HTTP requests for REST API too.
// The request logger uses chi.middleware.RequestLogger,
// chi.middleware.LogFormatter and chi.middleware.LogEntry to build a structured
// logger using zerolog
package logger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

const (
	dateFormat = "2006-01-02T15:04:05.000" // YYYY-MM-DDTHH:MM:SS.ZZZ
)

// LogLevel defines log levels.
type LogLevel uint8

// defines our own log level, just in case we'll change logger in future
const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError

	KeyEventID = `event_id`
)

var (
	logger        zerolog.Logger
	consoleLogger zerolog.Logger
	rollingLogger *lumberjack.Logger
)

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

	Log(LevelError, l.Sender, "", string(p))
	return
}

// LeveledLogger is a logger that accepts a message string and a variadic number of key-value pairs
type LeveledLogger struct {
	Sender string
}

func (l *LeveledLogger) addKeysAndValues(ev *zerolog.Event, keysAndValues ...interface{}) {
	kvLen := len(keysAndValues)
	if kvLen%2 != 0 {
		extra := keysAndValues[kvLen-1]
		keysAndValues = append(keysAndValues[:kvLen-1], "EXTRA_VALUE_AT_END", extra)
	}
	for i := 0; i < len(keysAndValues); i += 2 {
		key, val := keysAndValues[i], keysAndValues[i+1]
		if keyStr, ok := key.(string); ok {
			ev.Str(keyStr, fmt.Sprintf("%v", val))
		}
	}
}

// Error logs at error level for the specified sender
func (l *LeveledLogger) Error(msg string, keysAndValues ...interface{}) {
	ev := logger.Error()
	ev.Timestamp().Str("sender", l.Sender)
	ev.Str(KeyEventID, uuid.NewString())
	l.addKeysAndValues(ev, keysAndValues...)
	ev.Msg(msg)
}

// Info logs at info level for the specified sender
func (l *LeveledLogger) Info(msg string, keysAndValues ...interface{}) {
	ev := logger.Info()
	ev.Timestamp().Str("sender", l.Sender)
	ev.Str(KeyEventID, uuid.NewString())
	l.addKeysAndValues(ev, keysAndValues...)
	ev.Msg(msg)
}

// Debug logs at debug level for the specified sender
func (l *LeveledLogger) Debug(msg string, keysAndValues ...interface{}) {
	ev := logger.Debug()
	ev.Timestamp().Str("sender", l.Sender)
	ev.Str(KeyEventID, uuid.NewString())
	l.addKeysAndValues(ev, keysAndValues...)
	ev.Msg(msg)
}

// Warn logs at warn level for the specified sender
func (l *LeveledLogger) Warn(msg string, keysAndValues ...interface{}) {
	ev := logger.Warn()
	ev.Timestamp().Str("sender", l.Sender)
	ev.Str(KeyEventID, uuid.NewString())
	l.addKeysAndValues(ev, keysAndValues...)
	ev.Msg(msg)
}

// GetLogger get the configured logger instance
func GetLogger() *zerolog.Logger {
	return &logger
}

// InitLogger configures the logger using the given parameters
func InitLogger(logFilePath string, logMaxSize int, logMaxBackups int, logMaxAge int, logCompress bool, level zerolog.Level) {
	zerolog.TimeFieldFormat = dateFormat
	if isLogFilePathValid(logFilePath) {
		rollingLogger = &lumberjack.Logger{
			Filename:   logFilePath,
			MaxSize:    logMaxSize,
			MaxBackups: logMaxBackups,
			MaxAge:     logMaxAge,
			Compress:   logCompress,
		}
		logger = zerolog.New(rollingLogger)
		EnableConsoleLogger(level)
	} else {
		logger = zerolog.New(&logSyncWrapper{
			output: os.Stdout,
		})
		consoleLogger = zerolog.Nop()
	}
	logger = logger.Level(level)
}

// InitStdErrLogger configures the logger to write to stderr
func InitStdErrLogger(level zerolog.Level) {
	logger = zerolog.New(&logSyncWrapper{
		output: os.Stderr,
	}).Level(level)
	consoleLogger = zerolog.Nop()
}

// DisableLogger disable the main logger.
// ConsoleLogger will not be affected
func DisableLogger() {
	logger = zerolog.Nop()
	rollingLogger = nil
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

// RotateLogFile closes the existing log file and immediately create a new one
func RotateLogFile() error {
	if rollingLogger != nil {
		return rollingLogger.Rotate()
	}
	return errors.New("logging to file is disabled")
}

// Log logs at the specified level for the specified sender
func Log(level LogLevel, sender string, connectionID string, format string, v ...interface{}) {
	var ev *zerolog.Event
	switch level {
	case LevelDebug:
		ev = logger.Debug()
	case LevelInfo:
		ev = logger.Info()
	case LevelWarn:
		ev = logger.Warn()
	default:
		ev = logger.Error()
	}
	ev.Timestamp().Str("sender", sender)
	if connectionID != "" {
		ev.Str("connection_id", connectionID)
	}
	ev.Str(KeyEventID, uuid.NewString())
	ev.Msg(fmt.Sprintf(format, v...))
}

// Debug logs at debug level for the specified sender
func Debug(sender string, connectionID string, format string, v ...interface{}) {
	Log(LevelDebug, sender, connectionID, format, v...)
}

// Info logs at info level for the specified sender
func Info(sender string, connectionID string, format string, v ...interface{}) {
	Log(LevelInfo, sender, connectionID, format, v...)
}

// Warn logs at warn level for the specified sender
func Warn(sender string, connectionID string, format string, v ...interface{}) {
	Log(LevelWarn, sender, connectionID, format, v...)
}

// Error logs at error level for the specified sender
func Error(sender string, connectionID string, format string, v ...interface{}) {
	Log(LevelError, sender, connectionID, format, v...)
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

// TransferLog logs uploads or downloads
func TransferLog(operation string, path string, elapsed int64, size int64, user string, connectionID string, protocol string, dataChannel ftpserver.DataChannel) {
	Event := logger.Info().
		Timestamp().
		Str("sender", operation).
		Int64("elapsed_ms", elapsed).
		Int64("size_bytes", size).
		Str("username", user).
		Str("file_path", path).
		Str("connection_id", connectionID).
		Str("protocol", protocol).
		Str(KeyEventID, uuid.NewString())
	switch dataChannel {
	case ftpserver.DataChannelActive:
		Event.Str(`data_channel`, `active`)
	case ftpserver.DataChannelPassive:
		Event.Str(`data_channel`, `passive`)
	}
	Event.Send()
}

// CommandLog logs an SFTP/SCP/SSH command
func CommandLog(command, path, target, user, fileMode, connectionID, protocol string, uid, gid int, atime, mtime,
	sshCommand string, size int64) {
	logger.Info().
		Timestamp().
		Str("sender", command).
		Str("username", user).
		Str("file_path", path).
		Str("target_path", target).
		Str("filemode", fileMode).
		Int("uid", uid).
		Int("gid", gid).
		Str("access_time", atime).
		Str("modification_time", atime).
		Int64("size", size).
		Str("ssh_command", sshCommand).
		Str("connection_id", connectionID).
		Str("protocol", protocol).
		Str(KeyEventID, uuid.NewString()).
		Send()
}

// ConnectionFailedLog logs failed attempts to initialize a connection.
// A connection can fail for an authentication error or other errors such as
// a client abort or a time out if the login does not happen in two minutes.
// These logs are useful for better integration with Fail2ban and similar tools.
func ConnectionFailedLog(user, ip, loginType, protocol, errorString string) {
	logger.Debug().
		Timestamp().
		Str("sender", "connection_failed").
		Str("client_ip", ip).
		Str("username", user).
		Str("login_type", loginType).
		Str("protocol", protocol).
		Str("error", errorString).
		Str(KeyEventID, uuid.NewString()).
		Send()
}

func isLogFilePathValid(logFilePath string) bool {
	cleanInput := filepath.Clean(logFilePath)
	if cleanInput == "." || cleanInput == ".." {
		return false
	}
	return true
}
