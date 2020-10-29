package logger

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/rs/zerolog"
)

// StructuredLogger defines a simple wrapper around zerolog logger.
// It implements chi.middleware.LogFormatter interface
type StructuredLogger struct {
	Logger *zerolog.Logger
}

// StructuredLoggerEntry ...
type StructuredLoggerEntry struct {
	Logger *zerolog.Logger
	fields map[string]interface{}
}

// NewStructuredLogger returns a chi.middleware.RequestLogger using our StructuredLogger.
// This structured logger is called by the chi.middleware.Logger handler to log each HTTP request
func NewStructuredLogger(logger *zerolog.Logger) func(next http.Handler) http.Handler {
	return middleware.RequestLogger(&StructuredLogger{logger})
}

// NewLogEntry creates a new log entry for an HTTP request
func (l *StructuredLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	fields := map[string]interface{}{
		"remote_addr": r.RemoteAddr,
		"proto":       r.Proto,
		"method":      r.Method,
		"user_agent":  r.UserAgent(),
		"uri":         fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)}

	reqID := middleware.GetReqID(r.Context())
	if reqID != "" {
		fields["request_id"] = reqID
	}

	return &StructuredLoggerEntry{Logger: l.Logger, fields: fields}
}

// Write logs a new entry at the end of the HTTP request
func (l *StructuredLoggerEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	l.Logger.Info().
		Timestamp().
		Str("sender", "httpd").
		Fields(l.fields).
		Int("resp_status", status).
		Int("resp_size", bytes).
		Int64("elapsed_ms", elapsed.Nanoseconds()/1000000).
		Send()
}

// Panic logs panics
func (l *StructuredLoggerEntry) Panic(v interface{}, stack []byte) {
	l.Logger.Error().
		Timestamp().
		Str("sender", "httpd").
		Fields(l.fields).
		Str("stack", string(stack)).
		Str("panic", fmt.Sprintf("%+v", v)).
		Send()
}
