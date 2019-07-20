package logger

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/rs/zerolog"
)

// StructuredLogger that uses zerolog
type StructuredLogger struct {
	Logger *zerolog.Logger
}

// StructuredLoggerEntry using zerolog logger
type StructuredLoggerEntry struct {
	Logger *zerolog.Logger
	fields map[string]interface{}
}

// NewStructuredLogger returns RequestLogger
func NewStructuredLogger(logger *zerolog.Logger) func(next http.Handler) http.Handler {
	return middleware.RequestLogger(&StructuredLogger{logger})
}

// NewLogEntry creates a new log entry
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

// Write a new entry
func (l *StructuredLoggerEntry) Write(status, bytes int, elapsed time.Duration) {
	l.Logger.Info().Fields(l.fields).Int(
		"resp_status", status).Int(
		"resp_size", bytes).Int64(
		"elapsed_ms", elapsed.Nanoseconds()/1000000).Str(
		"sender", "httpd").Msg(
		"")
}

// Panic logs panics
func (l *StructuredLoggerEntry) Panic(v interface{}, stack []byte) {
	l.Logger.Error().Fields(l.fields).Str(
		"stack", string(stack)).Str(
		"panic", fmt.Sprintf("%+v", v)).Msg("")
}
