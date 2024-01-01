// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package logger

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/drakkan/sftpgo/v2/internal/metric"
)

// StructuredLogger defines a simple wrapper around zerolog logger.
// It implements chi.middleware.LogFormatter interface
type StructuredLogger struct {
	Logger *zerolog.Logger
}

// StructuredLoggerEntry defines a log entry.
// It implements chi.middleware.LogEntry interface
type StructuredLoggerEntry struct {
	// The zerolog logger
	Logger *zerolog.Logger
	// fields to write in the log
	fields map[string]any
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

	fields := map[string]any{
		"local_addr":  getLocalAddress(r),
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
func (l *StructuredLoggerEntry) Write(status, bytes int, _ http.Header, elapsed time.Duration, _ any) {
	metric.HTTPRequestServed(status)
	var ev *zerolog.Event
	if status >= http.StatusInternalServerError {
		ev = l.Logger.Error()
	} else if status >= http.StatusBadRequest {
		ev = l.Logger.Warn()
	} else {
		ev = l.Logger.Debug()
	}
	ev.
		Timestamp().
		Str("sender", "httpd").
		Fields(l.fields).
		Int("resp_status", status).
		Int("resp_size", bytes).
		Int64("elapsed_ms", elapsed.Nanoseconds()/1000000).
		Send()
}

// Panic logs panics
func (l *StructuredLoggerEntry) Panic(v any, stack []byte) {
	l.Logger.Error().
		Timestamp().
		Str("sender", "httpd").
		Fields(l.fields).
		Str("stack", string(stack)).
		Str("panic", fmt.Sprintf("%+v", v)).
		Send()
}

func getLocalAddress(r *http.Request) string {
	if r == nil {
		return ""
	}
	localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if ok {
		return localAddr.String()
	}
	return ""
}
