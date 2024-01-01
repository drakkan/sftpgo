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
	"io"
	"log"

	"github.com/hashicorp/go-hclog"
	"github.com/rs/zerolog"
)

// HCLogAdapter is an adapter for hclog.Logger
type HCLogAdapter struct {
	hclog.Logger
}

// Log emits a message and key/value pairs at a provided log level
func (l *HCLogAdapter) Log(level hclog.Level, msg string, args ...any) {
	var ev *zerolog.Event
	switch level {
	case hclog.Info:
		ev = logger.Info()
	case hclog.Warn:
		ev = logger.Warn()
	case hclog.Error:
		ev = logger.Error()
	default:
		ev = logger.Debug()
	}
	ev.Timestamp().Str("sender", l.Name())
	addKeysAndValues(ev, args...)
	ev.Msg(msg)
}

// Trace emits a message and key/value pairs at the TRACE level
func (l *HCLogAdapter) Trace(msg string, args ...any) {
	l.Log(hclog.Debug, msg, args...)
}

// Debug emits a message and key/value pairs at the DEBUG level
func (l *HCLogAdapter) Debug(msg string, args ...any) {
	l.Log(hclog.Debug, msg, args...)
}

// Info emits a message and key/value pairs at the INFO level
func (l *HCLogAdapter) Info(msg string, args ...any) {
	l.Log(hclog.Info, msg, args...)
}

// Warn emits a message and key/value pairs at the WARN level
func (l *HCLogAdapter) Warn(msg string, args ...any) {
	l.Log(hclog.Warn, msg, args...)
}

// Error emits a message and key/value pairs at the ERROR level
func (l *HCLogAdapter) Error(msg string, args ...any) {
	l.Log(hclog.Error, msg, args...)
}

// With creates a sub-logger
func (l *HCLogAdapter) With(args ...any) hclog.Logger {
	return &HCLogAdapter{Logger: l.Logger.With(args...)}
}

// Named creates a logger that will prepend the name string on the front of all messages
func (l *HCLogAdapter) Named(name string) hclog.Logger {
	return &HCLogAdapter{Logger: l.Logger.Named(name)}
}

// StandardLogger returns a value that conforms to the stdlib log.Logger interface
func (l *HCLogAdapter) StandardLogger(_ *hclog.StandardLoggerOptions) *log.Logger {
	return log.New(&StdLoggerWrapper{Sender: l.Name()}, "", 0)
}

// StandardWriter returns a value that conforms to io.Writer, which can be passed into log.SetOutput()
func (l *HCLogAdapter) StandardWriter(_ *hclog.StandardLoggerOptions) io.Writer {
	return &StdLoggerWrapper{Sender: l.Name()}
}
