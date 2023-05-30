// Copyright (C) 2019-2023 Nicola Murino
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

const (
	mailLogSender = "smtpclient"
)

// MailAdapter is an adapter for mail.Logger
type MailAdapter struct {
	ConnectionID string
}

// Errorf emits a log at Error level
func (l *MailAdapter) Errorf(format string, v ...any) {
	ErrorToConsole(format, v...)
	Log(LevelError, mailLogSender, l.ConnectionID, format, v...)
}

// Warnf emits a log at Warn level
func (l *MailAdapter) Warnf(format string, v ...any) {
	WarnToConsole(format, v...)
	Log(LevelWarn, mailLogSender, l.ConnectionID, format, v...)
}

// Infof emits a log at Info level
func (l *MailAdapter) Infof(format string, v ...any) {
	InfoToConsole(format, v...)
	Log(LevelInfo, mailLogSender, l.ConnectionID, format, v...)
}

// Debugf emits a log at Debug level
func (l *MailAdapter) Debugf(format string, v ...any) {
	DebugToConsole(format, v...)
	Log(LevelDebug, mailLogSender, l.ConnectionID, format, v...)
}
