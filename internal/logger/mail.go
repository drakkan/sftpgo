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

	"github.com/wneessen/go-mail/log"
)

const (
	mailLogSender = "smtpclient"
)

// MailAdapter is an adapter for mail.Logger
type MailAdapter struct {
	ConnectionID string
}

// Errorf emits a log at Error level
func (l *MailAdapter) Errorf(logMsg log.Log) {
	format := l.getFormatString(&logMsg)
	ErrorToConsole(format, logMsg.Messages...)
	Log(LevelError, mailLogSender, l.ConnectionID, format, logMsg.Messages...)
}

// Warnf emits a log at Warn level
func (l *MailAdapter) Warnf(logMsg log.Log) {
	format := l.getFormatString(&logMsg)
	WarnToConsole(format, logMsg.Messages...)
	Log(LevelWarn, mailLogSender, l.ConnectionID, format, logMsg.Messages...)
}

// Infof emits a log at Info level
func (l *MailAdapter) Infof(logMsg log.Log) {
	format := l.getFormatString(&logMsg)
	InfoToConsole(format, logMsg.Messages...)
	Log(LevelInfo, mailLogSender, l.ConnectionID, format, logMsg.Messages...)
}

// Debugf emits a log at Debug level
func (l *MailAdapter) Debugf(logMsg log.Log) {
	format := l.getFormatString(&logMsg)
	DebugToConsole(format, logMsg.Messages...)
	Log(LevelDebug, mailLogSender, l.ConnectionID, format, logMsg.Messages...)
}

func (*MailAdapter) getFormatString(logMsg *log.Log) string {
	p := "C <-- S:"
	if logMsg.Direction == log.DirClientToServer {
		p = "C --> S:"
	}
	return fmt.Sprintf("%s %s", p, logMsg.Format)
}
