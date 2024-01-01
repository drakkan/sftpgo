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

import "fmt"

const (
	legoLogSender = "lego"
)

// LegoAdapter is an adapter for lego.StdLogger
type LegoAdapter struct {
	LogToConsole bool
}

// Fatal emits a log at Error level
func (l *LegoAdapter) Fatal(args ...any) {
	if l.LogToConsole {
		ErrorToConsole(fmt.Sprint(args...))
		return
	}
	Log(LevelError, legoLogSender, "", fmt.Sprint(args...))
}

// Fatalln is the same as Fatal
func (l *LegoAdapter) Fatalln(args ...any) {
	l.Fatal(args...)
}

// Fatalf emits a log at Error level
func (l *LegoAdapter) Fatalf(format string, args ...any) {
	if l.LogToConsole {
		ErrorToConsole(format, args...)
		return
	}
	Log(LevelError, legoLogSender, "", format, args...)
}

// Print emits a log at Info level
func (l *LegoAdapter) Print(args ...any) {
	if l.LogToConsole {
		InfoToConsole(fmt.Sprint(args...))
		return
	}
	Log(LevelInfo, legoLogSender, "", fmt.Sprint(args...))
}

// Println is the same as Print
func (l *LegoAdapter) Println(args ...any) {
	l.Print(args...)
}

// Printf emits a log at Info level
func (l *LegoAdapter) Printf(format string, args ...any) {
	if l.LogToConsole {
		InfoToConsole(format, args...)
		return
	}
	Log(LevelInfo, legoLogSender, "", format, args...)
}
