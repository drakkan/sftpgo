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
