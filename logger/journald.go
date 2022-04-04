//go:build linux
// +build linux

package logger

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/journald"
)

// InitJournalDLogger configures the logger to write to journald
func InitJournalDLogger(level zerolog.Level) {
	logger = zerolog.New(journald.NewJournalDWriter()).Level(level)
	consoleLogger = zerolog.Nop()
}
