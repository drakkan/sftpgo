//go:build !linux || nojournald
// +build !linux nojournald

package logger

import "github.com/rs/zerolog"

// InitJournalDLogger configures the logger to write to journald
func InitJournalDLogger(level zerolog.Level) {
	InitStdErrLogger(level)
}
