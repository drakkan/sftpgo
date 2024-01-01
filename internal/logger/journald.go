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
