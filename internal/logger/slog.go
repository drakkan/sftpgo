// Copyright (C) 2025 Nicola Murino
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
	"context"
	"log/slog"
	"slices"

	"github.com/rs/zerolog"
)

// slogAdapter is an adapter for slog.Handler
type slogAdapter struct {
	sender  string
	attrs   []slog.Attr
	console bool
}

// NewSlogAdapter creates a slog.Handler adapter
func NewSlogAdapter(sender string, attrs []slog.Attr) *slogAdapter {
	return &slogAdapter{
		sender: sender,
		attrs:  attrs,
	}
}

// NewConsoleSlogAdapter creates a slog.Handler adapter that writes to the console logger
func NewConsoleSlogAdapter(sender string) *slogAdapter {
	return &slogAdapter{
		sender:  sender,
		console: true,
	}
}

func (l *slogAdapter) Enabled(ctx context.Context, level slog.Level) bool {
	// Log level is handled by our implementation
	return true
}

func (l *slogAdapter) Handle(ctx context.Context, r slog.Record) error {
	target := &logger
	if l.console {
		target = &consoleLogger
	}
	var ev *zerolog.Event
	switch r.Level {
	case slog.LevelDebug:
		ev = target.Debug()
	case slog.LevelInfo:
		ev = target.Info()
	case slog.LevelWarn:
		ev = target.Warn()
	case slog.LevelError:
		ev = target.Error()
	default:
		ev = target.Debug()
	}

	ev.Timestamp()
	if l.sender != "" {
		ev.Str("sender", l.sender)
	}

	addSlogAttr := func(a slog.Attr) {
		if a.Key == "time" {
			return
		}
		ev.Any(a.Key, a.Value.Any())
	}

	for _, a := range l.attrs {
		addSlogAttr(a)
	}

	r.Attrs(func(a slog.Attr) bool {
		addSlogAttr(a)
		return true
	})

	ev.Msg(r.Message)

	return nil
}

func (l *slogAdapter) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandler := *l
	newHandler.attrs = slices.Concat(l.attrs, attrs)
	return &newHandler
}

func (l *slogAdapter) WithGroup(name string) slog.Handler {
	newHandler := *l
	if name != "" {
		newHandler.sender = name
	}
	return &newHandler
}
