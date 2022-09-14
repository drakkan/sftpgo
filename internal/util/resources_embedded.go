// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//go:build bundle
// +build bundle

package util

import (
	"html/template"

	"github.com/drakkan/sftpgo/v2/internal/bundle"
	"github.com/drakkan/sftpgo/v2/internal/logger"
)

// FindSharedDataPath searches for the specified directory name in searchDir
// and in system-wide shared data directories.
// If name is an absolute path it is returned unmodified.
func FindSharedDataPath(name, _ string) string {
	return name
}

// LoadTemplate parses the given template paths.
// It behaves like template.Must but it writes a log before exiting.
// You can optionally provide a base template (e.g. to define some custom functions)
func LoadTemplate(base *template.Template, paths ...string) *template.Template {
	var t *template.Template
	var err error

	templateFs := bundle.GetTemplatesFs()
	if base != nil {
		base, err = base.Clone()
		if err == nil {
			t, err = base.ParseFS(templateFs, paths...)
		}
	} else {
		t, err = template.ParseFS(templateFs, paths...)
	}

	if err != nil {
		logger.ErrorToConsole("error loading required template: %v", err)
		logger.ErrorToConsole(templateLoadErrorHints)
		logger.Error(logSender, "", "error loading required template: %v", err)
		os.Exit(1)
	}
	return t
}
