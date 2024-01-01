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

//go:build bundle
// +build bundle

package bundle

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/drakkan/sftpgo/v2/internal/version"
)

func init() {
	version.AddFeature("+bundle")
}

//go:embed templates/*
var templatesFs embed.FS

//go:embed static/*
var staticFs embed.FS

//go:embed openapi/*
var openapiFs embed.FS

// GetTemplatesFs returns the embedded filesystem with the SFTPGo templates
func GetTemplatesFs() embed.FS {
	return templatesFs
}

// GetStaticFs return the http Filesystem with the embedded static files
func GetStaticFs() http.FileSystem {
	fsys, err := fs.Sub(staticFs, "static")
	if err != nil {
		err = fmt.Errorf("unable to get embedded filesystem for static files: %w", err)
		panic(err)
	}
	return http.FS(fsys)
}

// GetOpenAPIFs return the http Filesystem with the embedded static files
func GetOpenAPIFs() http.FileSystem {
	fsys, err := fs.Sub(openapiFs, "openapi")
	if err != nil {
		err = fmt.Errorf("unable to get embedded filesystem for OpenAPI files: %w", err)
		panic(err)
	}
	return http.FS(fsys)
}
