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

//go:build noazblob
// +build noazblob

package vfs

import (
	"errors"

	"github.com/drakkan/sftpgo/v2/internal/version"
)

func init() {
	version.AddFeature("-azblob")
}

// NewAzBlobFs returns an error, Azure Blob storage is disabled
func NewAzBlobFs(_, _, _ string, _ AzBlobFsConfig) (Fs, error) {
	return nil, errors.New("Azure Blob Storage disabled at build time")
}
