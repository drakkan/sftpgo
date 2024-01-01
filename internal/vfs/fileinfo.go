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

package vfs

import (
	"os"
	"path"
	"time"
)

// FileInfo implements os.FileInfo for a Cloud Storage file.
type FileInfo struct {
	name        string
	sizeInBytes int64
	modTime     time.Time
	mode        os.FileMode
}

// NewFileInfo creates file info.
func NewFileInfo(name string, isDirectory bool, sizeInBytes int64, modTime time.Time, fullName bool) *FileInfo {
	mode := os.FileMode(0644)
	if isDirectory {
		mode = os.FileMode(0755) | os.ModeDir
	}
	if !fullName {
		// we have always Unix style paths here
		name = path.Base(name)
	}

	return &FileInfo{
		name:        name,
		sizeInBytes: sizeInBytes,
		modTime:     modTime,
		mode:        mode,
	}
}

// Name provides the base name of the file.
func (fi *FileInfo) Name() string {
	return fi.name
}

// Size provides the length in bytes for a file.
func (fi *FileInfo) Size() int64 {
	return fi.sizeInBytes
}

// Mode provides the file mode bits
func (fi *FileInfo) Mode() os.FileMode {
	return fi.mode
}

// ModTime provides the last modification time.
func (fi *FileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir provides the abbreviation for Mode().IsDir()
func (fi *FileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// SetMode sets the file mode
func (fi *FileInfo) SetMode(mode os.FileMode) {
	fi.mode = mode
}

// Sys provides the underlying data source (can return nil)
func (fi *FileInfo) Sys() any {
	return nil
}
