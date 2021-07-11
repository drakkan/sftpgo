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
func (fi *FileInfo) Sys() interface{} {
	return nil
}
