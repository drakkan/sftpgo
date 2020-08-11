package vfs

import (
	"os"
	"path"
	"time"
)

// FileContentTyper is an optional interface for vfs.FileInfo
type FileContentTyper interface {
	GetContentType() string
}

// FileInfo implements os.FileInfo for a Cloud Storage file.
type FileInfo struct {
	name        string
	sizeInBytes int64
	modTime     time.Time
	mode        os.FileMode
	contentType string
}

// NewFileInfo creates file info.
func NewFileInfo(name string, isDirectory bool, sizeInBytes int64, modTime time.Time) FileInfo {
	mode := os.FileMode(0644)
	contentType := ""
	if isDirectory {
		mode = os.FileMode(0755) | os.ModeDir
		contentType = "inode/directory"
	}

	return FileInfo{
		name:        path.Base(name), // we have always Unix style paths here
		sizeInBytes: sizeInBytes,
		modTime:     modTime,
		mode:        mode,
		contentType: contentType,
	}
}

// Name provides the base name of the file.
func (fi FileInfo) Name() string {
	return fi.name
}

// Size provides the length in bytes for a file.
func (fi FileInfo) Size() int64 {
	return fi.sizeInBytes
}

// Mode provides the file mode bits
func (fi FileInfo) Mode() os.FileMode {
	return fi.mode
}

// ModTime provides the last modification time.
func (fi FileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir provides the abbreviation for Mode().IsDir()
func (fi FileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys provides the underlying data source (can return nil)
func (fi FileInfo) Sys() interface{} {
	return fi.getFileInfoSys()
}

func (fi *FileInfo) setContentType(contenType string) {
	fi.contentType = contenType
}

// GetContentType implements FileContentTyper interface
func (fi FileInfo) GetContentType() string {
	return fi.contentType
}
