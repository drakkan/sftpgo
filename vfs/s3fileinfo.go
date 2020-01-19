package vfs

import (
	"os"
	"time"
)

// S3FileInfo implements os.FileInfo for a file in S3.
type S3FileInfo struct {
	name        string
	sizeInBytes int64
	modTime     time.Time
	mode        os.FileMode
	sys         interface{}
}

// NewS3FileInfo creates file info.
func NewS3FileInfo(name string, isDirectory bool, sizeInBytes int64, modTime time.Time) S3FileInfo {
	mode := os.FileMode(0644)
	if isDirectory {
		mode = os.FileMode(0755) | os.ModeDir
	}

	return S3FileInfo{
		name:        name,
		sizeInBytes: sizeInBytes,
		modTime:     modTime,
		mode:        mode,
	}
}

// Name provides the base name of the file.
func (fi S3FileInfo) Name() string {
	return fi.name
}

// Size provides the length in bytes for a file.
func (fi S3FileInfo) Size() int64 {
	return fi.sizeInBytes
}

// Mode provides the file mode bits
func (fi S3FileInfo) Mode() os.FileMode {
	return fi.mode
}

// ModTime provides the last modification time.
func (fi S3FileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir provides the abbreviation for Mode().IsDir()
func (fi S3FileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys provides the underlying data source (can return nil)
func (fi S3FileInfo) Sys() interface{} {
	return fi.getFileInfoSys()
}
