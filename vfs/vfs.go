// Package vfs provides local and remote filesystems support
package vfs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/logger"
	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
)

// Fs defines the interface for filesystem backends
type Fs interface {
	Name() string
	ConnectionID() string
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Open(name string) (*os.File, *pipeat.PipeReaderAt, func(), error)
	Create(name string, flag int) (*os.File, *pipeat.PipeWriterAt, func(), error)
	Rename(source, target string) error
	Remove(name string, isDir bool) error
	Mkdir(name string) error
	Symlink(source, target string) error
	Chown(name string, uid int, gid int) error
	Chmod(name string, mode os.FileMode) error
	Chtimes(name string, atime, mtime time.Time) error
	ReadDir(dirname string) ([]os.FileInfo, error)
	IsUploadResumeSupported() bool
	IsAtomicUploadSupported() bool
	CheckRootPath(username string, uid int, gid int) bool
	ResolvePath(sftpPath string) (string, error)
	IsNotExist(err error) bool
	IsPermission(err error) bool
	ScanRootDirContents() (int, int64, error)
	GetAtomicUploadPath(name string) string
	GetRelativePath(name string) string
	Join(elem ...string) string
}

// IsDirectory checks if a path exists and is a directory
func IsDirectory(fs Fs, path string) (bool, error) {
	fileInfo, err := fs.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), err
}

// GetSFTPError returns an sftp error from a filesystem error
func GetSFTPError(fs Fs, err error) error {
	if fs.IsNotExist(err) {
		return sftp.ErrSSHFxNoSuchFile
	} else if fs.IsPermission(err) {
		return sftp.ErrSSHFxPermissionDenied
	} else if err != nil {
		return sftp.ErrSSHFxFailure
	}
	return nil
}

// IsLocalOsFs returns true if fs is the local filesystem implementation
func IsLocalOsFs(fs Fs) bool {
	return fs.Name() == osFsName
}

// ValidateS3FsConfig returns nil if the specified s3 config is valid, otherwise an error
func ValidateS3FsConfig(config *S3FsConfig) error {
	if len(config.Bucket) == 0 {
		return errors.New("bucket cannot be empty")
	}
	if len(config.Region) == 0 {
		return errors.New("region cannot be empty")
	}
	if len(config.AccessKey) == 0 {
		return errors.New("access_key cannot be empty")
	}
	if len(config.AccessSecret) == 0 {
		return errors.New("access_secret cannot be empty")
	}
	if len(config.KeyPrefix) > 0 {
		if strings.HasPrefix(config.KeyPrefix, "/") {
			return errors.New("key_prefix cannot start with /")
		}
		config.KeyPrefix = path.Clean(config.KeyPrefix)
		if !strings.HasSuffix(config.KeyPrefix, "/") {
			config.KeyPrefix += "/"
		}
	}
	return nil
}

// ValidateGCSFsConfig returns nil if the specified GCS config is valid, otherwise an error
func ValidateGCSFsConfig(config *GCSFsConfig, credentialsFilePath string) error {
	if len(config.Bucket) == 0 {
		return errors.New("bucket cannot be empty")
	}
	if len(config.KeyPrefix) > 0 {
		if strings.HasPrefix(config.KeyPrefix, "/") {
			return errors.New("key_prefix cannot start with /")
		}
		config.KeyPrefix = path.Clean(config.KeyPrefix)
		if !strings.HasSuffix(config.KeyPrefix, "/") {
			config.KeyPrefix += "/"
		}
	}
	if len(config.Credentials) == 0 {
		fi, err := os.Stat(credentialsFilePath)
		if err != nil {
			return fmt.Errorf("invalid credentials %v", err)
		}
		if fi.Size() == 0 {
			return errors.New("credentials cannot be empty")
		}
	}
	return nil
}

// SetPathPermissions calls fs.Chown.
// It does nothing for local filesystem on windows
func SetPathPermissions(fs Fs, path string, uid int, gid int) {
	if IsLocalOsFs(fs) {
		if runtime.GOOS == "windows" {
			return
		}
	}
	if err := fs.Chown(path, uid, gid); err != nil {
		fsLog(fs, logger.LevelWarn, "error chowning path %v: %v", path, err)
	}
}

func fsLog(fs Fs, level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, fs.Name(), fs.ConnectionID(), format, v...)
}
