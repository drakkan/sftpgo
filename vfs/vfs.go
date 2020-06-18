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

	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/logger"
)

// Fs defines the interface for filesystem backends
type Fs interface {
	Name() string
	ConnectionID() string
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Open(name string) (*os.File, *pipeat.PipeReaderAt, func(), error)
	Create(name string, flag int) (*os.File, *PipeWriter, func(), error)
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
	GetDirSize(dirname string) (int, int64, error)
	GetAtomicUploadPath(name string) string
	GetRelativePath(name string) string
	Join(elem ...string) string
}

// QuotaCheckResult defines the result for a quota check
type QuotaCheckResult struct {
	HasSpace     bool
	AllowedSize  int64
	AllowedFiles int
	UsedSize     int64
	UsedFiles    int
	QuotaSize    int64
	QuotaFiles   int
}

// GetRemainingSize returns the remaining allowed size
func (q *QuotaCheckResult) GetRemainingSize() int64 {
	if q.QuotaSize > 0 {
		return q.QuotaSize - q.UsedSize
	}
	return 0
}

// GetRemainingFiles returns the remaining allowed files
func (q *QuotaCheckResult) GetRemainingFiles() int {
	if q.QuotaFiles > 0 {
		return q.QuotaFiles - q.UsedFiles
	}
	return 0
}

// S3FsConfig defines the configuration for S3 based filesystem
type S3FsConfig struct {
	Bucket string `json:"bucket,omitempty"`
	// KeyPrefix is similar to a chroot directory for local filesystem.
	// If specified then the SFTP user will only see objects that starts
	// with this prefix and so you can restrict access to a specific
	// folder. The prefix, if not empty, must not start with "/" and must
	// end with "/".
	// If empty the whole bucket contents will be available
	KeyPrefix    string `json:"key_prefix,omitempty"`
	Region       string `json:"region,omitempty"`
	AccessKey    string `json:"access_key,omitempty"`
	AccessSecret string `json:"access_secret,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	StorageClass string `json:"storage_class,omitempty"`
	// The buffer size (in MB) to use for multipart uploads. The minimum allowed part size is 5MB,
	// and if this value is set to zero, the default value (5MB) for the AWS SDK will be used.
	// The minimum allowed value is 5.
	// Please note that if the upload bandwidth between the SFTP client and SFTPGo is greater than
	// the upload bandwidth between SFTPGo and S3 then the SFTP client have to wait for the upload
	// of the last parts to S3 after it ends the file upload to SFTPGo, and it may time out.
	// Keep this in mind if you customize these parameters.
	UploadPartSize int64 `json:"upload_part_size,omitempty"`
	// How many parts are uploaded in parallel
	UploadConcurrency int `json:"upload_concurrency,omitempty"`
}

// GCSFsConfig defines the configuration for Google Cloud Storage based filesystem
type GCSFsConfig struct {
	Bucket string `json:"bucket,omitempty"`
	// KeyPrefix is similar to a chroot directory for local filesystem.
	// If specified then the SFTP user will only see objects that starts
	// with this prefix and so you can restrict access to a specific
	// folder. The prefix, if not empty, must not start with "/" and must
	// end with "/".
	// If empty the whole bucket contents will be available
	KeyPrefix            string `json:"key_prefix,omitempty"`
	CredentialFile       string `json:"-"`
	Credentials          string `json:"credentials,omitempty"`
	AutomaticCredentials int    `json:"automatic_credentials,omitempty"`
	StorageClass         string `json:"storage_class,omitempty"`
}

// PipeWriter defines a wrapper for pipeat.PipeWriterAt.
type PipeWriter struct {
	writer *pipeat.PipeWriterAt
	err    error
	done   chan bool
}

// NewPipeWriter initializes a new PipeWriter
func NewPipeWriter(w *pipeat.PipeWriterAt) *PipeWriter {
	return &PipeWriter{
		writer: w,
		err:    nil,
		done:   make(chan bool),
	}
}

// Close waits for the upload to end, closes the pipeat.PipeWriterAt and returns an error if any.
func (p *PipeWriter) Close() error {
	p.writer.Close() //nolint:errcheck // the returned error is always null
	<-p.done
	return p.err
}

// Done unlocks other goroutines waiting on Close().
// It must be called when the upload ends
func (p *PipeWriter) Done(err error) {
	p.err = err
	p.done <- true
}

// WriteAt is a wrapper for pipeat WriteAt
func (p *PipeWriter) WriteAt(data []byte, off int64) (int, error) {
	return p.writer.WriteAt(data, off)
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
	if len(config.AccessKey) == 0 && len(config.AccessSecret) > 0 {
		return errors.New("access_key cannot be empty with access_secret not empty")
	}
	if len(config.AccessSecret) == 0 && len(config.AccessKey) > 0 {
		return errors.New("access_secret cannot be empty with access_key not empty")
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
	if config.UploadPartSize != 0 && config.UploadPartSize < 5 {
		return errors.New("upload_part_size cannot be != 0 and lower than 5 (MB)")
	}
	if config.UploadConcurrency < 0 {
		return fmt.Errorf("invalid upload concurrency: %v", config.UploadConcurrency)
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
	if len(config.Credentials) == 0 && config.AutomaticCredentials == 0 {
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
