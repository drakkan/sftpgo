// Package vfs provides local and remote filesystems support
package vfs

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eikenb/pipeat"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const dirMimeType = "inode/directory"

var validAzAccessTier = []string{"", "Archive", "Hot", "Cool"}

// Fs defines the interface for filesystem backends
type Fs interface {
	Name() string
	ConnectionID() string
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Open(name string, offset int64) (*os.File, *pipeat.PipeReaderAt, func(), error)
	Create(name string, flag int) (*os.File, *PipeWriter, func(), error)
	Rename(source, target string) error
	Remove(name string, isDir bool) error
	Mkdir(name string) error
	Symlink(source, target string) error
	Chown(name string, uid int, gid int) error
	Chmod(name string, mode os.FileMode) error
	Chtimes(name string, atime, mtime time.Time) error
	Truncate(name string, size int64) error
	ReadDir(dirname string) ([]os.FileInfo, error)
	Readlink(name string) (string, error)
	IsUploadResumeSupported() bool
	IsAtomicUploadSupported() bool
	CheckRootPath(username string, uid int, gid int) bool
	ResolvePath(sftpPath string) (string, error)
	IsNotExist(err error) bool
	IsPermission(err error) bool
	IsNotSupported(err error) bool
	ScanRootDirContents() (int, int64, error)
	GetDirSize(dirname string) (int, int64, error)
	GetAtomicUploadPath(name string) string
	GetRelativePath(name string) string
	Walk(root string, walkFn filepath.WalkFunc) error
	Join(elem ...string) string
	HasVirtualFolders() bool
	GetMimeType(name string) (string, error)
}

var ErrVfsUnsupported = errors.New("Not supported")

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
	Credentials          []byte `json:"credentials,omitempty"`
	AutomaticCredentials int    `json:"automatic_credentials,omitempty"`
	StorageClass         string `json:"storage_class,omitempty"`
}

// AzBlobFsConfig defines the configuration for Azure Blob Storage based filesystem
type AzBlobFsConfig struct {
	Container string `json:"container,omitempty"`
	// Storage Account Name, leave blank to use SAS URL
	AccountName string `json:"account_name,omitempty"`
	// Storage Account Key leave blank to use SAS URL.
	// The access key is stored encrypted (AES-256-GCM)
	AccountKey string `json:"account_key,omitempty"`
	// Optional endpoint. Default is "blob.core.windows.net".
	// If you use the emulator the endpoint must include the protocol,
	// for example "http://127.0.0.1:10000"
	Endpoint string `json:"endpoint,omitempty"`
	// Shared access signature URL, leave blank if using account/key
	SASURL string `json:"sas_url,omitempty"`
	// KeyPrefix is similar to a chroot directory for local filesystem.
	// If specified then the SFTPGo userd will only see objects that starts
	// with this prefix and so you can restrict access to a specific
	// folder. The prefix, if not empty, must not start with "/" and must
	// end with "/".
	// If empty the whole bucket contents will be available
	KeyPrefix string `json:"key_prefix,omitempty"`
	// The buffer size (in MB) to use for multipart uploads.
	// If this value is set to zero, the default value (1MB) for the Azure SDK will be used.
	// Please note that if the upload bandwidth between the SFTPGo client and SFTPGo server is
	// greater than the upload bandwidth between SFTPGo and Azure then the SFTP client have
	// to wait for the upload of the last parts to Azure after it ends the file upload to SFTPGo,
	// and it may time out.
	// Keep this in mind if you customize these parameters.
	UploadPartSize int64 `json:"upload_part_size,omitempty"`
	// How many parts are uploaded in parallel
	UploadConcurrency int `json:"upload_concurrency,omitempty"`
	// Set to true if you use an Azure emulator such as Azurite
	UseEmulator bool `json:"use_emulator,omitempty"`
	// Blob Access Tier
	AccessTier string `json:"access_tier,omitempty"`
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

// Write is a wrapper for pipeat Write
func (p *PipeWriter) Write(data []byte) (int, error) {
	return p.writer.Write(data)
}

// IsDirectory checks if a path exists and is a directory
func IsDirectory(fs Fs, path string) (bool, error) {
	fileInfo, err := fs.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), err
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
	if config.KeyPrefix != "" {
		if strings.HasPrefix(config.KeyPrefix, "/") {
			return errors.New("key_prefix cannot start with /")
		}
		config.KeyPrefix = path.Clean(config.KeyPrefix)
		if !strings.HasSuffix(config.KeyPrefix, "/") {
			config.KeyPrefix += "/"
		}
	}
	if config.UploadPartSize != 0 && (config.UploadPartSize < 5 || config.UploadPartSize > 5000) {
		return errors.New("upload_part_size cannot be != 0, lower than 5 (MB) or greater than 5000 (MB)")
	}
	if config.UploadConcurrency < 0 || config.UploadConcurrency > 64 {
		return fmt.Errorf("invalid upload concurrency: %v", config.UploadConcurrency)
	}
	return nil
}

// ValidateGCSFsConfig returns nil if the specified GCS config is valid, otherwise an error
func ValidateGCSFsConfig(config *GCSFsConfig, credentialsFilePath string) error {
	if config.Bucket == "" {
		return errors.New("bucket cannot be empty")
	}
	if config.KeyPrefix != "" {
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

// ValidateAzBlobFsConfig returns nil if the specified Azure Blob config is valid, otherwise an error
func ValidateAzBlobFsConfig(config *AzBlobFsConfig) error {
	if config.SASURL != "" {
		_, err := url.Parse(config.SASURL)
		return err
	}
	if config.Container == "" {
		return errors.New("container cannot be empty")
	}
	if config.AccountName == "" || config.AccountKey == "" {
		return errors.New("credentials cannot be empty")
	}
	if config.KeyPrefix != "" {
		if strings.HasPrefix(config.KeyPrefix, "/") {
			return errors.New("key_prefix cannot start with /")
		}
		config.KeyPrefix = path.Clean(config.KeyPrefix)
		if !strings.HasSuffix(config.KeyPrefix, "/") {
			config.KeyPrefix += "/"
		}
	}
	if config.UploadPartSize < 0 || config.UploadPartSize > 100 {
		return fmt.Errorf("invalid upload part size: %v", config.UploadPartSize)
	}
	if config.UploadConcurrency < 0 || config.UploadConcurrency > 64 {
		return fmt.Errorf("invalid upload concurrency: %v", config.UploadConcurrency)
	}
	if !utils.IsStringInSlice(config.AccessTier, validAzAccessTier) {
		return fmt.Errorf("invalid access tier %#v, valid values: \"''%v\"", config.AccessTier, strings.Join(validAzAccessTier, ", "))
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
