// Package vfs provides local and remote filesystems support
package vfs

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
	"github.com/sftpgo/sdk"
	"github.com/sftpgo/sdk/plugin/metadata"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
)

const dirMimeType = "inode/directory"

var (
	validAzAccessTier = []string{"", "Archive", "Hot", "Cool"}
	// ErrStorageSizeUnavailable is returned if the storage backend does not support getting the size
	ErrStorageSizeUnavailable = errors.New("unable to get available size for this storage backend")
	// ErrVfsUnsupported defines the error for an unsupported VFS operation
	ErrVfsUnsupported  = errors.New("not supported")
	credentialsDirPath string
	tempPath           string
	sftpFingerprints   []string
)

// SetCredentialsDirPath sets the credentials dir path
func SetCredentialsDirPath(credentialsPath string) {
	credentialsDirPath = credentialsPath
}

// GetCredentialsDirPath returns the credentials dir path
func GetCredentialsDirPath() string {
	return credentialsDirPath
}

// SetTempPath sets the path for temporary files
func SetTempPath(fsPath string) {
	tempPath = fsPath
}

// GetTempPath returns the path for temporary files
func GetTempPath() string {
	return tempPath
}

// SetSFTPFingerprints sets the SFTP host key fingerprints
func SetSFTPFingerprints(fp []string) {
	sftpFingerprints = fp
}

// Fs defines the interface for filesystem backends
type Fs interface {
	Name() string
	ConnectionID() string
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error)
	Create(name string, flag int) (File, *PipeWriter, func(), error)
	Rename(source, target string) error
	Remove(name string, isDir bool) error
	Mkdir(name string) error
	Symlink(source, target string) error
	Chown(name string, uid int, gid int) error
	Chmod(name string, mode os.FileMode) error
	Chtimes(name string, atime, mtime time.Time, isUploading bool) error
	Truncate(name string, size int64) error
	ReadDir(dirname string) ([]os.FileInfo, error)
	Readlink(name string) (string, error)
	IsUploadResumeSupported() bool
	IsAtomicUploadSupported() bool
	CheckRootPath(username string, uid int, gid int) bool
	ResolvePath(virtualPath string) (string, error)
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
	GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error)
	CheckMetadata() error
	Close() error
}

// fsMetadataChecker is a Fs that implements the getFileNamesInPrefix method.
// This interface is used to abstract metadata consistency checks
type fsMetadataChecker interface {
	Fs
	getFileNamesInPrefix(fsPrefix string) (map[string]bool, error)
}

// File defines an interface representing a SFTPGo file
type File interface {
	io.Reader
	io.Writer
	io.Closer
	io.ReaderAt
	io.WriterAt
	io.Seeker
	Stat() (os.FileInfo, error)
	Name() string
	Truncate(size int64) error
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
	sdk.BaseS3FsConfig
	AccessSecret *kms.Secret `json:"access_secret,omitempty"`
}

// HideConfidentialData hides confidential data
func (c *S3FsConfig) HideConfidentialData() {
	if c.AccessSecret != nil {
		c.AccessSecret.Hide()
	}
}

func (c *S3FsConfig) isEqual(other *S3FsConfig) bool {
	if c.Bucket != other.Bucket {
		return false
	}
	if c.KeyPrefix != other.KeyPrefix {
		return false
	}
	if c.Region != other.Region {
		return false
	}
	if c.AccessKey != other.AccessKey {
		return false
	}
	if c.RoleARN != other.RoleARN {
		return false
	}
	if c.Endpoint != other.Endpoint {
		return false
	}
	if c.StorageClass != other.StorageClass {
		return false
	}
	if c.ACL != other.ACL {
		return false
	}
	if !c.areMultipartFieldsEqual(other) {
		return false
	}

	if c.ForcePathStyle != other.ForcePathStyle {
		return false
	}
	return c.isSecretEqual(other)
}

func (c *S3FsConfig) areMultipartFieldsEqual(other *S3FsConfig) bool {
	if c.UploadPartSize != other.UploadPartSize {
		return false
	}
	if c.UploadConcurrency != other.UploadConcurrency {
		return false
	}
	if c.DownloadConcurrency != other.DownloadConcurrency {
		return false
	}
	if c.DownloadPartSize != other.DownloadPartSize {
		return false
	}
	if c.DownloadPartMaxTime != other.DownloadPartMaxTime {
		return false
	}
	if c.UploadPartMaxTime != other.UploadPartMaxTime {
		return false
	}
	return true
}

func (c *S3FsConfig) isSecretEqual(other *S3FsConfig) bool {
	if c.AccessSecret == nil {
		c.AccessSecret = kms.NewEmptySecret()
	}
	if other.AccessSecret == nil {
		other.AccessSecret = kms.NewEmptySecret()
	}
	return c.AccessSecret.IsEqual(other.AccessSecret)
}

func (c *S3FsConfig) checkCredentials() error {
	if c.AccessKey == "" && !c.AccessSecret.IsEmpty() {
		return errors.New("access_key cannot be empty with access_secret not empty")
	}
	if c.AccessSecret.IsEmpty() && c.AccessKey != "" {
		return errors.New("access_secret cannot be empty with access_key not empty")
	}
	if c.AccessSecret.IsEncrypted() && !c.AccessSecret.IsValid() {
		return errors.New("invalid encrypted access_secret")
	}
	if !c.AccessSecret.IsEmpty() && !c.AccessSecret.IsValidInput() {
		return errors.New("invalid access_secret")
	}
	return nil
}

// EncryptCredentials encrypts access secret if it is in plain text
func (c *S3FsConfig) EncryptCredentials(additionalData string) error {
	if c.AccessSecret.IsPlain() {
		c.AccessSecret.SetAdditionalData(additionalData)
		err := c.AccessSecret.Encrypt()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *S3FsConfig) checkPartSizeAndConcurrency() error {
	if c.UploadPartSize != 0 && (c.UploadPartSize < 5 || c.UploadPartSize > 5000) {
		return errors.New("upload_part_size cannot be != 0, lower than 5 (MB) or greater than 5000 (MB)")
	}
	if c.UploadConcurrency < 0 || c.UploadConcurrency > 64 {
		return fmt.Errorf("invalid upload concurrency: %v", c.UploadConcurrency)
	}
	if c.DownloadPartSize != 0 && (c.DownloadPartSize < 5 || c.DownloadPartSize > 5000) {
		return errors.New("download_part_size cannot be != 0, lower than 5 (MB) or greater than 5000 (MB)")
	}
	if c.DownloadConcurrency < 0 || c.DownloadConcurrency > 64 {
		return fmt.Errorf("invalid download concurrency: %v", c.DownloadConcurrency)
	}
	return nil
}

// Validate returns an error if the configuration is not valid
func (c *S3FsConfig) Validate() error {
	if c.AccessSecret == nil {
		c.AccessSecret = kms.NewEmptySecret()
	}
	if c.Bucket == "" {
		return errors.New("bucket cannot be empty")
	}
	if c.Region == "" {
		return errors.New("region cannot be empty")
	}
	if err := c.checkCredentials(); err != nil {
		return err
	}
	if c.KeyPrefix != "" {
		if strings.HasPrefix(c.KeyPrefix, "/") {
			return errors.New("key_prefix cannot start with /")
		}
		c.KeyPrefix = path.Clean(c.KeyPrefix)
		if !strings.HasSuffix(c.KeyPrefix, "/") {
			c.KeyPrefix += "/"
		}
	}
	c.StorageClass = strings.TrimSpace(c.StorageClass)
	c.ACL = strings.TrimSpace(c.ACL)
	return c.checkPartSizeAndConcurrency()
}

// GCSFsConfig defines the configuration for Google Cloud Storage based filesystem
type GCSFsConfig struct {
	sdk.BaseGCSFsConfig
	Credentials *kms.Secret `json:"credentials,omitempty"`
}

// HideConfidentialData hides confidential data
func (c *GCSFsConfig) HideConfidentialData() {
	if c.Credentials != nil {
		c.Credentials.Hide()
	}
}

func (c *GCSFsConfig) isEqual(other *GCSFsConfig) bool {
	if c.Bucket != other.Bucket {
		return false
	}
	if c.KeyPrefix != other.KeyPrefix {
		return false
	}
	if c.AutomaticCredentials != other.AutomaticCredentials {
		return false
	}
	if c.StorageClass != other.StorageClass {
		return false
	}
	if c.ACL != other.ACL {
		return false
	}
	if c.Credentials == nil {
		c.Credentials = kms.NewEmptySecret()
	}
	if other.Credentials == nil {
		other.Credentials = kms.NewEmptySecret()
	}
	return c.Credentials.IsEqual(other.Credentials)
}

// Validate returns an error if the configuration is not valid
func (c *GCSFsConfig) Validate(credentialsFilePath string) error {
	if c.Credentials == nil || c.AutomaticCredentials == 1 {
		c.Credentials = kms.NewEmptySecret()
	}
	if c.Bucket == "" {
		return errors.New("bucket cannot be empty")
	}
	if c.KeyPrefix != "" {
		if strings.HasPrefix(c.KeyPrefix, "/") {
			return errors.New("key_prefix cannot start with /")
		}
		c.KeyPrefix = path.Clean(c.KeyPrefix)
		if !strings.HasSuffix(c.KeyPrefix, "/") {
			c.KeyPrefix += "/"
		}
	}
	if c.Credentials.IsEncrypted() && !c.Credentials.IsValid() {
		return errors.New("invalid encrypted credentials")
	}
	if c.AutomaticCredentials == 0 && !c.Credentials.IsValidInput() {
		fi, err := os.Stat(credentialsFilePath)
		if err != nil {
			return fmt.Errorf("invalid credentials %v", err)
		}
		if fi.Size() == 0 {
			return errors.New("credentials cannot be empty")
		}
	}
	c.StorageClass = strings.TrimSpace(c.StorageClass)
	c.ACL = strings.TrimSpace(c.ACL)
	return nil
}

// AzBlobFsConfig defines the configuration for Azure Blob Storage based filesystem
type AzBlobFsConfig struct {
	sdk.BaseAzBlobFsConfig
	// Storage Account Key leave blank to use SAS URL.
	// The access key is stored encrypted based on the kms configuration
	AccountKey *kms.Secret `json:"account_key,omitempty"`
	// Shared access signature URL, leave blank if using account/key
	SASURL *kms.Secret `json:"sas_url,omitempty"`
}

// HideConfidentialData hides confidential data
func (c *AzBlobFsConfig) HideConfidentialData() {
	if c.AccountKey != nil {
		c.AccountKey.Hide()
	}
	if c.SASURL != nil {
		c.SASURL.Hide()
	}
}

func (c *AzBlobFsConfig) isEqual(other *AzBlobFsConfig) bool {
	if c.Container != other.Container {
		return false
	}
	if c.AccountName != other.AccountName {
		return false
	}
	if c.Endpoint != other.Endpoint {
		return false
	}
	if c.SASURL.IsEmpty() {
		c.SASURL = kms.NewEmptySecret()
	}
	if other.SASURL.IsEmpty() {
		other.SASURL = kms.NewEmptySecret()
	}
	if !c.SASURL.IsEqual(other.SASURL) {
		return false
	}
	if c.KeyPrefix != other.KeyPrefix {
		return false
	}
	if c.UploadPartSize != other.UploadPartSize {
		return false
	}
	if c.UploadConcurrency != other.UploadConcurrency {
		return false
	}
	if c.DownloadPartSize != other.DownloadPartSize {
		return false
	}
	if c.DownloadConcurrency != other.DownloadConcurrency {
		return false
	}
	if c.UseEmulator != other.UseEmulator {
		return false
	}
	if c.AccessTier != other.AccessTier {
		return false
	}
	return c.isSecretEqual(other)
}

func (c *AzBlobFsConfig) isSecretEqual(other *AzBlobFsConfig) bool {
	if c.AccountKey == nil {
		c.AccountKey = kms.NewEmptySecret()
	}
	if other.AccountKey == nil {
		other.AccountKey = kms.NewEmptySecret()
	}
	return c.AccountKey.IsEqual(other.AccountKey)
}

// EncryptCredentials encrypts access secret if it is in plain text
func (c *AzBlobFsConfig) EncryptCredentials(additionalData string) error {
	if c.AccountKey.IsPlain() {
		c.AccountKey.SetAdditionalData(additionalData)
		if err := c.AccountKey.Encrypt(); err != nil {
			return err
		}
	}
	if c.SASURL.IsPlain() {
		c.SASURL.SetAdditionalData(additionalData)
		if err := c.SASURL.Encrypt(); err != nil {
			return err
		}
	}
	return nil
}

func (c *AzBlobFsConfig) checkCredentials() error {
	if c.SASURL.IsPlain() {
		_, err := url.Parse(c.SASURL.GetPayload())
		return err
	}
	if c.SASURL.IsEncrypted() && !c.SASURL.IsValid() {
		return errors.New("invalid encrypted sas_url")
	}
	if !c.SASURL.IsEmpty() {
		return nil
	}
	if c.AccountName == "" || !c.AccountKey.IsValidInput() {
		return errors.New("credentials cannot be empty or invalid")
	}
	if c.AccountKey.IsEncrypted() && !c.AccountKey.IsValid() {
		return errors.New("invalid encrypted account_key")
	}
	return nil
}

func (c *AzBlobFsConfig) checkPartSizeAndConcurrency() error {
	if c.UploadPartSize < 0 || c.UploadPartSize > 100 {
		return fmt.Errorf("invalid upload part size: %v", c.UploadPartSize)
	}
	if c.UploadConcurrency < 0 || c.UploadConcurrency > 64 {
		return fmt.Errorf("invalid upload concurrency: %v", c.UploadConcurrency)
	}
	if c.DownloadPartSize < 0 || c.DownloadPartSize > 100 {
		return fmt.Errorf("invalid download part size: %v", c.DownloadPartSize)
	}
	if c.DownloadConcurrency < 0 || c.DownloadConcurrency > 64 {
		return fmt.Errorf("invalid upload concurrency: %v", c.DownloadConcurrency)
	}
	return nil
}

func (c *AzBlobFsConfig) tryDecrypt() error {
	if err := c.AccountKey.TryDecrypt(); err != nil {
		return fmt.Errorf("unable to decrypt account key: %w", err)
	}
	if err := c.SASURL.TryDecrypt(); err != nil {
		return fmt.Errorf("unable to decrypt SAS URL: %w", err)
	}
	return nil
}

// Validate returns an error if the configuration is not valid
func (c *AzBlobFsConfig) Validate() error {
	if c.AccountKey == nil {
		c.AccountKey = kms.NewEmptySecret()
	}
	if c.SASURL == nil {
		c.SASURL = kms.NewEmptySecret()
	}
	// container could be embedded within SAS URL we check this at runtime
	if c.SASURL.IsEmpty() && c.Container == "" {
		return errors.New("container cannot be empty")
	}
	if err := c.checkCredentials(); err != nil {
		return err
	}
	if c.KeyPrefix != "" {
		if strings.HasPrefix(c.KeyPrefix, "/") {
			return errors.New("key_prefix cannot start with /")
		}
		c.KeyPrefix = path.Clean(c.KeyPrefix)
		if !strings.HasSuffix(c.KeyPrefix, "/") {
			c.KeyPrefix += "/"
		}
	}
	if err := c.checkPartSizeAndConcurrency(); err != nil {
		return err
	}
	if !util.IsStringInSlice(c.AccessTier, validAzAccessTier) {
		return fmt.Errorf("invalid access tier %#v, valid values: \"''%v\"", c.AccessTier, strings.Join(validAzAccessTier, ", "))
	}
	return nil
}

// CryptFsConfig defines the configuration to store local files as encrypted
type CryptFsConfig struct {
	Passphrase *kms.Secret `json:"passphrase,omitempty"`
}

// HideConfidentialData hides confidential data
func (c *CryptFsConfig) HideConfidentialData() {
	if c.Passphrase != nil {
		c.Passphrase.Hide()
	}
}

func (c *CryptFsConfig) isEqual(other *CryptFsConfig) bool {
	if c.Passphrase == nil {
		c.Passphrase = kms.NewEmptySecret()
	}
	if other.Passphrase == nil {
		other.Passphrase = kms.NewEmptySecret()
	}
	return c.Passphrase.IsEqual(other.Passphrase)
}

// EncryptCredentials encrypts access secret if it is in plain text
func (c *CryptFsConfig) EncryptCredentials(additionalData string) error {
	if c.Passphrase.IsPlain() {
		c.Passphrase.SetAdditionalData(additionalData)
		if err := c.Passphrase.Encrypt(); err != nil {
			return err
		}
	}
	return nil
}

// Validate returns an error if the configuration is not valid
func (c *CryptFsConfig) Validate() error {
	if c.Passphrase == nil || c.Passphrase.IsEmpty() {
		return errors.New("invalid passphrase")
	}
	if !c.Passphrase.IsValidInput() {
		return errors.New("passphrase cannot be empty or invalid")
	}
	if c.Passphrase.IsEncrypted() && !c.Passphrase.IsValid() {
		return errors.New("invalid encrypted passphrase")
	}
	return nil
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

// IsLocalOsFs returns true if fs is a local filesystem implementation
func IsLocalOsFs(fs Fs) bool {
	return fs.Name() == osFsName
}

// IsCryptOsFs returns true if fs is an encrypted local filesystem implementation
func IsCryptOsFs(fs Fs) bool {
	return fs.Name() == cryptFsName
}

// IsSFTPFs returns true if fs is an SFTP filesystem
func IsSFTPFs(fs Fs) bool {
	return strings.HasPrefix(fs.Name(), sftpFsName)
}

// IsBufferedSFTPFs returns true if this is a buffered SFTP filesystem
func IsBufferedSFTPFs(fs Fs) bool {
	if !IsSFTPFs(fs) {
		return false
	}
	return !fs.IsUploadResumeSupported()
}

// IsLocalOrUnbufferedSFTPFs returns true if fs is local or SFTP with no buffer
func IsLocalOrUnbufferedSFTPFs(fs Fs) bool {
	if IsLocalOsFs(fs) {
		return true
	}
	if IsSFTPFs(fs) {
		return fs.IsUploadResumeSupported()
	}
	return false
}

// IsLocalOrSFTPFs returns true if fs is local or SFTP
func IsLocalOrSFTPFs(fs Fs) bool {
	return IsLocalOsFs(fs) || IsSFTPFs(fs)
}

// HasOpenRWSupport returns true if the fs can open a file
// for reading and writing at the same time
func HasOpenRWSupport(fs Fs) bool {
	if IsLocalOsFs(fs) {
		return true
	}
	if IsSFTPFs(fs) && fs.IsUploadResumeSupported() {
		return true
	}
	return false
}

// IsLocalOrCryptoFs returns true if fs is local or local encrypted
func IsLocalOrCryptoFs(fs Fs) bool {
	return IsLocalOsFs(fs) || IsCryptOsFs(fs)
}

// SetPathPermissions calls fs.Chown.
// It does nothing for local filesystem on windows
func SetPathPermissions(fs Fs, path string, uid int, gid int) {
	if uid == -1 && gid == -1 {
		return
	}
	if IsLocalOsFs(fs) {
		if runtime.GOOS == "windows" {
			return
		}
	}
	if err := fs.Chown(path, uid, gid); err != nil {
		fsLog(fs, logger.LevelWarn, "error chowning path %v: %v", path, err)
	}
}

func updateFileInfoModTime(storageID, objectPath string, info *FileInfo) (*FileInfo, error) {
	if !plugin.Handler.HasMetadater() {
		return info, nil
	}
	if info.IsDir() {
		return info, nil
	}
	mTime, err := plugin.Handler.GetModificationTime(storageID, ensureAbsPath(objectPath), info.IsDir())
	if errors.Is(err, metadata.ErrNoSuchObject) {
		return info, nil
	}
	if err != nil {
		return info, err
	}
	info.modTime = util.GetTimeFromMsecSinceEpoch(mTime)
	return info, nil
}

func getFolderModTimes(storageID, dirName string) (map[string]int64, error) {
	var err error
	modTimes := make(map[string]int64)
	if plugin.Handler.HasMetadater() {
		modTimes, err = plugin.Handler.GetModificationTimes(storageID, ensureAbsPath(dirName))
		if err != nil && !errors.Is(err, metadata.ErrNoSuchObject) {
			return modTimes, err
		}
	}
	return modTimes, nil
}

func ensureAbsPath(name string) string {
	if path.IsAbs(name) {
		return name
	}
	return path.Join("/", name)
}

func fsMetadataCheck(fs fsMetadataChecker, storageID, keyPrefix string) error {
	if !plugin.Handler.HasMetadater() {
		return nil
	}
	limit := 100
	from := ""
	for {
		metadataFolders, err := plugin.Handler.GetMetadataFolders(storageID, from, limit)
		if err != nil {
			fsLog(fs, logger.LevelError, "unable to get folders: %v", err)
			return err
		}
		for _, folder := range metadataFolders {
			from = folder
			fsPrefix := folder
			if !strings.HasSuffix(folder, "/") {
				fsPrefix += "/"
			}
			if keyPrefix != "" {
				if !strings.HasPrefix(fsPrefix, "/"+keyPrefix) {
					fsLog(fs, logger.LevelDebug, "skip metadata check for folder %#v outside prefix %#v",
						folder, keyPrefix)
					continue
				}
			}
			fsLog(fs, logger.LevelDebug, "check metadata for folder %#v", folder)
			metadataValues, err := plugin.Handler.GetModificationTimes(storageID, folder)
			if err != nil {
				fsLog(fs, logger.LevelError, "unable to get modification times for folder %#v: %v", folder, err)
				return err
			}
			if len(metadataValues) == 0 {
				fsLog(fs, logger.LevelDebug, "no metadata for folder %#v", folder)
				continue
			}
			fileNames, err := fs.getFileNamesInPrefix(fsPrefix)
			if err != nil {
				fsLog(fs, logger.LevelError, "unable to get content for prefix %#v: %v", fsPrefix, err)
				return err
			}
			// now check if we have metadata for a missing object
			for k := range metadataValues {
				if _, ok := fileNames[k]; !ok {
					filePath := ensureAbsPath(path.Join(folder, k))
					if err = plugin.Handler.RemoveMetadata(storageID, filePath); err != nil {
						fsLog(fs, logger.LevelError, "unable to remove metadata for missing file %#v: %v", filePath, err)
					} else {
						fsLog(fs, logger.LevelDebug, "metadata removed for missing file %#v", filePath)
					}
				}
			}
		}

		if len(metadataFolders) < limit {
			return nil
		}
	}
}

func getMountPath(mountPath string) string {
	if mountPath == "/" {
		return ""
	}
	return mountPath
}

func fsLog(fs Fs, level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, fs.Name(), fs.ConnectionID(), format, v...)
}
