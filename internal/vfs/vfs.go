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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	dirMimeType       = "inode/directory"
	s3fsName          = "S3Fs"
	gcsfsName         = "GCSFs"
	azBlobFsName      = "AzureBlobFs"
	lastModifiedField = "sftpgo_last_modified"
	preResumeTimeout  = 90 * time.Second
	// ListerBatchSize defines the default limit for DirLister implementations
	ListerBatchSize = 1000
)

// Additional checks for files
const (
	CheckParentDir = 1
	CheckResume    = 2
)

var (
	validAzAccessTier = []string{"", "Archive", "Hot", "Cool"}
	// ErrStorageSizeUnavailable is returned if the storage backend does not support getting the size
	ErrStorageSizeUnavailable = errors.New("unable to get available size for this storage backend")
	// ErrVfsUnsupported defines the error for an unsupported VFS operation
	ErrVfsUnsupported        = errors.New("not supported")
	errInvalidDirListerLimit = errors.New("dir lister: invalid limit, must be > 0")
	tempPath                 string
	sftpFingerprints         []string
	allowSelfConnections     int
	renameMode               int
	readMetadata             int
	resumeMaxSize            int64
	uploadMode               int
)

// SetAllowSelfConnections sets the desired behaviour for self connections
func SetAllowSelfConnections(value int) {
	allowSelfConnections = value
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

// SetRenameMode sets the rename mode
func SetRenameMode(val int) {
	renameMode = val
}

// SetReadMetadataMode sets the read metadata mode
func SetReadMetadataMode(val int) {
	readMetadata = val
}

// SetResumeMaxSize sets the max size allowed for resuming uploads for backends
// with immutable objects
func SetResumeMaxSize(val int64) {
	resumeMaxSize = val
}

// SetUploadMode sets the upload mode
func SetUploadMode(val int) {
	uploadMode = val
}

// Fs defines the interface for filesystem backends
type Fs interface {
	Name() string
	ConnectionID() string
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Open(name string, offset int64) (File, PipeReader, func(), error)
	Create(name string, flag, checks int) (File, PipeWriter, func(), error)
	Rename(source, target string) (int, int64, error)
	Remove(name string, isDir bool) error
	Mkdir(name string) error
	Symlink(source, target string) error
	Chown(name string, uid int, gid int) error
	Chmod(name string, mode os.FileMode) error
	Chtimes(name string, atime, mtime time.Time, isUploading bool) error
	Truncate(name string, size int64) error
	ReadDir(dirname string) (DirLister, error)
	Readlink(name string) (string, error)
	IsUploadResumeSupported() bool
	IsConditionalUploadResumeSupported(size int64) bool
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
	Close() error
}

// FsRealPather is a Fs that implements the RealPath method.
type FsRealPather interface {
	Fs
	RealPath(p string) (string, error)
}

// FsFileCopier is a Fs that implements the CopyFile method.
type FsFileCopier interface {
	Fs
	CopyFile(source, target string, srcSize int64) (int, int64, error)
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

// PipeWriter defines an interface representing a SFTPGo pipe writer
type PipeWriter interface {
	io.Writer
	io.WriterAt
	io.Closer
	Done(err error)
	GetWrittenBytes() int64
}

// PipeReader defines an interface representing a SFTPGo pipe reader
type PipeReader interface {
	io.Reader
	io.ReaderAt
	io.Closer
	setMetadata(value map[string]string)
	setMetadataFromPointerVal(value map[string]*string)
	Metadata() map[string]string
}

// DirLister defines an interface for a directory lister
type DirLister interface {
	Next(limit int) ([]os.FileInfo, error)
	Close() error
}

// Metadater defines an interface to implement to return metadata for a file
type Metadater interface {
	Metadata() map[string]string
}

type baseDirLister struct {
	cache []os.FileInfo
}

func (l *baseDirLister) Next(limit int) ([]os.FileInfo, error) {
	if limit <= 0 {
		return nil, errInvalidDirListerLimit
	}
	if len(l.cache) >= limit {
		return l.returnFromCache(limit), nil
	}
	return l.returnFromCache(limit), io.EOF
}

func (l *baseDirLister) returnFromCache(limit int) []os.FileInfo {
	if len(l.cache) >= limit {
		result := l.cache[:limit]
		l.cache = l.cache[limit:]
		return result
	}
	result := l.cache
	l.cache = nil
	return result
}

func (l *baseDirLister) Close() error {
	l.cache = nil
	return nil
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

func (c *S3FsConfig) isEqual(other S3FsConfig) bool {
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
	if c.SkipTLSVerify != other.SkipTLSVerify {
		return false
	}
	return c.isSecretEqual(other)
}

func (c *S3FsConfig) areMultipartFieldsEqual(other S3FsConfig) bool {
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

func (c *S3FsConfig) isSecretEqual(other S3FsConfig) bool {
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
		return util.NewI18nError(
			errors.New("access_key cannot be empty with access_secret not empty"),
			util.I18nErrorAccessKeyRequired,
		)
	}
	if c.AccessSecret.IsEmpty() && c.AccessKey != "" {
		return util.NewI18nError(
			errors.New("access_secret cannot be empty with access_key not empty"),
			util.I18nErrorAccessSecretRequired,
		)
	}
	if c.AccessSecret.IsEncrypted() && !c.AccessSecret.IsValid() {
		return errors.New("invalid encrypted access_secret")
	}
	if !c.AccessSecret.IsEmpty() && !c.AccessSecret.IsValidInput() {
		return errors.New("invalid access_secret")
	}
	return nil
}

// ValidateAndEncryptCredentials validates the configuration and encrypts access secret if it is in plain text
func (c *S3FsConfig) ValidateAndEncryptCredentials(additionalData string) error {
	if err := c.validate(); err != nil {
		var errI18n *util.I18nError
		errValidation := util.NewValidationError(fmt.Sprintf("could not validate s3config: %v", err))
		if errors.As(err, &errI18n) {
			return util.NewI18nError(errValidation, errI18n.Message)
		}
		return util.NewI18nError(errValidation, util.I18nErrorFsValidation)
	}
	if c.AccessSecret.IsPlain() {
		c.AccessSecret.SetAdditionalData(additionalData)
		err := c.AccessSecret.Encrypt()
		if err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt s3 access secret: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	return nil
}

func (c *S3FsConfig) checkPartSizeAndConcurrency() error {
	if c.UploadPartSize != 0 && (c.UploadPartSize < 5 || c.UploadPartSize > 5000) {
		return util.NewI18nError(
			errors.New("upload_part_size cannot be != 0, lower than 5 (MB) or greater than 5000 (MB)"),
			util.I18nErrorULPartSizeInvalid,
		)
	}
	if c.UploadConcurrency < 0 || c.UploadConcurrency > 64 {
		return util.NewI18nError(
			fmt.Errorf("invalid upload concurrency: %v", c.UploadConcurrency),
			util.I18nErrorULConcurrencyInvalid,
		)
	}
	if c.DownloadPartSize != 0 && (c.DownloadPartSize < 5 || c.DownloadPartSize > 5000) {
		return util.NewI18nError(
			errors.New("download_part_size cannot be != 0, lower than 5 (MB) or greater than 5000 (MB)"),
			util.I18nErrorDLPartSizeInvalid,
		)
	}
	if c.DownloadConcurrency < 0 || c.DownloadConcurrency > 64 {
		return util.NewI18nError(
			fmt.Errorf("invalid download concurrency: %v", c.DownloadConcurrency),
			util.I18nErrorDLConcurrencyInvalid,
		)
	}
	return nil
}

func (c *S3FsConfig) isSameResource(other S3FsConfig) bool {
	if c.Bucket != other.Bucket {
		return false
	}
	if c.Endpoint != other.Endpoint {
		return false
	}
	return c.Region == other.Region
}

// validate returns an error if the configuration is not valid
func (c *S3FsConfig) validate() error {
	if c.AccessSecret == nil {
		c.AccessSecret = kms.NewEmptySecret()
	}
	if c.Bucket == "" {
		return util.NewI18nError(errors.New("bucket cannot be empty"), util.I18nErrorBucketRequired)
	}
	// the region may be embedded within the endpoint for some S3 compatible
	// object storage, for example B2
	if c.Endpoint == "" && c.Region == "" {
		return util.NewI18nError(errors.New("region cannot be empty"), util.I18nErrorRegionRequired)
	}
	if err := c.checkCredentials(); err != nil {
		return err
	}
	if c.KeyPrefix != "" {
		if strings.HasPrefix(c.KeyPrefix, "/") {
			return util.NewI18nError(errors.New("key_prefix cannot start with /"), util.I18nErrorKeyPrefixInvalid)
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

// ValidateAndEncryptCredentials validates the configuration and encrypts credentials if they are in plain text
func (c *GCSFsConfig) ValidateAndEncryptCredentials(additionalData string) error {
	if err := c.validate(); err != nil {
		var errI18n *util.I18nError
		errValidation := util.NewValidationError(fmt.Sprintf("could not validate GCS config: %v", err))
		if errors.As(err, &errI18n) {
			return util.NewI18nError(errValidation, errI18n.Message)
		}
		return util.NewI18nError(errValidation, util.I18nErrorFsValidation)
	}
	if c.Credentials.IsPlain() {
		c.Credentials.SetAdditionalData(additionalData)
		err := c.Credentials.Encrypt()
		if err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt GCS credentials: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	return nil
}

func (c *GCSFsConfig) isEqual(other GCSFsConfig) bool {
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
	if c.UploadPartSize != other.UploadPartSize {
		return false
	}
	if c.UploadPartMaxTime != other.UploadPartMaxTime {
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

func (c *GCSFsConfig) isSameResource(other GCSFsConfig) bool {
	return c.Bucket == other.Bucket
}

// validate returns an error if the configuration is not valid
func (c *GCSFsConfig) validate() error {
	if c.Credentials == nil || c.AutomaticCredentials == 1 {
		c.Credentials = kms.NewEmptySecret()
	}
	if c.Bucket == "" {
		return util.NewI18nError(errors.New("bucket cannot be empty"), util.I18nErrorBucketRequired)
	}
	if c.KeyPrefix != "" {
		if strings.HasPrefix(c.KeyPrefix, "/") {
			return util.NewI18nError(errors.New("key_prefix cannot start with /"), util.I18nErrorKeyPrefixInvalid)
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
		return util.NewI18nError(errors.New("invalid credentials"), util.I18nErrorFsCredentialsRequired)
	}
	c.StorageClass = strings.TrimSpace(c.StorageClass)
	c.ACL = strings.TrimSpace(c.ACL)
	if c.UploadPartSize < 0 {
		c.UploadPartSize = 0
	}
	if c.UploadPartMaxTime < 0 {
		c.UploadPartMaxTime = 0
	}
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

func (c *AzBlobFsConfig) isEqual(other AzBlobFsConfig) bool {
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

func (c *AzBlobFsConfig) isSecretEqual(other AzBlobFsConfig) bool {
	if c.AccountKey == nil {
		c.AccountKey = kms.NewEmptySecret()
	}
	if other.AccountKey == nil {
		other.AccountKey = kms.NewEmptySecret()
	}
	return c.AccountKey.IsEqual(other.AccountKey)
}

// ValidateAndEncryptCredentials validates the configuration and  encrypts access secret if it is in plain text
func (c *AzBlobFsConfig) ValidateAndEncryptCredentials(additionalData string) error {
	if err := c.validate(); err != nil {
		var errI18n *util.I18nError
		errValidation := util.NewValidationError(fmt.Sprintf("could not validate Azure Blob config: %v", err))
		if errors.As(err, &errI18n) {
			return util.NewI18nError(errValidation, errI18n.Message)
		}
		return util.NewI18nError(errValidation, util.I18nErrorFsValidation)
	}
	if c.AccountKey.IsPlain() {
		c.AccountKey.SetAdditionalData(additionalData)
		if err := c.AccountKey.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt Azure blob account key: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	if c.SASURL.IsPlain() {
		c.SASURL.SetAdditionalData(additionalData)
		if err := c.SASURL.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt Azure blob SAS URL: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	return nil
}

func (c *AzBlobFsConfig) checkCredentials() error {
	if c.SASURL.IsPlain() {
		_, err := url.Parse(c.SASURL.GetPayload())
		if err != nil {
			return util.NewI18nError(err, util.I18nErrorSASURLInvalid)
		}
		return nil
	}
	if c.SASURL.IsEncrypted() && !c.SASURL.IsValid() {
		return errors.New("invalid encrypted sas_url")
	}
	if !c.SASURL.IsEmpty() {
		return nil
	}
	if c.AccountName == "" || !c.AccountKey.IsValidInput() {
		return util.NewI18nError(errors.New("credentials cannot be empty or invalid"), util.I18nErrorAccountNameRequired)
	}
	if c.AccountKey.IsEncrypted() && !c.AccountKey.IsValid() {
		return errors.New("invalid encrypted account_key")
	}
	return nil
}

func (c *AzBlobFsConfig) checkPartSizeAndConcurrency() error {
	if c.UploadPartSize < 0 || c.UploadPartSize > 100 {
		return util.NewI18nError(
			fmt.Errorf("invalid upload part size: %v", c.UploadPartSize),
			util.I18nErrorULPartSizeInvalid,
		)
	}
	if c.UploadConcurrency < 0 || c.UploadConcurrency > 64 {
		return util.NewI18nError(
			fmt.Errorf("invalid upload concurrency: %v", c.UploadConcurrency),
			util.I18nErrorULConcurrencyInvalid,
		)
	}
	if c.DownloadPartSize < 0 || c.DownloadPartSize > 100 {
		return util.NewI18nError(
			fmt.Errorf("invalid download part size: %v", c.DownloadPartSize),
			util.I18nErrorDLPartSizeInvalid,
		)
	}
	if c.DownloadConcurrency < 0 || c.DownloadConcurrency > 64 {
		return util.NewI18nError(
			fmt.Errorf("invalid upload concurrency: %v", c.DownloadConcurrency),
			util.I18nErrorDLConcurrencyInvalid,
		)
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

func (c *AzBlobFsConfig) isSameResource(other AzBlobFsConfig) bool {
	if c.AccountName != other.AccountName {
		return false
	}
	if c.Endpoint != other.Endpoint {
		return false
	}
	return c.SASURL.GetPayload() == other.SASURL.GetPayload()
}

// validate returns an error if the configuration is not valid
func (c *AzBlobFsConfig) validate() error {
	if c.AccountKey == nil {
		c.AccountKey = kms.NewEmptySecret()
	}
	if c.SASURL == nil {
		c.SASURL = kms.NewEmptySecret()
	}
	// container could be embedded within SAS URL we check this at runtime
	if c.SASURL.IsEmpty() && c.Container == "" {
		return util.NewI18nError(errors.New("container cannot be empty"), util.I18nErrorContainerRequired)
	}
	if err := c.checkCredentials(); err != nil {
		return err
	}
	if c.KeyPrefix != "" {
		if strings.HasPrefix(c.KeyPrefix, "/") {
			return util.NewI18nError(errors.New("key_prefix cannot start with /"), util.I18nErrorKeyPrefixInvalid)
		}
		c.KeyPrefix = path.Clean(c.KeyPrefix)
		if !strings.HasSuffix(c.KeyPrefix, "/") {
			c.KeyPrefix += "/"
		}
	}
	if err := c.checkPartSizeAndConcurrency(); err != nil {
		return err
	}
	if !util.Contains(validAzAccessTier, c.AccessTier) {
		return fmt.Errorf("invalid access tier %q, valid values: \"''%v\"", c.AccessTier, strings.Join(validAzAccessTier, ", "))
	}
	return nil
}

// CryptFsConfig defines the configuration to store local files as encrypted
type CryptFsConfig struct {
	sdk.OSFsConfig
	Passphrase *kms.Secret `json:"passphrase,omitempty"`
}

// HideConfidentialData hides confidential data
func (c *CryptFsConfig) HideConfidentialData() {
	if c.Passphrase != nil {
		c.Passphrase.Hide()
	}
}

func (c *CryptFsConfig) isEqual(other CryptFsConfig) bool {
	if c.Passphrase == nil {
		c.Passphrase = kms.NewEmptySecret()
	}
	if other.Passphrase == nil {
		other.Passphrase = kms.NewEmptySecret()
	}
	return c.Passphrase.IsEqual(other.Passphrase)
}

// ValidateAndEncryptCredentials validates the configuration and encrypts the passphrase if it is in plain text
func (c *CryptFsConfig) ValidateAndEncryptCredentials(additionalData string) error {
	if err := c.validate(); err != nil {
		var errI18n *util.I18nError
		errValidation := util.NewValidationError(fmt.Sprintf("could not validate crypt fs config: %v", err))
		if errors.As(err, &errI18n) {
			return util.NewI18nError(errValidation, errI18n.Message)
		}
		return util.NewI18nError(errValidation, util.I18nErrorFsValidation)
	}
	if c.Passphrase.IsPlain() {
		c.Passphrase.SetAdditionalData(additionalData)
		if err := c.Passphrase.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt Crypt fs passphrase: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	return nil
}

func (c *CryptFsConfig) isSameResource(other CryptFsConfig) bool {
	return c.Passphrase.GetPayload() == other.Passphrase.GetPayload()
}

// validate returns an error if the configuration is not valid
func (c *CryptFsConfig) validate() error {
	if c.Passphrase == nil || c.Passphrase.IsEmpty() {
		return util.NewI18nError(errors.New("invalid passphrase"), util.I18nErrorPassphraseRequired)
	}
	if !c.Passphrase.IsValidInput() {
		return util.NewI18nError(errors.New("passphrase cannot be empty or invalid"), util.I18nErrorPassphraseRequired)
	}
	if c.Passphrase.IsEncrypted() && !c.Passphrase.IsValid() {
		return errors.New("invalid encrypted passphrase")
	}
	return nil
}

// pipeWriter defines a wrapper for pipeat.PipeWriterAt.
type pipeWriter struct {
	*pipeat.PipeWriterAt
	err  error
	done chan bool
}

// NewPipeWriter initializes a new PipeWriter
func NewPipeWriter(w *pipeat.PipeWriterAt) PipeWriter {
	return &pipeWriter{
		PipeWriterAt: w,
		err:          nil,
		done:         make(chan bool),
	}
}

// Close waits for the upload to end, closes the pipeat.PipeWriterAt and returns an error if any.
func (p *pipeWriter) Close() error {
	p.PipeWriterAt.Close() //nolint:errcheck // the returned error is always null
	<-p.done
	return p.err
}

// Done unlocks other goroutines waiting on Close().
// It must be called when the upload ends
func (p *pipeWriter) Done(err error) {
	p.err = err
	p.done <- true
}

func newPipeWriterAtOffset(w *pipeat.PipeWriterAt, offset int64) PipeWriter {
	return &pipeWriterAtOffset{
		pipeWriter: &pipeWriter{
			PipeWriterAt: w,
			err:          nil,
			done:         make(chan bool),
		},
		offset:      offset,
		writeOffset: offset,
	}
}

type pipeWriterAtOffset struct {
	*pipeWriter
	offset      int64
	writeOffset int64
}

func (p *pipeWriterAtOffset) WriteAt(buf []byte, off int64) (int, error) {
	if off < p.offset {
		return 0, fmt.Errorf("invalid offset %d, minimum accepted %d", off, p.offset)
	}
	return p.pipeWriter.WriteAt(buf, off-p.offset)
}

func (p *pipeWriterAtOffset) Write(buf []byte) (int, error) {
	n, err := p.WriteAt(buf, p.writeOffset)
	p.writeOffset += int64(n)
	return n, err
}

// NewPipeReader initializes a new PipeReader
func NewPipeReader(r *pipeat.PipeReaderAt) PipeReader {
	return &pipeReader{
		PipeReaderAt: r,
	}
}

// pipeReader defines a wrapper for pipeat.PipeReaderAt.
type pipeReader struct {
	*pipeat.PipeReaderAt
	mu       sync.RWMutex
	metadata map[string]string
}

func (p *pipeReader) setMetadata(value map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.metadata = value
}

func (p *pipeReader) setMetadataFromPointerVal(value map[string]*string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(value) == 0 {
		p.metadata = nil
		return
	}

	p.metadata = map[string]string{}
	for k, v := range value {
		val := util.GetStringFromPointer(v)
		if val != "" {
			p.metadata[k] = val
		}
	}
}

// Metadata implements the Metadater interface
func (p *pipeReader) Metadata() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.metadata) == 0 {
		return nil
	}
	result := make(map[string]string)
	for k, v := range p.metadata {
		result[k] = v
	}
	return result
}

func isEqualityCheckModeValid(mode int) bool {
	return mode >= 0 || mode <= 1
}

// isDirectory checks if a path exists and is a directory
func isDirectory(fs Fs, path string) (bool, error) {
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

// IsHTTPFs returns true if fs is an HTTP filesystem
func IsHTTPFs(fs Fs) bool {
	return strings.HasPrefix(fs.Name(), httpFsName)
}

// IsBufferedLocalOrSFTPFs returns true if this is a buffered SFTP or local filesystem
func IsBufferedLocalOrSFTPFs(fs Fs) bool {
	if osFs, ok := fs.(*OsFs); ok {
		return osFs.writeBufferSize > 0
	}
	if !IsSFTPFs(fs) {
		return false
	}
	return !fs.IsUploadResumeSupported()
}

// FsOpenReturnsFile returns true if fs.Open returns a *os.File handle
func FsOpenReturnsFile(fs Fs) bool {
	if osFs, ok := fs.(*OsFs); ok {
		return osFs.readBufferSize == 0
	}
	if sftpFs, ok := fs.(*SFTPFs); ok {
		return sftpFs.config.BufferSize == 0
	}
	return false
}

// IsLocalOrSFTPFs returns true if fs is local or SFTP
func IsLocalOrSFTPFs(fs Fs) bool {
	return IsLocalOsFs(fs) || IsSFTPFs(fs)
}

// HasTruncateSupport returns true if the fs supports truncate files
func HasTruncateSupport(fs Fs) bool {
	return IsLocalOsFs(fs) || IsSFTPFs(fs) || IsHTTPFs(fs)
}

// IsRenameAtomic returns true if renaming a directory is supposed to be atomic
func IsRenameAtomic(fs Fs) bool {
	if strings.HasPrefix(fs.Name(), s3fsName) {
		return false
	}
	if strings.HasPrefix(fs.Name(), gcsfsName) {
		return false
	}
	if strings.HasPrefix(fs.Name(), azBlobFsName) {
		return false
	}
	return true
}

// HasImplicitAtomicUploads returns true if the fs don't persists partial files on error
func HasImplicitAtomicUploads(fs Fs) bool {
	if strings.HasPrefix(fs.Name(), s3fsName) {
		return uploadMode&4 == 0
	}
	if strings.HasPrefix(fs.Name(), gcsfsName) {
		return uploadMode&8 == 0
	}
	if strings.HasPrefix(fs.Name(), azBlobFsName) {
		return uploadMode&16 == 0
	}
	return false
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

// IsUploadResumeSupported returns true if resuming uploads is supported
func IsUploadResumeSupported(fs Fs, size int64) bool {
	if fs.IsUploadResumeSupported() {
		return true
	}
	return fs.IsConditionalUploadResumeSupported(size)
}

func getLastModified(metadata map[string]string) int64 {
	if val, ok := metadata[lastModifiedField]; ok {
		lastModified, err := strconv.ParseInt(val, 10, 64)
		if err == nil {
			return lastModified
		}
	}
	return 0
}

func getAzureLastModified(metadata map[string]*string) int64 {
	for k, v := range metadata {
		if strings.ToLower(k) == lastModifiedField {
			if val := util.GetStringFromPointer(v); val != "" {
				lastModified, err := strconv.ParseInt(val, 10, 64)
				if err == nil {
					return lastModified
				}
			}
			return 0
		}
	}
	return 0
}

func validateOSFsConfig(config *sdk.OSFsConfig) error {
	if config.ReadBufferSize < 0 || config.ReadBufferSize > 10 {
		return fmt.Errorf("invalid read buffer size must be between 0 and 10 MB")
	}
	if config.WriteBufferSize < 0 || config.WriteBufferSize > 10 {
		return fmt.Errorf("invalid write buffer size must be between 0 and 10 MB")
	}
	return nil
}

func doCopy(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	if buf == nil {
		buf = make([]byte, 32768)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func getMountPath(mountPath string) string {
	if mountPath == "/" {
		return ""
	}
	return mountPath
}

func getLocalTempDir() string {
	if tempPath != "" {
		return tempPath
	}
	return filepath.Clean(os.TempDir())
}

func doRecursiveRename(fs Fs, source, target string,
	renameFn func(string, string, os.FileInfo, int) (int, int64, error),
	recursion int,
) (int, int64, error) {
	var numFiles int
	var filesSize int64

	if recursion > util.MaxRecursion {
		return numFiles, filesSize, util.ErrRecursionTooDeep
	}
	recursion++

	lister, err := fs.ReadDir(source)
	if err != nil {
		return numFiles, filesSize, err
	}
	defer lister.Close()

	for {
		entries, err := lister.Next(ListerBatchSize)
		finished := errors.Is(err, io.EOF)
		if err != nil && !finished {
			return numFiles, filesSize, err
		}
		for _, info := range entries {
			sourceEntry := fs.Join(source, info.Name())
			targetEntry := fs.Join(target, info.Name())
			files, size, err := renameFn(sourceEntry, targetEntry, info, recursion)
			if err != nil {
				if fs.IsNotExist(err) {
					fsLog(fs, logger.LevelInfo, "skipping rename for %q: %v", sourceEntry, err)
					continue
				}
				return numFiles, filesSize, err
			}
			numFiles += files
			filesSize += size
		}
		if finished {
			return numFiles, filesSize, nil
		}
	}
}

func fsLog(fs Fs, level logger.LogLevel, format string, v ...any) {
	logger.Log(level, fs.Name(), fs.ConnectionID(), format, v...)
}
