package vfs

import (
	"fmt"

	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/utils"
)

// FilesystemProvider defines the supported storage filesystems
type FilesystemProvider int

// supported values for FilesystemProvider
const (
	LocalFilesystemProvider     FilesystemProvider = iota // Local
	S3FilesystemProvider                                  // AWS S3 compatible
	GCSFilesystemProvider                                 // Google Cloud Storage
	AzureBlobFilesystemProvider                           // Azure Blob Storage
	CryptedFilesystemProvider                             // Local encrypted
	SFTPFilesystemProvider                                // SFTP
)

// GetProviderByName returns the FilesystemProvider matching a given name
//
// to provide backwards compatibility, numeric strings are accepted as well
func GetProviderByName(name string) FilesystemProvider {
	switch name {
	case "0", "osfs":
		return LocalFilesystemProvider
	case "1", "s3fs":
		return S3FilesystemProvider
	case "2", "gcsfs":
		return GCSFilesystemProvider
	case "3", "azblobfs":
		return AzureBlobFilesystemProvider
	case "4", "cryptfs":
		return CryptedFilesystemProvider
	case "5", "sftpfs":
		return SFTPFilesystemProvider
	}

	// TODO think about returning an error value instead of silently defaulting to LocalFilesystemProvider
	return LocalFilesystemProvider
}

// ValidatorHelper implements methods we need for Filesystem.ValidateConfig.
// It is implemented by vfs.Folder and dataprovider.User
type ValidatorHelper interface {
	GetGCSCredentialsFilePath() string
	GetEncryptionAdditionalData() string
}

// Filesystem defines cloud storage filesystem details
type Filesystem struct {
	RedactedSecret string             `json:"-"`
	Provider       FilesystemProvider `json:"provider"`
	S3Config       S3FsConfig         `json:"s3config,omitempty"`
	GCSConfig      GCSFsConfig        `json:"gcsconfig,omitempty"`
	AzBlobConfig   AzBlobFsConfig     `json:"azblobconfig,omitempty"`
	CryptConfig    CryptFsConfig      `json:"cryptconfig,omitempty"`
	SFTPConfig     SFTPFsConfig       `json:"sftpconfig,omitempty"`
}

// SetEmptySecretsIfNil sets the secrets to empty if nil
func (f *Filesystem) SetEmptySecretsIfNil() {
	if f.S3Config.AccessSecret == nil {
		f.S3Config.AccessSecret = kms.NewEmptySecret()
	}
	if f.GCSConfig.Credentials == nil {
		f.GCSConfig.Credentials = kms.NewEmptySecret()
	}
	if f.AzBlobConfig.AccountKey == nil {
		f.AzBlobConfig.AccountKey = kms.NewEmptySecret()
	}
	if f.AzBlobConfig.SASURL == nil {
		f.AzBlobConfig.SASURL = kms.NewEmptySecret()
	}
	if f.CryptConfig.Passphrase == nil {
		f.CryptConfig.Passphrase = kms.NewEmptySecret()
	}
	if f.SFTPConfig.Password == nil {
		f.SFTPConfig.Password = kms.NewEmptySecret()
	}
	if f.SFTPConfig.PrivateKey == nil {
		f.SFTPConfig.PrivateKey = kms.NewEmptySecret()
	}
}

// SetNilSecretsIfEmpty set the secrets to nil if empty.
// This is useful before rendering as JSON so the empty fields
// will not be serialized.
func (f *Filesystem) SetNilSecretsIfEmpty() {
	if f.S3Config.AccessSecret != nil && f.S3Config.AccessSecret.IsEmpty() {
		f.S3Config.AccessSecret = nil
	}
	if f.GCSConfig.Credentials != nil && f.GCSConfig.Credentials.IsEmpty() {
		f.GCSConfig.Credentials = nil
	}
	if f.AzBlobConfig.AccountKey != nil && f.AzBlobConfig.AccountKey.IsEmpty() {
		f.AzBlobConfig.AccountKey = nil
	}
	if f.AzBlobConfig.SASURL != nil && f.AzBlobConfig.SASURL.IsEmpty() {
		f.AzBlobConfig.SASURL = nil
	}
	if f.CryptConfig.Passphrase != nil && f.CryptConfig.Passphrase.IsEmpty() {
		f.CryptConfig.Passphrase = nil
	}
	if f.SFTPConfig.Password != nil && f.SFTPConfig.Password.IsEmpty() {
		f.SFTPConfig.Password = nil
	}
	if f.SFTPConfig.PrivateKey != nil && f.SFTPConfig.PrivateKey.IsEmpty() {
		f.SFTPConfig.PrivateKey = nil
	}
}

// IsEqual returns true if the fs is equal to other
func (f *Filesystem) IsEqual(other *Filesystem) bool {
	if f.Provider != other.Provider {
		return false
	}
	switch f.Provider {
	case S3FilesystemProvider:
		return f.S3Config.isEqual(&other.S3Config)
	case GCSFilesystemProvider:
		return f.GCSConfig.isEqual(&other.GCSConfig)
	case AzureBlobFilesystemProvider:
		return f.AzBlobConfig.isEqual(&other.AzBlobConfig)
	case CryptedFilesystemProvider:
		return f.CryptConfig.isEqual(&other.CryptConfig)
	case SFTPFilesystemProvider:
		return f.SFTPConfig.isEqual(&other.SFTPConfig)
	default:
		return true
	}
}

// Validate verifies the FsConfig matching the configured provider and sets all other
// Filesystem.*Config to their zero value if successful
func (f *Filesystem) Validate(helper ValidatorHelper) error {
	switch f.Provider {
	case S3FilesystemProvider:
		if err := f.S3Config.Validate(); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not validate s3config: %v", err))
		}
		if err := f.S3Config.EncryptCredentials(helper.GetEncryptionAdditionalData()); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not encrypt s3 access secret: %v", err))
		}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	case GCSFilesystemProvider:
		if err := f.GCSConfig.Validate(helper.GetGCSCredentialsFilePath()); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not validate GCS config: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	case AzureBlobFilesystemProvider:
		if err := f.AzBlobConfig.Validate(); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not validate Azure Blob config: %v", err))
		}
		if err := f.AzBlobConfig.EncryptCredentials(helper.GetEncryptionAdditionalData()); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not encrypt Azure blob account key: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	case CryptedFilesystemProvider:
		if err := f.CryptConfig.Validate(); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not validate Crypt fs config: %v", err))
		}
		if err := f.CryptConfig.EncryptCredentials(helper.GetEncryptionAdditionalData()); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not encrypt Crypt fs passphrase: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	case SFTPFilesystemProvider:
		if err := f.SFTPConfig.Validate(); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not validate SFTP fs config: %v", err))
		}
		if err := f.SFTPConfig.EncryptCredentials(helper.GetEncryptionAdditionalData()); err != nil {
			return utils.NewValidationError(fmt.Sprintf("could not encrypt SFTP fs credentials: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		return nil
	default:
		f.Provider = LocalFilesystemProvider
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	}
}

// HasRedactedSecret returns true if configured the filesystem configuration has a redacted secret
func (f *Filesystem) HasRedactedSecret() bool {
	// TODO move vfs specific code into each *FsConfig struct
	switch f.Provider {
	case S3FilesystemProvider:
		if f.S3Config.AccessSecret.IsRedacted() {
			return true
		}
	case GCSFilesystemProvider:
		if f.GCSConfig.Credentials.IsRedacted() {
			return true
		}
	case AzureBlobFilesystemProvider:
		if f.AzBlobConfig.AccountKey.IsRedacted() {
			return true
		}
	case CryptedFilesystemProvider:
		if f.CryptConfig.Passphrase.IsRedacted() {
			return true
		}
	case SFTPFilesystemProvider:
		if f.SFTPConfig.Password.IsRedacted() {
			return true
		}
		if f.SFTPConfig.PrivateKey.IsRedacted() {
			return true
		}
	}

	return false
}

// HideConfidentialData hides filesystem confidential data
func (f *Filesystem) HideConfidentialData() {
	switch f.Provider {
	case S3FilesystemProvider:
		f.S3Config.AccessSecret.Hide()
	case GCSFilesystemProvider:
		f.GCSConfig.Credentials.Hide()
	case AzureBlobFilesystemProvider:
		f.AzBlobConfig.AccountKey.Hide()
		f.AzBlobConfig.SASURL.Hide()
	case CryptedFilesystemProvider:
		f.CryptConfig.Passphrase.Hide()
	case SFTPFilesystemProvider:
		f.SFTPConfig.Password.Hide()
		f.SFTPConfig.PrivateKey.Hide()
	}
}

// GetACopy returns a copy
func (f *Filesystem) GetACopy() Filesystem {
	f.SetEmptySecretsIfNil()
	fs := Filesystem{
		Provider: f.Provider,
		S3Config: S3FsConfig{
			Bucket:            f.S3Config.Bucket,
			Region:            f.S3Config.Region,
			AccessKey:         f.S3Config.AccessKey,
			AccessSecret:      f.S3Config.AccessSecret.Clone(),
			Endpoint:          f.S3Config.Endpoint,
			StorageClass:      f.S3Config.StorageClass,
			KeyPrefix:         f.S3Config.KeyPrefix,
			UploadPartSize:    f.S3Config.UploadPartSize,
			UploadConcurrency: f.S3Config.UploadConcurrency,
		},
		GCSConfig: GCSFsConfig{
			Bucket:               f.GCSConfig.Bucket,
			CredentialFile:       f.GCSConfig.CredentialFile,
			Credentials:          f.GCSConfig.Credentials.Clone(),
			AutomaticCredentials: f.GCSConfig.AutomaticCredentials,
			StorageClass:         f.GCSConfig.StorageClass,
			KeyPrefix:            f.GCSConfig.KeyPrefix,
		},
		AzBlobConfig: AzBlobFsConfig{
			Container:         f.AzBlobConfig.Container,
			AccountName:       f.AzBlobConfig.AccountName,
			AccountKey:        f.AzBlobConfig.AccountKey.Clone(),
			Endpoint:          f.AzBlobConfig.Endpoint,
			SASURL:            f.AzBlobConfig.SASURL.Clone(),
			KeyPrefix:         f.AzBlobConfig.KeyPrefix,
			UploadPartSize:    f.AzBlobConfig.UploadPartSize,
			UploadConcurrency: f.AzBlobConfig.UploadConcurrency,
			UseEmulator:       f.AzBlobConfig.UseEmulator,
			AccessTier:        f.AzBlobConfig.AccessTier,
		},
		CryptConfig: CryptFsConfig{
			Passphrase: f.CryptConfig.Passphrase.Clone(),
		},
		SFTPConfig: SFTPFsConfig{
			Endpoint:                f.SFTPConfig.Endpoint,
			Username:                f.SFTPConfig.Username,
			Password:                f.SFTPConfig.Password.Clone(),
			PrivateKey:              f.SFTPConfig.PrivateKey.Clone(),
			Prefix:                  f.SFTPConfig.Prefix,
			DisableCouncurrentReads: f.SFTPConfig.DisableCouncurrentReads,
			BufferSize:              f.SFTPConfig.BufferSize,
		},
	}
	if len(f.SFTPConfig.Fingerprints) > 0 {
		fs.SFTPConfig.Fingerprints = make([]string, len(f.SFTPConfig.Fingerprints))
		copy(fs.SFTPConfig.Fingerprints, f.SFTPConfig.Fingerprints)
	}
	return fs
}
