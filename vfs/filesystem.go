package vfs

import (
	"fmt"

	"github.com/drakkan/sftpgo/kms"
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

// ValidatorHelper implements methods we need for Filesystem.ValidateConfig (it is implemented by vfs.Folder and dataprovider.User)
type ValidatorHelper interface {
	GetGCSCredentialsFilePath() string
	GetEncrytionAdditionalData() string
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
			SASURL:            f.AzBlobConfig.SASURL,
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

// ValidateConfig verifies the FsConfig matching the configured .Provider and sets all other Filesystem.*Config to their zero value if successful
func (f *Filesystem) ValidateConfig(helper ValidatorHelper) error {
	if f.Provider == S3FilesystemProvider {
		if err := f.S3Config.Validate(); err != nil {
			return NewValidationError(fmt.Sprintf("could not validate s3config: %v", err))
		}
		if err := f.S3Config.EncryptCredentials(helper.GetEncrytionAdditionalData()); err != nil {
			return NewValidationError(fmt.Sprintf("could not encrypt s3 access secret: %v", err))
		}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	} else if f.Provider == GCSFilesystemProvider {
		if err := f.GCSConfig.Validate(helper.GetGCSCredentialsFilePath()); err != nil {
			return NewValidationError(fmt.Sprintf("could not validate GCS config: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	} else if f.Provider == AzureBlobFilesystemProvider {
		if err := f.AzBlobConfig.Validate(); err != nil {
			return NewValidationError(fmt.Sprintf("could not validate Azure Blob config: %v", err))
		}
		if err := f.AzBlobConfig.EncryptCredentials(helper.GetEncrytionAdditionalData()); err != nil {
			return NewValidationError(fmt.Sprintf("could not encrypt Azure blob account key: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	} else if f.Provider == CryptedFilesystemProvider {
		if err := f.CryptConfig.Validate(); err != nil {
			return NewValidationError(fmt.Sprintf("could not validate Crypt fs config: %v", err))
		}
		if err := f.CryptConfig.EncryptCredentials(helper.GetEncrytionAdditionalData()); err != nil {
			return NewValidationError(fmt.Sprintf("could not encrypt Crypt fs passphrase: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	} else if f.Provider == SFTPFilesystemProvider {
		if err := f.SFTPConfig.Validate(); err != nil {
			return NewValidationError(fmt.Sprintf("could not validate SFTP fs config: %v", err))
		}
		if err := f.SFTPConfig.EncryptCredentials(helper.GetEncrytionAdditionalData()); err != nil {
			return NewValidationError(fmt.Sprintf("could not encrypt SFTP fs credentials: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		return nil
	}
	f.Provider = LocalFilesystemProvider
	f.S3Config = S3FsConfig{}
	f.GCSConfig = GCSFsConfig{}
	f.AzBlobConfig = AzBlobFsConfig{}
	f.CryptConfig = CryptFsConfig{}
	f.SFTPConfig = SFTPFsConfig{}
	return nil
}

// ValidationError raised if input data is not valid
type ValidationError struct {
	err string
}

// Validation error details
func (e *ValidationError) Error() string {
	return fmt.Sprintf("Validation error: %s", e.err)
}

// NewValidationError returns a validation errors
func NewValidationError(error string) *ValidationError {
	return &ValidationError{
		err: error,
	}
}
