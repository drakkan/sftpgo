package vfs

import (
	"fmt"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/util"
)

// ValidatorHelper implements methods we need for Filesystem.ValidateConfig.
// It is implemented by vfs.Folder and dataprovider.User
type ValidatorHelper interface {
	GetGCSCredentialsFilePath() string
	GetEncryptionAdditionalData() string
}

// Filesystem defines filesystem details
type Filesystem struct {
	RedactedSecret string                 `json:"-"`
	Provider       sdk.FilesystemProvider `json:"provider"`
	S3Config       S3FsConfig             `json:"s3config,omitempty"`
	GCSConfig      GCSFsConfig            `json:"gcsconfig,omitempty"`
	AzBlobConfig   AzBlobFsConfig         `json:"azblobconfig,omitempty"`
	CryptConfig    CryptFsConfig          `json:"cryptconfig,omitempty"`
	SFTPConfig     SFTPFsConfig           `json:"sftpconfig,omitempty"`
}

// SetEmptySecrets sets the secrets to empty
func (f *Filesystem) SetEmptySecrets() {
	f.S3Config.AccessSecret = kms.NewEmptySecret()
	f.GCSConfig.Credentials = kms.NewEmptySecret()
	f.AzBlobConfig.AccountKey = kms.NewEmptySecret()
	f.AzBlobConfig.SASURL = kms.NewEmptySecret()
	f.CryptConfig.Passphrase = kms.NewEmptySecret()
	f.SFTPConfig.Password = kms.NewEmptySecret()
	f.SFTPConfig.PrivateKey = kms.NewEmptySecret()
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
	case sdk.S3FilesystemProvider:
		return f.S3Config.isEqual(&other.S3Config)
	case sdk.GCSFilesystemProvider:
		return f.GCSConfig.isEqual(&other.GCSConfig)
	case sdk.AzureBlobFilesystemProvider:
		return f.AzBlobConfig.isEqual(&other.AzBlobConfig)
	case sdk.CryptedFilesystemProvider:
		return f.CryptConfig.isEqual(&other.CryptConfig)
	case sdk.SFTPFilesystemProvider:
		return f.SFTPConfig.isEqual(&other.SFTPConfig)
	default:
		return true
	}
}

// Validate verifies the FsConfig matching the configured provider and sets all other
// Filesystem.*Config to their zero value if successful
func (f *Filesystem) Validate(helper ValidatorHelper) error {
	switch f.Provider {
	case sdk.S3FilesystemProvider:
		if err := f.S3Config.Validate(); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not validate s3config: %v", err))
		}
		if err := f.S3Config.EncryptCredentials(helper.GetEncryptionAdditionalData()); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not encrypt s3 access secret: %v", err))
		}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	case sdk.GCSFilesystemProvider:
		if err := f.GCSConfig.Validate(helper.GetGCSCredentialsFilePath()); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not validate GCS config: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	case sdk.AzureBlobFilesystemProvider:
		if err := f.AzBlobConfig.Validate(); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not validate Azure Blob config: %v", err))
		}
		if err := f.AzBlobConfig.EncryptCredentials(helper.GetEncryptionAdditionalData()); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not encrypt Azure blob account key: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	case sdk.CryptedFilesystemProvider:
		if err := f.CryptConfig.Validate(); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not validate Crypt fs config: %v", err))
		}
		if err := f.CryptConfig.EncryptCredentials(helper.GetEncryptionAdditionalData()); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not encrypt Crypt fs passphrase: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	case sdk.SFTPFilesystemProvider:
		if err := f.SFTPConfig.Validate(); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not validate SFTP fs config: %v", err))
		}
		if err := f.SFTPConfig.EncryptCredentials(helper.GetEncryptionAdditionalData()); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not encrypt SFTP fs credentials: %v", err))
		}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		return nil
	default:
		f.Provider = sdk.LocalFilesystemProvider
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
	case sdk.S3FilesystemProvider:
		if f.S3Config.AccessSecret.IsRedacted() {
			return true
		}
	case sdk.GCSFilesystemProvider:
		if f.GCSConfig.Credentials.IsRedacted() {
			return true
		}
	case sdk.AzureBlobFilesystemProvider:
		if f.AzBlobConfig.AccountKey.IsRedacted() {
			return true
		}
		if f.AzBlobConfig.SASURL.IsRedacted() {
			return true
		}
	case sdk.CryptedFilesystemProvider:
		if f.CryptConfig.Passphrase.IsRedacted() {
			return true
		}
	case sdk.SFTPFilesystemProvider:
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
	case sdk.S3FilesystemProvider:
		f.S3Config.HideConfidentialData()
	case sdk.GCSFilesystemProvider:
		f.GCSConfig.HideConfidentialData()
	case sdk.AzureBlobFilesystemProvider:
		f.AzBlobConfig.HideConfidentialData()
	case sdk.CryptedFilesystemProvider:
		f.CryptConfig.HideConfidentialData()
	case sdk.SFTPFilesystemProvider:
		f.SFTPConfig.HideConfidentialData()
	}
}

// GetACopy returns a filesystem copy
func (f *Filesystem) GetACopy() Filesystem {
	f.SetEmptySecretsIfNil()
	fs := Filesystem{
		Provider: f.Provider,
		S3Config: S3FsConfig{
			BaseS3FsConfig: sdk.BaseS3FsConfig{
				Bucket:              f.S3Config.Bucket,
				Region:              f.S3Config.Region,
				AccessKey:           f.S3Config.AccessKey,
				RoleARN:             f.S3Config.RoleARN,
				Endpoint:            f.S3Config.Endpoint,
				StorageClass:        f.S3Config.StorageClass,
				ACL:                 f.S3Config.ACL,
				KeyPrefix:           f.S3Config.KeyPrefix,
				UploadPartSize:      f.S3Config.UploadPartSize,
				UploadConcurrency:   f.S3Config.UploadConcurrency,
				DownloadPartSize:    f.S3Config.DownloadPartSize,
				DownloadConcurrency: f.S3Config.DownloadConcurrency,
				DownloadPartMaxTime: f.S3Config.DownloadPartMaxTime,
				UploadPartMaxTime:   f.S3Config.UploadPartMaxTime,
				ForcePathStyle:      f.S3Config.ForcePathStyle,
			},
			AccessSecret: f.S3Config.AccessSecret.Clone(),
		},
		GCSConfig: GCSFsConfig{
			BaseGCSFsConfig: sdk.BaseGCSFsConfig{
				Bucket:               f.GCSConfig.Bucket,
				CredentialFile:       f.GCSConfig.CredentialFile,
				AutomaticCredentials: f.GCSConfig.AutomaticCredentials,
				StorageClass:         f.GCSConfig.StorageClass,
				ACL:                  f.GCSConfig.ACL,
				KeyPrefix:            f.GCSConfig.KeyPrefix,
			},
			Credentials: f.GCSConfig.Credentials.Clone(),
		},
		AzBlobConfig: AzBlobFsConfig{
			BaseAzBlobFsConfig: sdk.BaseAzBlobFsConfig{
				Container:           f.AzBlobConfig.Container,
				AccountName:         f.AzBlobConfig.AccountName,
				Endpoint:            f.AzBlobConfig.Endpoint,
				KeyPrefix:           f.AzBlobConfig.KeyPrefix,
				UploadPartSize:      f.AzBlobConfig.UploadPartSize,
				UploadConcurrency:   f.AzBlobConfig.UploadConcurrency,
				DownloadPartSize:    f.AzBlobConfig.DownloadPartSize,
				DownloadConcurrency: f.AzBlobConfig.DownloadConcurrency,
				UseEmulator:         f.AzBlobConfig.UseEmulator,
				AccessTier:          f.AzBlobConfig.AccessTier,
			},
			AccountKey: f.AzBlobConfig.AccountKey.Clone(),
			SASURL:     f.AzBlobConfig.SASURL.Clone(),
		},
		CryptConfig: CryptFsConfig{
			Passphrase: f.CryptConfig.Passphrase.Clone(),
		},
		SFTPConfig: SFTPFsConfig{
			BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
				Endpoint:                f.SFTPConfig.Endpoint,
				Username:                f.SFTPConfig.Username,
				Prefix:                  f.SFTPConfig.Prefix,
				DisableCouncurrentReads: f.SFTPConfig.DisableCouncurrentReads,
				BufferSize:              f.SFTPConfig.BufferSize,
			},
			Password:   f.SFTPConfig.Password.Clone(),
			PrivateKey: f.SFTPConfig.PrivateKey.Clone(),
		},
	}
	if len(f.SFTPConfig.Fingerprints) > 0 {
		fs.SFTPConfig.Fingerprints = make([]string, len(f.SFTPConfig.Fingerprints))
		copy(fs.SFTPConfig.Fingerprints, f.SFTPConfig.Fingerprints)
	}
	return fs
}
