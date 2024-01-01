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

package vfs

import (
	"os"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/kms"
)

// Filesystem defines filesystem details
type Filesystem struct {
	RedactedSecret string                 `json:"-"`
	Provider       sdk.FilesystemProvider `json:"provider"`
	OSConfig       sdk.OSFsConfig         `json:"osconfig,omitempty"`
	S3Config       S3FsConfig             `json:"s3config,omitempty"`
	GCSConfig      GCSFsConfig            `json:"gcsconfig,omitempty"`
	AzBlobConfig   AzBlobFsConfig         `json:"azblobconfig,omitempty"`
	CryptConfig    CryptFsConfig          `json:"cryptconfig,omitempty"`
	SFTPConfig     SFTPFsConfig           `json:"sftpconfig,omitempty"`
	HTTPConfig     HTTPFsConfig           `json:"httpconfig,omitempty"`
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
	f.SFTPConfig.KeyPassphrase = kms.NewEmptySecret()
	f.HTTPConfig.Password = kms.NewEmptySecret()
	f.HTTPConfig.APIKey = kms.NewEmptySecret()
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
	if f.SFTPConfig.KeyPassphrase == nil {
		f.SFTPConfig.KeyPassphrase = kms.NewEmptySecret()
	}
	if f.HTTPConfig.Password == nil {
		f.HTTPConfig.Password = kms.NewEmptySecret()
	}
	if f.HTTPConfig.APIKey == nil {
		f.HTTPConfig.APIKey = kms.NewEmptySecret()
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
	f.SFTPConfig.setNilSecretsIfEmpty()
	f.HTTPConfig.setNilSecretsIfEmpty()
}

// IsEqual returns true if the fs is equal to other
func (f *Filesystem) IsEqual(other Filesystem) bool {
	if f.Provider != other.Provider {
		return false
	}
	switch f.Provider {
	case sdk.S3FilesystemProvider:
		return f.S3Config.isEqual(other.S3Config)
	case sdk.GCSFilesystemProvider:
		return f.GCSConfig.isEqual(other.GCSConfig)
	case sdk.AzureBlobFilesystemProvider:
		return f.AzBlobConfig.isEqual(other.AzBlobConfig)
	case sdk.CryptedFilesystemProvider:
		return f.CryptConfig.isEqual(other.CryptConfig)
	case sdk.SFTPFilesystemProvider:
		return f.SFTPConfig.isEqual(other.SFTPConfig)
	case sdk.HTTPFilesystemProvider:
		return f.HTTPConfig.isEqual(other.HTTPConfig)
	default:
		return true
	}
}

// IsSameResource returns true if fs point to the same resource as other
func (f *Filesystem) IsSameResource(other Filesystem) bool {
	if f.Provider != other.Provider {
		return false
	}
	switch f.Provider {
	case sdk.S3FilesystemProvider:
		return f.S3Config.isSameResource(other.S3Config)
	case sdk.GCSFilesystemProvider:
		return f.GCSConfig.isSameResource(other.GCSConfig)
	case sdk.AzureBlobFilesystemProvider:
		return f.AzBlobConfig.isSameResource(other.AzBlobConfig)
	case sdk.CryptedFilesystemProvider:
		return f.CryptConfig.isSameResource(other.CryptConfig)
	case sdk.SFTPFilesystemProvider:
		return f.SFTPConfig.isSameResource(other.SFTPConfig)
	case sdk.HTTPFilesystemProvider:
		return f.HTTPConfig.isSameResource(other.HTTPConfig)
	default:
		return true
	}
}

// GetPathSeparator returns the path separator
func (f *Filesystem) GetPathSeparator() string {
	switch f.Provider {
	case sdk.LocalFilesystemProvider, sdk.CryptedFilesystemProvider:
		return string(os.PathSeparator)
	default:
		return "/"
	}
}

// Validate verifies the FsConfig matching the configured provider and sets all other
// Filesystem.*Config to their zero value if successful
func (f *Filesystem) Validate(additionalData string) error {
	switch f.Provider {
	case sdk.S3FilesystemProvider:
		if err := f.S3Config.ValidateAndEncryptCredentials(additionalData); err != nil {
			return err
		}
		f.OSConfig = sdk.OSFsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		f.HTTPConfig = HTTPFsConfig{}
		return nil
	case sdk.GCSFilesystemProvider:
		if err := f.GCSConfig.ValidateAndEncryptCredentials(additionalData); err != nil {
			return err
		}
		f.OSConfig = sdk.OSFsConfig{}
		f.S3Config = S3FsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		f.HTTPConfig = HTTPFsConfig{}
		return nil
	case sdk.AzureBlobFilesystemProvider:
		if err := f.AzBlobConfig.ValidateAndEncryptCredentials(additionalData); err != nil {
			return err
		}
		f.OSConfig = sdk.OSFsConfig{}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		f.HTTPConfig = HTTPFsConfig{}
		return nil
	case sdk.CryptedFilesystemProvider:
		if err := f.CryptConfig.ValidateAndEncryptCredentials(additionalData); err != nil {
			return err
		}
		f.OSConfig = sdk.OSFsConfig{}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		f.HTTPConfig = HTTPFsConfig{}
		return validateOSFsConfig(&f.CryptConfig.OSFsConfig)
	case sdk.SFTPFilesystemProvider:
		if err := f.SFTPConfig.ValidateAndEncryptCredentials(additionalData); err != nil {
			return err
		}
		f.OSConfig = sdk.OSFsConfig{}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.HTTPConfig = HTTPFsConfig{}
		return nil
	case sdk.HTTPFilesystemProvider:
		if err := f.HTTPConfig.ValidateAndEncryptCredentials(additionalData); err != nil {
			return err
		}
		f.OSConfig = sdk.OSFsConfig{}
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		return nil
	default:
		f.Provider = sdk.LocalFilesystemProvider
		f.S3Config = S3FsConfig{}
		f.GCSConfig = GCSFsConfig{}
		f.AzBlobConfig = AzBlobFsConfig{}
		f.CryptConfig = CryptFsConfig{}
		f.SFTPConfig = SFTPFsConfig{}
		f.HTTPConfig = HTTPFsConfig{}
		return validateOSFsConfig(&f.OSConfig)
	}
}

// HasRedactedSecret returns true if configured the filesystem configuration has a redacted secret
func (f *Filesystem) HasRedactedSecret() bool {
	// TODO move vfs specific code into each *FsConfig struct
	switch f.Provider {
	case sdk.S3FilesystemProvider:
		return f.S3Config.AccessSecret.IsRedacted()
	case sdk.GCSFilesystemProvider:
		return f.GCSConfig.Credentials.IsRedacted()
	case sdk.AzureBlobFilesystemProvider:
		if f.AzBlobConfig.AccountKey.IsRedacted() {
			return true
		}
		return f.AzBlobConfig.SASURL.IsRedacted()
	case sdk.CryptedFilesystemProvider:
		return f.CryptConfig.Passphrase.IsRedacted()
	case sdk.SFTPFilesystemProvider:
		if f.SFTPConfig.Password.IsRedacted() {
			return true
		}
		if f.SFTPConfig.PrivateKey.IsRedacted() {
			return true
		}
		return f.SFTPConfig.KeyPassphrase.IsRedacted()
	case sdk.HTTPFilesystemProvider:
		if f.HTTPConfig.Password.IsRedacted() {
			return true
		}
		return f.HTTPConfig.APIKey.IsRedacted()
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
	case sdk.HTTPFilesystemProvider:
		f.HTTPConfig.HideConfidentialData()
	}
}

// GetACopy returns a filesystem copy
func (f *Filesystem) GetACopy() Filesystem {
	f.SetEmptySecretsIfNil()
	fs := Filesystem{
		Provider: f.Provider,
		OSConfig: sdk.OSFsConfig{
			ReadBufferSize:  f.OSConfig.ReadBufferSize,
			WriteBufferSize: f.OSConfig.WriteBufferSize,
		},
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
				SkipTLSVerify:       f.S3Config.SkipTLSVerify,
			},
			AccessSecret: f.S3Config.AccessSecret.Clone(),
		},
		GCSConfig: GCSFsConfig{
			BaseGCSFsConfig: sdk.BaseGCSFsConfig{
				Bucket:               f.GCSConfig.Bucket,
				AutomaticCredentials: f.GCSConfig.AutomaticCredentials,
				StorageClass:         f.GCSConfig.StorageClass,
				ACL:                  f.GCSConfig.ACL,
				KeyPrefix:            f.GCSConfig.KeyPrefix,
				UploadPartSize:       f.GCSConfig.UploadPartSize,
				UploadPartMaxTime:    f.GCSConfig.UploadPartMaxTime,
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
			OSFsConfig: sdk.OSFsConfig{
				ReadBufferSize:  f.CryptConfig.ReadBufferSize,
				WriteBufferSize: f.CryptConfig.WriteBufferSize,
			},
			Passphrase: f.CryptConfig.Passphrase.Clone(),
		},
		SFTPConfig: SFTPFsConfig{
			BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
				Endpoint:                f.SFTPConfig.Endpoint,
				Username:                f.SFTPConfig.Username,
				Prefix:                  f.SFTPConfig.Prefix,
				DisableCouncurrentReads: f.SFTPConfig.DisableCouncurrentReads,
				BufferSize:              f.SFTPConfig.BufferSize,
				EqualityCheckMode:       f.SFTPConfig.EqualityCheckMode,
			},
			Password:      f.SFTPConfig.Password.Clone(),
			PrivateKey:    f.SFTPConfig.PrivateKey.Clone(),
			KeyPassphrase: f.SFTPConfig.KeyPassphrase.Clone(),
		},
		HTTPConfig: HTTPFsConfig{
			BaseHTTPFsConfig: sdk.BaseHTTPFsConfig{
				Endpoint:          f.HTTPConfig.Endpoint,
				Username:          f.HTTPConfig.Username,
				SkipTLSVerify:     f.HTTPConfig.SkipTLSVerify,
				EqualityCheckMode: f.HTTPConfig.EqualityCheckMode,
			},
			Password: f.HTTPConfig.Password.Clone(),
			APIKey:   f.HTTPConfig.APIKey.Clone(),
		},
	}
	if len(f.SFTPConfig.Fingerprints) > 0 {
		fs.SFTPConfig.Fingerprints = make([]string, len(f.SFTPConfig.Fingerprints))
		copy(fs.SFTPConfig.Fingerprints, f.SFTPConfig.Fingerprints)
	}
	return fs
}
