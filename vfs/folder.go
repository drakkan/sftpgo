package vfs

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/util"
)

// BaseVirtualFolder defines the path for the virtual folder and the used quota limits.
// The same folder can be shared among multiple users and each user can have different
// quota limits or a different virtual path.
type BaseVirtualFolder struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	MappedPath    string `json:"mapped_path,omitempty"`
	Description   string `json:"description,omitempty"`
	UsedQuotaSize int64  `json:"used_quota_size"`
	// Used quota as number of files
	UsedQuotaFiles int `json:"used_quota_files"`
	// Last quota update as unix timestamp in milliseconds
	LastQuotaUpdate int64 `json:"last_quota_update"`
	// list of usernames associated with this virtual folder
	Users []string `json:"users,omitempty"`
	// Filesystem configuration details
	FsConfig Filesystem `json:"filesystem"`
}

// GetEncryptionAdditionalData returns the additional data to use for AEAD
func (v *BaseVirtualFolder) GetEncryptionAdditionalData() string {
	return fmt.Sprintf("folder_%v", v.Name)
}

// GetGCSCredentialsFilePath returns the path for GCS credentials
func (v *BaseVirtualFolder) GetGCSCredentialsFilePath() string {
	return filepath.Join(credentialsDirPath, "folders", fmt.Sprintf("%v_gcs_credentials.json", v.Name))
}

// GetACopy returns a copy
func (v *BaseVirtualFolder) GetACopy() BaseVirtualFolder {
	users := make([]string, len(v.Users))
	copy(users, v.Users)
	return BaseVirtualFolder{
		ID:              v.ID,
		Name:            v.Name,
		Description:     v.Description,
		MappedPath:      v.MappedPath,
		UsedQuotaSize:   v.UsedQuotaSize,
		UsedQuotaFiles:  v.UsedQuotaFiles,
		LastQuotaUpdate: v.LastQuotaUpdate,
		Users:           users,
		FsConfig:        v.FsConfig.GetACopy(),
	}
}

// GetUsersAsString returns the list of users as comma separated string
func (v *BaseVirtualFolder) GetUsersAsString() string {
	return strings.Join(v.Users, ",")
}

// GetQuotaSummary returns used quota and last update as string
func (v *BaseVirtualFolder) GetQuotaSummary() string {
	var result string
	result = "Files: " + strconv.Itoa(v.UsedQuotaFiles)
	if v.UsedQuotaSize > 0 {
		result += ". Size: " + util.ByteCountIEC(v.UsedQuotaSize)
	}
	if v.LastQuotaUpdate > 0 {
		t := util.GetTimeFromMsecSinceEpoch(v.LastQuotaUpdate)
		result += fmt.Sprintf(". Last update: %v ", t.Format("2006-01-02 15:04")) // YYYY-MM-DD HH:MM
	}
	return result
}

// GetStorageDescrition returns the storage description
func (v *BaseVirtualFolder) GetStorageDescrition() string {
	switch v.FsConfig.Provider {
	case sdk.LocalFilesystemProvider:
		return fmt.Sprintf("Local: %v", v.MappedPath)
	case sdk.S3FilesystemProvider:
		return fmt.Sprintf("S3: %v", v.FsConfig.S3Config.Bucket)
	case sdk.GCSFilesystemProvider:
		return fmt.Sprintf("GCS: %v", v.FsConfig.GCSConfig.Bucket)
	case sdk.AzureBlobFilesystemProvider:
		return fmt.Sprintf("AzBlob: %v", v.FsConfig.AzBlobConfig.Container)
	case sdk.CryptedFilesystemProvider:
		return fmt.Sprintf("Encrypted: %v", v.MappedPath)
	case sdk.SFTPFilesystemProvider:
		return fmt.Sprintf("SFTP: %v", v.FsConfig.SFTPConfig.Endpoint)
	default:
		return ""
	}
}

// IsLocalOrLocalCrypted returns true if the folder provider is local or local encrypted
func (v *BaseVirtualFolder) IsLocalOrLocalCrypted() bool {
	return v.FsConfig.Provider == sdk.LocalFilesystemProvider || v.FsConfig.Provider == sdk.CryptedFilesystemProvider
}

// hideConfidentialData hides folder confidential data
func (v *BaseVirtualFolder) hideConfidentialData() {
	switch v.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		v.FsConfig.S3Config.HideConfidentialData()
	case sdk.GCSFilesystemProvider:
		v.FsConfig.GCSConfig.HideConfidentialData()
	case sdk.AzureBlobFilesystemProvider:
		v.FsConfig.AzBlobConfig.HideConfidentialData()
	case sdk.CryptedFilesystemProvider:
		v.FsConfig.CryptConfig.HideConfidentialData()
	case sdk.SFTPFilesystemProvider:
		v.FsConfig.SFTPConfig.HideConfidentialData()
	}
}

// PrepareForRendering prepares a folder for rendering.
// It hides confidential data and set to nil the empty secrets
// so they are not serialized
func (v *BaseVirtualFolder) PrepareForRendering() {
	v.hideConfidentialData()
	v.FsConfig.SetEmptySecretsIfNil()
}

// HasRedactedSecret returns true if the folder has a redacted secret
func (v *BaseVirtualFolder) HasRedactedSecret() bool {
	switch v.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		if v.FsConfig.S3Config.AccessSecret.IsRedacted() {
			return true
		}
	case sdk.GCSFilesystemProvider:
		if v.FsConfig.GCSConfig.Credentials.IsRedacted() {
			return true
		}
	case sdk.AzureBlobFilesystemProvider:
		if v.FsConfig.AzBlobConfig.AccountKey.IsRedacted() {
			return true
		}
		if v.FsConfig.AzBlobConfig.SASURL.IsRedacted() {
			return true
		}
	case sdk.CryptedFilesystemProvider:
		if v.FsConfig.CryptConfig.Passphrase.IsRedacted() {
			return true
		}
	case sdk.SFTPFilesystemProvider:
		if v.FsConfig.SFTPConfig.Password.IsRedacted() {
			return true
		}
		if v.FsConfig.SFTPConfig.PrivateKey.IsRedacted() {
			return true
		}
	}
	return false
}

// VirtualFolder defines a mapping between an SFTPGo exposed virtual path and a
// filesystem path outside the user home directory.
// The specified paths must be absolute and the virtual path cannot be "/",
// it must be a sub directory. The parent directory for the specified virtual
// path must exist. SFTPGo will try to automatically create any missing
// parent directory for the configured virtual folders at user login.
type VirtualFolder struct {
	BaseVirtualFolder
	VirtualPath string `json:"virtual_path"`
	// Maximum size allowed as bytes. 0 means unlimited, -1 included in user quota
	QuotaSize int64 `json:"quota_size"`
	// Maximum number of files allowed. 0 means unlimited, -1 included in user quota
	QuotaFiles int `json:"quota_files"`
}

// GetFilesystem returns the filesystem for this folder
func (v *VirtualFolder) GetFilesystem(connectionID string, forbiddenSelfUsers []string) (Fs, error) {
	switch v.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		return NewS3Fs(connectionID, v.MappedPath, v.VirtualPath, v.FsConfig.S3Config)
	case sdk.GCSFilesystemProvider:
		config := v.FsConfig.GCSConfig
		config.CredentialFile = v.GetGCSCredentialsFilePath()
		return NewGCSFs(connectionID, v.MappedPath, v.VirtualPath, config)
	case sdk.AzureBlobFilesystemProvider:
		return NewAzBlobFs(connectionID, v.MappedPath, v.VirtualPath, v.FsConfig.AzBlobConfig)
	case sdk.CryptedFilesystemProvider:
		return NewCryptFs(connectionID, v.MappedPath, v.VirtualPath, v.FsConfig.CryptConfig)
	case sdk.SFTPFilesystemProvider:
		return NewSFTPFs(connectionID, v.VirtualPath, v.MappedPath, forbiddenSelfUsers, v.FsConfig.SFTPConfig)
	default:
		return NewOsFs(connectionID, v.MappedPath, v.VirtualPath), nil
	}
}

// CheckMetadataConsistency checks the consistency between the metadata stored
// in the configured metadata plugin and the filesystem
func (v *VirtualFolder) CheckMetadataConsistency() error {
	fs, err := v.GetFilesystem("", nil)
	if err != nil {
		return err
	}
	defer fs.Close()

	return fs.CheckMetadata()
}

// ScanQuota scans the folder and returns the number of files and their size
func (v *VirtualFolder) ScanQuota() (int, int64, error) {
	fs, err := v.GetFilesystem("", nil)
	if err != nil {
		return 0, 0, err
	}
	defer fs.Close()

	return fs.ScanRootDirContents()
}

// IsIncludedInUserQuota returns true if the virtual folder is included in user quota
func (v *VirtualFolder) IsIncludedInUserQuota() bool {
	return v.QuotaFiles == -1 && v.QuotaSize == -1
}

// HasNoQuotaRestrictions returns true if no quota restrictions need to be applyed
func (v *VirtualFolder) HasNoQuotaRestrictions(checkFiles bool) bool {
	if v.QuotaSize == 0 && (!checkFiles || v.QuotaFiles == 0) {
		return true
	}
	return false
}

// GetACopy returns a copy
func (v *VirtualFolder) GetACopy() VirtualFolder {
	return VirtualFolder{
		BaseVirtualFolder: v.BaseVirtualFolder.GetACopy(),
		VirtualPath:       v.VirtualPath,
		QuotaSize:         v.QuotaSize,
		QuotaFiles:        v.QuotaFiles,
	}
}
