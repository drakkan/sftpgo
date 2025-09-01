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
	"errors"
	"fmt"
	"strings"

	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
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
	// list of group names associated with this virtual folder
	Groups []string `json:"groups,omitempty"`
	// Filesystem configuration details
	FsConfig Filesystem `json:"filesystem"`
}

// GetEncryptionAdditionalData returns the additional data to use for AEAD
func (v *BaseVirtualFolder) GetEncryptionAdditionalData() string {
	return fmt.Sprintf("folder_%v", v.Name)
}

// GetACopy returns a copy
func (v *BaseVirtualFolder) GetACopy() BaseVirtualFolder {
	users := make([]string, len(v.Users))
	copy(users, v.Users)
	groups := make([]string, len(v.Groups))
	copy(groups, v.Groups)
	return BaseVirtualFolder{
		ID:              v.ID,
		Name:            v.Name,
		Description:     v.Description,
		MappedPath:      v.MappedPath,
		UsedQuotaSize:   v.UsedQuotaSize,
		UsedQuotaFiles:  v.UsedQuotaFiles,
		LastQuotaUpdate: v.LastQuotaUpdate,
		Users:           users,
		Groups:          v.Groups,
		FsConfig:        v.FsConfig.GetACopy(),
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
	case sdk.HTTPFilesystemProvider:
		v.FsConfig.HTTPConfig.HideConfidentialData()
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
	return v.FsConfig.HasRedactedSecret()
}

// hasPathPlaceholder returns true if the folder has a path placeholder
func (v *BaseVirtualFolder) hasPathPlaceholder() bool {
	placeholders := []string{"%username%", "%role%"}
	var config string
	switch v.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		config = v.FsConfig.S3Config.KeyPrefix
	case sdk.GCSFilesystemProvider:
		config = v.FsConfig.GCSConfig.KeyPrefix
	case sdk.AzureBlobFilesystemProvider:
		config = v.FsConfig.AzBlobConfig.KeyPrefix
	case sdk.SFTPFilesystemProvider:
		config = v.FsConfig.SFTPConfig.Prefix
	case sdk.LocalFilesystemProvider, sdk.CryptedFilesystemProvider:
		config = v.MappedPath
	}
	for _, placeholder := range placeholders {
		if strings.Contains(config, placeholder) {
			return true
		}
	}
	return false
}

// VirtualFolder defines a mapping between an SFTPGo virtual path and a
// filesystem path outside the user home directory.
// The specified paths must be absolute and the virtual path cannot be "/",
// it must be a sub directory. The parent directory for the specified virtual
// path must exist. SFTPGo will try to automatically create any missing
// parent directory for the configured virtual folders at user login.
type VirtualFolder struct {
	BaseVirtualFolder
	VirtualPath string `json:"virtual_path"`
	// Optional subdirectory within the mapped path where files are stored
	VirtualSubdirectory string `json:"virtual_subdirectory,omitempty"`
	// Maximum size allowed as bytes. 0 means unlimited, -1 included in user quota
	QuotaSize int64 `json:"quota_size"`
	// Maximum number of files allowed. 0 means unlimited, -1 included in user quota
	QuotaFiles int `json:"quota_files"`
}

// GetFilesystem returns the filesystem for this folder
func (v *VirtualFolder) GetFilesystem(connectionID string, forbiddenSelfUsers []string) (Fs, error) {
	switch v.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		return NewS3Fs(connectionID, v.MappedPath, v.VirtualSubdirectory, v.VirtualPath, v.FsConfig.S3Config)
	case sdk.GCSFilesystemProvider:
		return NewGCSFs(connectionID, v.MappedPath, v.VirtualSubdirectory, v.VirtualPath, v.FsConfig.GCSConfig)
	case sdk.AzureBlobFilesystemProvider:
		return NewAzBlobFs(connectionID, v.MappedPath, v.VirtualSubdirectory, v.VirtualPath, v.FsConfig.AzBlobConfig)
	case sdk.CryptedFilesystemProvider:
		return NewCryptFs(connectionID, v.MappedPath, v.VirtualSubdirectory, v.VirtualPath, v.FsConfig.CryptConfig)
	case sdk.SFTPFilesystemProvider:
		return NewSFTPFs(connectionID, v.VirtualPath, v.VirtualSubdirectory, v.MappedPath, forbiddenSelfUsers, v.FsConfig.SFTPConfig)
	case sdk.HTTPFilesystemProvider:
		return NewHTTPFs(connectionID, v.MappedPath, v.VirtualSubdirectory, v.VirtualPath, v.FsConfig.HTTPConfig)
	default:
		return NewOsFs(connectionID, v.MappedPath, v.VirtualSubdirectory, v.VirtualPath, &v.FsConfig.OSConfig), nil
	}
}

// ScanQuota scans the folder and returns the number of files and their size
func (v *VirtualFolder) ScanQuota() (int, int64, error) {
	if v.hasPathPlaceholder() {
		return 0, 0, errors.New("cannot scan quota: this folder has a path placeholder")
	}
	fs, err := v.GetFilesystem(xid.New().String(), nil)
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
		BaseVirtualFolder:   v.BaseVirtualFolder.GetACopy(),
		VirtualPath:         v.VirtualPath,
		VirtualSubdirectory: v.VirtualSubdirectory,
		QuotaSize:           v.QuotaSize,
		QuotaFiles:          v.QuotaFiles,
	}
}
