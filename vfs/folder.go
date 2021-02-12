package vfs

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/drakkan/sftpgo/utils"
)

// BaseVirtualFolder defines the path for the virtual folder and the used quota limits.
// The same folder can be shared among multiple users and each user can have different
// quota limits or a different virtual path.
type BaseVirtualFolder struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	MappedPath    string `json:"mapped_path,omitempty"`
	UsedQuotaSize int64  `json:"used_quota_size"`
	// Used quota as number of files
	UsedQuotaFiles int `json:"used_quota_files"`
	// Last quota update as unix timestamp in milliseconds
	LastQuotaUpdate int64 `json:"last_quota_update"`
	// list of usernames associated with this virtual folder
	Users []string `json:"users,omitempty"`
}

// GetACopy returns a copy
func (v *BaseVirtualFolder) GetACopy() BaseVirtualFolder {
	users := make([]string, len(v.Users))
	copy(users, v.Users)
	return BaseVirtualFolder{
		ID:              v.ID,
		Name:            v.Name,
		MappedPath:      v.MappedPath,
		UsedQuotaSize:   v.UsedQuotaSize,
		UsedQuotaFiles:  v.UsedQuotaFiles,
		LastQuotaUpdate: v.LastQuotaUpdate,
		Users:           users,
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
		result += ". Size: " + utils.ByteCountIEC(v.UsedQuotaSize)
	}
	if v.LastQuotaUpdate > 0 {
		t := utils.GetTimeFromMsecSinceEpoch(v.LastQuotaUpdate)
		result += fmt.Sprintf(". Last update: %v ", t.Format("2006-01-02 15:04:05")) // YYYY-MM-DD HH:MM:SS
	}
	return result
}

// VirtualFolder defines a mapping between a SFTP/SCP virtual path and a
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
