package dataprovider

import (
	"encoding/json"
	"path/filepath"

	"github.com/drakkan/sftpgo/utils"
)

// Permissions
const (
	PermAny            = "*"
	PermListItems      = "list"
	PermDownload       = "download"
	PermUpload         = "upload"
	PermDelete         = "delete"
	PermRename         = "rename"
	PermCreateDirs     = "create_dirs"
	PermCreateSymlinks = "create_symlinks"
)

// User defines an SFTP user
type User struct {
	ID                int64    `json:"id"`
	Username          string   `json:"username"`
	Password          string   `json:"password,omitempty"`
	PublicKey         string   `json:"public_key,omitempty"`
	HomeDir           string   `json:"home_dir"`
	UID               int      `json:"uid"`
	GID               int      `json:"gid"`
	MaxSessions       int      `json:"max_sessions"`
	QuotaSize         int64    `json:"quota_size"`
	QuotaFiles        int      `json:"quota_files"`
	Permissions       []string `json:"permissions"`
	UsedQuotaSize     int64    `json:"used_quota_size"`
	UsedQuotaFiles    int      `json:"used_quota_files"`
	LastQuotaUpdate   int64    `json:"last_quota_update"`
	UploadBandwidth   int64    `json:"upload_bandwidth"`
	DownloadBandwidth int64    `json:"download_bandwidth"`
}

// HasPerm returns true if the user has the given permission or any permission
func (u *User) HasPerm(permission string) bool {
	if utils.IsStringInSlice(PermAny, u.Permissions) {
		return true
	}
	return utils.IsStringInSlice(permission, u.Permissions)
}

// HasOption returns true if the user has the give option
/*func (u *User) HasOption(option string) bool {
	return utils.IsStringInSlice(option, u.Options)
}*/

// GetPermissionsAsJSON returns the permission as json byte array
func (u *User) GetPermissionsAsJSON() ([]byte, error) {
	return json.Marshal(u.Permissions)
}

// GetOptionsAsJSON returns the permission as json byte array
/*func (u *User) GetOptionsAsJSON() ([]byte, error) {
	return json.Marshal(u.Options)
}*/

// GetUID returns a validate uid
func (u *User) GetUID() int {
	if u.UID <= 0 || u.UID > 65535 {
		return -1
	}
	return u.UID
}

// GetGID returns a validate gid
func (u *User) GetGID() int {
	if u.GID <= 0 || u.GID > 65535 {
		return -1
	}
	return u.GID
}

// GetHomeDir returns user home dir cleaned
func (u *User) GetHomeDir() string {
	return filepath.Clean(u.HomeDir)
}

// HasQuotaRestrictions returns true if there is a quota restriction on number of files
// or size or both
func (u *User) HasQuotaRestrictions() bool {
	return u.QuotaFiles > 0 || u.QuotaSize > 0
}
