package dataprovider

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/drakkan/sftpgo/utils"
)

// Available permissions for SFTP users
const (
	// All permissions are granted
	PermAny = "*"
	// List items such as files and directories is allowed
	PermListItems = "list"
	// download files is allowed
	PermDownload = "download"
	// upload files is allowed
	PermUpload = "upload"
	// overwrite an existing file, while uploading, is allowed
	// upload permission is required to allow file overwrite
	PermOverwrite = "overwrite"
	// delete files or directories is allowed
	PermDelete = "delete"
	// rename files or directories is allowed
	PermRename = "rename"
	// create directories is allowed
	PermCreateDirs = "create_dirs"
	// create symbolic links is allowed
	PermCreateSymlinks = "create_symlinks"
)

// User defines an SFTP user
type User struct {
	// Database unique identifier
	ID int64 `json:"id"`
	// Username
	Username string `json:"username"`
	// Password used for password authentication.
	// For users created using SFTPGo REST API the password is be stored using argon2id hashing algo.
	// Checking passwords stored with bcrypt is supported too.
	// Currently, as fallback, there is a clear text password checking but you should not store passwords
	// as clear text and this support could be removed at any time, so please don't depend on it.
	Password string `json:"password,omitempty"`
	// PublicKeys used for public key authentication. At least one between password and a public key is mandatory
	PublicKeys []string `json:"public_keys,omitempty"`
	// The user cannot upload or download files outside this directory. Must be an absolute path
	HomeDir string `json:"home_dir"`
	// If sftpgo runs as root system user then the created files and directories will be assigned to this system UID
	UID int `json:"uid"`
	// If sftpgo runs as root system user then the created files and directories will be assigned to this system GID
	GID int `json:"gid"`
	// Maximum concurrent sessions. 0 means unlimited
	MaxSessions int `json:"max_sessions"`
	// Maximum size allowed as bytes. 0 means unlimited
	QuotaSize int64 `json:"quota_size"`
	// Maximum number of files allowed. 0 means unlimited
	QuotaFiles int `json:"quota_files"`
	// List of the granted permissions
	Permissions []string `json:"permissions"`
	// Used quota as bytes
	UsedQuotaSize int64 `json:"used_quota_size"`
	// Used quota as number of files
	UsedQuotaFiles int `json:"used_quota_files"`
	// Last quota update as unix timestamp in milliseconds
	LastQuotaUpdate int64 `json:"last_quota_update"`
	// Maximum upload bandwidth as KB/s, 0 means unlimited
	UploadBandwidth int64 `json:"upload_bandwidth"`
	// Maximum download bandwidth as KB/s, 0 means unlimited
	DownloadBandwidth int64 `json:"download_bandwidth"`
}

// HasPerm returns true if the user has the given permission or any permission
func (u *User) HasPerm(permission string) bool {
	if utils.IsStringInSlice(PermAny, u.Permissions) {
		return true
	}
	return utils.IsStringInSlice(permission, u.Permissions)
}

// GetPermissionsAsJSON returns the permissions as json byte array
func (u *User) GetPermissionsAsJSON() ([]byte, error) {
	return json.Marshal(u.Permissions)
}

// GetPublicKeysAsJSON returns the public keys as json byte array
func (u *User) GetPublicKeysAsJSON() ([]byte, error) {
	return json.Marshal(u.PublicKeys)
}

// GetUID returns a validate uid, suitable for use with os.Chown
func (u *User) GetUID() int {
	if u.UID <= 0 || u.UID > 65535 {
		return -1
	}
	return u.UID
}

// GetGID returns a validate gid, suitable for use with os.Chown
func (u *User) GetGID() int {
	if u.GID <= 0 || u.GID > 65535 {
		return -1
	}
	return u.GID
}

// GetHomeDir returns the shortest path name equivalent to the user's home directory
func (u *User) GetHomeDir() string {
	return filepath.Clean(u.HomeDir)
}

// HasQuotaRestrictions returns true if there is a quota restriction on number of files or size or both
func (u *User) HasQuotaRestrictions() bool {
	return u.QuotaFiles > 0 || u.QuotaSize > 0
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTP users
func (u *User) GetRelativePath(path string) string {
	rel, err := filepath.Rel(u.GetHomeDir(), path)
	if err != nil {
		return ""
	}
	return "/" + filepath.ToSlash(rel)
}

// GetQuotaSummary returns used quota and limits if defined
func (u *User) GetQuotaSummary() string {
	var result string
	result = "Files: " + strconv.Itoa(u.UsedQuotaFiles)
	if u.QuotaFiles > 0 {
		result += "/" + strconv.Itoa(u.QuotaFiles)
	}
	if u.UsedQuotaSize > 0 || u.QuotaSize > 0 {
		result += ". Size: " + utils.ByteCountSI(u.UsedQuotaSize)
		if u.QuotaSize > 0 {
			result += "/" + utils.ByteCountSI(u.QuotaSize)
		}
	}
	return result
}

// GetPermissionsAsString returns the user's permissions as comma separated string
func (u *User) GetPermissionsAsString() string {
	var result string
	for _, p := range u.Permissions {
		if len(result) > 0 {
			result += ", "
		}
		result += p
	}
	return result
}

// GetBandwidthAsString returns bandwidth limits if defines
func (u *User) GetBandwidthAsString() string {
	result := "Download: "
	if u.DownloadBandwidth > 0 {
		result += utils.ByteCountSI(u.DownloadBandwidth*1000) + "/s."
	} else {
		result += "ulimited."
	}
	result += " Upload: "
	if u.UploadBandwidth > 0 {
		result += utils.ByteCountSI(u.UploadBandwidth*1000) + "/s."
	} else {
		result += "ulimited."
	}
	return result
}

// GetInfoString returns user's info as string.
// Number of public keys, max sessions, uid and gid are returned
func (u *User) GetInfoString() string {
	var result string
	if len(u.PublicKeys) > 0 {
		result += fmt.Sprintf("Public keys: %v ", len(u.PublicKeys))
	}
	if u.MaxSessions > 0 {
		result += fmt.Sprintf("Max sessions: %v ", u.MaxSessions)
	}
	if u.UID > 0 {
		result += fmt.Sprintf("UID: %v ", u.UID)
	}
	if u.GID > 0 {
		result += fmt.Sprintf("GID: %v ", u.GID)
	}
	return result
}

func (u *User) getACopy() User {
	pubKeys := make([]string, len(u.PublicKeys))
	copy(pubKeys, u.PublicKeys)
	permissions := make([]string, len(u.Permissions))
	copy(permissions, u.Permissions)
	return User{
		ID:                u.ID,
		Username:          u.Username,
		Password:          u.Password,
		PublicKeys:        pubKeys,
		HomeDir:           u.HomeDir,
		UID:               u.UID,
		GID:               u.GID,
		MaxSessions:       u.MaxSessions,
		QuotaSize:         u.QuotaSize,
		QuotaFiles:        u.QuotaFiles,
		Permissions:       permissions,
		UsedQuotaSize:     u.UsedQuotaSize,
		UsedQuotaFiles:    u.UsedQuotaFiles,
		LastQuotaUpdate:   u.LastQuotaUpdate,
		UploadBandwidth:   u.UploadBandwidth,
		DownloadBandwidth: u.DownloadBandwidth,
	}
}
