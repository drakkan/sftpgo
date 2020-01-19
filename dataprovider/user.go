package dataprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"strconv"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
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
	// changing file or directory permissions is allowed
	PermChmod = "chmod"
	// changing file or directory owner and group is allowed
	PermChown = "chown"
	// changing file or directory access and modification time is allowed
	PermChtimes = "chtimes"
)

// UserFilters defines additional restrictions for a user
type UserFilters struct {
	// only clients connecting from these IP/Mask are allowed.
	// IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291
	// for example "192.0.2.0/24" or "2001:db8::/32"
	AllowedIP []string `json:"allowed_ip"`
	// clients connecting from these IP/Mask are not allowed.
	// Denied rules will be evaluated before allowed ones
	DeniedIP []string `json:"denied_ip"`
}

// Filesystem defines cloud storage filesystem details
type Filesystem struct {
	// 0 local filesystem, 1 Amazon S3 compatible
	Provider int            `json:"provider"`
	S3Config vfs.S3FsConfig `json:"s3config,omitempty"`
}

// User defines an SFTP user
type User struct {
	// Database unique identifier
	ID int64 `json:"id"`
	// 1 enabled, 0 disabled (login is not allowed)
	Status int `json:"status"`
	// Username
	Username string `json:"username"`
	// Account expiration date as unix timestamp in milliseconds. An expired account cannot login.
	// 0 means no expiration
	ExpirationDate int64 `json:"expiration_date"`
	// Password used for password authentication.
	// For users created using SFTPGo REST API the password is be stored using argon2id hashing algo.
	// Checking passwords stored with bcrypt, pbkdf2 and sha512crypt is supported too.
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
	Permissions map[string][]string `json:"permissions"`
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
	// Last login as unix timestamp in milliseconds
	LastLogin int64 `json:"last_login"`
	// Additional restrictions
	Filters UserFilters `json:"filters"`
	// Filesystem configuration details
	FsConfig Filesystem `json:"filesystem"`
}

// GetFilesystem returns the filesystem for this user
func (u *User) GetFilesystem(connectionID string) (vfs.Fs, error) {
	if u.FsConfig.Provider == 1 {
		return vfs.NewS3Fs(connectionID, u.GetHomeDir(), u.FsConfig.S3Config)
	}
	return vfs.NewOsFs(connectionID), nil
}

// GetPermissionsForPath returns the permissions for the given path.
// The path must be an SFTP path
func (u *User) GetPermissionsForPath(p string) []string {
	permissions := []string{}
	if perms, ok := u.Permissions["/"]; ok {
		// if only root permissions are defined returns them unconditionally
		if len(u.Permissions) == 1 {
			return perms
		}
		// fallback permissions
		permissions = perms
	}
	sftpPath := filepath.ToSlash(p)
	if !path.IsAbs(p) {
		sftpPath = "/" + sftpPath
	}
	sftpPath = path.Clean(sftpPath)
	dirsForPath := []string{sftpPath}
	for {
		if sftpPath == "/" {
			break
		}
		sftpPath = path.Dir(sftpPath)
		dirsForPath = append(dirsForPath, sftpPath)
	}
	// dirsForPath contains all the dirs for a given path in reverse order
	// for example if the path is: /1/2/3/4 it contains:
	// [ "/1/2/3/4", "/1/2/3", "/1/2", "/1", "/" ]
	// so the first match is the one we are interested to
	for _, val := range dirsForPath {
		if perms, ok := u.Permissions[val]; ok {
			permissions = perms
			break
		}
	}
	return permissions
}

// HasPerm returns true if the user has the given permission or any permission
func (u *User) HasPerm(permission, path string) bool {
	perms := u.GetPermissionsForPath(path)
	if utils.IsStringInSlice(PermAny, perms) {
		return true
	}
	return utils.IsStringInSlice(permission, perms)
}

// HasPerms return true if the user has all the given permissions
func (u *User) HasPerms(permissions []string, path string) bool {
	perms := u.GetPermissionsForPath(path)
	if utils.IsStringInSlice(PermAny, perms) {
		return true
	}
	for _, permission := range permissions {
		if !utils.IsStringInSlice(permission, perms) {
			return false
		}
	}
	return true
}

// IsLoginAllowed return true if the login is allowed from the specified remoteAddr.
// If AllowedIP is defined only the specified IP/Mask can login.
// If DeniedIP is defined the specified IP/Mask cannot login.
// If an IP is both allowed and denied then login will be denied
func (u *User) IsLoginAllowed(remoteAddr string) bool {
	if len(u.Filters.AllowedIP) == 0 && len(u.Filters.DeniedIP) == 0 {
		return true
	}
	remoteIP := net.ParseIP(utils.GetIPFromRemoteAddress(remoteAddr))
	// if remoteIP is invalid we allow login, this should never happen
	if remoteIP == nil {
		logger.Warn(logSender, "", "login allowed for invalid IP. remote address: %#v", remoteAddr)
		return true
	}
	for _, IPMask := range u.Filters.DeniedIP {
		_, IPNet, err := net.ParseCIDR(IPMask)
		if err != nil {
			return false
		}
		if IPNet.Contains(remoteIP) {
			return false
		}
	}
	for _, IPMask := range u.Filters.AllowedIP {
		_, IPNet, err := net.ParseCIDR(IPMask)
		if err != nil {
			return false
		}
		if IPNet.Contains(remoteIP) {
			return true
		}
	}
	return len(u.Filters.AllowedIP) == 0
}

// GetPermissionsAsJSON returns the permissions as json byte array
func (u *User) GetPermissionsAsJSON() ([]byte, error) {
	return json.Marshal(u.Permissions)
}

// GetPublicKeysAsJSON returns the public keys as json byte array
func (u *User) GetPublicKeysAsJSON() ([]byte, error) {
	return json.Marshal(u.PublicKeys)
}

// GetFiltersAsJSON returns the filters as json byte array
func (u *User) GetFiltersAsJSON() ([]byte, error) {
	return json.Marshal(u.Filters)
}

// GetFsConfigAsJSON returns the filesystem config as json byte array
func (u *User) GetFsConfigAsJSON() ([]byte, error) {
	return json.Marshal(u.FsConfig)
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
	result := ""
	for dir, perms := range u.Permissions {
		var dirPerms string
		for _, p := range perms {
			if len(dirPerms) > 0 {
				dirPerms += ", "
			}
			dirPerms += p
		}
		dp := fmt.Sprintf("%#v: %#v", dir, dirPerms)
		if dir == "/" {
			if len(result) > 0 {
				result = dp + ", " + result
			} else {
				result = dp
			}
		} else {
			if len(result) > 0 {
				result += ", "
			}
			result += dp
		}
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
	if u.LastLogin > 0 {
		t := utils.GetTimeFromMsecSinceEpoch(u.LastLogin)
		result += fmt.Sprintf("Last login: %v ", t.Format("2006-01-02 15:04:05")) // YYYY-MM-DD HH:MM:SS
	}
	if u.FsConfig.Provider == 1 {
		result += fmt.Sprintf("Storage: S3")
	}
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
	if len(u.Filters.DeniedIP) > 0 {
		result += fmt.Sprintf("Denied IP/Mask: %v ", len(u.Filters.DeniedIP))
	}
	if len(u.Filters.AllowedIP) > 0 {
		result += fmt.Sprintf("Allowed IP/Mask: %v ", len(u.Filters.AllowedIP))
	}
	return result
}

// GetExpirationDateAsString returns expiration date formatted as YYYY-MM-DD
func (u *User) GetExpirationDateAsString() string {
	if u.ExpirationDate > 0 {
		t := utils.GetTimeFromMsecSinceEpoch(u.ExpirationDate)
		return t.Format("2006-01-02")
	}
	return ""
}

// GetAllowedIPAsString returns the allowed IP as comma separated string
func (u User) GetAllowedIPAsString() string {
	result := ""
	for _, IPMask := range u.Filters.AllowedIP {
		if len(result) > 0 {
			result += ","
		}
		result += IPMask
	}
	return result
}

// GetDeniedIPAsString returns the denied IP as comma separated string
func (u User) GetDeniedIPAsString() string {
	result := ""
	for _, IPMask := range u.Filters.DeniedIP {
		if len(result) > 0 {
			result += ","
		}
		result += IPMask
	}
	return result
}

func (u *User) getACopy() User {
	pubKeys := make([]string, len(u.PublicKeys))
	copy(pubKeys, u.PublicKeys)
	permissions := make(map[string][]string)
	for k, v := range u.Permissions {
		perms := make([]string, len(v))
		copy(perms, v)
		permissions[k] = perms
	}
	filters := UserFilters{}
	filters.AllowedIP = make([]string, len(u.Filters.AllowedIP))
	copy(filters.AllowedIP, u.Filters.AllowedIP)
	filters.DeniedIP = make([]string, len(u.Filters.DeniedIP))
	copy(filters.DeniedIP, u.Filters.DeniedIP)
	fsConfig := Filesystem{
		Provider: u.FsConfig.Provider,
		S3Config: vfs.S3FsConfig{
			Bucket:       u.FsConfig.S3Config.Bucket,
			Region:       u.FsConfig.S3Config.Region,
			AccessKey:    u.FsConfig.S3Config.AccessKey,
			AccessSecret: u.FsConfig.S3Config.AccessSecret,
			Endpoint:     u.FsConfig.S3Config.Endpoint,
			StorageClass: u.FsConfig.S3Config.StorageClass,
		},
	}

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
		Status:            u.Status,
		ExpirationDate:    u.ExpirationDate,
		LastLogin:         u.LastLogin,
		Filters:           filters,
		FsConfig:          fsConfig,
	}
}

func (u *User) getNotificationFieldsAsSlice(action string) []string {
	return []string{action, u.Username,
		strconv.FormatInt(u.ID, 10),
		strconv.FormatInt(int64(u.Status), 10),
		strconv.FormatInt(int64(u.ExpirationDate), 10),
		u.HomeDir,
		strconv.FormatInt(int64(u.UID), 10),
		strconv.FormatInt(int64(u.GID), 10),
	}
}

func (u *User) getNotificationFieldsAsEnvVars(action string) []string {
	return []string{fmt.Sprintf("SFTPGO_USER_ACTION=%v", action),
		fmt.Sprintf("SFTPGO_USER_USERNAME=%v", u.Username),
		fmt.Sprintf("SFTPGO_USER_ID=%v", u.ID),
		fmt.Sprintf("SFTPGO_USER_STATUS=%v", u.Status),
		fmt.Sprintf("SFTPGO_USER_EXPIRATION_DATE=%v", u.ExpirationDate),
		fmt.Sprintf("SFTPGO_USER_HOME_DIR=%v", u.HomeDir),
		fmt.Sprintf("SFTPGO_USER_UID=%v", u.UID),
		fmt.Sprintf("SFTPGO_USER_GID=%v", u.GID)}
}
