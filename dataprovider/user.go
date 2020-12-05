package dataprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/webdav"

	"github.com/drakkan/sftpgo/kms"
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

// Available login methods
const (
	LoginMethodNoAuthTryed            = "no_auth_tryed"
	LoginMethodPassword               = "password"
	SSHLoginMethodPublicKey           = "publickey"
	SSHLoginMethodKeyboardInteractive = "keyboard-interactive"
	SSHLoginMethodKeyAndPassword      = "publickey+password"
	SSHLoginMethodKeyAndKeyboardInt   = "publickey+keyboard-interactive"
)

var (
	errNoMatchingVirtualFolder = errors.New("no matching virtual folder found")
)

// CachedUser adds fields useful for caching to a SFTPGo user
type CachedUser struct {
	User       User
	Expiration time.Time
	Password   string
	LockSystem webdav.LockSystem
}

// IsExpired returns true if the cached user is expired
func (c *CachedUser) IsExpired() bool {
	if c.Expiration.IsZero() {
		return false
	}
	return c.Expiration.Before(time.Now())
}

// ExtensionsFilter defines filters based on file extensions.
// These restrictions do not apply to files listing for performance reasons, so
// a denied file cannot be downloaded/overwritten/renamed but will still be
// in the list of files.
// System commands such as Git and rsync interacts with the filesystem directly
// and they are not aware about these restrictions so they are not allowed
// inside paths with extensions filters
type ExtensionsFilter struct {
	// Virtual path, if no other specific filter is defined, the filter apply for
	// sub directories too.
	// For example if filters are defined for the paths "/" and "/sub" then the
	// filters for "/" are applied for any file outside the "/sub" directory
	Path string `json:"path"`
	// only files with these, case insensitive, extensions are allowed.
	// Shell like expansion is not supported so you have to specify ".jpg" and
	// not "*.jpg". If you want shell like patterns use pattern filters
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
	// files with these, case insensitive, extensions are not allowed.
	// Denied file extensions are evaluated before the allowed ones
	DeniedExtensions []string `json:"denied_extensions,omitempty"`
}

// PatternsFilter defines filters based on shell like patterns.
// These restrictions do not apply to files listing for performance reasons, so
// a denied file cannot be downloaded/overwritten/renamed but will still be
// in the list of files.
// System commands such as Git and rsync interacts with the filesystem directly
// and they are not aware about these restrictions so they are not allowed
// inside paths with extensions filters
type PatternsFilter struct {
	// Virtual path, if no other specific filter is defined, the filter apply for
	// sub directories too.
	// For example if filters are defined for the paths "/" and "/sub" then the
	// filters for "/" are applied for any file outside the "/sub" directory
	Path string `json:"path"`
	// files with these, case insensitive, patterns are allowed.
	// Denied file patterns are evaluated before the allowed ones
	AllowedPatterns []string `json:"allowed_patterns,omitempty"`
	// files with these, case insensitive, patterns are not allowed.
	// Denied file patterns are evaluated before the allowed ones
	DeniedPatterns []string `json:"denied_patterns,omitempty"`
}

// UserFilters defines additional restrictions for a user
type UserFilters struct {
	// only clients connecting from these IP/Mask are allowed.
	// IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291
	// for example "192.0.2.0/24" or "2001:db8::/32"
	AllowedIP []string `json:"allowed_ip,omitempty"`
	// clients connecting from these IP/Mask are not allowed.
	// Denied rules will be evaluated before allowed ones
	DeniedIP []string `json:"denied_ip,omitempty"`
	// these login methods are not allowed.
	// If null or empty any available login method is allowed
	DeniedLoginMethods []string `json:"denied_login_methods,omitempty"`
	// these protocols are not allowed.
	// If null or empty any available protocol is allowed
	DeniedProtocols []string `json:"denied_protocols,omitempty"`
	// filters based on file extensions.
	// Please note that these restrictions can be easily bypassed.
	FileExtensions []ExtensionsFilter `json:"file_extensions,omitempty"`
	// filter based on shell patterns
	FilePatterns []PatternsFilter `json:"file_patterns,omitempty"`
	// max size allowed for a single upload, 0 means unlimited
	MaxUploadFileSize int64 `json:"max_upload_file_size,omitempty"`
}

// FilesystemProvider defines the supported storages
type FilesystemProvider int

// supported values for FilesystemProvider
const (
	LocalFilesystemProvider     FilesystemProvider = iota // Local
	S3FilesystemProvider                                  // AWS S3 compatible
	GCSFilesystemProvider                                 // Google Cloud Storage
	AzureBlobFilesystemProvider                           // Azure Blob Storage
	CryptedFilesystemProvider                             // Local encrypted
)

// Filesystem defines cloud storage filesystem details
type Filesystem struct {
	Provider     FilesystemProvider `json:"provider"`
	S3Config     vfs.S3FsConfig     `json:"s3config,omitempty"`
	GCSConfig    vfs.GCSFsConfig    `json:"gcsconfig,omitempty"`
	AzBlobConfig vfs.AzBlobFsConfig `json:"azblobconfig,omitempty"`
	CryptConfig  vfs.CryptFsConfig  `json:"cryptconfig,omitempty"`
}

// User defines a SFTPGo user
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
	// Checking passwords stored with bcrypt, pbkdf2, md5crypt and sha512crypt is supported too.
	Password string `json:"password,omitempty"`
	// PublicKeys used for public key authentication. At least one between password and a public key is mandatory
	PublicKeys []string `json:"public_keys,omitempty"`
	// The user cannot upload or download files outside this directory. Must be an absolute path
	HomeDir string `json:"home_dir"`
	// Mapping between virtual paths and filesystem paths outside the home directory.
	// Supported for local filesystem only
	VirtualFolders []vfs.VirtualFolder `json:"virtual_folders,omitempty"`
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
	// free form text field for external systems
	AdditionalInfo string `json:"additional_info,omitempty"`
}

// GetFilesystem returns the filesystem for this user
func (u *User) GetFilesystem(connectionID string) (vfs.Fs, error) {
	switch u.FsConfig.Provider {
	case S3FilesystemProvider:
		return vfs.NewS3Fs(connectionID, u.GetHomeDir(), u.FsConfig.S3Config)
	case GCSFilesystemProvider:
		config := u.FsConfig.GCSConfig
		config.CredentialFile = u.getGCSCredentialsFilePath()
		return vfs.NewGCSFs(connectionID, u.GetHomeDir(), config)
	case AzureBlobFilesystemProvider:
		return vfs.NewAzBlobFs(connectionID, u.GetHomeDir(), u.FsConfig.AzBlobConfig)
	case CryptedFilesystemProvider:
		return vfs.NewCryptFs(connectionID, u.GetHomeDir(), u.FsConfig.CryptConfig)
	default:
		return vfs.NewOsFs(connectionID, u.GetHomeDir(), u.VirtualFolders), nil
	}
}

// HideConfidentialData hides user confidential data
func (u *User) HideConfidentialData() {
	u.Password = ""
	switch u.FsConfig.Provider {
	case S3FilesystemProvider:
		u.FsConfig.S3Config.AccessSecret.Hide()
	case GCSFilesystemProvider:
		u.FsConfig.GCSConfig.Credentials.Hide()
	case AzureBlobFilesystemProvider:
		u.FsConfig.AzBlobConfig.AccountKey.Hide()
	case CryptedFilesystemProvider:
		u.FsConfig.CryptConfig.Passphrase.Hide()
	}
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
	dirsForPath := utils.GetDirsForSFTPPath(p)
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

// GetVirtualFolderForPath returns the virtual folder containing the specified sftp path.
// If the path is not inside a virtual folder an error is returned
func (u *User) GetVirtualFolderForPath(sftpPath string) (vfs.VirtualFolder, error) {
	var folder vfs.VirtualFolder
	if len(u.VirtualFolders) == 0 || u.FsConfig.Provider != LocalFilesystemProvider {
		return folder, errNoMatchingVirtualFolder
	}
	dirsForPath := utils.GetDirsForSFTPPath(sftpPath)
	for _, val := range dirsForPath {
		for _, v := range u.VirtualFolders {
			if v.VirtualPath == val {
				return v, nil
			}
		}
	}
	return folder, errNoMatchingVirtualFolder
}

// AddVirtualDirs adds virtual folders, if defined, to the given files list
func (u *User) AddVirtualDirs(list []os.FileInfo, sftpPath string) []os.FileInfo {
	if len(u.VirtualFolders) == 0 {
		return list
	}
	for _, v := range u.VirtualFolders {
		if path.Dir(v.VirtualPath) == sftpPath {
			fi := vfs.NewFileInfo(v.VirtualPath, true, 0, time.Now(), false)
			found := false
			for index, f := range list {
				if f.Name() == fi.Name() {
					list[index] = fi
					found = true
					break
				}
			}
			if !found {
				list = append(list, fi)
			}
		}
	}
	return list
}

// IsMappedPath returns true if the specified filesystem path has a virtual folder mapping.
// The filesystem path must be cleaned before calling this method
func (u *User) IsMappedPath(fsPath string) bool {
	for _, v := range u.VirtualFolders {
		if fsPath == v.MappedPath {
			return true
		}
	}
	return false
}

// IsVirtualFolder returns true if the specified sftp path is a virtual folder
func (u *User) IsVirtualFolder(sftpPath string) bool {
	for _, v := range u.VirtualFolders {
		if sftpPath == v.VirtualPath {
			return true
		}
	}
	return false
}

// HasVirtualFoldersInside returns true if there are virtual folders inside the
// specified SFTP path. We assume that path are cleaned
func (u *User) HasVirtualFoldersInside(sftpPath string) bool {
	if sftpPath == "/" && len(u.VirtualFolders) > 0 {
		return true
	}
	for _, v := range u.VirtualFolders {
		if len(v.VirtualPath) > len(sftpPath) {
			if strings.HasPrefix(v.VirtualPath, sftpPath+"/") {
				return true
			}
		}
	}
	return false
}

// HasPermissionsInside returns true if the specified sftpPath has no permissions itself and
// no subdirs with defined permissions
func (u *User) HasPermissionsInside(sftpPath string) bool {
	for dir := range u.Permissions {
		if dir == sftpPath {
			return true
		} else if len(dir) > len(sftpPath) {
			if strings.HasPrefix(dir, sftpPath+"/") {
				return true
			}
		}
	}
	return false
}

// HasOverlappedMappedPaths returns true if this user has virtual folders with overlapped mapped paths
func (u *User) HasOverlappedMappedPaths() bool {
	if len(u.VirtualFolders) <= 1 {
		return false
	}
	for _, v1 := range u.VirtualFolders {
		for _, v2 := range u.VirtualFolders {
			if v1.VirtualPath == v2.VirtualPath {
				continue
			}
			if isMappedDirOverlapped(v1.MappedPath, v2.MappedPath) {
				return true
			}
		}
	}
	return false
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

// HasNoQuotaRestrictions returns true if no quota restrictions need to be applyed
func (u *User) HasNoQuotaRestrictions(checkFiles bool) bool {
	if u.QuotaSize == 0 && (!checkFiles || u.QuotaFiles == 0) {
		return true
	}
	return false
}

// IsLoginMethodAllowed returns true if the specified login method is allowed
func (u *User) IsLoginMethodAllowed(loginMethod string, partialSuccessMethods []string) bool {
	if len(u.Filters.DeniedLoginMethods) == 0 {
		return true
	}
	if len(partialSuccessMethods) == 1 {
		for _, method := range u.GetNextAuthMethods(partialSuccessMethods, true) {
			if method == loginMethod {
				return true
			}
		}
	}
	if utils.IsStringInSlice(loginMethod, u.Filters.DeniedLoginMethods) {
		return false
	}
	return true
}

// GetNextAuthMethods returns the list of authentications methods that
// can continue for multi-step authentication
func (u *User) GetNextAuthMethods(partialSuccessMethods []string, isPasswordAuthEnabled bool) []string {
	var methods []string
	if len(partialSuccessMethods) != 1 {
		return methods
	}
	if partialSuccessMethods[0] != SSHLoginMethodPublicKey {
		return methods
	}
	for _, method := range u.GetAllowedLoginMethods() {
		if method == SSHLoginMethodKeyAndPassword && isPasswordAuthEnabled {
			methods = append(methods, LoginMethodPassword)
		}
		if method == SSHLoginMethodKeyAndKeyboardInt {
			methods = append(methods, SSHLoginMethodKeyboardInteractive)
		}
	}
	return methods
}

// IsPartialAuth returns true if the specified login method is a step for
// a multi-step Authentication.
// We support publickey+password and publickey+keyboard-interactive, so
// only publickey can returns partial success.
// We can have partial success if only multi-step Auth methods are enabled
func (u *User) IsPartialAuth(loginMethod string) bool {
	if loginMethod != SSHLoginMethodPublicKey {
		return false
	}
	for _, method := range u.GetAllowedLoginMethods() {
		if !utils.IsStringInSlice(method, SSHMultiStepsLoginMethods) {
			return false
		}
	}
	return true
}

// GetAllowedLoginMethods returns the allowed login methods
func (u *User) GetAllowedLoginMethods() []string {
	var allowedMethods []string
	for _, method := range ValidSSHLoginMethods {
		if !utils.IsStringInSlice(method, u.Filters.DeniedLoginMethods) {
			allowedMethods = append(allowedMethods, method)
		}
	}
	return allowedMethods
}

// IsFileAllowed returns true if the specified file is allowed by the file restrictions filters
func (u *User) IsFileAllowed(virtualPath string) bool {
	return u.isFilePatternAllowed(virtualPath) && u.isFileExtensionAllowed(virtualPath)
}

func (u *User) isFileExtensionAllowed(virtualPath string) bool {
	if len(u.Filters.FileExtensions) == 0 {
		return true
	}
	dirsForPath := utils.GetDirsForSFTPPath(path.Dir(virtualPath))
	var filter ExtensionsFilter
	for _, dir := range dirsForPath {
		for _, f := range u.Filters.FileExtensions {
			if f.Path == dir {
				filter = f
				break
			}
		}
		if filter.Path != "" {
			break
		}
	}
	if filter.Path != "" {
		toMatch := strings.ToLower(virtualPath)
		for _, denied := range filter.DeniedExtensions {
			if strings.HasSuffix(toMatch, denied) {
				return false
			}
		}
		for _, allowed := range filter.AllowedExtensions {
			if strings.HasSuffix(toMatch, allowed) {
				return true
			}
		}
		return len(filter.AllowedExtensions) == 0
	}
	return true
}

func (u *User) isFilePatternAllowed(virtualPath string) bool {
	if len(u.Filters.FilePatterns) == 0 {
		return true
	}
	dirsForPath := utils.GetDirsForSFTPPath(path.Dir(virtualPath))
	var filter PatternsFilter
	for _, dir := range dirsForPath {
		for _, f := range u.Filters.FilePatterns {
			if f.Path == dir {
				filter = f
				break
			}
		}
		if filter.Path != "" {
			break
		}
	}
	if filter.Path != "" {
		toMatch := strings.ToLower(path.Base(virtualPath))
		for _, denied := range filter.DeniedPatterns {
			matched, err := path.Match(denied, toMatch)
			if err != nil || matched {
				return false
			}
		}
		for _, allowed := range filter.AllowedPatterns {
			matched, err := path.Match(allowed, toMatch)
			if err == nil && matched {
				return true
			}
		}
		return len(filter.AllowedPatterns) == 0
	}
	return true
}

// IsLoginFromAddrAllowed returns true if the login is allowed from the specified remoteAddr.
// If AllowedIP is defined only the specified IP/Mask can login.
// If DeniedIP is defined the specified IP/Mask cannot login.
// If an IP is both allowed and denied then login will be denied
func (u *User) IsLoginFromAddrAllowed(remoteAddr string) bool {
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
		result += "unlimited."
	}
	result += " Upload: "
	if u.UploadBandwidth > 0 {
		result += utils.ByteCountSI(u.UploadBandwidth*1000) + "/s."
	} else {
		result += "unlimited."
	}
	return result
}

// GetInfoString returns user's info as string.
// Storage provider, number of public keys, max sessions, uid,
// gid, denied and allowed IP/Mask are returned
func (u *User) GetInfoString() string {
	var result string
	if u.LastLogin > 0 {
		t := utils.GetTimeFromMsecSinceEpoch(u.LastLogin)
		result += fmt.Sprintf("Last login: %v ", t.Format("2006-01-02 15:04:05")) // YYYY-MM-DD HH:MM:SS
	}
	if u.FsConfig.Provider == S3FilesystemProvider {
		result += "Storage: S3 "
	} else if u.FsConfig.Provider == GCSFilesystemProvider {
		result += "Storage: GCS "
	} else if u.FsConfig.Provider == AzureBlobFilesystemProvider {
		result += "Storage: Azure "
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

// SetEmptySecretsIfNil sets the secrets to empty if nil
func (u *User) SetEmptySecretsIfNil() {
	if u.FsConfig.S3Config.AccessSecret == nil {
		u.FsConfig.S3Config.AccessSecret = kms.NewEmptySecret()
	}
	if u.FsConfig.GCSConfig.Credentials == nil {
		u.FsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
	}
	if u.FsConfig.AzBlobConfig.AccountKey == nil {
		u.FsConfig.AzBlobConfig.AccountKey = kms.NewEmptySecret()
	}
	if u.FsConfig.CryptConfig.Passphrase == nil {
		u.FsConfig.CryptConfig.Passphrase = kms.NewEmptySecret()
	}
}

func (u *User) getACopy() User {
	u.SetEmptySecretsIfNil()
	pubKeys := make([]string, len(u.PublicKeys))
	copy(pubKeys, u.PublicKeys)
	virtualFolders := make([]vfs.VirtualFolder, len(u.VirtualFolders))
	copy(virtualFolders, u.VirtualFolders)
	permissions := make(map[string][]string)
	for k, v := range u.Permissions {
		perms := make([]string, len(v))
		copy(perms, v)
		permissions[k] = perms
	}
	filters := UserFilters{}
	filters.MaxUploadFileSize = u.Filters.MaxUploadFileSize
	filters.AllowedIP = make([]string, len(u.Filters.AllowedIP))
	copy(filters.AllowedIP, u.Filters.AllowedIP)
	filters.DeniedIP = make([]string, len(u.Filters.DeniedIP))
	copy(filters.DeniedIP, u.Filters.DeniedIP)
	filters.DeniedLoginMethods = make([]string, len(u.Filters.DeniedLoginMethods))
	copy(filters.DeniedLoginMethods, u.Filters.DeniedLoginMethods)
	filters.FileExtensions = make([]ExtensionsFilter, len(u.Filters.FileExtensions))
	copy(filters.FileExtensions, u.Filters.FileExtensions)
	filters.FilePatterns = make([]PatternsFilter, len(u.Filters.FilePatterns))
	copy(filters.FilePatterns, u.Filters.FilePatterns)
	filters.DeniedProtocols = make([]string, len(u.Filters.DeniedProtocols))
	copy(filters.DeniedProtocols, u.Filters.DeniedProtocols)
	fsConfig := Filesystem{
		Provider: u.FsConfig.Provider,
		S3Config: vfs.S3FsConfig{
			Bucket:            u.FsConfig.S3Config.Bucket,
			Region:            u.FsConfig.S3Config.Region,
			AccessKey:         u.FsConfig.S3Config.AccessKey,
			AccessSecret:      u.FsConfig.S3Config.AccessSecret.Clone(),
			Endpoint:          u.FsConfig.S3Config.Endpoint,
			StorageClass:      u.FsConfig.S3Config.StorageClass,
			KeyPrefix:         u.FsConfig.S3Config.KeyPrefix,
			UploadPartSize:    u.FsConfig.S3Config.UploadPartSize,
			UploadConcurrency: u.FsConfig.S3Config.UploadConcurrency,
		},
		GCSConfig: vfs.GCSFsConfig{
			Bucket:               u.FsConfig.GCSConfig.Bucket,
			CredentialFile:       u.FsConfig.GCSConfig.CredentialFile,
			Credentials:          u.FsConfig.GCSConfig.Credentials.Clone(),
			AutomaticCredentials: u.FsConfig.GCSConfig.AutomaticCredentials,
			StorageClass:         u.FsConfig.GCSConfig.StorageClass,
			KeyPrefix:            u.FsConfig.GCSConfig.KeyPrefix,
		},
		AzBlobConfig: vfs.AzBlobFsConfig{
			Container:         u.FsConfig.AzBlobConfig.Container,
			AccountName:       u.FsConfig.AzBlobConfig.AccountName,
			AccountKey:        u.FsConfig.AzBlobConfig.AccountKey.Clone(),
			Endpoint:          u.FsConfig.AzBlobConfig.Endpoint,
			SASURL:            u.FsConfig.AzBlobConfig.SASURL,
			KeyPrefix:         u.FsConfig.AzBlobConfig.KeyPrefix,
			UploadPartSize:    u.FsConfig.AzBlobConfig.UploadPartSize,
			UploadConcurrency: u.FsConfig.AzBlobConfig.UploadConcurrency,
			UseEmulator:       u.FsConfig.AzBlobConfig.UseEmulator,
			AccessTier:        u.FsConfig.AzBlobConfig.AccessTier,
		},
		CryptConfig: vfs.CryptFsConfig{
			Passphrase: u.FsConfig.CryptConfig.Passphrase.Clone(),
		},
	}

	return User{
		ID:                u.ID,
		Username:          u.Username,
		Password:          u.Password,
		PublicKeys:        pubKeys,
		HomeDir:           u.HomeDir,
		VirtualFolders:    virtualFolders,
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
		AdditionalInfo:    u.AdditionalInfo,
	}
}

func (u *User) getNotificationFieldsAsSlice(action string) []string {
	return []string{action, u.Username,
		strconv.FormatInt(u.ID, 10),
		strconv.FormatInt(int64(u.Status), 10),
		strconv.FormatInt(u.ExpirationDate, 10),
		u.HomeDir,
		strconv.FormatInt(int64(u.UID), 10),
		strconv.FormatInt(int64(u.GID), 10),
	}
}

func (u *User) getNotificationFieldsAsEnvVars(action string) []string {
	return []string{fmt.Sprintf("SFTPGO_USER_ACTION=%v", action),
		fmt.Sprintf("SFTPGO_USER_USERNAME=%v", u.Username),
		fmt.Sprintf("SFTPGO_USER_PASSWORD=%v", u.Password),
		fmt.Sprintf("SFTPGO_USER_ID=%v", u.ID),
		fmt.Sprintf("SFTPGO_USER_STATUS=%v", u.Status),
		fmt.Sprintf("SFTPGO_USER_EXPIRATION_DATE=%v", u.ExpirationDate),
		fmt.Sprintf("SFTPGO_USER_HOME_DIR=%v", u.HomeDir),
		fmt.Sprintf("SFTPGO_USER_UID=%v", u.UID),
		fmt.Sprintf("SFTPGO_USER_GID=%v", u.GID),
		fmt.Sprintf("SFTPGO_USER_QUOTA_FILES=%v", u.QuotaFiles),
		fmt.Sprintf("SFTPGO_USER_QUOTA_SIZE=%v", u.QuotaSize),
		fmt.Sprintf("SFTPGO_USER_UPLOAD_BANDWIDTH=%v", u.UploadBandwidth),
		fmt.Sprintf("SFTPGO_USER_DOWNLOAD_BANDWIDTH=%v", u.DownloadBandwidth),
		fmt.Sprintf("SFTPGO_USER_MAX_SESSIONS=%v", u.MaxSessions),
		fmt.Sprintf("SFTPGO_USER_FS_PROVIDER=%v", u.FsConfig.Provider)}
}

func (u *User) getGCSCredentialsFilePath() string {
	return filepath.Join(credentialsDirPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
}
