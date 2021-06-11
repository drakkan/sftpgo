package dataprovider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

// Available permissions for SFTPGo users
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

// Web Client restrictions
const (
	WebClientPubKeyChangeDisabled = "publickey-change-disabled"
)

var (
	// WebClientOptions defines the available options for the web client interface
	WebClientOptions = []string{WebClientPubKeyChangeDisabled}
)

// Available login methods
const (
	LoginMethodNoAuthTryed            = "no_auth_tryed"
	LoginMethodPassword               = "password"
	SSHLoginMethodPublicKey           = "publickey"
	SSHLoginMethodKeyboardInteractive = "keyboard-interactive"
	SSHLoginMethodKeyAndPassword      = "publickey+password"
	SSHLoginMethodKeyAndKeyboardInt   = "publickey+keyboard-interactive"
	LoginMethodTLSCertificate         = "TLSCertificate"
	LoginMethodTLSCertificateAndPwd   = "TLSCertificate+password"
)

// TLSUsername defines the TLS certificate attribute to use as username
type TLSUsername string

// Supported certificate attributes to use as username
const (
	TLSUsernameNone TLSUsername = "None"
	TLSUsernameCN   TLSUsername = "CommonName"
)

var (
	errNoMatchingVirtualFolder = errors.New("no matching virtual folder found")
)

// DirectoryPermissions defines permissions for a directory path
type DirectoryPermissions struct {
	Path        string
	Permissions []string
}

// HasPerm returns true if the directory has the specified permissions
func (d *DirectoryPermissions) HasPerm(perm string) bool {
	return utils.IsStringInSlice(perm, d.Permissions)
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

// GetCommaSeparatedPatterns returns the first non empty patterns list comma separated
func (p *PatternsFilter) GetCommaSeparatedPatterns() string {
	if len(p.DeniedPatterns) > 0 {
		return strings.Join(p.DeniedPatterns, ",")
	}
	return strings.Join(p.AllowedPatterns, ",")
}

// IsDenied returns true if the patterns has one or more denied patterns
func (p *PatternsFilter) IsDenied() bool {
	return len(p.DeniedPatterns) > 0
}

// IsAllowed returns true if the patterns has one or more allowed patterns
func (p *PatternsFilter) IsAllowed() bool {
	return len(p.AllowedPatterns) > 0
}

// HooksFilter defines user specific overrides for global hooks
type HooksFilter struct {
	ExternalAuthDisabled  bool `json:"external_auth_disabled"`
	PreLoginDisabled      bool `json:"pre_login_disabled"`
	CheckPasswordDisabled bool `json:"check_password_disabled"`
}

// UserFilters defines additional restrictions for a user
// TODO: rename to UserOptions in v3
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
	// filter based on shell patterns.
	// Please note that these restrictions can be easily bypassed.
	FilePatterns []PatternsFilter `json:"file_patterns,omitempty"`
	// max size allowed for a single upload, 0 means unlimited
	MaxUploadFileSize int64 `json:"max_upload_file_size,omitempty"`
	// TLS certificate attribute to use as username.
	// For FTP clients it must match the name provided using the
	// "USER" command
	TLSUsername TLSUsername `json:"tls_username,omitempty"`
	// user specific hook overrides
	Hooks HooksFilter `json:"hooks,omitempty"`
	// Disable checks for existence and automatic creation of home directory
	// and virtual folders.
	// SFTPGo requires that the user's home directory, virtual folder root,
	// and intermediate paths to virtual folders exist to work properly.
	// If you already know that the required directories exist, disabling
	// these checks will speed up login.
	// You could, for example, disable these checks after the first login
	DisableFsChecks bool `json:"disable_fs_checks,omitempty"`
	// WebClient related configuration options
	WebClient []string `json:"web_client,omitempty"`
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
	// For users created using SFTPGo REST API the password is be stored using bcrypt or argon2id hashing algo.
	// Checking passwords stored with pbkdf2, md5crypt and sha512crypt is supported too.
	Password string `json:"password,omitempty"`
	// PublicKeys used for public key authentication. At least one between password and a public key is mandatory
	PublicKeys []string `json:"public_keys,omitempty"`
	// The user cannot upload or download files outside this directory. Must be an absolute path
	HomeDir string `json:"home_dir"`
	// Mapping between virtual paths and virtual folders
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
	FsConfig vfs.Filesystem `json:"filesystem"`
	// optional description, for example full name
	Description string `json:"description,omitempty"`
	// free form text field for external systems
	AdditionalInfo string `json:"additional_info,omitempty"`
	// we store the filesystem here using the base path as key.
	fsCache map[string]vfs.Fs `json:"-"`
}

// GetFilesystem returns the base filesystem for this user
func (u *User) GetFilesystem(connectionID string) (fs vfs.Fs, err error) {
	fs, err = u.getRootFs(connectionID)
	if err != nil {
		return fs, err
	}
	u.fsCache = make(map[string]vfs.Fs)
	u.fsCache["/"] = fs
	return fs, err
}

func (u *User) getRootFs(connectionID string) (fs vfs.Fs, err error) {
	switch u.FsConfig.Provider {
	case vfs.S3FilesystemProvider:
		return vfs.NewS3Fs(connectionID, u.GetHomeDir(), "", u.FsConfig.S3Config)
	case vfs.GCSFilesystemProvider:
		config := u.FsConfig.GCSConfig
		config.CredentialFile = u.GetGCSCredentialsFilePath()
		return vfs.NewGCSFs(connectionID, u.GetHomeDir(), "", config)
	case vfs.AzureBlobFilesystemProvider:
		return vfs.NewAzBlobFs(connectionID, u.GetHomeDir(), "", u.FsConfig.AzBlobConfig)
	case vfs.CryptedFilesystemProvider:
		return vfs.NewCryptFs(connectionID, u.GetHomeDir(), "", u.FsConfig.CryptConfig)
	case vfs.SFTPFilesystemProvider:
		forbiddenSelfUsers, err := u.getForbiddenSFTPSelfUsers(u.FsConfig.SFTPConfig.Username)
		if err != nil {
			return nil, err
		}
		forbiddenSelfUsers = append(forbiddenSelfUsers, u.Username)
		return vfs.NewSFTPFs(connectionID, "", u.GetHomeDir(), forbiddenSelfUsers, u.FsConfig.SFTPConfig)
	default:
		return vfs.NewOsFs(connectionID, u.GetHomeDir(), ""), nil
	}
}

// CheckFsRoot check the root directory for the main fs and the virtual folders.
// It returns an error if the main filesystem cannot be created
func (u *User) CheckFsRoot(connectionID string) error {
	if u.Filters.DisableFsChecks {
		return nil
	}
	fs, err := u.GetFilesystemForPath("/", connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "could not create main filesystem for user %#v err: %v", u.Username, err)
		return err
	}
	fs.CheckRootPath(u.Username, u.GetUID(), u.GetGID())
	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		fs, err = u.GetFilesystemForPath(v.VirtualPath, connectionID)
		if err == nil {
			fs.CheckRootPath(u.Username, u.GetUID(), u.GetGID())
		}
		// now check intermediary folders
		fs, err = u.GetFilesystemForPath(path.Dir(v.VirtualPath), connectionID)
		if err == nil && !fs.HasVirtualFolders() {
			fsPath, err := fs.ResolvePath(v.VirtualPath)
			if err != nil {
				continue
			}
			err = fs.MkdirAll(fsPath, u.GetUID(), u.GetGID())
			logger.Debug(logSender, connectionID, "create intermediary dir to %#v, path %#v, err: %v",
				v.VirtualPath, fsPath, err)
		}
	}
	return nil
}

// isFsEqual returns true if the fs has the same configuration
func (u *User) isFsEqual(other *User) bool {
	if u.FsConfig.Provider == vfs.LocalFilesystemProvider && u.GetHomeDir() != other.GetHomeDir() {
		return false
	}
	if !u.FsConfig.IsEqual(&other.FsConfig) {
		return false
	}
	if len(u.VirtualFolders) != len(other.VirtualFolders) {
		return false
	}
	for idx := range u.VirtualFolders {
		f := &u.VirtualFolders[idx]
		found := false
		for idx1 := range other.VirtualFolders {
			f1 := &other.VirtualFolders[idx1]
			if f.VirtualPath == f1.VirtualPath {
				found = true
				if f.FsConfig.Provider == vfs.LocalFilesystemProvider && f.MappedPath != f1.MappedPath {
					return false
				}
				if !f.FsConfig.IsEqual(&f1.FsConfig) {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// hideConfidentialData hides user confidential data
func (u *User) hideConfidentialData() {
	u.Password = ""
	switch u.FsConfig.Provider {
	case vfs.S3FilesystemProvider:
		u.FsConfig.S3Config.AccessSecret.Hide()
	case vfs.GCSFilesystemProvider:
		u.FsConfig.GCSConfig.Credentials.Hide()
	case vfs.AzureBlobFilesystemProvider:
		u.FsConfig.AzBlobConfig.AccountKey.Hide()
		u.FsConfig.AzBlobConfig.SASURL.Hide()
	case vfs.CryptedFilesystemProvider:
		u.FsConfig.CryptConfig.Passphrase.Hide()
	case vfs.SFTPFilesystemProvider:
		u.FsConfig.SFTPConfig.Password.Hide()
		u.FsConfig.SFTPConfig.PrivateKey.Hide()
	}
}

// GetSubDirPermissions returns permissions for sub directories
func (u *User) GetSubDirPermissions() []DirectoryPermissions {
	var result []DirectoryPermissions
	for k, v := range u.Permissions {
		if k == "/" {
			continue
		}
		dirPerms := DirectoryPermissions{
			Path:        k,
			Permissions: v,
		}
		result = append(result, dirPerms)
	}
	return result
}

// PrepareForRendering prepares a user for rendering.
// It hides confidential data and set to nil the empty secrets
// so they are not serialized
func (u *User) PrepareForRendering() {
	u.hideConfidentialData()
	u.FsConfig.SetNilSecretsIfEmpty()
	for idx := range u.VirtualFolders {
		folder := &u.VirtualFolders[idx]
		folder.PrepareForRendering()
	}
}

func (u *User) hasRedactedSecret() bool {
	switch u.FsConfig.Provider {
	case vfs.S3FilesystemProvider:
		if u.FsConfig.S3Config.AccessSecret.IsRedacted() {
			return true
		}
	case vfs.GCSFilesystemProvider:
		if u.FsConfig.GCSConfig.Credentials.IsRedacted() {
			return true
		}
	case vfs.AzureBlobFilesystemProvider:
		if u.FsConfig.AzBlobConfig.AccountKey.IsRedacted() {
			return true
		}
		if u.FsConfig.AzBlobConfig.SASURL.IsRedacted() {
			return true
		}
	case vfs.CryptedFilesystemProvider:
		if u.FsConfig.CryptConfig.Passphrase.IsRedacted() {
			return true
		}
	case vfs.SFTPFilesystemProvider:
		if u.FsConfig.SFTPConfig.Password.IsRedacted() {
			return true
		}
		if u.FsConfig.SFTPConfig.PrivateKey.IsRedacted() {
			return true
		}
	}

	for idx := range u.VirtualFolders {
		folder := &u.VirtualFolders[idx]
		if folder.HasRedactedSecret() {
			return true
		}
	}

	return false
}

// CloseFs closes the underlying filesystems
func (u *User) CloseFs() error {
	if u.fsCache == nil {
		return nil
	}

	var err error
	for _, fs := range u.fsCache {
		errClose := fs.Close()
		if err == nil {
			err = errClose
		}
	}
	return err
}

// IsPasswordHashed returns true if the password is hashed
func (u *User) IsPasswordHashed() bool {
	return utils.IsStringPrefixInSlice(u.Password, hashPwdPrefixes)
}

// IsTLSUsernameVerificationEnabled returns true if we need to extract the username
// from the client TLS certificate
func (u *User) IsTLSUsernameVerificationEnabled() bool {
	if u.Filters.TLSUsername != "" {
		return u.Filters.TLSUsername != TLSUsernameNone
	}
	return false
}

// SetEmptySecrets sets to empty any user secret
func (u *User) SetEmptySecrets() {
	u.FsConfig.S3Config.AccessSecret = kms.NewEmptySecret()
	u.FsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
	u.FsConfig.AzBlobConfig.AccountKey = kms.NewEmptySecret()
	u.FsConfig.AzBlobConfig.SASURL = kms.NewEmptySecret()
	u.FsConfig.CryptConfig.Passphrase = kms.NewEmptySecret()
	u.FsConfig.SFTPConfig.Password = kms.NewEmptySecret()
	u.FsConfig.SFTPConfig.PrivateKey = kms.NewEmptySecret()
	for idx := range u.VirtualFolders {
		folder := &u.VirtualFolders[idx]
		folder.FsConfig.SetEmptySecretsIfNil()
	}
}

// GetPermissionsForPath returns the permissions for the given path.
// The path must be a SFTPGo exposed path
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
	dirsForPath := utils.GetDirsForVirtualPath(p)
	// dirsForPath contains all the dirs for a given path in reverse order
	// for example if the path is: /1/2/3/4 it contains:
	// [ "/1/2/3/4", "/1/2/3", "/1/2", "/1", "/" ]
	// so the first match is the one we are interested to
	for idx := range dirsForPath {
		if perms, ok := u.Permissions[dirsForPath[idx]]; ok {
			permissions = perms
			break
		}
	}
	return permissions
}

func (u *User) getForbiddenSFTPSelfUsers(username string) ([]string, error) {
	sftpUser, err := UserExists(username)
	if err == nil {
		// we don't allow local nested SFTP folders
		var forbiddens []string
		if sftpUser.FsConfig.Provider == vfs.SFTPFilesystemProvider {
			forbiddens = append(forbiddens, sftpUser.Username)
			return forbiddens, nil
		}
		for idx := range sftpUser.VirtualFolders {
			v := &sftpUser.VirtualFolders[idx]
			if v.FsConfig.Provider == vfs.SFTPFilesystemProvider {
				forbiddens = append(forbiddens, sftpUser.Username)
				return forbiddens, nil
			}
		}
		return forbiddens, nil
	}
	if _, ok := err.(*RecordNotFoundError); !ok {
		return nil, err
	}

	return nil, nil
}

// GetFsConfigForPath returns the file system configuration for the specified virtual path
func (u *User) GetFsConfigForPath(virtualPath string) vfs.Filesystem {
	if virtualPath != "" && virtualPath != "/" && len(u.VirtualFolders) > 0 {
		folder, err := u.GetVirtualFolderForPath(virtualPath)
		if err == nil {
			return folder.FsConfig
		}
	}

	return u.FsConfig
}

// GetFilesystemForPath returns the filesystem for the given path
func (u *User) GetFilesystemForPath(virtualPath, connectionID string) (vfs.Fs, error) {
	if u.fsCache == nil {
		u.fsCache = make(map[string]vfs.Fs)
	}
	if virtualPath != "" && virtualPath != "/" && len(u.VirtualFolders) > 0 {
		folder, err := u.GetVirtualFolderForPath(virtualPath)
		if err == nil {
			if fs, ok := u.fsCache[folder.VirtualPath]; ok {
				return fs, nil
			}
			forbiddenSelfUsers := []string{u.Username}
			if folder.FsConfig.Provider == vfs.SFTPFilesystemProvider {
				forbiddens, err := u.getForbiddenSFTPSelfUsers(folder.FsConfig.SFTPConfig.Username)
				if err != nil {
					return nil, err
				}
				forbiddenSelfUsers = append(forbiddenSelfUsers, forbiddens...)
			}
			fs, err := folder.GetFilesystem(connectionID, forbiddenSelfUsers)
			if err == nil {
				u.fsCache[folder.VirtualPath] = fs
			}
			return fs, err
		}
	}

	if val, ok := u.fsCache["/"]; ok {
		return val, nil
	}

	return u.GetFilesystem(connectionID)
}

// GetVirtualFolderForPath returns the virtual folder containing the specified virtual path.
// If the path is not inside a virtual folder an error is returned
func (u *User) GetVirtualFolderForPath(virtualPath string) (vfs.VirtualFolder, error) {
	var folder vfs.VirtualFolder
	if len(u.VirtualFolders) == 0 {
		return folder, errNoMatchingVirtualFolder
	}
	dirsForPath := utils.GetDirsForVirtualPath(virtualPath)
	for index := range dirsForPath {
		for idx := range u.VirtualFolders {
			v := &u.VirtualFolders[idx]
			if v.VirtualPath == dirsForPath[index] {
				return *v, nil
			}
		}
	}
	return folder, errNoMatchingVirtualFolder
}

// ScanQuota scans the user home dir and virtual folders, included in its quota,
// and returns the number of files and their size
func (u *User) ScanQuota() (int, int64, error) {
	fs, err := u.getRootFs("")
	if err != nil {
		return 0, 0, err
	}
	defer fs.Close()
	numFiles, size, err := fs.ScanRootDirContents()
	if err != nil {
		return numFiles, size, err
	}
	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		if !v.IsIncludedInUserQuota() {
			continue
		}
		num, s, err := v.ScanQuota()
		if err != nil {
			return numFiles, size, err
		}
		numFiles += num
		size += s
	}

	return numFiles, size, nil
}

// GetVirtualFoldersInPath returns the virtual folders inside virtualPath including
// any parents
func (u *User) GetVirtualFoldersInPath(virtualPath string) map[string]bool {
	result := make(map[string]bool)

	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		dirsForPath := utils.GetDirsForVirtualPath(v.VirtualPath)
		for index := range dirsForPath {
			d := dirsForPath[index]
			if d == "/" {
				continue
			}
			if path.Dir(d) == virtualPath {
				result[d] = true
			}
		}
	}

	return result
}

// AddVirtualDirs adds virtual folders, if defined, to the given files list
func (u *User) AddVirtualDirs(list []os.FileInfo, virtualPath string) []os.FileInfo {
	if len(u.VirtualFolders) == 0 {
		return list
	}

	for dir := range u.GetVirtualFoldersInPath(virtualPath) {
		fi := vfs.NewFileInfo(dir, true, 0, time.Now(), false)
		found := false
		for index := range list {
			if list[index].Name() == fi.Name() {
				list[index] = fi
				found = true
				break
			}
		}
		if !found {
			list = append(list, fi)
		}
	}
	return list
}

// IsMappedPath returns true if the specified filesystem path has a virtual folder mapping.
// The filesystem path must be cleaned before calling this method
func (u *User) IsMappedPath(fsPath string) bool {
	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		if fsPath == v.MappedPath {
			return true
		}
	}
	return false
}

// IsVirtualFolder returns true if the specified virtual path is a virtual folder
func (u *User) IsVirtualFolder(virtualPath string) bool {
	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		if virtualPath == v.VirtualPath {
			return true
		}
	}
	return false
}

// HasVirtualFoldersInside returns true if there are virtual folders inside the
// specified virtual path. We assume that path are cleaned
func (u *User) HasVirtualFoldersInside(virtualPath string) bool {
	if virtualPath == "/" && len(u.VirtualFolders) > 0 {
		return true
	}
	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		if len(v.VirtualPath) > len(virtualPath) {
			if strings.HasPrefix(v.VirtualPath, virtualPath+"/") {
				return true
			}
		}
	}
	return false
}

// HasPermissionsInside returns true if the specified virtualPath has no permissions itself and
// no subdirs with defined permissions
func (u *User) HasPermissionsInside(virtualPath string) bool {
	for dir := range u.Permissions {
		if dir == virtualPath {
			return true
		} else if len(dir) > len(virtualPath) {
			if strings.HasPrefix(dir, virtualPath+"/") {
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
		if method == LoginMethodTLSCertificate || method == LoginMethodTLSCertificateAndPwd {
			continue
		}
		if !utils.IsStringInSlice(method, SSHMultiStepsLoginMethods) {
			return false
		}
	}
	return true
}

// GetAllowedLoginMethods returns the allowed login methods
func (u *User) GetAllowedLoginMethods() []string {
	var allowedMethods []string
	for _, method := range ValidLoginMethods {
		if !utils.IsStringInSlice(method, u.Filters.DeniedLoginMethods) {
			allowedMethods = append(allowedMethods, method)
		}
	}
	return allowedMethods
}

// GetFlatFilePatterns returns file patterns as flat list
// duplicating a path if it has both allowed and denied patterns
func (u *User) GetFlatFilePatterns() []PatternsFilter {
	var result []PatternsFilter

	for _, pattern := range u.Filters.FilePatterns {
		if len(pattern.AllowedPatterns) > 0 {
			result = append(result, PatternsFilter{
				Path:            pattern.Path,
				AllowedPatterns: pattern.AllowedPatterns,
			})
		}
		if len(pattern.DeniedPatterns) > 0 {
			result = append(result, PatternsFilter{
				Path:           pattern.Path,
				DeniedPatterns: pattern.DeniedPatterns,
			})
		}
	}
	return result
}

// IsFileAllowed returns true if the specified file is allowed by the file restrictions filters
func (u *User) IsFileAllowed(virtualPath string) bool {
	return u.isFilePatternAllowed(virtualPath)
}

func (u *User) isFilePatternAllowed(virtualPath string) bool {
	if len(u.Filters.FilePatterns) == 0 {
		return true
	}
	dirsForPath := utils.GetDirsForVirtualPath(path.Dir(virtualPath))
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

// CanManagePublicKeys return true if this user is allowed to manage public keys
// from the web client
func (u *User) CanManagePublicKeys() bool {
	return !utils.IsStringInSlice(WebClientPubKeyChangeDisabled, u.Filters.WebClient)
}

// GetSignature returns a signature for this admin.
// It could change after an update
func (u *User) GetSignature() string {
	data := []byte(fmt.Sprintf("%v_%v_%v", u.Username, u.Status, u.ExpirationDate))
	data = append(data, []byte(u.Password)...)
	signature := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(signature[:])
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
	if u.UID <= 0 || u.UID > math.MaxInt32 {
		return -1
	}
	return u.UID
}

// GetGID returns a validate gid, suitable for use with os.Chown
func (u *User) GetGID() int {
	if u.GID <= 0 || u.GID > math.MaxInt32 {
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
		result += ". Size: " + utils.ByteCountIEC(u.UsedQuotaSize)
		if u.QuotaSize > 0 {
			result += "/" + utils.ByteCountIEC(u.QuotaSize)
		}
	}
	if u.LastQuotaUpdate > 0 {
		t := utils.GetTimeFromMsecSinceEpoch(u.LastQuotaUpdate)
		result += fmt.Sprintf(". Last update: %v ", t.Format("2006-01-02 15:04")) // YYYY-MM-DD HH:MM
	}
	return result
}

// GetPermissionsAsString returns the user's permissions as comma separated string
func (u *User) GetPermissionsAsString() string {
	result := ""
	for dir, perms := range u.Permissions {
		dirPerms := strings.Join(perms, ", ")
		dp := fmt.Sprintf("%#v: %#v", dir, dirPerms)
		if dir == "/" {
			if result != "" {
				result = dp + ", " + result
			} else {
				result = dp
			}
		} else {
			if result != "" {
				result += ", "
			}
			result += dp
		}
	}
	return result
}

// GetBandwidthAsString returns bandwidth limits if defines
func (u *User) GetBandwidthAsString() string {
	result := "DL: "
	if u.DownloadBandwidth > 0 {
		result += utils.ByteCountIEC(u.DownloadBandwidth*1000) + "/s."
	} else {
		result += "unlimited."
	}
	result += " UL: "
	if u.UploadBandwidth > 0 {
		result += utils.ByteCountIEC(u.UploadBandwidth*1000) + "/s."
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
		result += fmt.Sprintf("Last login: %v ", t.Format("2006-01-02 15:04")) // YYYY-MM-DD HH:MM
	}
	switch u.FsConfig.Provider {
	case vfs.S3FilesystemProvider:
		result += "Storage: S3 "
	case vfs.GCSFilesystemProvider:
		result += "Storage: GCS "
	case vfs.AzureBlobFilesystemProvider:
		result += "Storage: AzBlob "
	case vfs.CryptedFilesystemProvider:
		result += "Storage: Encrypted "
	case vfs.SFTPFilesystemProvider:
		result += "Storage: SFTP "
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

// GetStatusAsString returns the user status as a string
func (u *User) GetStatusAsString() string {
	if u.ExpirationDate > 0 && u.ExpirationDate < utils.GetTimeAsMsSinceEpoch(time.Now()) {
		return "Expired"
	}
	if u.Status == 1 {
		return "Active"
	}
	return "Inactive"
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
func (u *User) GetAllowedIPAsString() string {
	return strings.Join(u.Filters.AllowedIP, ",")
}

// GetDeniedIPAsString returns the denied IP as comma separated string
func (u *User) GetDeniedIPAsString() string {
	return strings.Join(u.Filters.DeniedIP, ",")
}

// SetEmptySecretsIfNil sets the secrets to empty if nil
func (u *User) SetEmptySecretsIfNil() {
	u.FsConfig.SetEmptySecretsIfNil()
	for idx := range u.VirtualFolders {
		vfolder := &u.VirtualFolders[idx]
		vfolder.FsConfig.SetEmptySecretsIfNil()
	}
}

func (u *User) getACopy() User {
	u.SetEmptySecretsIfNil()
	pubKeys := make([]string, len(u.PublicKeys))
	copy(pubKeys, u.PublicKeys)
	virtualFolders := make([]vfs.VirtualFolder, 0, len(u.VirtualFolders))
	for idx := range u.VirtualFolders {
		vfolder := u.VirtualFolders[idx].GetACopy()
		virtualFolders = append(virtualFolders, vfolder)
	}
	permissions := make(map[string][]string)
	for k, v := range u.Permissions {
		perms := make([]string, len(v))
		copy(perms, v)
		permissions[k] = perms
	}
	filters := UserFilters{}
	filters.MaxUploadFileSize = u.Filters.MaxUploadFileSize
	filters.TLSUsername = u.Filters.TLSUsername
	filters.AllowedIP = make([]string, len(u.Filters.AllowedIP))
	copy(filters.AllowedIP, u.Filters.AllowedIP)
	filters.DeniedIP = make([]string, len(u.Filters.DeniedIP))
	copy(filters.DeniedIP, u.Filters.DeniedIP)
	filters.DeniedLoginMethods = make([]string, len(u.Filters.DeniedLoginMethods))
	copy(filters.DeniedLoginMethods, u.Filters.DeniedLoginMethods)
	filters.FilePatterns = make([]PatternsFilter, len(u.Filters.FilePatterns))
	copy(filters.FilePatterns, u.Filters.FilePatterns)
	filters.DeniedProtocols = make([]string, len(u.Filters.DeniedProtocols))
	copy(filters.DeniedProtocols, u.Filters.DeniedProtocols)
	filters.Hooks.ExternalAuthDisabled = u.Filters.Hooks.ExternalAuthDisabled
	filters.Hooks.PreLoginDisabled = u.Filters.Hooks.PreLoginDisabled
	filters.Hooks.CheckPasswordDisabled = u.Filters.Hooks.CheckPasswordDisabled
	filters.DisableFsChecks = u.Filters.DisableFsChecks
	filters.WebClient = make([]string, len(u.Filters.WebClient))
	copy(filters.WebClient, u.Filters.WebClient)

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
		FsConfig:          u.FsConfig.GetACopy(),
		AdditionalInfo:    u.AdditionalInfo,
		Description:       u.Description,
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

// GetEncrytionAdditionalData returns the additional data to use for AEAD
func (u *User) GetEncrytionAdditionalData() string {
	return u.Username
}

// GetGCSCredentialsFilePath returns the path for GCS credentials
func (u *User) GetGCSCredentialsFilePath() string {
	return filepath.Join(credentialsDirPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
}
