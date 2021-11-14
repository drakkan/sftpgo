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

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/sdk"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
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
	// delete files is allowed
	PermDeleteFiles = "delete_files"
	// delete directories is allowed
	PermDeleteDirs = "delete_dirs"
	// rename files or directories is allowed
	PermRename = "rename"
	// rename files is allowed
	PermRenameFiles = "rename_files"
	// rename directories is allowed
	PermRenameDirs = "rename_dirs"
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
	LoginMethodTLSCertificate         = "TLSCertificate"
	LoginMethodTLSCertificateAndPwd   = "TLSCertificate+password"
)

var (
	errNoMatchingVirtualFolder = errors.New("no matching virtual folder found")
	permsRenameAny             = []string{PermRename, PermRenameDirs, PermRenameFiles}
	permsDeleteAny             = []string{PermDelete, PermDeleteDirs, PermDeleteFiles}
	permsCreateAny             = []string{PermUpload, PermCreateDirs}
)

// User defines a SFTPGo user
type User struct {
	sdk.BaseUser
	// Mapping between virtual paths and virtual folders
	VirtualFolders []vfs.VirtualFolder `json:"virtual_folders,omitempty"`
	// Filesystem configuration details
	FsConfig vfs.Filesystem `json:"filesystem"`
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
	case sdk.S3FilesystemProvider:
		return vfs.NewS3Fs(connectionID, u.GetHomeDir(), "", u.FsConfig.S3Config)
	case sdk.GCSFilesystemProvider:
		config := u.FsConfig.GCSConfig
		config.CredentialFile = u.GetGCSCredentialsFilePath()
		return vfs.NewGCSFs(connectionID, u.GetHomeDir(), "", config)
	case sdk.AzureBlobFilesystemProvider:
		return vfs.NewAzBlobFs(connectionID, u.GetHomeDir(), "", u.FsConfig.AzBlobConfig)
	case sdk.CryptedFilesystemProvider:
		return vfs.NewCryptFs(connectionID, u.GetHomeDir(), "", u.FsConfig.CryptConfig)
	case sdk.SFTPFilesystemProvider:
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
	if u.FsConfig.Provider == sdk.LocalFilesystemProvider && u.GetHomeDir() != other.GetHomeDir() {
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
				if f.FsConfig.Provider == sdk.LocalFilesystemProvider && f.MappedPath != f1.MappedPath {
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

// CheckLoginConditions checks if the user is active and not expired
func (u *User) CheckLoginConditions() error {
	if u.Status < 1 {
		return fmt.Errorf("user %#v is disabled", u.Username)
	}
	if u.ExpirationDate > 0 && u.ExpirationDate < util.GetTimeAsMsSinceEpoch(time.Now()) {
		return fmt.Errorf("user %#v is expired, expiration timestamp: %v current timestamp: %v", u.Username,
			u.ExpirationDate, util.GetTimeAsMsSinceEpoch(time.Now()))
	}
	return nil
}

// hideConfidentialData hides user confidential data
func (u *User) hideConfidentialData() {
	u.Password = ""
	u.FsConfig.HideConfidentialData()
	if u.Filters.TOTPConfig.Secret != nil {
		u.Filters.TOTPConfig.Secret.Hide()
	}
	for _, code := range u.Filters.RecoveryCodes {
		if code.Secret != nil {
			code.Secret.Hide()
		}
	}
}

// GetSubDirPermissions returns permissions for sub directories
func (u *User) GetSubDirPermissions() []sdk.DirectoryPermissions {
	var result []sdk.DirectoryPermissions
	for k, v := range u.Permissions {
		if k == "/" {
			continue
		}
		dirPerms := sdk.DirectoryPermissions{
			Path:        k,
			Permissions: v,
		}
		result = append(result, dirPerms)
	}
	return result
}

// RenderAsJSON implements the renderer interface used within plugins
func (u *User) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		user, err := provider.userExists(u.Username)
		if err != nil {
			providerLog(logger.LevelWarn, "unable to reload user before rendering as json: %v", err)
			return nil, err
		}
		user.PrepareForRendering()
		return json.Marshal(user)
	}
	u.PrepareForRendering()
	return json.Marshal(u)
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

// HasRedactedSecret returns true if the user has a redacted secret
func (u *User) hasRedactedSecret() bool {
	if u.FsConfig.HasRedactedSecret() {
		return true
	}

	for idx := range u.VirtualFolders {
		folder := &u.VirtualFolders[idx]
		if folder.HasRedactedSecret() {
			return true
		}
	}

	return u.Filters.TOTPConfig.Secret.IsRedacted()
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
	return util.IsStringPrefixInSlice(u.Password, hashPwdPrefixes)
}

// IsTLSUsernameVerificationEnabled returns true if we need to extract the username
// from the client TLS certificate
func (u *User) IsTLSUsernameVerificationEnabled() bool {
	if u.Filters.TLSUsername != "" {
		return u.Filters.TLSUsername != sdk.TLSUsernameNone
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
	u.Filters.TOTPConfig.Secret = kms.NewEmptySecret()
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
	dirsForPath := util.GetDirsForVirtualPath(p)
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
		if sftpUser.FsConfig.Provider == sdk.SFTPFilesystemProvider {
			forbiddens = append(forbiddens, sftpUser.Username)
			return forbiddens, nil
		}
		for idx := range sftpUser.VirtualFolders {
			v := &sftpUser.VirtualFolders[idx]
			if v.FsConfig.Provider == sdk.SFTPFilesystemProvider {
				forbiddens = append(forbiddens, sftpUser.Username)
				return forbiddens, nil
			}
		}
		return forbiddens, nil
	}
	if _, ok := err.(*util.RecordNotFoundError); !ok {
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
			if folder.FsConfig.Provider == sdk.SFTPFilesystemProvider {
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
	dirsForPath := util.GetDirsForVirtualPath(virtualPath)
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
		dirsForPath := util.GetDirsForVirtualPath(v.VirtualPath)
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
	if util.IsStringInSlice(PermAny, perms) {
		return true
	}
	return util.IsStringInSlice(permission, perms)
}

// HasAnyPerm returns true if the user has at least one of the given permissions
func (u *User) HasAnyPerm(permissions []string, path string) bool {
	perms := u.GetPermissionsForPath(path)
	if util.IsStringInSlice(PermAny, perms) {
		return true
	}
	for _, permission := range permissions {
		if util.IsStringInSlice(permission, perms) {
			return true
		}
	}
	return false
}

// HasPerms returns true if the user has all the given permissions
func (u *User) HasPerms(permissions []string, path string) bool {
	perms := u.GetPermissionsForPath(path)
	if util.IsStringInSlice(PermAny, perms) {
		return true
	}
	for _, permission := range permissions {
		if !util.IsStringInSlice(permission, perms) {
			return false
		}
	}
	return true
}

// HasPermsDeleteAll returns true if the user can delete both files and directories
// for the given path
func (u *User) HasPermsDeleteAll(path string) bool {
	perms := u.GetPermissionsForPath(path)
	canDeleteFiles := false
	canDeleteDirs := false
	for _, permission := range perms {
		if permission == PermAny || permission == PermDelete {
			return true
		}
		if permission == PermDeleteFiles {
			canDeleteFiles = true
		}
		if permission == PermDeleteDirs {
			canDeleteDirs = true
		}
	}
	return canDeleteFiles && canDeleteDirs
}

// HasPermsRenameAll returns true if the user can rename both files and directories
// for the given path
func (u *User) HasPermsRenameAll(path string) bool {
	perms := u.GetPermissionsForPath(path)
	canRenameFiles := false
	canRenameDirs := false
	for _, permission := range perms {
		if permission == PermAny || permission == PermRename {
			return true
		}
		if permission == PermRenameFiles {
			canRenameFiles = true
		}
		if permission == PermRenameDirs {
			canRenameDirs = true
		}
	}
	return canRenameFiles && canRenameDirs
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
	if util.IsStringInSlice(loginMethod, u.Filters.DeniedLoginMethods) {
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
		if !util.IsStringInSlice(method, SSHMultiStepsLoginMethods) {
			return false
		}
	}
	return true
}

// GetAllowedLoginMethods returns the allowed login methods
func (u *User) GetAllowedLoginMethods() []string {
	var allowedMethods []string
	for _, method := range ValidLoginMethods {
		if !util.IsStringInSlice(method, u.Filters.DeniedLoginMethods) {
			allowedMethods = append(allowedMethods, method)
		}
	}
	return allowedMethods
}

// GetFlatFilePatterns returns file patterns as flat list
// duplicating a path if it has both allowed and denied patterns
func (u *User) GetFlatFilePatterns() []sdk.PatternsFilter {
	var result []sdk.PatternsFilter

	for _, pattern := range u.Filters.FilePatterns {
		if len(pattern.AllowedPatterns) > 0 {
			result = append(result, sdk.PatternsFilter{
				Path:            pattern.Path,
				AllowedPatterns: pattern.AllowedPatterns,
			})
		}
		if len(pattern.DeniedPatterns) > 0 {
			result = append(result, sdk.PatternsFilter{
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
	dirsForPath := util.GetDirsForVirtualPath(path.Dir(virtualPath))
	var filter sdk.PatternsFilter
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

// CanManageMFA returns true if the user can add a multi-factor authentication configuration
func (u *User) CanManageMFA() bool {
	if util.IsStringInSlice(sdk.WebClientMFADisabled, u.Filters.WebClient) {
		return false
	}
	return len(mfa.GetAvailableTOTPConfigs()) > 0
}

// CanManageShares returns true if the user can add, update and list shares
func (u *User) CanManageShares() bool {
	return !util.IsStringInSlice(sdk.WebClientSharesDisabled, u.Filters.WebClient)
}

// CanResetPassword returns true if this user is allowed to reset its password
func (u *User) CanResetPassword() bool {
	return !util.IsStringInSlice(sdk.WebClientPasswordResetDisabled, u.Filters.WebClient)
}

// CanChangePassword returns true if this user is allowed to change its password
func (u *User) CanChangePassword() bool {
	return !util.IsStringInSlice(sdk.WebClientPasswordChangeDisabled, u.Filters.WebClient)
}

// CanChangeAPIKeyAuth returns true if this user is allowed to enable/disable API key authentication
func (u *User) CanChangeAPIKeyAuth() bool {
	return !util.IsStringInSlice(sdk.WebClientAPIKeyAuthChangeDisabled, u.Filters.WebClient)
}

// CanChangeInfo returns true if this user is allowed to change its info such as email and description
func (u *User) CanChangeInfo() bool {
	return !util.IsStringInSlice(sdk.WebClientInfoChangeDisabled, u.Filters.WebClient)
}

// CanManagePublicKeys returns true if this user is allowed to manage public keys
// from the web client. Used in web client UI
func (u *User) CanManagePublicKeys() bool {
	return !util.IsStringInSlice(sdk.WebClientPubKeyChangeDisabled, u.Filters.WebClient)
}

// CanAddFilesFromWeb returns true if the client can add files from the web UI.
// The specified target is the directory where the files must be uploaded
func (u *User) CanAddFilesFromWeb(target string) bool {
	if util.IsStringInSlice(sdk.WebClientWriteDisabled, u.Filters.WebClient) {
		return false
	}
	return u.HasPerm(PermUpload, target) || u.HasPerm(PermOverwrite, target)
}

// CanAddDirsFromWeb returns true if the client can add directories from the web UI.
// The specified target is the directory where the new directory must be created
func (u *User) CanAddDirsFromWeb(target string) bool {
	if util.IsStringInSlice(sdk.WebClientWriteDisabled, u.Filters.WebClient) {
		return false
	}
	return u.HasPerm(PermCreateDirs, target)
}

// CanRenameFromWeb returns true if the client can rename objects from the web UI.
// The specified src and dest are the source and target directories for the rename.
func (u *User) CanRenameFromWeb(src, dest string) bool {
	if util.IsStringInSlice(sdk.WebClientWriteDisabled, u.Filters.WebClient) {
		return false
	}
	if u.HasAnyPerm(permsRenameAny, src) && u.HasAnyPerm(permsRenameAny, dest) {
		return true
	}
	if !u.HasAnyPerm(permsDeleteAny, src) {
		return false
	}
	return u.HasAnyPerm(permsCreateAny, dest)
}

// CanDeleteFromWeb returns true if the client can delete objects from the web UI.
// The specified target is the parent directory for the object to delete
func (u *User) CanDeleteFromWeb(target string) bool {
	if util.IsStringInSlice(sdk.WebClientWriteDisabled, u.Filters.WebClient) {
		return false
	}
	return u.HasAnyPerm(permsDeleteAny, target)
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
	remoteIP := net.ParseIP(util.GetIPFromRemoteAddress(remoteAddr))
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
		result += ". Size: " + util.ByteCountIEC(u.UsedQuotaSize)
		if u.QuotaSize > 0 {
			result += "/" + util.ByteCountIEC(u.QuotaSize)
		}
	}
	if u.LastQuotaUpdate > 0 {
		t := util.GetTimeFromMsecSinceEpoch(u.LastQuotaUpdate)
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
		result += util.ByteCountIEC(u.DownloadBandwidth*1000) + "/s."
	} else {
		result += "unlimited."
	}
	result += " UL: "
	if u.UploadBandwidth > 0 {
		result += util.ByteCountIEC(u.UploadBandwidth*1000) + "/s."
	} else {
		result += "unlimited."
	}
	return result
}

// GetInfoString returns user's info as string.
// Storage provider, number of public keys, max sessions, uid,
// gid, denied and allowed IP/Mask are returned
func (u *User) GetInfoString() string {
	var result strings.Builder
	if u.LastLogin > 0 {
		t := util.GetTimeFromMsecSinceEpoch(u.LastLogin)
		result.WriteString(fmt.Sprintf("Last login: %v. ", t.Format("2006-01-02 15:04"))) // YYYY-MM-DD HH:MM
	}
	if u.FsConfig.Provider != sdk.LocalFilesystemProvider {
		result.WriteString(fmt.Sprintf("Storage: %s. ", u.FsConfig.Provider.ShortInfo()))
	}
	if len(u.PublicKeys) > 0 {
		result.WriteString(fmt.Sprintf("Public keys: %v. ", len(u.PublicKeys)))
	}
	if u.MaxSessions > 0 {
		result.WriteString(fmt.Sprintf("Max sessions: %v. ", u.MaxSessions))
	}
	if u.UID > 0 {
		result.WriteString(fmt.Sprintf("UID: %v. ", u.UID))
	}
	if u.GID > 0 {
		result.WriteString(fmt.Sprintf("GID: %v. ", u.GID))
	}
	if len(u.Filters.DeniedIP) > 0 {
		result.WriteString(fmt.Sprintf("Denied IP/Mask: %v. ", len(u.Filters.DeniedIP)))
	}
	if len(u.Filters.AllowedIP) > 0 {
		result.WriteString(fmt.Sprintf("Allowed IP/Mask: %v", len(u.Filters.AllowedIP)))
	}
	return result.String()
}

// GetStatusAsString returns the user status as a string
func (u *User) GetStatusAsString() string {
	if u.ExpirationDate > 0 && u.ExpirationDate < util.GetTimeAsMsSinceEpoch(time.Now()) {
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
		t := util.GetTimeFromMsecSinceEpoch(u.ExpirationDate)
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

// CountUnusedRecoveryCodes returns the number of unused recovery codes
func (u *User) CountUnusedRecoveryCodes() int {
	unused := 0
	for _, code := range u.Filters.RecoveryCodes {
		if !code.Used {
			unused++
		}
	}
	return unused
}

// SetEmptySecretsIfNil sets the secrets to empty if nil
func (u *User) SetEmptySecretsIfNil() {
	u.FsConfig.SetEmptySecretsIfNil()
	for idx := range u.VirtualFolders {
		vfolder := &u.VirtualFolders[idx]
		vfolder.FsConfig.SetEmptySecretsIfNil()
	}
	if u.Filters.TOTPConfig.Secret == nil {
		u.Filters.TOTPConfig.Secret = kms.NewEmptySecret()
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
	filters := sdk.UserFilters{}
	filters.MaxUploadFileSize = u.Filters.MaxUploadFileSize
	filters.TLSUsername = u.Filters.TLSUsername
	filters.UserType = u.Filters.UserType
	filters.TOTPConfig.Enabled = u.Filters.TOTPConfig.Enabled
	filters.TOTPConfig.ConfigName = u.Filters.TOTPConfig.ConfigName
	filters.TOTPConfig.Secret = u.Filters.TOTPConfig.Secret.Clone()
	filters.TOTPConfig.Protocols = make([]string, len(u.Filters.TOTPConfig.Protocols))
	copy(filters.TOTPConfig.Protocols, u.Filters.TOTPConfig.Protocols)
	filters.AllowedIP = make([]string, len(u.Filters.AllowedIP))
	copy(filters.AllowedIP, u.Filters.AllowedIP)
	filters.DeniedIP = make([]string, len(u.Filters.DeniedIP))
	copy(filters.DeniedIP, u.Filters.DeniedIP)
	filters.DeniedLoginMethods = make([]string, len(u.Filters.DeniedLoginMethods))
	copy(filters.DeniedLoginMethods, u.Filters.DeniedLoginMethods)
	filters.FilePatterns = make([]sdk.PatternsFilter, len(u.Filters.FilePatterns))
	copy(filters.FilePatterns, u.Filters.FilePatterns)
	filters.DeniedProtocols = make([]string, len(u.Filters.DeniedProtocols))
	copy(filters.DeniedProtocols, u.Filters.DeniedProtocols)
	filters.Hooks.ExternalAuthDisabled = u.Filters.Hooks.ExternalAuthDisabled
	filters.Hooks.PreLoginDisabled = u.Filters.Hooks.PreLoginDisabled
	filters.Hooks.CheckPasswordDisabled = u.Filters.Hooks.CheckPasswordDisabled
	filters.DisableFsChecks = u.Filters.DisableFsChecks
	filters.AllowAPIKeyAuth = u.Filters.AllowAPIKeyAuth
	filters.WebClient = make([]string, len(u.Filters.WebClient))
	copy(filters.WebClient, u.Filters.WebClient)
	filters.RecoveryCodes = make([]sdk.RecoveryCode, 0)
	for _, code := range u.Filters.RecoveryCodes {
		if code.Secret == nil {
			code.Secret = kms.NewEmptySecret()
		}
		filters.RecoveryCodes = append(filters.RecoveryCodes, sdk.RecoveryCode{
			Secret: code.Secret.Clone(),
			Used:   code.Used,
		})
	}

	return User{
		BaseUser: sdk.BaseUser{
			ID:                u.ID,
			Username:          u.Username,
			Email:             u.Email,
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
			AdditionalInfo:    u.AdditionalInfo,
			Description:       u.Description,
			CreatedAt:         u.CreatedAt,
			UpdatedAt:         u.UpdatedAt,
		},
		VirtualFolders: virtualFolders,
		FsConfig:       u.FsConfig.GetACopy(),
	}
}

// GetEncryptionAdditionalData returns the additional data to use for AEAD
func (u *User) GetEncryptionAdditionalData() string {
	return u.Username
}

// GetGCSCredentialsFilePath returns the path for GCS credentials
func (u *User) GetGCSCredentialsFilePath() string {
	return filepath.Join(credentialsDirPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
}
