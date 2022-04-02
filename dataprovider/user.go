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
	"strings"
	"time"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/plugin"
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
	SSHLoginMethodPassword            = "password-over-SSH"
	SSHLoginMethodPublicKey           = "publickey"
	SSHLoginMethodKeyboardInteractive = "keyboard-interactive"
	SSHLoginMethodKeyAndPassword      = "publickey+password"
	SSHLoginMethodKeyAndKeyboardInt   = "publickey+keyboard-interactive"
	LoginMethodTLSCertificate         = "TLSCertificate"
	LoginMethodTLSCertificateAndPwd   = "TLSCertificate+password"
	LoginMethodIDP                    = "IDP"
)

var (
	errNoMatchingVirtualFolder = errors.New("no matching virtual folder found")
	permsRenameAny             = []string{PermRename, PermRenameDirs, PermRenameFiles}
	permsDeleteAny             = []string{PermDelete, PermDeleteDirs, PermDeleteFiles}
)

// RecoveryCode defines a 2FA recovery code
type RecoveryCode struct {
	Secret *kms.Secret `json:"secret"`
	Used   bool        `json:"used,omitempty"`
}

// UserTOTPConfig defines the time-based one time password configuration
type UserTOTPConfig struct {
	Enabled    bool        `json:"enabled,omitempty"`
	ConfigName string      `json:"config_name,omitempty"`
	Secret     *kms.Secret `json:"secret,omitempty"`
	// TOTP will be required for the specified protocols.
	// SSH protocol (SFTP/SCP/SSH commands) will ask for the TOTP passcode if the client uses keyboard interactive
	// authentication.
	// FTP have no standard way to support two factor authentication, if you
	// enable the support for this protocol you have to add the TOTP passcode after the password.
	// For example if your password is "password" and your one time passcode is
	// "123456" you have to use "password123456" as password.
	Protocols []string `json:"protocols,omitempty"`
}

// UserFilters defines additional restrictions for a user
// TODO: rename to UserOptions in v3
type UserFilters struct {
	sdk.BaseUserFilters
	// Time-based one time passwords configuration
	TOTPConfig UserTOTPConfig `json:"totp_config,omitempty"`
	// Recovery codes to use if the user loses access to their second factor auth device.
	// Each code can only be used once, you should use these codes to login and disable or
	// reset 2FA for your account
	RecoveryCodes []RecoveryCode `json:"recovery_codes,omitempty"`
}

// User defines a SFTPGo user
type User struct {
	sdk.BaseUser
	// Additional restrictions
	Filters UserFilters `json:"filters"`
	// Mapping between virtual paths and virtual folders
	VirtualFolders []vfs.VirtualFolder `json:"virtual_folders,omitempty"`
	// Filesystem configuration details
	FsConfig vfs.Filesystem `json:"filesystem"`
	// we store the filesystem here using the base path as key.
	fsCache map[string]vfs.Fs `json:"-"`
}

// GetFilesystem returns the base filesystem for this user
func (u *User) GetFilesystem(connectionID string) (fs vfs.Fs, err error) {
	return u.GetFilesystemForPath("/", connectionID)
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

func (u *User) checkDirWithParents(virtualDirPath, connectionID string) error {
	dirs := util.GetDirsForVirtualPath(virtualDirPath)
	for idx := len(dirs) - 1; idx >= 0; idx-- {
		vPath := dirs[idx]
		if vPath == "/" {
			continue
		}
		fs, err := u.GetFilesystemForPath(vPath, connectionID)
		if err != nil {
			return fmt.Errorf("unable to get fs for path %#v: %w", vPath, err)
		}
		if fs.HasVirtualFolders() {
			continue
		}
		fsPath, err := fs.ResolvePath(vPath)
		if err != nil {
			return fmt.Errorf("unable to resolve path %#v: %w", vPath, err)
		}
		_, err = fs.Stat(fsPath)
		if err == nil {
			continue
		}
		if fs.IsNotExist(err) {
			err = fs.Mkdir(fsPath)
			if err != nil {
				return err
			}
			vfs.SetPathPermissions(fs, fsPath, u.GetUID(), u.GetGID())
		} else {
			return fmt.Errorf("unable to stat path %#v: %w", vPath, err)
		}
	}

	return nil
}

// CheckFsRoot check the root directory for the main fs and the virtual folders.
// It returns an error if the main filesystem cannot be created
func (u *User) CheckFsRoot(connectionID string) error {
	if u.Filters.DisableFsChecks {
		return nil
	}
	delay := lastLoginMinDelay
	if u.Filters.ExternalAuthCacheTime > 0 {
		cacheTime := time.Duration(u.Filters.ExternalAuthCacheTime) * time.Second
		if cacheTime > delay {
			delay = cacheTime
		}
	}
	if isLastActivityRecent(u.LastLogin, delay) {
		if u.LastLogin > u.UpdatedAt {
			return nil
		}
	}
	fs, err := u.GetFilesystemForPath("/", connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "could not create main filesystem for user %#v err: %v", u.Username, err)
		return err
	}
	fs.CheckRootPath(u.Username, u.GetUID(), u.GetGID())
	if u.Filters.StartDirectory != "" {
		err = u.checkDirWithParents(u.Filters.StartDirectory, connectionID)
		if err != nil {
			logger.Warn(logSender, connectionID, "could not create start directory %#v, err: %v",
				u.Filters.StartDirectory, err)
		}
	}
	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		fs, err = u.GetFilesystemForPath(v.VirtualPath, connectionID)
		if err == nil {
			fs.CheckRootPath(u.Username, u.GetUID(), u.GetGID())
		}
		// now check intermediary folders
		err = u.checkDirWithParents(path.Dir(v.VirtualPath), connectionID)
		if err != nil {
			logger.Warn(logSender, connectionID, "could not create intermediary dir to %#v, err: %v", v.VirtualPath, err)
		}
	}
	return nil
}

// GetCleanedPath returns a clean POSIX absolute path using the user start directory as base
// if the provided rawVirtualPath is relative
func (u *User) GetCleanedPath(rawVirtualPath string) string {
	if u.Filters.StartDirectory != "" {
		if !path.IsAbs(rawVirtualPath) {
			var b strings.Builder

			b.Grow(len(u.Filters.StartDirectory) + 1 + len(rawVirtualPath))
			b.WriteString(u.Filters.StartDirectory)
			b.WriteString("/")
			b.WriteString(rawVirtualPath)
			return util.CleanPath(b.String())
		}
	}
	return util.CleanPath(rawVirtualPath)
}

// isFsEqual returns true if the filesystem configurations are the same
func (u *User) isFsEqual(other *User) bool {
	if u.FsConfig.Provider == sdk.LocalFilesystemProvider && u.GetHomeDir() != other.GetHomeDir() {
		return false
	}
	if !u.FsConfig.IsEqual(&other.FsConfig) {
		return false
	}
	if u.Filters.StartDirectory != other.Filters.StartDirectory {
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
			providerLog(logger.LevelError, "unable to reload user before rendering as json: %v", err)
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
	u.FsConfig.SetEmptySecrets()
	for idx := range u.VirtualFolders {
		folder := &u.VirtualFolders[idx]
		folder.FsConfig.SetEmptySecrets()
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

// HasBufferedSFTP returns true if the user has a SFTP filesystem with buffering enabled
func (u *User) HasBufferedSFTP(name string) bool {
	fs := u.GetFsConfigForPath(name)
	if fs.Provider == sdk.SFTPFilesystemProvider {
		return fs.SFTPConfig.BufferSize > 0
	}
	return false
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
	// allow to override the `/` path with a virtual folder
	if len(u.VirtualFolders) > 0 {
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
	fs, err := u.getRootFs(connectionID)
	if err != nil {
		return fs, err
	}
	u.fsCache["/"] = fs
	return fs, err
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

// CheckMetadataConsistency checks the consistency between the metadata stored
// in the configured metadata plugin and the filesystem
func (u *User) CheckMetadataConsistency() error {
	fs, err := u.getRootFs("")
	if err != nil {
		return err
	}
	defer fs.Close()

	if err = fs.CheckMetadata(); err != nil {
		return err
	}
	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		if err = v.CheckMetadataConsistency(); err != nil {
			return err
		}
	}
	return nil
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

	if u.Filters.StartDirectory != "" {
		dirsForPath := util.GetDirsForVirtualPath(u.Filters.StartDirectory)
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

func (u *User) hasVirtualDirs() bool {
	if u.Filters.StartDirectory != "" {
		return true
	}
	numFolders := len(u.VirtualFolders)
	if numFolders == 1 {
		return u.VirtualFolders[0].VirtualPath != "/"
	}
	return numFolders > 0
}

// FilterListDir adds virtual folders and remove hidden items from the given files list
func (u *User) FilterListDir(dirContents []os.FileInfo, virtualPath string) []os.FileInfo {
	filter := u.getPatternsFilterForPath(virtualPath)
	if !u.hasVirtualDirs() && filter.DenyPolicy != sdk.DenyPolicyHide {
		return dirContents
	}

	vdirs := make(map[string]bool)
	for dir := range u.GetVirtualFoldersInPath(virtualPath) {
		dirName := path.Base(dir)
		if filter.DenyPolicy == sdk.DenyPolicyHide {
			if !filter.CheckAllowed(dirName) {
				continue
			}
		}
		vdirs[dirName] = true
	}

	validIdx := 0
	for index, fi := range dirContents {
		for dir := range vdirs {
			if fi.Name() == dir {
				if !fi.IsDir() {
					fi = vfs.NewFileInfo(dir, true, 0, time.Now(), false)
					dirContents[index] = fi
				}
				delete(vdirs, dir)
			}
		}
		if filter.DenyPolicy == sdk.DenyPolicyHide {
			if filter.CheckAllowed(fi.Name()) {
				dirContents[validIdx] = fi
				validIdx++
			}
		}
	}

	if filter.DenyPolicy == sdk.DenyPolicyHide {
		for idx := validIdx; idx < len(dirContents); idx++ {
			dirContents[idx] = nil
		}
		dirContents = dirContents[:validIdx]
	}

	for dir := range vdirs {
		fi := vfs.NewFileInfo(dir, true, 0, time.Now(), false)
		dirContents = append(dirContents, fi)
	}
	return dirContents
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
func (u *User) IsLoginMethodAllowed(loginMethod, protocol string, partialSuccessMethods []string) bool {
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
	if protocol == protocolSSH && loginMethod == LoginMethodPassword {
		if util.IsStringInSlice(SSHLoginMethodPassword, u.Filters.DeniedLoginMethods) {
			return false
		}
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
		if method == LoginMethodTLSCertificate || method == LoginMethodTLSCertificateAndPwd ||
			method == SSHLoginMethodPassword {
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
		if method == SSHLoginMethodPassword {
			continue
		}
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
				DenyPolicy:      pattern.DenyPolicy,
			})
		}
		if len(pattern.DeniedPatterns) > 0 {
			result = append(result, sdk.PatternsFilter{
				Path:           pattern.Path,
				DeniedPatterns: pattern.DeniedPatterns,
				DenyPolicy:     pattern.DenyPolicy,
			})
		}
	}
	return result
}

func (u *User) getPatternsFilterForPath(virtualPath string) sdk.PatternsFilter {
	var filter sdk.PatternsFilter
	if len(u.Filters.FilePatterns) == 0 {
		return filter
	}
	dirsForPath := util.GetDirsForVirtualPath(virtualPath)
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
	return filter
}

func (u *User) isDirHidden(virtualPath string) bool {
	if len(u.Filters.FilePatterns) == 0 {
		return false
	}
	for _, dirPath := range util.GetDirsForVirtualPath(virtualPath) {
		if dirPath == "/" {
			return false
		}
		filter := u.getPatternsFilterForPath(dirPath)
		if filter.DenyPolicy == sdk.DenyPolicyHide {
			if !filter.CheckAllowed(path.Base(dirPath)) {
				return true
			}
		}
	}
	return false
}

// IsFileAllowed returns true if the specified file is allowed by the file restrictions filters.
// The second parameter returned is the deny policy
func (u *User) IsFileAllowed(virtualPath string) (bool, int) {
	dirPath := path.Dir(virtualPath)
	if u.isDirHidden(dirPath) {
		return false, sdk.DenyPolicyHide
	}
	filter := u.getPatternsFilterForPath(dirPath)
	return filter.CheckAllowed(path.Base(virtualPath)), filter.DenyPolicy
}

// CanManageMFA returns true if the user can add a multi-factor authentication configuration
func (u *User) CanManageMFA() bool {
	if util.IsStringInSlice(sdk.WebClientMFADisabled, u.Filters.WebClient) {
		return false
	}
	return len(mfa.GetAvailableTOTPConfigs()) > 0
}

func (u *User) isExternalAuthCached() bool {
	if u.ID <= 0 {
		return false
	}
	if u.Filters.ExternalAuthCacheTime <= 0 {
		return false
	}

	return isLastActivityRecent(u.LastLogin, time.Duration(u.Filters.ExternalAuthCacheTime)*time.Second)
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
	return u.HasAnyPerm(permsRenameAny, src) && u.HasAnyPerm(permsRenameAny, dest)
}

// CanDeleteFromWeb returns true if the client can delete objects from the web UI.
// The specified target is the parent directory for the object to delete
func (u *User) CanDeleteFromWeb(target string) bool {
	if util.IsStringInSlice(sdk.WebClientWriteDisabled, u.Filters.WebClient) {
		return false
	}
	return u.HasAnyPerm(permsDeleteAny, target)
}

// MustSetSecondFactor returns true if the user must set a second factor authentication
func (u *User) MustSetSecondFactor() bool {
	if len(u.Filters.TwoFactorAuthProtocols) > 0 {
		if !u.Filters.TOTPConfig.Enabled {
			return true
		}
		for _, p := range u.Filters.TwoFactorAuthProtocols {
			if !util.IsStringInSlice(p, u.Filters.TOTPConfig.Protocols) {
				return true
			}
		}
	}
	return false
}

// MustSetSecondFactorForProtocol returns true if the user must set a second factor authentication
// for the specified protocol
func (u *User) MustSetSecondFactorForProtocol(protocol string) bool {
	if util.IsStringInSlice(protocol, u.Filters.TwoFactorAuthProtocols) {
		if !u.Filters.TOTPConfig.Enabled {
			return true
		}
		if !util.IsStringInSlice(protocol, u.Filters.TOTPConfig.Protocols) {
			return true
		}
	}
	return false
}

// GetSignature returns a signature for this admin.
// It could change after an update
func (u *User) GetSignature() string {
	data := []byte(fmt.Sprintf("%v_%v_%v", u.Username, u.Status, u.ExpirationDate))
	data = append(data, []byte(u.Password)...)
	signature := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(signature[:])
}

// GetBandwidthForIP returns the upload and download bandwidth for the specified IP
func (u *User) GetBandwidthForIP(clientIP, connectionID string) (int64, int64) {
	if len(u.Filters.BandwidthLimits) > 0 {
		ip := net.ParseIP(clientIP)
		if ip != nil {
			for _, bwLimit := range u.Filters.BandwidthLimits {
				for _, source := range bwLimit.Sources {
					_, ipNet, err := net.ParseCIDR(source)
					if err == nil {
						if ipNet.Contains(ip) {
							logger.Debug(logSender, connectionID, "override bandwidth limit for ip %#v, upload limit: %v KB/s, download limit: %v KB/s",
								clientIP, bwLimit.UploadBandwidth, bwLimit.DownloadBandwidth)
							return bwLimit.UploadBandwidth, bwLimit.DownloadBandwidth
						}
					}
				}
			}
		}
	}
	return u.UploadBandwidth, u.DownloadBandwidth
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

// HasRecentActivity returns true if the last user login is recent and so we can skip some expensive checks
func (u *User) HasRecentActivity() bool {
	return isLastActivityRecent(u.LastLogin, lastLoginMinDelay)
}

// HasQuotaRestrictions returns true if there are any disk quota restrictions
func (u *User) HasQuotaRestrictions() bool {
	return u.QuotaFiles > 0 || u.QuotaSize > 0
}

// HasTransferQuotaRestrictions returns true if there are any data transfer restrictions
func (u *User) HasTransferQuotaRestrictions() bool {
	if len(u.Filters.DataTransferLimits) > 0 {
		return true
	}
	return u.UploadDataTransfer > 0 || u.TotalDataTransfer > 0 || u.DownloadDataTransfer > 0
}

// GetDataTransferLimits returns upload, download and total data transfer limits
func (u *User) GetDataTransferLimits(clientIP string) (int64, int64, int64) {
	var total, ul, dl int64
	if len(u.Filters.DataTransferLimits) > 0 {
		ip := net.ParseIP(clientIP)
		if ip != nil {
			for _, limit := range u.Filters.DataTransferLimits {
				for _, source := range limit.Sources {
					_, ipNet, err := net.ParseCIDR(source)
					if err == nil {
						if ipNet.Contains(ip) {
							if limit.TotalDataTransfer > 0 {
								total = limit.TotalDataTransfer * 1048576
							}
							if limit.DownloadDataTransfer > 0 {
								dl = limit.DownloadDataTransfer * 1048576
							}
							if limit.UploadDataTransfer > 0 {
								ul = limit.UploadDataTransfer * 1048576
							}
							return ul, dl, total
						}
					}
				}
			}
		}
	}
	if u.TotalDataTransfer > 0 {
		total = u.TotalDataTransfer * 1048576
	}
	if u.DownloadDataTransfer > 0 {
		dl = u.DownloadDataTransfer * 1048576
	}
	if u.UploadDataTransfer > 0 {
		ul = u.UploadDataTransfer * 1048576
	}
	return ul, dl, total
}

// GetQuotaSummary returns used quota and limits if defined
func (u *User) GetQuotaSummary() string {
	var sb strings.Builder

	addSection := func() {
		if sb.Len() > 0 {
			sb.WriteString(". ")
		}
	}

	if u.UsedQuotaFiles > 0 || u.QuotaFiles > 0 {
		sb.WriteString(fmt.Sprintf("Files: %v", u.UsedQuotaFiles))
		if u.QuotaFiles > 0 {
			sb.WriteString(fmt.Sprintf("/%v", u.QuotaFiles))
		}
	}
	if u.UsedQuotaSize > 0 || u.QuotaSize > 0 {
		addSection()
		sb.WriteString(fmt.Sprintf("Size: %v", util.ByteCountIEC(u.UsedQuotaSize)))
		if u.QuotaSize > 0 {
			sb.WriteString(fmt.Sprintf("/%v", util.ByteCountIEC(u.QuotaSize)))
		}
	}
	if u.TotalDataTransfer > 0 {
		addSection()
		total := u.UsedDownloadDataTransfer + u.UsedUploadDataTransfer
		sb.WriteString(fmt.Sprintf("Transfer: %v/%v", util.ByteCountIEC(total),
			util.ByteCountIEC(u.TotalDataTransfer*1048576)))
	}
	if u.UploadDataTransfer > 0 {
		addSection()
		sb.WriteString(fmt.Sprintf("UL: %v/%v", util.ByteCountIEC(u.UsedUploadDataTransfer),
			util.ByteCountIEC(u.UploadDataTransfer*1048576)))
	}
	if u.DownloadDataTransfer > 0 {
		addSection()
		sb.WriteString(fmt.Sprintf("DL: %v/%v", util.ByteCountIEC(u.UsedDownloadDataTransfer),
			util.ByteCountIEC(u.DownloadDataTransfer*1048576)))
	}
	if u.LastQuotaUpdate > 0 {
		addSection()
		t := util.GetTimeFromMsecSinceEpoch(u.LastQuotaUpdate)
		sb.WriteString(fmt.Sprintf("Last update: %v", t.Format("2006-01-02 15:04"))) // YYYY-MM-DD HH:MM
	}
	return sb.String()
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

// HasExternalAuth returns true if the external authentication is globally enabled
// and it is not disabled for this user
func (u *User) HasExternalAuth() bool {
	if u.Filters.Hooks.ExternalAuthDisabled {
		return false
	}
	if config.ExternalAuthHook != "" {
		return true
	}
	return plugin.Handler.HasAuthenticators()
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
	filters := UserFilters{}
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
	filters.TwoFactorAuthProtocols = make([]string, len(u.Filters.TwoFactorAuthProtocols))
	copy(filters.TwoFactorAuthProtocols, u.Filters.TwoFactorAuthProtocols)
	filters.Hooks.ExternalAuthDisabled = u.Filters.Hooks.ExternalAuthDisabled
	filters.Hooks.PreLoginDisabled = u.Filters.Hooks.PreLoginDisabled
	filters.Hooks.CheckPasswordDisabled = u.Filters.Hooks.CheckPasswordDisabled
	filters.DisableFsChecks = u.Filters.DisableFsChecks
	filters.StartDirectory = u.Filters.StartDirectory
	filters.AllowAPIKeyAuth = u.Filters.AllowAPIKeyAuth
	filters.ExternalAuthCacheTime = u.Filters.ExternalAuthCacheTime
	filters.WebClient = make([]string, len(u.Filters.WebClient))
	copy(filters.WebClient, u.Filters.WebClient)
	filters.RecoveryCodes = make([]RecoveryCode, 0, len(u.Filters.RecoveryCodes))
	for _, code := range u.Filters.RecoveryCodes {
		if code.Secret == nil {
			code.Secret = kms.NewEmptySecret()
		}
		filters.RecoveryCodes = append(filters.RecoveryCodes, RecoveryCode{
			Secret: code.Secret.Clone(),
			Used:   code.Used,
		})
	}
	filters.BandwidthLimits = make([]sdk.BandwidthLimit, 0, len(u.Filters.BandwidthLimits))
	for _, limit := range u.Filters.BandwidthLimits {
		bwLimit := sdk.BandwidthLimit{
			UploadBandwidth:   limit.UploadBandwidth,
			DownloadBandwidth: limit.DownloadBandwidth,
			Sources:           make([]string, 0, len(limit.Sources)),
		}
		bwLimit.Sources = make([]string, len(limit.Sources))
		copy(bwLimit.Sources, limit.Sources)
		filters.BandwidthLimits = append(filters.BandwidthLimits, bwLimit)
	}
	filters.DataTransferLimits = make([]sdk.DataTransferLimit, 0, len(u.Filters.DataTransferLimits))
	for _, limit := range u.Filters.DataTransferLimits {
		dtLimit := sdk.DataTransferLimit{
			UploadDataTransfer:   limit.UploadDataTransfer,
			DownloadDataTransfer: limit.DownloadDataTransfer,
			TotalDataTransfer:    limit.TotalDataTransfer,
			Sources:              make([]string, 0, len(limit.Sources)),
		}
		dtLimit.Sources = make([]string, len(limit.Sources))
		copy(dtLimit.Sources, limit.Sources)
		filters.DataTransferLimits = append(filters.DataTransferLimits, dtLimit)
	}

	return User{
		BaseUser: sdk.BaseUser{
			ID:                       u.ID,
			Username:                 u.Username,
			Email:                    u.Email,
			Password:                 u.Password,
			PublicKeys:               pubKeys,
			HomeDir:                  u.HomeDir,
			UID:                      u.UID,
			GID:                      u.GID,
			MaxSessions:              u.MaxSessions,
			QuotaSize:                u.QuotaSize,
			QuotaFiles:               u.QuotaFiles,
			Permissions:              permissions,
			UsedQuotaSize:            u.UsedQuotaSize,
			UsedQuotaFiles:           u.UsedQuotaFiles,
			LastQuotaUpdate:          u.LastQuotaUpdate,
			UploadBandwidth:          u.UploadBandwidth,
			DownloadBandwidth:        u.DownloadBandwidth,
			UploadDataTransfer:       u.UploadDataTransfer,
			DownloadDataTransfer:     u.DownloadDataTransfer,
			TotalDataTransfer:        u.TotalDataTransfer,
			UsedUploadDataTransfer:   u.UsedUploadDataTransfer,
			UsedDownloadDataTransfer: u.UsedDownloadDataTransfer,
			Status:                   u.Status,
			ExpirationDate:           u.ExpirationDate,
			LastLogin:                u.LastLogin,
			AdditionalInfo:           u.AdditionalInfo,
			Description:              u.Description,
			CreatedAt:                u.CreatedAt,
			UpdatedAt:                u.UpdatedAt,
		},
		Filters:        filters,
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
