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

package dataprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
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
	// copying files or directories is allowed
	PermCopy = "copy"
)

// Available login methods
const (
	LoginMethodNoAuthTried            = "no_auth_tried"
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
	// User must change password from WebClient/REST API at next login.
	RequirePasswordChange bool `json:"require_password_change,omitempty"`
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
	// groups associated with this user
	Groups []sdk.GroupMapping `json:"groups,omitempty"`
	// we store the filesystem here using the base path as key.
	fsCache map[string]vfs.Fs `json:"-"`
	// true if group settings are already applied for this user
	groupSettingsApplied bool `json:"-"`
	// in multi node setups we mark the user as deleted to be able to update the webdav cache
	DeletedAt int64 `json:"-"`
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
		return vfs.NewGCSFs(connectionID, u.GetHomeDir(), "", u.FsConfig.GCSConfig)
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
	case sdk.HTTPFilesystemProvider:
		return vfs.NewHTTPFs(connectionID, u.GetHomeDir(), "", u.FsConfig.HTTPConfig)
	default:
		return vfs.NewOsFs(connectionID, u.GetHomeDir(), "", &u.FsConfig.OSConfig), nil
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
			return fmt.Errorf("unable to get fs for path %q: %w", vPath, err)
		}
		if fs.HasVirtualFolders() {
			continue
		}
		fsPath, err := fs.ResolvePath(vPath)
		if err != nil {
			return fmt.Errorf("unable to resolve path %q: %w", vPath, err)
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
			return fmt.Errorf("unable to stat path %q: %w", vPath, err)
		}
	}

	return nil
}

func (u *User) checkLocalHomeDir(connectionID string) {
	switch u.FsConfig.Provider {
	case sdk.LocalFilesystemProvider, sdk.CryptedFilesystemProvider:
		return
	default:
		osFs := vfs.NewOsFs(connectionID, u.GetHomeDir(), "", nil)
		osFs.CheckRootPath(u.Username, u.GetUID(), u.GetGID())
	}
}

func (u *User) checkRootPath(connectionID string) error {
	fs, err := u.GetFilesystemForPath("/", connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "could not create main filesystem for user %q err: %v", u.Username, err)
		return fmt.Errorf("could not create root filesystem: %w", err)
	}
	fs.CheckRootPath(u.Username, u.GetUID(), u.GetGID())
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
			if config.IsShared == 1 {
				u.checkLocalHomeDir(connectionID)
			}
			return nil
		}
	}
	err := u.checkRootPath(connectionID)
	if err != nil {
		return err
	}
	if u.Filters.StartDirectory != "" {
		err = u.checkDirWithParents(u.Filters.StartDirectory, connectionID)
		if err != nil {
			logger.Warn(logSender, connectionID, "could not create start directory %q, err: %v",
				u.Filters.StartDirectory, err)
		}
	}
	for idx := range u.VirtualFolders {
		v := &u.VirtualFolders[idx]
		fs, err := u.GetFilesystemForPath(v.VirtualPath, connectionID)
		if err == nil {
			fs.CheckRootPath(u.Username, u.GetUID(), u.GetGID())
		}
		// now check intermediary folders
		err = u.checkDirWithParents(path.Dir(v.VirtualPath), connectionID)
		if err != nil {
			logger.Warn(logSender, connectionID, "could not create intermediary dir to %q, err: %v", v.VirtualPath, err)
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
	if !u.FsConfig.IsEqual(other.FsConfig) {
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
				if !f.FsConfig.IsEqual(f1.FsConfig) {
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

func (u *User) isTimeBasedAccessAllowed(when time.Time) bool {
	if len(u.Filters.AccessTime) == 0 {
		return true
	}
	if when.IsZero() {
		when = time.Now()
	}
	when = when.UTC()
	weekDay := when.Weekday()
	hhMM := when.Format("15:04")
	for _, p := range u.Filters.AccessTime {
		if p.DayOfWeek == int(weekDay) {
			if hhMM >= p.From && hhMM <= p.To {
				return true
			}
		}
	}
	return false
}

// CheckLoginConditions checks user access restrictions
func (u *User) CheckLoginConditions() error {
	if u.Status < 1 {
		return fmt.Errorf("user %q is disabled", u.Username)
	}
	if u.ExpirationDate > 0 && u.ExpirationDate < util.GetTimeAsMsSinceEpoch(time.Now()) {
		return fmt.Errorf("user %q is expired, expiration timestamp: %v current timestamp: %v", u.Username,
			u.ExpirationDate, util.GetTimeAsMsSinceEpoch(time.Now()))
	}
	if u.isTimeBasedAccessAllowed(time.Now()) {
		return nil
	}
	return errors.New("access is not allowed at this time")
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

// CheckMaxShareExpiration returns an error if the share expiration exceed the
// maximum allowed date.
func (u *User) CheckMaxShareExpiration(expiresAt time.Time) error {
	if u.Filters.MaxSharesExpiration == 0 {
		return nil
	}
	maxAllowedExpiration := time.Now().Add(24 * time.Hour * time.Duration(u.Filters.MaxSharesExpiration+1))
	maxAllowedExpiration = time.Date(maxAllowedExpiration.Year(), maxAllowedExpiration.Month(),
		maxAllowedExpiration.Day(), 0, 0, 0, 0, maxAllowedExpiration.Location())
	if util.GetTimeAsMsSinceEpoch(expiresAt) == 0 || expiresAt.After(maxAllowedExpiration) {
		return util.NewValidationError(fmt.Sprintf("the share must expire before %s", maxAllowedExpiration.Format(time.DateOnly)))
	}
	return nil
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

func (u *User) setAnonymousSettings() {
	for k := range u.Permissions {
		u.Permissions[k] = []string{PermListItems, PermDownload}
	}
	u.Filters.DeniedProtocols = append(u.Filters.DeniedProtocols, protocolSSH, protocolHTTP)
	u.Filters.DeniedProtocols = util.RemoveDuplicates(u.Filters.DeniedProtocols, false)
	for _, method := range ValidLoginMethods {
		if method != LoginMethodPassword {
			u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, method)
		}
	}
	u.Filters.DeniedLoginMethods = util.RemoveDuplicates(u.Filters.DeniedLoginMethods, false)
}

// RenderAsJSON implements the renderer interface used within plugins
func (u *User) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		user, err := provider.userExists(u.Username, "")
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

// IsTLSVerificationEnabled returns true if we need to check the TLS authentication
func (u *User) IsTLSVerificationEnabled() bool {
	if len(u.Filters.TLSCerts) > 0 {
		return true
	}
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
// The path must be a SFTPGo virtual path
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
			return perms
		}
		for dir, perms := range u.Permissions {
			if match, err := path.Match(dir, dirsForPath[idx]); err == nil && match {
				return perms
			}
		}
	}
	return permissions
}

func (u *User) getForbiddenSFTPSelfUsers(username string) ([]string, error) {
	if allowSelfConnections == 0 {
		return nil, nil
	}
	sftpUser, err := UserExists(username, "")
	if err == nil {
		err = sftpUser.LoadAndApplyGroupSettings()
	}
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
	if !errors.Is(err, util.ErrNotFound) {
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

// ScanQuota scans the user home dir and virtual folders, included in its quota,
// and returns the number of files and their size
func (u *User) ScanQuota() (int, int64, error) {
	fs, err := u.getRootFs(xid.New().String())
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
		dirsForPath := util.GetDirsForVirtualPath(u.VirtualFolders[idx].VirtualPath)
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

// GetVirtualFoldersInfo returns []os.FileInfo for virtual folders
func (u *User) GetVirtualFoldersInfo(virtualPath string) []os.FileInfo {
	filter := u.getPatternsFilterForPath(virtualPath)
	if !u.hasVirtualDirs() && filter.DenyPolicy != sdk.DenyPolicyHide {
		return nil
	}
	vdirs := u.GetVirtualFoldersInPath(virtualPath)
	result := make([]os.FileInfo, 0, len(vdirs))

	for dir := range u.GetVirtualFoldersInPath(virtualPath) {
		dirName := path.Base(dir)
		if filter.DenyPolicy == sdk.DenyPolicyHide {
			if !filter.CheckAllowed(dirName) {
				continue
			}
		}
		result = append(result, vfs.NewFileInfo(dirName, true, 0, time.Unix(0, 0), false))
	}

	return result
}

// FilterListDir removes hidden items from the given files list
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
	for idx := range dirContents {
		fi := dirContents[idx]

		if fi.Name() != "." && fi.Name() != ".." {
			if _, ok := vdirs[fi.Name()]; ok {
				continue
			}
			if filter.DenyPolicy == sdk.DenyPolicyHide {
				if !filter.CheckAllowed(fi.Name()) {
					continue
				}
			}
		}
		dirContents[validIdx] = fi
		validIdx++
	}

	return dirContents[:validIdx]
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
	for dir, perms := range u.Permissions {
		if len(perms) == 1 && perms[0] == PermAny {
			continue
		}
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
	if util.Contains(perms, PermAny) {
		return true
	}
	return util.Contains(perms, permission)
}

// HasAnyPerm returns true if the user has at least one of the given permissions
func (u *User) HasAnyPerm(permissions []string, path string) bool {
	perms := u.GetPermissionsForPath(path)
	if util.Contains(perms, PermAny) {
		return true
	}
	for _, permission := range permissions {
		if util.Contains(perms, permission) {
			return true
		}
	}
	return false
}

// HasPerms returns true if the user has all the given permissions
func (u *User) HasPerms(permissions []string, path string) bool {
	perms := u.GetPermissionsForPath(path)
	if util.Contains(perms, PermAny) {
		return true
	}
	for _, permission := range permissions {
		if !util.Contains(perms, permission) {
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
func (u *User) IsLoginMethodAllowed(loginMethod, protocol string) bool {
	if len(u.Filters.DeniedLoginMethods) == 0 {
		return true
	}
	if util.Contains(u.Filters.DeniedLoginMethods, loginMethod) {
		return false
	}
	if protocol == protocolSSH && loginMethod == LoginMethodPassword {
		if util.Contains(u.Filters.DeniedLoginMethods, SSHLoginMethodPassword) {
			return false
		}
	}
	return true
}

// GetNextAuthMethods returns the list of authentications methods that can
// continue for multi-step authentication. We call this method after a
// successful public key authentication.
func (u *User) GetNextAuthMethods() []string {
	var methods []string
	for _, method := range u.GetAllowedLoginMethods() {
		if method == SSHLoginMethodKeyAndPassword {
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
func (u *User) IsPartialAuth() bool {
	for _, method := range u.GetAllowedLoginMethods() {
		if method == LoginMethodTLSCertificate || method == LoginMethodTLSCertificateAndPwd ||
			method == SSHLoginMethodPassword {
			continue
		}
		if method == LoginMethodPassword && util.Contains(u.Filters.DeniedLoginMethods, SSHLoginMethodPassword) {
			continue
		}
		if !util.Contains(SSHMultiStepsLoginMethods, method) {
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
		if !util.Contains(u.Filters.DeniedLoginMethods, method) {
			allowedMethods = append(allowedMethods, method)
		}
	}
	return allowedMethods
}

func (u *User) getPatternsFilterForPath(virtualPath string) sdk.PatternsFilter {
	var filter sdk.PatternsFilter
	if len(u.Filters.FilePatterns) == 0 {
		return filter
	}
	dirsForPath := util.GetDirsForVirtualPath(virtualPath)
	for idx, dir := range dirsForPath {
		for _, f := range u.Filters.FilePatterns {
			if f.Path == dir {
				if idx > 0 && len(f.AllowedPatterns) > 0 && len(f.DeniedPatterns) > 0 && f.DeniedPatterns[0] == "*" {
					if f.CheckAllowed(path.Base(dirsForPath[idx-1])) {
						return filter
					}
				}
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
		if filter.DenyPolicy == sdk.DenyPolicyHide && filter.Path != dirPath {
			if !filter.CheckAllowed(path.Base(dirPath)) {
				return true
			}
		}
	}
	return false
}

func (u *User) getMinPasswordEntropy() float64 {
	if u.Filters.PasswordStrength > 0 {
		return float64(u.Filters.PasswordStrength)
	}
	return config.PasswordValidation.Users.MinEntropy
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
	if util.Contains(u.Filters.WebClient, sdk.WebClientMFADisabled) {
		return false
	}
	return len(mfa.GetAvailableTOTPConfigs()) > 0
}

func (u *User) skipExternalAuth() bool {
	if u.Filters.Hooks.ExternalAuthDisabled {
		return true
	}
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
	return !util.Contains(u.Filters.WebClient, sdk.WebClientSharesDisabled)
}

// CanResetPassword returns true if this user is allowed to reset its password
func (u *User) CanResetPassword() bool {
	return !util.Contains(u.Filters.WebClient, sdk.WebClientPasswordResetDisabled)
}

// CanChangePassword returns true if this user is allowed to change its password
func (u *User) CanChangePassword() bool {
	return !util.Contains(u.Filters.WebClient, sdk.WebClientPasswordChangeDisabled)
}

// CanChangeAPIKeyAuth returns true if this user is allowed to enable/disable API key authentication
func (u *User) CanChangeAPIKeyAuth() bool {
	return !util.Contains(u.Filters.WebClient, sdk.WebClientAPIKeyAuthChangeDisabled)
}

// CanChangeInfo returns true if this user is allowed to change its info such as email and description
func (u *User) CanChangeInfo() bool {
	return !util.Contains(u.Filters.WebClient, sdk.WebClientInfoChangeDisabled)
}

// CanManagePublicKeys returns true if this user is allowed to manage public keys
// from the web client. Used in web client UI
func (u *User) CanManagePublicKeys() bool {
	return !util.Contains(u.Filters.WebClient, sdk.WebClientPubKeyChangeDisabled)
}

// CanAddFilesFromWeb returns true if the client can add files from the web UI.
// The specified target is the directory where the files must be uploaded
func (u *User) CanAddFilesFromWeb(target string) bool {
	if util.Contains(u.Filters.WebClient, sdk.WebClientWriteDisabled) {
		return false
	}
	return u.HasPerm(PermUpload, target) || u.HasPerm(PermOverwrite, target)
}

// CanAddDirsFromWeb returns true if the client can add directories from the web UI.
// The specified target is the directory where the new directory must be created
func (u *User) CanAddDirsFromWeb(target string) bool {
	if util.Contains(u.Filters.WebClient, sdk.WebClientWriteDisabled) {
		return false
	}
	return u.HasPerm(PermCreateDirs, target)
}

// CanRenameFromWeb returns true if the client can rename objects from the web UI.
// The specified src and dest are the source and target directories for the rename.
func (u *User) CanRenameFromWeb(src, dest string) bool {
	if util.Contains(u.Filters.WebClient, sdk.WebClientWriteDisabled) {
		return false
	}
	return u.HasAnyPerm(permsRenameAny, src) && u.HasAnyPerm(permsRenameAny, dest)
}

// CanDeleteFromWeb returns true if the client can delete objects from the web UI.
// The specified target is the parent directory for the object to delete
func (u *User) CanDeleteFromWeb(target string) bool {
	if util.Contains(u.Filters.WebClient, sdk.WebClientWriteDisabled) {
		return false
	}
	return u.HasAnyPerm(permsDeleteAny, target)
}

// CanCopyFromWeb returns true if the client can copy objects from the web UI.
// The specified src and dest are the source and target directories for the copy.
func (u *User) CanCopyFromWeb(src, dest string) bool {
	if util.Contains(u.Filters.WebClient, sdk.WebClientWriteDisabled) {
		return false
	}
	if !u.HasPerm(PermListItems, src) {
		return false
	}
	if !u.HasPerm(PermDownload, src) {
		return false
	}
	return u.HasPerm(PermCopy, src) && u.HasPerm(PermCopy, dest)
}

// InactivityDays returns the number of days of inactivity
func (u *User) InactivityDays(when time.Time) int {
	if when.IsZero() {
		when = time.Now()
	}
	lastActivity := u.LastLogin
	if lastActivity == 0 {
		lastActivity = u.CreatedAt
	}
	if lastActivity == 0 {
		// unable to determine inactivity
		return 0
	}
	return int(float64(when.Sub(util.GetTimeFromMsecSinceEpoch(lastActivity))) / float64(24*time.Hour))
}

// PasswordExpiresIn returns the number of days before the password expires.
// The returned value is negative if the password is expired.
// The caller must ensure that a PasswordExpiration is set
func (u *User) PasswordExpiresIn() int {
	lastPwdChange := util.GetTimeFromMsecSinceEpoch(u.LastPasswordChange)
	pwdExpiration := lastPwdChange.Add(time.Duration(u.Filters.PasswordExpiration) * 24 * time.Hour)
	res := int(math.Round(float64(time.Until(pwdExpiration)) / float64(24*time.Hour)))
	if res == 0 && pwdExpiration.After(time.Now()) {
		res = 1
	}
	return res
}

// MustChangePassword returns true if the user must change the password
func (u *User) MustChangePassword() bool {
	if u.Filters.RequirePasswordChange {
		return true
	}
	if u.Filters.PasswordExpiration == 0 {
		return false
	}
	lastPwdChange := util.GetTimeFromMsecSinceEpoch(u.LastPasswordChange)
	return lastPwdChange.Add(time.Duration(u.Filters.PasswordExpiration) * 24 * time.Hour).Before(time.Now())
}

// MustSetSecondFactor returns true if the user must set a second factor authentication
func (u *User) MustSetSecondFactor() bool {
	if len(u.Filters.TwoFactorAuthProtocols) > 0 {
		if !u.Filters.TOTPConfig.Enabled {
			return true
		}
		for _, p := range u.Filters.TwoFactorAuthProtocols {
			if !util.Contains(u.Filters.TOTPConfig.Protocols, p) {
				return true
			}
		}
	}
	return false
}

// MustSetSecondFactorForProtocol returns true if the user must set a second factor authentication
// for the specified protocol
func (u *User) MustSetSecondFactorForProtocol(protocol string) bool {
	if util.Contains(u.Filters.TwoFactorAuthProtocols, protocol) {
		if !u.Filters.TOTPConfig.Enabled {
			return true
		}
		if !util.Contains(u.Filters.TOTPConfig.Protocols, protocol) {
			return true
		}
	}
	return false
}

// GetSignature returns a signature for this user.
// It will change after an update
func (u *User) GetSignature() string {
	return strconv.FormatInt(u.UpdatedAt, 10)
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
							logger.Debug(logSender, connectionID, "override bandwidth limit for ip %q, upload limit: %v KB/s, download limit: %v KB/s",
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
// If an IP is both allowed and denied then login will be allowed
func (u *User) IsLoginFromAddrAllowed(remoteAddr string) bool {
	if len(u.Filters.AllowedIP) == 0 && len(u.Filters.DeniedIP) == 0 {
		return true
	}
	remoteIP := net.ParseIP(util.GetIPFromRemoteAddress(remoteAddr))
	// if remoteIP is invalid we allow login, this should never happen
	if remoteIP == nil {
		logger.Warn(logSender, "", "login allowed for invalid IP. remote address: %q", remoteAddr)
		return true
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
	for _, IPMask := range u.Filters.DeniedIP {
		_, IPNet, err := net.ParseCIDR(IPMask)
		if err != nil {
			return false
		}
		if IPNet.Contains(remoteIP) {
			return false
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
	return u.HomeDir
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
	return u.UploadDataTransfer > 0 || u.TotalDataTransfer > 0 || u.DownloadDataTransfer > 0
}

// GetDataTransferLimits returns upload, download and total data transfer limits
func (u *User) GetDataTransferLimits() (int64, int64, int64) {
	var total, ul, dl int64
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
	return sb.String()
}

// GetPermissionsAsString returns the user's permissions as comma separated string
func (u *User) GetPermissionsAsString() string {
	result := ""
	for dir, perms := range u.Permissions {
		dirPerms := strings.Join(perms, ", ")
		dp := fmt.Sprintf("%q: %q", dir, dirPerms)
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
	var sb strings.Builder
	sb.WriteString("DL: ")
	if u.DownloadBandwidth > 0 {
		sb.WriteString(util.ByteCountIEC(u.DownloadBandwidth*1000) + "/s.")
	} else {
		sb.WriteString("unlimited.")
	}
	sb.WriteString(" UL: ")
	if u.UploadBandwidth > 0 {
		sb.WriteString(util.ByteCountIEC(u.UploadBandwidth*1000) + "/s.")
	} else {
		sb.WriteString("unlimited.")
	}
	return sb.String()
}

// GetMFAStatusAsString returns MFA status
func (u *User) GetMFAStatusAsString() string {
	if u.Filters.TOTPConfig.Enabled {
		return strings.Join(u.Filters.TOTPConfig.Protocols, ", ")
	}
	return "Disabled"
}

// GetLastLoginAsString returns the last login as string
func (u *User) GetLastLoginAsString() string {
	if u.LastLogin > 0 {
		return util.GetTimeFromMsecSinceEpoch(u.LastLogin).UTC().Format(iso8601UTCFormat)
	}
	return ""
}

// GetLastQuotaUpdateAsString returns the last quota update as string
func (u *User) GetLastQuotaUpdateAsString() string {
	if u.LastQuotaUpdate > 0 {
		return util.GetTimeFromMsecSinceEpoch(u.LastQuotaUpdate).UTC().Format(iso8601UTCFormat)
	}
	return ""
}

// GetStorageDescrition returns the storage description
func (u *User) GetStorageDescrition() string {
	switch u.FsConfig.Provider {
	case sdk.LocalFilesystemProvider:
		return fmt.Sprintf("Local: %v", u.GetHomeDir())
	case sdk.S3FilesystemProvider:
		return fmt.Sprintf("S3: %v", u.FsConfig.S3Config.Bucket)
	case sdk.GCSFilesystemProvider:
		return fmt.Sprintf("GCS: %v", u.FsConfig.GCSConfig.Bucket)
	case sdk.AzureBlobFilesystemProvider:
		return fmt.Sprintf("AzBlob: %v", u.FsConfig.AzBlobConfig.Container)
	case sdk.CryptedFilesystemProvider:
		return fmt.Sprintf("Encrypted: %v", u.GetHomeDir())
	case sdk.SFTPFilesystemProvider:
		return fmt.Sprintf("SFTP: %v", u.FsConfig.SFTPConfig.Endpoint)
	case sdk.HTTPFilesystemProvider:
		return fmt.Sprintf("HTTP: %v", u.FsConfig.HTTPConfig.Endpoint)
	default:
		return ""
	}
}

// GetGroupsAsString returns the user's groups as a string
func (u *User) GetGroupsAsString() string {
	if len(u.Groups) == 0 {
		return ""
	}
	var groups []string
	for _, g := range u.Groups {
		if g.Type == sdk.GroupTypePrimary {
			groups = append(groups, "")
			copy(groups[1:], groups)
			groups[0] = g.Name
		} else {
			groups = append(groups, g.Name)
		}
	}

	return strings.Join(groups, ",")
}

// GetInfoString returns user's info as string.
// Storage provider, number of public keys, max sessions, uid,
// gid, denied and allowed IP/Mask are returned
func (u *User) GetInfoString() string {
	var result strings.Builder
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
	if len(u.Filters.DeniedLoginMethods) > 0 {
		result.WriteString(fmt.Sprintf("Denied login methods: %v. ", strings.Join(u.Filters.DeniedLoginMethods, ",")))
	}
	if len(u.Filters.DeniedProtocols) > 0 {
		result.WriteString(fmt.Sprintf("Denied protocols: %v. ", strings.Join(u.Filters.DeniedProtocols, ",")))
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
	u.HasPassword = u.Password != ""
	u.FsConfig.SetEmptySecretsIfNil()
	for idx := range u.VirtualFolders {
		vfolder := &u.VirtualFolders[idx]
		vfolder.FsConfig.SetEmptySecretsIfNil()
	}
	if u.Filters.TOTPConfig.Secret == nil {
		u.Filters.TOTPConfig.Secret = kms.NewEmptySecret()
	}
}

func (u *User) hasMainDataTransferLimits() bool {
	return u.UploadDataTransfer > 0 || u.DownloadDataTransfer > 0 || u.TotalDataTransfer > 0
}

// HasPrimaryGroup returns true if the user has the specified primary group
func (u *User) HasPrimaryGroup(name string) bool {
	for _, g := range u.Groups {
		if g.Name == name {
			return g.Type == sdk.GroupTypePrimary
		}
	}
	return false
}

// HasSecondaryGroup returns true if the user has the specified secondary group
func (u *User) HasSecondaryGroup(name string) bool {
	for _, g := range u.Groups {
		if g.Name == name {
			return g.Type == sdk.GroupTypeSecondary
		}
	}
	return false
}

// HasMembershipGroup returns true if the user has the specified membership group
func (u *User) HasMembershipGroup(name string) bool {
	for _, g := range u.Groups {
		if g.Name == name {
			return g.Type == sdk.GroupTypeMembership
		}
	}
	return false
}

func (u *User) hasSettingsFromGroups() bool {
	for _, g := range u.Groups {
		if g.Type != sdk.GroupTypeMembership {
			return true
		}
	}
	return false
}

func (u *User) applyGroupSettings(groupsMapping map[string]Group) {
	if !u.hasSettingsFromGroups() {
		return
	}
	if u.groupSettingsApplied {
		return
	}
	replacer := u.getGroupPlacehodersReplacer()
	for _, g := range u.Groups {
		if g.Type == sdk.GroupTypePrimary {
			if group, ok := groupsMapping[g.Name]; ok {
				u.mergeWithPrimaryGroup(&group, replacer)
			} else {
				providerLog(logger.LevelError, "mapping not found for user %s, group %s", u.Username, g.Name)
			}
			break
		}
	}
	for _, g := range u.Groups {
		if g.Type == sdk.GroupTypeSecondary {
			if group, ok := groupsMapping[g.Name]; ok {
				u.mergeAdditiveProperties(&group, sdk.GroupTypeSecondary, replacer)
			} else {
				providerLog(logger.LevelError, "mapping not found for user %s, group %s", u.Username, g.Name)
			}
		}
	}
	u.removeDuplicatesAfterGroupMerge()
}

// LoadAndApplyGroupSettings update the user by loading and applying the group settings
func (u *User) LoadAndApplyGroupSettings() error {
	if !u.hasSettingsFromGroups() {
		return nil
	}
	if u.groupSettingsApplied {
		return nil
	}
	names := make([]string, 0, len(u.Groups))
	var primaryGroupName string
	for _, g := range u.Groups {
		if g.Type == sdk.GroupTypePrimary {
			primaryGroupName = g.Name
		}
		if g.Type != sdk.GroupTypeMembership {
			names = append(names, g.Name)
		}
	}
	groups, err := provider.getGroupsWithNames(names)
	if err != nil {
		return fmt.Errorf("unable to get groups: %w", err)
	}
	replacer := u.getGroupPlacehodersReplacer()
	// make sure to always merge with the primary group first
	for idx := range groups {
		g := groups[idx]
		if g.Name == primaryGroupName {
			u.mergeWithPrimaryGroup(&g, replacer)
			lastIdx := len(groups) - 1
			groups[idx] = groups[lastIdx]
			groups = groups[:lastIdx]
			break
		}
	}
	for idx := range groups {
		g := groups[idx]
		u.mergeAdditiveProperties(&g, sdk.GroupTypeSecondary, replacer)
	}
	u.removeDuplicatesAfterGroupMerge()
	return nil
}

func (u *User) getGroupPlacehodersReplacer() *strings.Replacer {
	return strings.NewReplacer("%username%", u.Username, "%role%", u.Role)
}

func (u *User) replacePlaceholder(value string, replacer *strings.Replacer) string {
	if value == "" {
		return value
	}
	return replacer.Replace(value)
}

func (u *User) replaceFsConfigPlaceholders(fsConfig vfs.Filesystem, replacer *strings.Replacer) vfs.Filesystem {
	switch fsConfig.Provider {
	case sdk.S3FilesystemProvider:
		fsConfig.S3Config.KeyPrefix = u.replacePlaceholder(fsConfig.S3Config.KeyPrefix, replacer)
	case sdk.GCSFilesystemProvider:
		fsConfig.GCSConfig.KeyPrefix = u.replacePlaceholder(fsConfig.GCSConfig.KeyPrefix, replacer)
	case sdk.AzureBlobFilesystemProvider:
		fsConfig.AzBlobConfig.KeyPrefix = u.replacePlaceholder(fsConfig.AzBlobConfig.KeyPrefix, replacer)
	case sdk.SFTPFilesystemProvider:
		fsConfig.SFTPConfig.Username = u.replacePlaceholder(fsConfig.SFTPConfig.Username, replacer)
		fsConfig.SFTPConfig.Prefix = u.replacePlaceholder(fsConfig.SFTPConfig.Prefix, replacer)
	case sdk.HTTPFilesystemProvider:
		fsConfig.HTTPConfig.Username = u.replacePlaceholder(fsConfig.HTTPConfig.Username, replacer)
	}
	return fsConfig
}

func (u *User) mergeCryptFsConfig(group *Group) {
	if group.UserSettings.FsConfig.Provider == sdk.CryptedFilesystemProvider {
		if u.FsConfig.CryptConfig.ReadBufferSize == 0 {
			u.FsConfig.CryptConfig.ReadBufferSize = group.UserSettings.FsConfig.CryptConfig.ReadBufferSize
		}
		if u.FsConfig.CryptConfig.WriteBufferSize == 0 {
			u.FsConfig.CryptConfig.WriteBufferSize = group.UserSettings.FsConfig.CryptConfig.WriteBufferSize
		}
	}
}

func (u *User) mergeWithPrimaryGroup(group *Group, replacer *strings.Replacer) {
	if group.UserSettings.HomeDir != "" {
		u.HomeDir = u.replacePlaceholder(group.UserSettings.HomeDir, replacer)
	}
	if group.UserSettings.FsConfig.Provider != 0 {
		u.FsConfig = u.replaceFsConfigPlaceholders(group.UserSettings.FsConfig, replacer)
		u.mergeCryptFsConfig(group)
	} else {
		if u.FsConfig.OSConfig.ReadBufferSize == 0 {
			u.FsConfig.OSConfig.ReadBufferSize = group.UserSettings.FsConfig.OSConfig.ReadBufferSize
		}
		if u.FsConfig.OSConfig.WriteBufferSize == 0 {
			u.FsConfig.OSConfig.WriteBufferSize = group.UserSettings.FsConfig.OSConfig.WriteBufferSize
		}
	}
	if u.MaxSessions == 0 {
		u.MaxSessions = group.UserSettings.MaxSessions
	}
	if u.QuotaSize == 0 {
		u.QuotaSize = group.UserSettings.QuotaSize
	}
	if u.QuotaFiles == 0 {
		u.QuotaFiles = group.UserSettings.QuotaFiles
	}
	if u.UploadBandwidth == 0 {
		u.UploadBandwidth = group.UserSettings.UploadBandwidth
	}
	if u.DownloadBandwidth == 0 {
		u.DownloadBandwidth = group.UserSettings.DownloadBandwidth
	}
	if !u.hasMainDataTransferLimits() {
		u.UploadDataTransfer = group.UserSettings.UploadDataTransfer
		u.DownloadDataTransfer = group.UserSettings.DownloadDataTransfer
		u.TotalDataTransfer = group.UserSettings.TotalDataTransfer
	}
	if u.ExpirationDate == 0 && group.UserSettings.ExpiresIn > 0 {
		u.ExpirationDate = u.CreatedAt + int64(group.UserSettings.ExpiresIn)*86400000
	}
	u.mergePrimaryGroupFilters(&group.UserSettings.Filters, replacer)
	u.mergeAdditiveProperties(group, sdk.GroupTypePrimary, replacer)
}

func (u *User) mergePrimaryGroupFilters(filters *sdk.BaseUserFilters, replacer *strings.Replacer) { //nolint:gocyclo
	if u.Filters.MaxUploadFileSize == 0 {
		u.Filters.MaxUploadFileSize = filters.MaxUploadFileSize
	}
	if !u.IsTLSVerificationEnabled() {
		u.Filters.TLSUsername = filters.TLSUsername
	}
	if !u.Filters.Hooks.CheckPasswordDisabled {
		u.Filters.Hooks.CheckPasswordDisabled = filters.Hooks.CheckPasswordDisabled
	}
	if !u.Filters.Hooks.PreLoginDisabled {
		u.Filters.Hooks.PreLoginDisabled = filters.Hooks.PreLoginDisabled
	}
	if !u.Filters.Hooks.ExternalAuthDisabled {
		u.Filters.Hooks.ExternalAuthDisabled = filters.Hooks.ExternalAuthDisabled
	}
	if !u.Filters.DisableFsChecks {
		u.Filters.DisableFsChecks = filters.DisableFsChecks
	}
	if !u.Filters.AllowAPIKeyAuth {
		u.Filters.AllowAPIKeyAuth = filters.AllowAPIKeyAuth
	}
	if !u.Filters.IsAnonymous {
		u.Filters.IsAnonymous = filters.IsAnonymous
	}
	if u.Filters.ExternalAuthCacheTime == 0 {
		u.Filters.ExternalAuthCacheTime = filters.ExternalAuthCacheTime
	}
	if u.Filters.FTPSecurity == 0 {
		u.Filters.FTPSecurity = filters.FTPSecurity
	}
	if u.Filters.StartDirectory == "" {
		u.Filters.StartDirectory = u.replacePlaceholder(filters.StartDirectory, replacer)
	}
	if u.Filters.DefaultSharesExpiration == 0 {
		u.Filters.DefaultSharesExpiration = filters.DefaultSharesExpiration
	}
	if u.Filters.MaxSharesExpiration == 0 {
		u.Filters.MaxSharesExpiration = filters.MaxSharesExpiration
	}
	if u.Filters.PasswordExpiration == 0 {
		u.Filters.PasswordExpiration = filters.PasswordExpiration
	}
	if u.Filters.PasswordStrength == 0 {
		u.Filters.PasswordStrength = filters.PasswordStrength
	}
}

func (u *User) mergeAdditiveProperties(group *Group, groupType int, replacer *strings.Replacer) {
	u.mergeVirtualFolders(group, groupType, replacer)
	u.mergePermissions(group, groupType, replacer)
	u.mergeFilePatterns(group, groupType, replacer)
	u.Filters.BandwidthLimits = append(u.Filters.BandwidthLimits, group.UserSettings.Filters.BandwidthLimits...)
	u.Filters.AllowedIP = append(u.Filters.AllowedIP, group.UserSettings.Filters.AllowedIP...)
	u.Filters.DeniedIP = append(u.Filters.DeniedIP, group.UserSettings.Filters.DeniedIP...)
	u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, group.UserSettings.Filters.DeniedLoginMethods...)
	u.Filters.DeniedProtocols = append(u.Filters.DeniedProtocols, group.UserSettings.Filters.DeniedProtocols...)
	u.Filters.WebClient = append(u.Filters.WebClient, group.UserSettings.Filters.WebClient...)
	u.Filters.TwoFactorAuthProtocols = append(u.Filters.TwoFactorAuthProtocols, group.UserSettings.Filters.TwoFactorAuthProtocols...)
	u.Filters.AccessTime = append(u.Filters.AccessTime, group.UserSettings.Filters.AccessTime...)
}

func (u *User) mergeVirtualFolders(group *Group, groupType int, replacer *strings.Replacer) {
	if len(group.VirtualFolders) > 0 {
		folderPaths := make(map[string]bool)
		for _, folder := range u.VirtualFolders {
			folderPaths[folder.VirtualPath] = true
		}
		for _, folder := range group.VirtualFolders {
			if folder.VirtualPath == "/" && groupType != sdk.GroupTypePrimary {
				continue
			}
			folder.VirtualPath = u.replacePlaceholder(folder.VirtualPath, replacer)
			if _, ok := folderPaths[folder.VirtualPath]; !ok {
				folder.MappedPath = u.replacePlaceholder(folder.MappedPath, replacer)
				folder.FsConfig = u.replaceFsConfigPlaceholders(folder.FsConfig, replacer)
				u.VirtualFolders = append(u.VirtualFolders, folder)
			}
		}
	}
}

func (u *User) mergePermissions(group *Group, groupType int, replacer *strings.Replacer) {
	if u.Permissions == nil {
		u.Permissions = make(map[string][]string)
	}
	for k, v := range group.UserSettings.Permissions {
		if k == "/" {
			if groupType == sdk.GroupTypePrimary {
				u.Permissions[k] = v
			} else {
				continue
			}
		}
		k = u.replacePlaceholder(k, replacer)
		if _, ok := u.Permissions[k]; !ok {
			u.Permissions[k] = v
		}
	}
}

func (u *User) mergeFilePatterns(group *Group, groupType int, replacer *strings.Replacer) {
	if len(group.UserSettings.Filters.FilePatterns) > 0 {
		patternPaths := make(map[string]bool)
		for _, pattern := range u.Filters.FilePatterns {
			patternPaths[pattern.Path] = true
		}
		for _, pattern := range group.UserSettings.Filters.FilePatterns {
			if pattern.Path == "/" && groupType != sdk.GroupTypePrimary {
				continue
			}
			pattern.Path = u.replacePlaceholder(pattern.Path, replacer)
			if _, ok := patternPaths[pattern.Path]; !ok {
				u.Filters.FilePatterns = append(u.Filters.FilePatterns, pattern)
			}
		}
	}
}

func (u *User) removeDuplicatesAfterGroupMerge() {
	u.Filters.AllowedIP = util.RemoveDuplicates(u.Filters.AllowedIP, false)
	u.Filters.DeniedIP = util.RemoveDuplicates(u.Filters.DeniedIP, false)
	u.Filters.DeniedLoginMethods = util.RemoveDuplicates(u.Filters.DeniedLoginMethods, false)
	u.Filters.DeniedProtocols = util.RemoveDuplicates(u.Filters.DeniedProtocols, false)
	u.Filters.WebClient = util.RemoveDuplicates(u.Filters.WebClient, false)
	u.Filters.TwoFactorAuthProtocols = util.RemoveDuplicates(u.Filters.TwoFactorAuthProtocols, false)
	u.SetEmptySecretsIfNil()
	u.groupSettingsApplied = true
}

func (u *User) hasRole(role string) bool {
	if role == "" {
		return true
	}
	return role == u.Role
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
	groups := make([]sdk.GroupMapping, 0, len(u.Groups))
	for _, g := range u.Groups {
		groups = append(groups, sdk.GroupMapping{
			Name: g.Name,
			Type: g.Type,
		})
	}
	permissions := make(map[string][]string)
	for k, v := range u.Permissions {
		perms := make([]string, len(v))
		copy(perms, v)
		permissions[k] = perms
	}
	filters := UserFilters{
		BaseUserFilters: copyBaseUserFilters(u.Filters.BaseUserFilters),
	}
	filters.RequirePasswordChange = u.Filters.RequirePasswordChange
	filters.TOTPConfig.Enabled = u.Filters.TOTPConfig.Enabled
	filters.TOTPConfig.ConfigName = u.Filters.TOTPConfig.ConfigName
	filters.TOTPConfig.Secret = u.Filters.TOTPConfig.Secret.Clone()
	filters.TOTPConfig.Protocols = make([]string, len(u.Filters.TOTPConfig.Protocols))
	copy(filters.TOTPConfig.Protocols, u.Filters.TOTPConfig.Protocols)
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

	return User{
		BaseUser: sdk.BaseUser{
			ID:                       u.ID,
			Username:                 u.Username,
			Email:                    u.Email,
			Password:                 u.Password,
			PublicKeys:               pubKeys,
			HasPassword:              u.HasPassword,
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
			FirstDownload:            u.FirstDownload,
			FirstUpload:              u.FirstUpload,
			LastPasswordChange:       u.LastPasswordChange,
			AdditionalInfo:           u.AdditionalInfo,
			Description:              u.Description,
			CreatedAt:                u.CreatedAt,
			UpdatedAt:                u.UpdatedAt,
			Role:                     u.Role,
		},
		Filters:              filters,
		VirtualFolders:       virtualFolders,
		Groups:               groups,
		FsConfig:             u.FsConfig.GetACopy(),
		groupSettingsApplied: u.groupSettingsApplied,
	}
}

// GetEncryptionAdditionalData returns the additional data to use for AEAD
func (u *User) GetEncryptionAdditionalData() string {
	return u.Username
}
