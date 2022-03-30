package common

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/pkg/sftp"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

// BaseConnection defines common fields for a connection using any supported protocol
type BaseConnection struct {
	// last activity for this connection.
	// Since this field is accessed atomically we put it as first element of the struct to achieve 64 bit alignment
	lastActivity int64
	// unique ID for a transfer.
	// This field is accessed atomically so we put it at the beginning of the struct to achieve 64 bit alignment
	transferID int64
	// Unique identifier for the connection
	ID string
	// user associated with this connection if any
	User dataprovider.User
	// start time for this connection
	startTime  time.Time
	protocol   string
	remoteAddr string
	localAddr  string
	sync.RWMutex
	activeTransfers []ActiveTransfer
}

// NewBaseConnection returns a new BaseConnection
func NewBaseConnection(id, protocol, localAddr, remoteAddr string, user dataprovider.User) *BaseConnection {
	connID := id
	if util.IsStringInSlice(protocol, supportedProtocols) {
		connID = fmt.Sprintf("%s_%s", protocol, id)
	}
	user.UploadBandwidth, user.DownloadBandwidth = user.GetBandwidthForIP(util.GetIPFromRemoteAddress(remoteAddr), connID)
	return &BaseConnection{
		ID:           connID,
		User:         user,
		startTime:    time.Now(),
		protocol:     protocol,
		localAddr:    localAddr,
		remoteAddr:   remoteAddr,
		lastActivity: time.Now().UnixNano(),
		transferID:   0,
	}
}

// Log outputs a log entry to the configured logger
func (c *BaseConnection) Log(level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, c.protocol, c.ID, format, v...)
}

// GetTransferID returns an unique transfer ID for this connection
func (c *BaseConnection) GetTransferID() int64 {
	return atomic.AddInt64(&c.transferID, 1)
}

// GetID returns the connection ID
func (c *BaseConnection) GetID() string {
	return c.ID
}

// GetUsername returns the authenticated username associated with this connection if any
func (c *BaseConnection) GetUsername() string {
	return c.User.Username
}

// GetProtocol returns the protocol for the connection
func (c *BaseConnection) GetProtocol() string {
	return c.protocol
}

// GetRemoteIP returns the remote ip address
func (c *BaseConnection) GetRemoteIP() string {
	return util.GetIPFromRemoteAddress(c.remoteAddr)
}

// SetProtocol sets the protocol for this connection
func (c *BaseConnection) SetProtocol(protocol string) {
	c.protocol = protocol
	if util.IsStringInSlice(c.protocol, supportedProtocols) {
		c.ID = fmt.Sprintf("%v_%v", c.protocol, c.ID)
	}
}

// GetConnectionTime returns the initial connection time
func (c *BaseConnection) GetConnectionTime() time.Time {
	return c.startTime
}

// UpdateLastActivity updates last activity for this connection
func (c *BaseConnection) UpdateLastActivity() {
	atomic.StoreInt64(&c.lastActivity, time.Now().UnixNano())
}

// GetLastActivity returns the last connection activity
func (c *BaseConnection) GetLastActivity() time.Time {
	return time.Unix(0, atomic.LoadInt64(&c.lastActivity))
}

// CloseFS closes the underlying fs
func (c *BaseConnection) CloseFS() error {
	return c.User.CloseFs()
}

// AddTransfer associates a new transfer to this connection
func (c *BaseConnection) AddTransfer(t ActiveTransfer) {
	c.Lock()
	defer c.Unlock()

	c.activeTransfers = append(c.activeTransfers, t)
	c.Log(logger.LevelDebug, "transfer added, id: %v, active transfers: %v", t.GetID(), len(c.activeTransfers))
	if t.HasSizeLimit() {
		folderName := ""
		if t.GetType() == TransferUpload {
			vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(t.GetVirtualPath()))
			if err == nil {
				if !vfolder.IsIncludedInUserQuota() {
					folderName = vfolder.Name
				}
			}
		}
		go transfersChecker.AddTransfer(dataprovider.ActiveTransfer{
			ID:            t.GetID(),
			Type:          t.GetType(),
			ConnID:        c.ID,
			Username:      c.GetUsername(),
			FolderName:    folderName,
			IP:            c.GetRemoteIP(),
			TruncatedSize: t.GetTruncatedSize(),
			CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
			UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		})
	}
}

// RemoveTransfer removes the specified transfer from the active ones
func (c *BaseConnection) RemoveTransfer(t ActiveTransfer) {
	c.Lock()
	defer c.Unlock()

	if t.HasSizeLimit() {
		go transfersChecker.RemoveTransfer(t.GetID(), c.ID)
	}

	for idx, transfer := range c.activeTransfers {
		if transfer.GetID() == t.GetID() {
			lastIdx := len(c.activeTransfers) - 1
			c.activeTransfers[idx] = c.activeTransfers[lastIdx]
			c.activeTransfers[lastIdx] = nil
			c.activeTransfers = c.activeTransfers[:lastIdx]
			c.Log(logger.LevelDebug, "transfer removed, id: %v active transfers: %v", t.GetID(), len(c.activeTransfers))
			return
		}
	}
	c.Log(logger.LevelWarn, "transfer to remove with id %v not found!", t.GetID())
}

// SignalTransferClose makes the transfer fail on the next read/write with the
// specified error
func (c *BaseConnection) SignalTransferClose(transferID int64, err error) {
	c.RLock()
	defer c.RUnlock()

	for _, t := range c.activeTransfers {
		if t.GetID() == transferID {
			c.Log(logger.LevelInfo, "signal transfer close for transfer id %v", transferID)
			t.SignalClose(err)
		}
	}
}

// GetTransfers returns the active transfers
func (c *BaseConnection) GetTransfers() []ConnectionTransfer {
	c.RLock()
	defer c.RUnlock()

	transfers := make([]ConnectionTransfer, 0, len(c.activeTransfers))
	for _, t := range c.activeTransfers {
		var operationType string
		switch t.GetType() {
		case TransferDownload:
			operationType = operationDownload
		case TransferUpload:
			operationType = operationUpload
		}
		transfers = append(transfers, ConnectionTransfer{
			ID:            t.GetID(),
			OperationType: operationType,
			StartTime:     util.GetTimeAsMsSinceEpoch(t.GetStartTime()),
			Size:          t.GetSize(),
			VirtualPath:   t.GetVirtualPath(),
			HasSizeLimit:  t.HasSizeLimit(),
			ULSize:        t.GetUploadedSize(),
			DLSize:        t.GetDownloadedSize(),
		})
	}

	return transfers
}

// SignalTransfersAbort signals to the active transfers to exit as soon as possible
func (c *BaseConnection) SignalTransfersAbort() error {
	c.RLock()
	defer c.RUnlock()

	if len(c.activeTransfers) == 0 {
		return errors.New("no active transfer found")
	}

	for _, t := range c.activeTransfers {
		t.SignalClose(ErrTransferAborted)
	}
	return nil
}

func (c *BaseConnection) getRealFsPath(fsPath string) string {
	c.RLock()
	defer c.RUnlock()

	for _, t := range c.activeTransfers {
		if p := t.GetRealFsPath(fsPath); len(p) > 0 {
			return p
		}
	}
	return fsPath
}

func (c *BaseConnection) setTimes(fsPath string, atime time.Time, mtime time.Time) bool {
	c.RLock()
	defer c.RUnlock()

	for _, t := range c.activeTransfers {
		if t.SetTimes(fsPath, atime, mtime) {
			return true
		}
	}
	return false
}

func (c *BaseConnection) truncateOpenHandle(fsPath string, size int64) (int64, error) {
	c.RLock()
	defer c.RUnlock()

	for _, t := range c.activeTransfers {
		initialSize, err := t.Truncate(fsPath, size)
		if err != errTransferMismatch {
			return initialSize, err
		}
	}

	return 0, errNoTransfer
}

// ListDir reads the directory matching virtualPath and returns a list of directory entries
func (c *BaseConnection) ListDir(virtualPath string) ([]os.FileInfo, error) {
	if !c.User.HasPerm(dataprovider.PermListItems, virtualPath) {
		return nil, c.GetPermissionDeniedError()
	}
	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return nil, err
	}
	files, err := fs.ReadDir(fsPath)
	if err != nil {
		c.Log(logger.LevelDebug, "error listing directory: %+v", err)
		return nil, c.GetFsError(fs, err)
	}
	return c.User.FilterListDir(files, virtualPath), nil
}

// CheckParentDirs tries to create the specified directory and any missing parent dirs
func (c *BaseConnection) CheckParentDirs(virtualPath string) error {
	fs, err := c.User.GetFilesystemForPath(virtualPath, "")
	if err != nil {
		return err
	}
	if fs.HasVirtualFolders() {
		return nil
	}
	if _, err := c.DoStat(virtualPath, 0, false); !c.IsNotExistError(err) {
		return err
	}
	dirs := util.GetDirsForVirtualPath(virtualPath)
	for idx := len(dirs) - 1; idx >= 0; idx-- {
		fs, err = c.User.GetFilesystemForPath(dirs[idx], "")
		if err != nil {
			return err
		}
		if fs.HasVirtualFolders() {
			continue
		}
		if err = c.createDirIfMissing(dirs[idx]); err != nil {
			return fmt.Errorf("unable to check/create missing parent dir %#v for virtual path %#v: %w",
				dirs[idx], virtualPath, err)
		}
	}
	return nil
}

// CreateDir creates a new directory at the specified fsPath
func (c *BaseConnection) CreateDir(virtualPath string, checkFilePatterns bool) error {
	if !c.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(virtualPath)) {
		return c.GetPermissionDeniedError()
	}
	if checkFilePatterns {
		if ok, _ := c.User.IsFileAllowed(virtualPath); !ok {
			return c.GetPermissionDeniedError()
		}
	}
	if c.User.IsVirtualFolder(virtualPath) {
		c.Log(logger.LevelWarn, "mkdir not allowed %#v is a virtual folder", virtualPath)
		return c.GetPermissionDeniedError()
	}
	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return err
	}
	if err := fs.Mkdir(fsPath); err != nil {
		c.Log(logger.LevelError, "error creating dir: %#v error: %+v", fsPath, err)
		return c.GetFsError(fs, err)
	}
	vfs.SetPathPermissions(fs, fsPath, c.User.GetUID(), c.User.GetGID())

	logger.CommandLog(mkdirLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1,
		c.localAddr, c.remoteAddr)
	ExecuteActionNotification(c, operationMkdir, fsPath, virtualPath, "", "", "", 0, nil)
	return nil
}

// IsRemoveFileAllowed returns an error if removing this file is not allowed
func (c *BaseConnection) IsRemoveFileAllowed(virtualPath string) error {
	if !c.User.HasAnyPerm([]string{dataprovider.PermDeleteFiles, dataprovider.PermDelete}, path.Dir(virtualPath)) {
		return c.GetPermissionDeniedError()
	}
	if ok, policy := c.User.IsFileAllowed(virtualPath); !ok {
		c.Log(logger.LevelDebug, "removing file %#v is not allowed", virtualPath)
		return c.GetErrorForDeniedFile(policy)
	}
	return nil
}

// RemoveFile removes a file at the specified fsPath
func (c *BaseConnection) RemoveFile(fs vfs.Fs, fsPath, virtualPath string, info os.FileInfo) error {
	if err := c.IsRemoveFileAllowed(virtualPath); err != nil {
		return err
	}

	size := info.Size()
	actionErr := ExecutePreAction(c, operationPreDelete, fsPath, virtualPath, size, 0)
	if actionErr == nil {
		c.Log(logger.LevelDebug, "remove for path %#v handled by pre-delete action", fsPath)
	} else {
		if err := fs.Remove(fsPath, false); err != nil {
			c.Log(logger.LevelError, "failed to remove file/symlink %#v: %+v", fsPath, err)
			return c.GetFsError(fs, err)
		}
	}

	logger.CommandLog(removeLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1,
		c.localAddr, c.remoteAddr)
	if info.Mode()&os.ModeSymlink == 0 {
		vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(virtualPath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(&vfolder.BaseVirtualFolder, -1, -size, false) //nolint:errcheck
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(&c.User, -1, -size, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(&c.User, -1, -size, false) //nolint:errcheck
		}
	}
	if actionErr != nil {
		ExecuteActionNotification(c, operationDelete, fsPath, virtualPath, "", "", "", size, nil)
	}
	return nil
}

// IsRemoveDirAllowed returns an error if removing this directory is not allowed
func (c *BaseConnection) IsRemoveDirAllowed(fs vfs.Fs, fsPath, virtualPath string) error {
	if fs.GetRelativePath(fsPath) == "/" {
		c.Log(logger.LevelWarn, "removing root dir is not allowed")
		return c.GetPermissionDeniedError()
	}
	if c.User.IsVirtualFolder(virtualPath) {
		c.Log(logger.LevelWarn, "removing a virtual folder is not allowed: %#v", virtualPath)
		return c.GetPermissionDeniedError()
	}
	if c.User.HasVirtualFoldersInside(virtualPath) {
		c.Log(logger.LevelWarn, "removing a directory with a virtual folder inside is not allowed: %#v", virtualPath)
		return c.GetOpUnsupportedError()
	}
	if c.User.IsMappedPath(fsPath) {
		c.Log(logger.LevelWarn, "removing a directory mapped as virtual folder is not allowed: %#v", fsPath)
		return c.GetPermissionDeniedError()
	}
	if !c.User.HasAnyPerm([]string{dataprovider.PermDeleteDirs, dataprovider.PermDelete}, path.Dir(virtualPath)) {
		return c.GetPermissionDeniedError()
	}
	if ok, policy := c.User.IsFileAllowed(virtualPath); !ok {
		c.Log(logger.LevelDebug, "removing directory %#v is not allowed", virtualPath)
		return c.GetErrorForDeniedFile(policy)
	}
	return nil
}

// RemoveDir removes a directory at the specified fsPath
func (c *BaseConnection) RemoveDir(virtualPath string) error {
	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return err
	}
	if err := c.IsRemoveDirAllowed(fs, fsPath, virtualPath); err != nil {
		return err
	}

	var fi os.FileInfo
	if fi, err = fs.Lstat(fsPath); err != nil {
		// see #149
		if fs.IsNotExist(err) && fs.HasVirtualFolders() {
			return nil
		}
		c.Log(logger.LevelError, "failed to remove a dir %#v: stat error: %+v", fsPath, err)
		return c.GetFsError(fs, err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		c.Log(logger.LevelError, "cannot remove %#v is not a directory", fsPath)
		return c.GetGenericError(nil)
	}

	if err := fs.Remove(fsPath, true); err != nil {
		c.Log(logger.LevelError, "failed to remove directory %#v: %+v", fsPath, err)
		return c.GetFsError(fs, err)
	}

	logger.CommandLog(rmdirLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1,
		c.localAddr, c.remoteAddr)
	ExecuteActionNotification(c, operationRmdir, fsPath, virtualPath, "", "", "", 0, nil)
	return nil
}

// Rename renames (moves) virtualSourcePath to virtualTargetPath
func (c *BaseConnection) Rename(virtualSourcePath, virtualTargetPath string) error {
	if virtualSourcePath == virtualTargetPath {
		return fmt.Errorf("the rename source and target cannot be the same: %w", c.GetOpUnsupportedError())
	}
	fsSrc, fsSourcePath, err := c.GetFsAndResolvedPath(virtualSourcePath)
	if err != nil {
		return err
	}
	fsDst, fsTargetPath, err := c.GetFsAndResolvedPath(virtualTargetPath)
	if err != nil {
		return err
	}
	srcInfo, err := fsSrc.Lstat(fsSourcePath)
	if err != nil {
		return c.GetFsError(fsSrc, err)
	}
	if !c.isRenamePermitted(fsSrc, fsDst, fsSourcePath, fsTargetPath, virtualSourcePath, virtualTargetPath, srcInfo) {
		return c.GetPermissionDeniedError()
	}
	initialSize := int64(-1)
	if dstInfo, err := fsDst.Lstat(fsTargetPath); err == nil {
		if dstInfo.IsDir() {
			c.Log(logger.LevelWarn, "attempted to rename %#v overwriting an existing directory %#v",
				fsSourcePath, fsTargetPath)
			return c.GetOpUnsupportedError()
		}
		// we are overwriting an existing file/symlink
		if dstInfo.Mode().IsRegular() {
			initialSize = dstInfo.Size()
		}
		if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(virtualTargetPath)) {
			c.Log(logger.LevelDebug, "renaming %#v -> %#v is not allowed. Target exists but the user %#v"+
				"has no overwrite permission", virtualSourcePath, virtualTargetPath, c.User.Username)
			return c.GetPermissionDeniedError()
		}
	}
	if srcInfo.IsDir() {
		if c.User.HasVirtualFoldersInside(virtualSourcePath) {
			c.Log(logger.LevelDebug, "renaming the folder %#v is not supported: it has virtual folders inside it",
				virtualSourcePath)
			return c.GetOpUnsupportedError()
		}
		if err = c.checkRecursiveRenameDirPermissions(fsSrc, fsDst, fsSourcePath, fsTargetPath); err != nil {
			c.Log(logger.LevelDebug, "error checking recursive permissions before renaming %#v: %+v", fsSourcePath, err)
			return err
		}
	}
	if !c.hasSpaceForRename(fsSrc, virtualSourcePath, virtualTargetPath, initialSize, fsSourcePath) {
		c.Log(logger.LevelInfo, "denying cross rename due to space limit")
		return c.GetGenericError(ErrQuotaExceeded)
	}
	if err := fsSrc.Rename(fsSourcePath, fsTargetPath); err != nil {
		c.Log(logger.LevelError, "failed to rename %#v -> %#v: %+v", fsSourcePath, fsTargetPath, err)
		return c.GetFsError(fsSrc, err)
	}
	vfs.SetPathPermissions(fsDst, fsTargetPath, c.User.GetUID(), c.User.GetGID())
	c.updateQuotaAfterRename(fsDst, virtualSourcePath, virtualTargetPath, fsTargetPath, initialSize) //nolint:errcheck
	logger.CommandLog(renameLogSender, fsSourcePath, fsTargetPath, c.User.Username, "", c.ID, c.protocol, -1, -1,
		"", "", "", -1, c.localAddr, c.remoteAddr)
	ExecuteActionNotification(c, operationRename, fsSourcePath, virtualSourcePath, fsTargetPath, virtualTargetPath,
		"", 0, nil)

	return nil
}

// CreateSymlink creates fsTargetPath as a symbolic link to fsSourcePath
func (c *BaseConnection) CreateSymlink(virtualSourcePath, virtualTargetPath string) error {
	if c.isCrossFoldersRequest(virtualSourcePath, virtualTargetPath) {
		c.Log(logger.LevelWarn, "cross folder symlink is not supported, src: %v dst: %v", virtualSourcePath, virtualTargetPath)
		return c.GetOpUnsupportedError()
	}
	// we cannot have a cross folder request here so only one fs is enough
	fs, fsSourcePath, err := c.GetFsAndResolvedPath(virtualSourcePath)
	if err != nil {
		return err
	}
	fsTargetPath, err := fs.ResolvePath(virtualTargetPath)
	if err != nil {
		return c.GetFsError(fs, err)
	}
	if fs.GetRelativePath(fsSourcePath) == "/" {
		c.Log(logger.LevelError, "symlinking root dir is not allowed")
		return c.GetPermissionDeniedError()
	}
	if fs.GetRelativePath(fsTargetPath) == "/" {
		c.Log(logger.LevelError, "symlinking to root dir is not allowed")
		return c.GetPermissionDeniedError()
	}
	if !c.User.HasPerm(dataprovider.PermCreateSymlinks, path.Dir(virtualTargetPath)) {
		return c.GetPermissionDeniedError()
	}
	ok, policy := c.User.IsFileAllowed(virtualSourcePath)
	if !ok && policy == sdk.DenyPolicyHide {
		c.Log(logger.LevelError, "symlink source path %#v is not allowed", virtualSourcePath)
		return c.GetNotExistError()
	}
	if ok, _ = c.User.IsFileAllowed(virtualTargetPath); !ok {
		c.Log(logger.LevelError, "symlink target path %#v is not allowed", virtualTargetPath)
		return c.GetPermissionDeniedError()
	}
	if err := fs.Symlink(fsSourcePath, fsTargetPath); err != nil {
		c.Log(logger.LevelError, "failed to create symlink %#v -> %#v: %+v", fsSourcePath, fsTargetPath, err)
		return c.GetFsError(fs, err)
	}
	logger.CommandLog(symlinkLogSender, fsSourcePath, fsTargetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "",
		"", "", -1, c.localAddr, c.remoteAddr)
	return nil
}

func (c *BaseConnection) getPathForSetStatPerms(fs vfs.Fs, fsPath, virtualPath string) string {
	pathForPerms := virtualPath
	if fi, err := fs.Lstat(fsPath); err == nil {
		if fi.IsDir() {
			pathForPerms = path.Dir(virtualPath)
		}
	}
	return pathForPerms
}

// DoStat execute a Stat if mode = 0, Lstat if mode = 1
func (c *BaseConnection) DoStat(virtualPath string, mode int, checkFilePatterns bool) (os.FileInfo, error) {
	// for some vfs we don't create intermediary folders so we cannot simply check
	// if virtualPath is a virtual folder
	vfolders := c.User.GetVirtualFoldersInPath(path.Dir(virtualPath))
	if _, ok := vfolders[virtualPath]; ok {
		return vfs.NewFileInfo(virtualPath, true, 0, time.Now(), false), nil
	}
	if checkFilePatterns {
		ok, policy := c.User.IsFileAllowed(virtualPath)
		if !ok && policy == sdk.DenyPolicyHide {
			return nil, c.GetNotExistError()
		}
	}

	var info os.FileInfo

	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return info, err
	}

	if mode == 1 {
		info, err = fs.Lstat(c.getRealFsPath(fsPath))
	} else {
		info, err = fs.Stat(c.getRealFsPath(fsPath))
	}
	if err != nil {
		c.Log(logger.LevelError, "stat error for path %#v: %+v", virtualPath, err)
		return info, c.GetFsError(fs, err)
	}
	if vfs.IsCryptOsFs(fs) {
		info = fs.(*vfs.CryptFs).ConvertFileInfo(info)
	}
	return info, nil
}

func (c *BaseConnection) createDirIfMissing(name string) error {
	_, err := c.DoStat(name, 0, false)
	if c.IsNotExistError(err) {
		return c.CreateDir(name, false)
	}
	return err
}

func (c *BaseConnection) ignoreSetStat(fs vfs.Fs) bool {
	if Config.SetstatMode == 1 {
		return true
	}
	if Config.SetstatMode == 2 && !vfs.IsLocalOrSFTPFs(fs) && !vfs.IsCryptOsFs(fs) {
		return true
	}
	return false
}

func (c *BaseConnection) handleChmod(fs vfs.Fs, fsPath, pathForPerms string, attributes *StatAttributes) error {
	if !c.User.HasPerm(dataprovider.PermChmod, pathForPerms) {
		return c.GetPermissionDeniedError()
	}
	if c.ignoreSetStat(fs) {
		return nil
	}
	if err := fs.Chmod(c.getRealFsPath(fsPath), attributes.Mode); err != nil {
		c.Log(logger.LevelError, "failed to chmod path %#v, mode: %v, err: %+v", fsPath, attributes.Mode.String(), err)
		return c.GetFsError(fs, err)
	}
	logger.CommandLog(chmodLogSender, fsPath, "", c.User.Username, attributes.Mode.String(), c.ID, c.protocol,
		-1, -1, "", "", "", -1, c.localAddr, c.remoteAddr)
	return nil
}

func (c *BaseConnection) handleChown(fs vfs.Fs, fsPath, pathForPerms string, attributes *StatAttributes) error {
	if !c.User.HasPerm(dataprovider.PermChown, pathForPerms) {
		return c.GetPermissionDeniedError()
	}
	if c.ignoreSetStat(fs) {
		return nil
	}
	if err := fs.Chown(c.getRealFsPath(fsPath), attributes.UID, attributes.GID); err != nil {
		c.Log(logger.LevelError, "failed to chown path %#v, uid: %v, gid: %v, err: %+v", fsPath, attributes.UID,
			attributes.GID, err)
		return c.GetFsError(fs, err)
	}
	logger.CommandLog(chownLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, attributes.UID, attributes.GID,
		"", "", "", -1, c.localAddr, c.remoteAddr)
	return nil
}

func (c *BaseConnection) handleChtimes(fs vfs.Fs, fsPath, pathForPerms string, attributes *StatAttributes) error {
	if !c.User.HasPerm(dataprovider.PermChtimes, pathForPerms) {
		return c.GetPermissionDeniedError()
	}
	if Config.SetstatMode == 1 {
		return nil
	}
	isUploading := c.setTimes(fsPath, attributes.Atime, attributes.Mtime)
	if err := fs.Chtimes(c.getRealFsPath(fsPath), attributes.Atime, attributes.Mtime, isUploading); err != nil {
		c.setTimes(fsPath, time.Time{}, time.Time{})
		if errors.Is(err, vfs.ErrVfsUnsupported) && Config.SetstatMode == 2 {
			return nil
		}
		c.Log(logger.LevelError, "failed to chtimes for path %#v, access time: %v, modification time: %v, err: %+v",
			fsPath, attributes.Atime, attributes.Mtime, err)
		return c.GetFsError(fs, err)
	}
	accessTimeString := attributes.Atime.Format(chtimesFormat)
	modificationTimeString := attributes.Mtime.Format(chtimesFormat)
	logger.CommandLog(chtimesLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1,
		accessTimeString, modificationTimeString, "", -1, c.localAddr, c.remoteAddr)
	return nil
}

// SetStat set StatAttributes for the specified fsPath
func (c *BaseConnection) SetStat(virtualPath string, attributes *StatAttributes) error {
	if ok, policy := c.User.IsFileAllowed(virtualPath); !ok {
		return c.GetErrorForDeniedFile(policy)
	}
	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return err
	}
	pathForPerms := c.getPathForSetStatPerms(fs, fsPath, virtualPath)

	if attributes.Flags&StatAttrTimes != 0 {
		if err = c.handleChtimes(fs, fsPath, pathForPerms, attributes); err != nil {
			return err
		}
	}

	if attributes.Flags&StatAttrPerms != 0 {
		if err = c.handleChmod(fs, fsPath, pathForPerms, attributes); err != nil {
			return err
		}
	}

	if attributes.Flags&StatAttrUIDGID != 0 {
		if err = c.handleChown(fs, fsPath, pathForPerms, attributes); err != nil {
			return err
		}
	}

	if attributes.Flags&StatAttrSize != 0 {
		if !c.User.HasPerm(dataprovider.PermOverwrite, pathForPerms) {
			return c.GetPermissionDeniedError()
		}

		if err = c.truncateFile(fs, fsPath, virtualPath, attributes.Size); err != nil {
			c.Log(logger.LevelError, "failed to truncate path %#v, size: %v, err: %+v", fsPath, attributes.Size, err)
			return c.GetFsError(fs, err)
		}
		logger.CommandLog(truncateLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "",
			"", attributes.Size, c.localAddr, c.remoteAddr)
	}

	return nil
}

func (c *BaseConnection) truncateFile(fs vfs.Fs, fsPath, virtualPath string, size int64) error {
	// check first if we have an open transfer for the given path and try to truncate the file already opened
	// if we found no transfer we truncate by path.
	var initialSize int64
	var err error
	initialSize, err = c.truncateOpenHandle(fsPath, size)
	if err == errNoTransfer {
		c.Log(logger.LevelDebug, "file path %#v not found in active transfers, execute trucate by path", fsPath)
		var info os.FileInfo
		info, err = fs.Stat(fsPath)
		if err != nil {
			return err
		}
		initialSize = info.Size()
		err = fs.Truncate(fsPath, size)
	}
	if err == nil && vfs.IsLocalOrSFTPFs(fs) {
		sizeDiff := initialSize - size
		vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(virtualPath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(&vfolder.BaseVirtualFolder, 0, -sizeDiff, false) //nolint:errcheck
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(&c.User, 0, -sizeDiff, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(&c.User, 0, -sizeDiff, false) //nolint:errcheck
		}
	}
	return err
}

func (c *BaseConnection) checkRecursiveRenameDirPermissions(fsSrc, fsDst vfs.Fs, sourcePath, targetPath string) error {
	err := fsSrc.Walk(sourcePath, func(walkedPath string, info os.FileInfo, err error) error {
		if err != nil {
			return c.GetFsError(fsSrc, err)
		}
		dstPath := strings.Replace(walkedPath, sourcePath, targetPath, 1)
		virtualSrcPath := fsSrc.GetRelativePath(walkedPath)
		virtualDstPath := fsDst.GetRelativePath(dstPath)
		// walk scans the directory tree in order, checking the parent directory permissions we are sure that all contents
		// inside the parent path was checked. If the current dir has no subdirs with defined permissions inside it
		// and it has all the possible permissions we can stop scanning
		if !c.User.HasPermissionsInside(path.Dir(virtualSrcPath)) && !c.User.HasPermissionsInside(path.Dir(virtualDstPath)) {
			if c.User.HasPermsRenameAll(path.Dir(virtualSrcPath)) &&
				c.User.HasPermsRenameAll(path.Dir(virtualDstPath)) {
				return ErrSkipPermissionsCheck
			}
		}
		if !c.isRenamePermitted(fsSrc, fsDst, walkedPath, dstPath, virtualSrcPath, virtualDstPath, info) {
			c.Log(logger.LevelInfo, "rename %#v -> %#v is not allowed, virtual destination path: %#v",
				walkedPath, dstPath, virtualDstPath)
			return c.GetPermissionDeniedError()
		}
		return nil
	})
	if err == ErrSkipPermissionsCheck {
		err = nil
	}
	return err
}

func (c *BaseConnection) hasRenamePerms(virtualSourcePath, virtualTargetPath string, fi os.FileInfo) bool {
	if c.User.HasPermsRenameAll(path.Dir(virtualSourcePath)) &&
		c.User.HasPermsRenameAll(path.Dir(virtualTargetPath)) {
		return true
	}
	if fi == nil {
		// we don't know if this is a file or a directory and we don't have all the rename perms, return false
		return false
	}
	if fi.IsDir() {
		perms := []string{
			dataprovider.PermRenameDirs,
			dataprovider.PermRename,
		}
		return c.User.HasAnyPerm(perms, path.Dir(virtualSourcePath)) &&
			c.User.HasAnyPerm(perms, path.Dir(virtualTargetPath))
	}
	// file or symlink
	perms := []string{
		dataprovider.PermRenameFiles,
		dataprovider.PermRename,
	}
	return c.User.HasAnyPerm(perms, path.Dir(virtualSourcePath)) &&
		c.User.HasAnyPerm(perms, path.Dir(virtualTargetPath))
}

func (c *BaseConnection) isRenamePermitted(fsSrc, fsDst vfs.Fs, fsSourcePath, fsTargetPath, virtualSourcePath, virtualTargetPath string, fi os.FileInfo) bool {
	if !c.isLocalOrSameFolderRename(virtualSourcePath, virtualTargetPath) {
		c.Log(logger.LevelInfo, "rename %#v->%#v is not allowed: the paths must be local or on the same virtual folder",
			virtualSourcePath, virtualTargetPath)
		return false
	}
	if c.User.IsMappedPath(fsSourcePath) && vfs.IsLocalOrCryptoFs(fsSrc) {
		c.Log(logger.LevelWarn, "renaming a directory mapped as virtual folder is not allowed: %#v", fsSourcePath)
		return false
	}
	if c.User.IsMappedPath(fsTargetPath) && vfs.IsLocalOrCryptoFs(fsDst) {
		c.Log(logger.LevelWarn, "renaming to a directory mapped as virtual folder is not allowed: %#v", fsTargetPath)
		return false
	}
	if fsSrc.GetRelativePath(fsSourcePath) == "/" {
		c.Log(logger.LevelWarn, "renaming root dir is not allowed")
		return false
	}
	if c.User.IsVirtualFolder(virtualSourcePath) || c.User.IsVirtualFolder(virtualTargetPath) {
		c.Log(logger.LevelWarn, "renaming a virtual folder is not allowed")
		return false
	}
	isSrcAllowed, _ := c.User.IsFileAllowed(virtualSourcePath)
	isDstAllowed, _ := c.User.IsFileAllowed(virtualTargetPath)
	if !isSrcAllowed || !isDstAllowed {
		c.Log(logger.LevelDebug, "renaming source: %#v to target: %#v not allowed", virtualSourcePath,
			virtualTargetPath)
		return false
	}
	return c.hasRenamePerms(virtualSourcePath, virtualTargetPath, fi)
}

func (c *BaseConnection) hasSpaceForRename(fs vfs.Fs, virtualSourcePath, virtualTargetPath string, initialSize int64,
	fsSourcePath string) bool {
	if dataprovider.GetQuotaTracking() == 0 {
		return true
	}
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(path.Dir(virtualSourcePath))
	dstFolder, errDst := c.User.GetVirtualFolderForPath(path.Dir(virtualTargetPath))
	if errSrc != nil && errDst != nil {
		// rename inside the user home dir
		return true
	}
	if errSrc == nil && errDst == nil {
		// rename between virtual folders
		if sourceFolder.Name == dstFolder.Name {
			// rename inside the same virtual folder
			return true
		}
	}
	if errSrc != nil && dstFolder.IsIncludedInUserQuota() {
		// rename between user root dir and a virtual folder included in user quota
		return true
	}
	quotaResult, _ := c.HasSpace(true, false, virtualTargetPath)
	return c.hasSpaceForCrossRename(fs, quotaResult, initialSize, fsSourcePath)
}

// hasSpaceForCrossRename checks the quota after a rename between different folders
func (c *BaseConnection) hasSpaceForCrossRename(fs vfs.Fs, quotaResult vfs.QuotaCheckResult, initialSize int64, sourcePath string) bool {
	if !quotaResult.HasSpace && initialSize == -1 {
		// we are over quota and this is not a file replace
		return false
	}
	fi, err := fs.Lstat(sourcePath)
	if err != nil {
		c.Log(logger.LevelError, "cross rename denied, stat error for path %#v: %v", sourcePath, err)
		return false
	}
	var sizeDiff int64
	var filesDiff int
	if fi.Mode().IsRegular() {
		sizeDiff = fi.Size()
		filesDiff = 1
		if initialSize != -1 {
			sizeDiff -= initialSize
			filesDiff = 0
		}
	} else if fi.IsDir() {
		filesDiff, sizeDiff, err = fs.GetDirSize(sourcePath)
		if err != nil {
			c.Log(logger.LevelError, "cross rename denied, error getting size for directory %#v: %v", sourcePath, err)
			return false
		}
	}
	if !quotaResult.HasSpace && initialSize != -1 {
		// we are over quota but we are overwriting an existing file so we check if the quota size after the rename is ok
		if quotaResult.QuotaSize == 0 {
			return true
		}
		c.Log(logger.LevelDebug, "cross rename overwrite, source %#v, used size %v, size to add %v",
			sourcePath, quotaResult.UsedSize, sizeDiff)
		quotaResult.UsedSize += sizeDiff
		return quotaResult.GetRemainingSize() >= 0
	}
	if quotaResult.QuotaFiles > 0 {
		remainingFiles := quotaResult.GetRemainingFiles()
		c.Log(logger.LevelDebug, "cross rename, source %#v remaining file %v to add %v", sourcePath,
			remainingFiles, filesDiff)
		if remainingFiles < filesDiff {
			return false
		}
	}
	if quotaResult.QuotaSize > 0 {
		remainingSize := quotaResult.GetRemainingSize()
		c.Log(logger.LevelDebug, "cross rename, source %#v remaining size %v to add %v", sourcePath,
			remainingSize, sizeDiff)
		if remainingSize < sizeDiff {
			return false
		}
	}
	return true
}

// GetMaxWriteSize returns the allowed size for an upload or an error
// if no enough size is available for a resume/append
func (c *BaseConnection) GetMaxWriteSize(quotaResult vfs.QuotaCheckResult, isResume bool, fileSize int64,
	isUploadResumeSupported bool,
) (int64, error) {
	maxWriteSize := quotaResult.GetRemainingSize()

	if isResume {
		if !isUploadResumeSupported {
			return 0, c.GetOpUnsupportedError()
		}
		if c.User.Filters.MaxUploadFileSize > 0 && c.User.Filters.MaxUploadFileSize <= fileSize {
			return 0, c.GetQuotaExceededError()
		}
		if c.User.Filters.MaxUploadFileSize > 0 {
			maxUploadSize := c.User.Filters.MaxUploadFileSize - fileSize
			if maxUploadSize < maxWriteSize || maxWriteSize == 0 {
				maxWriteSize = maxUploadSize
			}
		}
	} else {
		if maxWriteSize > 0 {
			maxWriteSize += fileSize
		}
		if c.User.Filters.MaxUploadFileSize > 0 && (c.User.Filters.MaxUploadFileSize < maxWriteSize || maxWriteSize == 0) {
			maxWriteSize = c.User.Filters.MaxUploadFileSize
		}
	}

	return maxWriteSize, nil
}

// GetTransferQuota returns the data transfers quota
func (c *BaseConnection) GetTransferQuota() dataprovider.TransferQuota {
	result, _, _ := c.checkUserQuota()
	return result
}

func (c *BaseConnection) checkUserQuota() (dataprovider.TransferQuota, int, int64) {
	clientIP := c.GetRemoteIP()
	ul, dl, total := c.User.GetDataTransferLimits(clientIP)
	result := dataprovider.TransferQuota{
		ULSize:           ul,
		DLSize:           dl,
		TotalSize:        total,
		AllowedULSize:    0,
		AllowedDLSize:    0,
		AllowedTotalSize: 0,
	}
	if !c.User.HasTransferQuotaRestrictions() {
		return result, -1, -1
	}
	usedFiles, usedSize, usedULSize, usedDLSize, err := dataprovider.GetUsedQuota(c.User.Username)
	if err != nil {
		c.Log(logger.LevelError, "error getting used quota for %#v: %v", c.User.Username, err)
		result.AllowedTotalSize = -1
		return result, -1, -1
	}
	if result.TotalSize > 0 {
		result.AllowedTotalSize = result.TotalSize - (usedULSize + usedDLSize)
	}
	if result.ULSize > 0 {
		result.AllowedULSize = result.ULSize - usedULSize
	}
	if result.DLSize > 0 {
		result.AllowedDLSize = result.DLSize - usedDLSize
	}

	return result, usedFiles, usedSize
}

// HasSpace checks user's quota usage
func (c *BaseConnection) HasSpace(checkFiles, getUsage bool, requestPath string) (vfs.QuotaCheckResult,
	dataprovider.TransferQuota,
) {
	result := vfs.QuotaCheckResult{
		HasSpace:     true,
		AllowedSize:  0,
		AllowedFiles: 0,
		UsedSize:     0,
		UsedFiles:    0,
		QuotaSize:    0,
		QuotaFiles:   0,
	}
	if dataprovider.GetQuotaTracking() == 0 {
		return result, dataprovider.TransferQuota{}
	}
	transferQuota, usedFiles, usedSize := c.checkUserQuota()

	var err error
	var vfolder vfs.VirtualFolder
	vfolder, err = c.User.GetVirtualFolderForPath(path.Dir(requestPath))
	if err == nil && !vfolder.IsIncludedInUserQuota() {
		if vfolder.HasNoQuotaRestrictions(checkFiles) && !getUsage {
			return result, transferQuota
		}
		result.QuotaSize = vfolder.QuotaSize
		result.QuotaFiles = vfolder.QuotaFiles
		result.UsedFiles, result.UsedSize, err = dataprovider.GetUsedVirtualFolderQuota(vfolder.Name)
	} else {
		if c.User.HasNoQuotaRestrictions(checkFiles) && !getUsage {
			return result, transferQuota
		}
		result.QuotaSize = c.User.QuotaSize
		result.QuotaFiles = c.User.QuotaFiles
		if usedSize == -1 {
			result.UsedFiles, result.UsedSize, _, _, err = dataprovider.GetUsedQuota(c.User.Username)
		} else {
			err = nil
			result.UsedFiles = usedFiles
			result.UsedSize = usedSize
		}
	}
	if err != nil {
		c.Log(logger.LevelError, "error getting used quota for %#v request path %#v: %v", c.User.Username, requestPath, err)
		result.HasSpace = false
		return result, transferQuota
	}
	result.AllowedFiles = result.QuotaFiles - result.UsedFiles
	result.AllowedSize = result.QuotaSize - result.UsedSize
	if (checkFiles && result.QuotaFiles > 0 && result.UsedFiles >= result.QuotaFiles) ||
		(result.QuotaSize > 0 && result.UsedSize >= result.QuotaSize) {
		c.Log(logger.LevelDebug, "quota exceed for user %#v, request path %#v, num files: %v/%v, size: %v/%v check files: %v",
			c.User.Username, requestPath, result.UsedFiles, result.QuotaFiles, result.UsedSize, result.QuotaSize, checkFiles)
		result.HasSpace = false
		return result, transferQuota
	}
	return result, transferQuota
}

// returns true if this is a rename on the same fs or local virtual folders
func (c *BaseConnection) isLocalOrSameFolderRename(virtualSourcePath, virtualTargetPath string) bool {
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(virtualSourcePath)
	dstFolder, errDst := c.User.GetVirtualFolderForPath(virtualTargetPath)
	if errSrc != nil && errDst != nil {
		return true
	}
	if errSrc == nil && errDst == nil {
		if sourceFolder.Name == dstFolder.Name {
			return true
		}
		// we have different folders, only local fs is supported
		if sourceFolder.FsConfig.Provider == sdk.LocalFilesystemProvider &&
			dstFolder.FsConfig.Provider == sdk.LocalFilesystemProvider {
			return true
		}
		return false
	}
	if c.User.FsConfig.Provider != sdk.LocalFilesystemProvider {
		return false
	}
	if errSrc == nil {
		if sourceFolder.FsConfig.Provider == sdk.LocalFilesystemProvider {
			return true
		}
	}
	if errDst == nil {
		if dstFolder.FsConfig.Provider == sdk.LocalFilesystemProvider {
			return true
		}
	}
	return false
}

func (c *BaseConnection) isCrossFoldersRequest(virtualSourcePath, virtualTargetPath string) bool {
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(virtualSourcePath)
	dstFolder, errDst := c.User.GetVirtualFolderForPath(virtualTargetPath)
	if errSrc != nil && errDst != nil {
		return false
	}
	if errSrc == nil && errDst == nil {
		return sourceFolder.Name != dstFolder.Name
	}
	return true
}

func (c *BaseConnection) updateQuotaMoveBetweenVFolders(sourceFolder, dstFolder *vfs.VirtualFolder, initialSize,
	filesSize int64, numFiles int) {
	if sourceFolder.Name == dstFolder.Name {
		// both files are inside the same virtual folder
		if initialSize != -1 {
			dataprovider.UpdateVirtualFolderQuota(&dstFolder.BaseVirtualFolder, -numFiles, -initialSize, false) //nolint:errcheck
			if dstFolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(&c.User, -numFiles, -initialSize, false) //nolint:errcheck
			}
		}
		return
	}
	// files are inside different virtual folders
	dataprovider.UpdateVirtualFolderQuota(&sourceFolder.BaseVirtualFolder, -numFiles, -filesSize, false) //nolint:errcheck
	if sourceFolder.IsIncludedInUserQuota() {
		dataprovider.UpdateUserQuota(&c.User, -numFiles, -filesSize, false) //nolint:errcheck
	}
	if initialSize == -1 {
		dataprovider.UpdateVirtualFolderQuota(&dstFolder.BaseVirtualFolder, numFiles, filesSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(&c.User, numFiles, filesSize, false) //nolint:errcheck
		}
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateVirtualFolderQuota(&dstFolder.BaseVirtualFolder, 0, filesSize-initialSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(&c.User, 0, filesSize-initialSize, false) //nolint:errcheck
		}
	}
}

func (c *BaseConnection) updateQuotaMoveFromVFolder(sourceFolder *vfs.VirtualFolder, initialSize, filesSize int64, numFiles int) {
	// move between a virtual folder and the user home dir
	dataprovider.UpdateVirtualFolderQuota(&sourceFolder.BaseVirtualFolder, -numFiles, -filesSize, false) //nolint:errcheck
	if sourceFolder.IsIncludedInUserQuota() {
		dataprovider.UpdateUserQuota(&c.User, -numFiles, -filesSize, false) //nolint:errcheck
	}
	if initialSize == -1 {
		dataprovider.UpdateUserQuota(&c.User, numFiles, filesSize, false) //nolint:errcheck
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateUserQuota(&c.User, 0, filesSize-initialSize, false) //nolint:errcheck
	}
}

func (c *BaseConnection) updateQuotaMoveToVFolder(dstFolder *vfs.VirtualFolder, initialSize, filesSize int64, numFiles int) {
	// move between the user home dir and a virtual folder
	dataprovider.UpdateUserQuota(&c.User, -numFiles, -filesSize, false) //nolint:errcheck
	if initialSize == -1 {
		dataprovider.UpdateVirtualFolderQuota(&dstFolder.BaseVirtualFolder, numFiles, filesSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(&c.User, numFiles, filesSize, false) //nolint:errcheck
		}
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateVirtualFolderQuota(&dstFolder.BaseVirtualFolder, 0, filesSize-initialSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(&c.User, 0, filesSize-initialSize, false) //nolint:errcheck
		}
	}
}

func (c *BaseConnection) updateQuotaAfterRename(fs vfs.Fs, virtualSourcePath, virtualTargetPath, targetPath string, initialSize int64) error {
	if dataprovider.GetQuotaTracking() == 0 {
		return nil
	}
	// we don't allow to overwrite an existing directory so targetPath can be:
	// - a new file, a symlink is as a new file here
	// - a file overwriting an existing one
	// - a new directory
	// initialSize != -1 only when overwriting files
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(path.Dir(virtualSourcePath))
	dstFolder, errDst := c.User.GetVirtualFolderForPath(path.Dir(virtualTargetPath))
	if errSrc != nil && errDst != nil {
		// both files are contained inside the user home dir
		if initialSize != -1 {
			// we cannot have a directory here, we are overwriting an existing file
			// we need to subtract the size of the overwritten file from the user quota
			dataprovider.UpdateUserQuota(&c.User, -1, -initialSize, false) //nolint:errcheck
		}
		return nil
	}

	filesSize := int64(0)
	numFiles := 1
	if fi, err := fs.Stat(targetPath); err == nil {
		if fi.Mode().IsDir() {
			numFiles, filesSize, err = fs.GetDirSize(targetPath)
			if err != nil {
				c.Log(logger.LevelError, "failed to update quota after rename, error scanning moved folder %#v: %v",
					targetPath, err)
				return err
			}
		} else {
			filesSize = fi.Size()
		}
	} else {
		c.Log(logger.LevelError, "failed to update quota after rename, file %#v stat error: %+v", targetPath, err)
		return err
	}
	if errSrc == nil && errDst == nil {
		c.updateQuotaMoveBetweenVFolders(&sourceFolder, &dstFolder, initialSize, filesSize, numFiles)
	}
	if errSrc == nil && errDst != nil {
		c.updateQuotaMoveFromVFolder(&sourceFolder, initialSize, filesSize, numFiles)
	}
	if errSrc != nil && errDst == nil {
		c.updateQuotaMoveToVFolder(&dstFolder, initialSize, filesSize, numFiles)
	}
	return nil
}

// IsNotExistError returns true if the specified fs error is not exist for the connection protocol
func (c *BaseConnection) IsNotExistError(err error) bool {
	switch c.protocol {
	case ProtocolSFTP:
		return errors.Is(err, sftp.ErrSSHFxNoSuchFile)
	case ProtocolWebDAV, ProtocolFTP, ProtocolHTTP, ProtocolOIDC, ProtocolHTTPShare, ProtocolDataRetention:
		return errors.Is(err, os.ErrNotExist)
	default:
		return errors.Is(err, ErrNotExist)
	}
}

// GetErrorForDeniedFile return permission denied or not exist error based on the specified policy
func (c *BaseConnection) GetErrorForDeniedFile(policy int) error {
	switch policy {
	case sdk.DenyPolicyHide:
		return c.GetNotExistError()
	default:
		return c.GetPermissionDeniedError()
	}
}

// GetPermissionDeniedError returns an appropriate permission denied error for the connection protocol
func (c *BaseConnection) GetPermissionDeniedError() error {
	switch c.protocol {
	case ProtocolSFTP:
		return sftp.ErrSSHFxPermissionDenied
	case ProtocolWebDAV, ProtocolFTP, ProtocolHTTP, ProtocolOIDC, ProtocolHTTPShare, ProtocolDataRetention:
		return os.ErrPermission
	default:
		return ErrPermissionDenied
	}
}

// GetNotExistError returns an appropriate not exist error for the connection protocol
func (c *BaseConnection) GetNotExistError() error {
	switch c.protocol {
	case ProtocolSFTP:
		return sftp.ErrSSHFxNoSuchFile
	case ProtocolWebDAV, ProtocolFTP, ProtocolHTTP, ProtocolOIDC, ProtocolHTTPShare, ProtocolDataRetention:
		return os.ErrNotExist
	default:
		return ErrNotExist
	}
}

// GetOpUnsupportedError returns an appropriate operation not supported error for the connection protocol
func (c *BaseConnection) GetOpUnsupportedError() error {
	switch c.protocol {
	case ProtocolSFTP:
		return sftp.ErrSSHFxOpUnsupported
	default:
		return ErrOpUnsupported
	}
}

func getQuotaExceededError(protocol string) error {
	switch protocol {
	case ProtocolSFTP:
		return fmt.Errorf("%w: %v", sftp.ErrSSHFxFailure, ErrQuotaExceeded.Error())
	case ProtocolFTP:
		return ftpserver.ErrStorageExceeded
	default:
		return ErrQuotaExceeded
	}
}

func getReadQuotaExceededError(protocol string) error {
	switch protocol {
	case ProtocolSFTP:
		return fmt.Errorf("%w: %v", sftp.ErrSSHFxFailure, ErrReadQuotaExceeded.Error())
	default:
		return ErrReadQuotaExceeded
	}
}

// GetQuotaExceededError returns an appropriate storage limit exceeded error for the connection protocol
func (c *BaseConnection) GetQuotaExceededError() error {
	return getQuotaExceededError(c.protocol)
}

// GetReadQuotaExceededError returns an appropriate read quota limit exceeded error for the connection protocol
func (c *BaseConnection) GetReadQuotaExceededError() error {
	return getReadQuotaExceededError(c.protocol)
}

// IsQuotaExceededError returns true if the given error is a quota exceeded error
func (c *BaseConnection) IsQuotaExceededError(err error) bool {
	switch c.protocol {
	case ProtocolSFTP:
		if err == nil {
			return false
		}
		if errors.Is(err, ErrQuotaExceeded) {
			return true
		}
		return errors.Is(err, sftp.ErrSSHFxFailure) && strings.Contains(err.Error(), ErrQuotaExceeded.Error())
	case ProtocolFTP:
		return errors.Is(err, ftpserver.ErrStorageExceeded) || errors.Is(err, ErrQuotaExceeded)
	default:
		return errors.Is(err, ErrQuotaExceeded)
	}
}

// GetGenericError returns an appropriate generic error for the connection protocol
func (c *BaseConnection) GetGenericError(err error) error {
	switch c.protocol {
	case ProtocolSFTP:
		if err == vfs.ErrStorageSizeUnavailable {
			return fmt.Errorf("%w: %v", sftp.ErrSSHFxOpUnsupported, err.Error())
		}
		if err != nil {
			if e, ok := err.(*os.PathError); ok {
				return fmt.Errorf("%w: %v %v", sftp.ErrSSHFxFailure, e.Op, e.Err.Error())
			}
			return fmt.Errorf("%w: %v", sftp.ErrSSHFxFailure, err.Error())
		}
		return sftp.ErrSSHFxFailure
	default:
		if err == ErrPermissionDenied || err == ErrNotExist || err == ErrOpUnsupported ||
			err == ErrQuotaExceeded || err == vfs.ErrStorageSizeUnavailable {
			return err
		}
		return ErrGenericFailure
	}
}

// GetFsError converts a filesystem error to a protocol error
func (c *BaseConnection) GetFsError(fs vfs.Fs, err error) error {
	if fs.IsNotExist(err) {
		return c.GetNotExistError()
	} else if fs.IsPermission(err) {
		return c.GetPermissionDeniedError()
	} else if fs.IsNotSupported(err) {
		return c.GetOpUnsupportedError()
	} else if err != nil {
		return c.GetGenericError(err)
	}
	return nil
}

// GetFsAndResolvedPath returns the fs and the fs path matching virtualPath
func (c *BaseConnection) GetFsAndResolvedPath(virtualPath string) (vfs.Fs, string, error) {
	fs, err := c.User.GetFilesystemForPath(virtualPath, c.ID)
	if err != nil {
		if c.protocol == ProtocolWebDAV && strings.Contains(err.Error(), vfs.ErrSFTPLoop.Error()) {
			// if there is an SFTP loop we return a permission error, for WebDAV, so the problematic folder
			// will not be listed
			return nil, "", c.GetPermissionDeniedError()
		}
		return nil, "", err
	}

	fsPath, err := fs.ResolvePath(virtualPath)
	if err != nil {
		return nil, "", c.GetFsError(fs, err)
	}

	return fs, fsPath, nil
}
