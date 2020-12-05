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

	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

// BaseConnection defines common fields for a connection using any supported protocol
type BaseConnection struct {
	// Unique identifier for the connection
	ID string
	// user associated with this connection if any
	User dataprovider.User
	// start time for this connection
	startTime time.Time
	protocol  string
	Fs        vfs.Fs
	sync.RWMutex
	// last activity for this connection
	lastActivity    int64
	transferID      uint64
	activeTransfers []ActiveTransfer
}

// NewBaseConnection returns a new BaseConnection
func NewBaseConnection(ID, protocol string, user dataprovider.User, fs vfs.Fs) *BaseConnection {
	connID := ID
	if utils.IsStringInSlice(protocol, supportedProtocols) {
		connID = fmt.Sprintf("%v_%v", protocol, ID)
	}
	return &BaseConnection{
		ID:           connID,
		User:         user,
		startTime:    time.Now(),
		protocol:     protocol,
		Fs:           fs,
		lastActivity: time.Now().UnixNano(),
		transferID:   0,
	}
}

// Log outputs a log entry to the configured logger
func (c *BaseConnection) Log(level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, c.protocol, c.ID, format, v...)
}

// GetTransferID returns an unique transfer ID for this connection
func (c *BaseConnection) GetTransferID() uint64 {
	return atomic.AddUint64(&c.transferID, 1)
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

// SetProtocol sets the protocol for this connection
func (c *BaseConnection) SetProtocol(protocol string) {
	c.protocol = protocol
	if utils.IsStringInSlice(c.protocol, supportedProtocols) {
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

// AddTransfer associates a new transfer to this connection
func (c *BaseConnection) AddTransfer(t ActiveTransfer) {
	c.Lock()
	defer c.Unlock()

	c.activeTransfers = append(c.activeTransfers, t)
	c.Log(logger.LevelDebug, "transfer added, id: %v, active transfers: %v", t.GetID(), len(c.activeTransfers))
}

// RemoveTransfer removes the specified transfer from the active ones
func (c *BaseConnection) RemoveTransfer(t ActiveTransfer) {
	c.Lock()
	defer c.Unlock()

	indexToRemove := -1
	for i, v := range c.activeTransfers {
		if v.GetID() == t.GetID() {
			indexToRemove = i
			break
		}
	}
	if indexToRemove >= 0 {
		c.activeTransfers[indexToRemove] = c.activeTransfers[len(c.activeTransfers)-1]
		c.activeTransfers[len(c.activeTransfers)-1] = nil
		c.activeTransfers = c.activeTransfers[:len(c.activeTransfers)-1]
		c.Log(logger.LevelDebug, "transfer removed, id: %v active transfers: %v", t.GetID(), len(c.activeTransfers))
	} else {
		c.Log(logger.LevelWarn, "transfer to remove not found!")
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
			StartTime:     utils.GetTimeAsMsSinceEpoch(t.GetStartTime()),
			Size:          t.GetSize(),
			VirtualPath:   t.GetVirtualPath(),
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
		t.SignalClose()
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

// ListDir reads the directory named by fsPath and returns a list of directory entries
func (c *BaseConnection) ListDir(fsPath, virtualPath string) ([]os.FileInfo, error) {
	if !c.User.HasPerm(dataprovider.PermListItems, virtualPath) {
		return nil, c.GetPermissionDeniedError()
	}
	files, err := c.Fs.ReadDir(fsPath)
	if err != nil {
		c.Log(logger.LevelWarn, "error listing directory: %+v", err)
		return nil, c.GetFsError(err)
	}
	return c.User.AddVirtualDirs(files, virtualPath), nil
}

// CreateDir creates a new directory at the specified fsPath
func (c *BaseConnection) CreateDir(fsPath, virtualPath string) error {
	if !c.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(virtualPath)) {
		return c.GetPermissionDeniedError()
	}
	if c.User.IsVirtualFolder(virtualPath) {
		c.Log(logger.LevelWarn, "mkdir not allowed %#v is a virtual folder", virtualPath)
		return c.GetPermissionDeniedError()
	}
	if err := c.Fs.Mkdir(fsPath); err != nil {
		c.Log(logger.LevelWarn, "error creating dir: %#v error: %+v", fsPath, err)
		return c.GetFsError(err)
	}
	vfs.SetPathPermissions(c.Fs, fsPath, c.User.GetUID(), c.User.GetGID())

	logger.CommandLog(mkdirLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1)
	return nil
}

// IsRemoveFileAllowed returns an error if removing this file is not allowed
func (c *BaseConnection) IsRemoveFileAllowed(fsPath, virtualPath string) error {
	if !c.User.HasPerm(dataprovider.PermDelete, path.Dir(virtualPath)) {
		return c.GetPermissionDeniedError()
	}
	if !c.User.IsFileAllowed(virtualPath) {
		c.Log(logger.LevelDebug, "removing file %#v is not allowed", fsPath)
		return c.GetPermissionDeniedError()
	}
	return nil
}

// RemoveFile removes a file at the specified fsPath
func (c *BaseConnection) RemoveFile(fsPath, virtualPath string, info os.FileInfo) error {
	if err := c.IsRemoveFileAllowed(fsPath, virtualPath); err != nil {
		return err
	}
	size := info.Size()
	action := newActionNotification(&c.User, operationPreDelete, fsPath, "", "", c.protocol, size, nil)
	actionErr := actionHandler.Handle(action)
	if actionErr == nil {
		c.Log(logger.LevelDebug, "remove for path %#v handled by pre-delete action", fsPath)
	} else {
		if err := c.Fs.Remove(fsPath, false); err != nil {
			c.Log(logger.LevelWarn, "failed to remove a file/symlink %#v: %+v", fsPath, err)
			return c.GetFsError(err)
		}
	}

	logger.CommandLog(removeLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1)
	if info.Mode()&os.ModeSymlink == 0 {
		vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(virtualPath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(vfolder.BaseVirtualFolder, -1, -size, false) //nolint:errcheck
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(c.User, -1, -size, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(c.User, -1, -size, false) //nolint:errcheck
		}
	}
	if actionErr != nil {
		action := newActionNotification(&c.User, operationDelete, fsPath, "", "", c.protocol, size, nil)
		go actionHandler.Handle(action) // nolint:errcheck
	}
	return nil
}

// IsRemoveDirAllowed returns an error if removing this directory is not allowed
func (c *BaseConnection) IsRemoveDirAllowed(fsPath, virtualPath string) error {
	if c.Fs.GetRelativePath(fsPath) == "/" {
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
	if !c.User.HasPerm(dataprovider.PermDelete, path.Dir(virtualPath)) {
		return c.GetPermissionDeniedError()
	}
	return nil
}

// RemoveDir removes a directory at the specified fsPath
func (c *BaseConnection) RemoveDir(fsPath, virtualPath string) error {
	if err := c.IsRemoveDirAllowed(fsPath, virtualPath); err != nil {
		return err
	}

	var fi os.FileInfo
	var err error
	if fi, err = c.Fs.Lstat(fsPath); err != nil {
		// see #149
		if c.Fs.IsNotExist(err) && c.Fs.HasVirtualFolders() {
			return nil
		}
		c.Log(logger.LevelWarn, "failed to remove a dir %#v: stat error: %+v", fsPath, err)
		return c.GetFsError(err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		c.Log(logger.LevelDebug, "cannot remove %#v is not a directory", fsPath)
		return c.GetGenericError(nil)
	}

	if err := c.Fs.Remove(fsPath, true); err != nil {
		c.Log(logger.LevelWarn, "failed to remove directory %#v: %+v", fsPath, err)
		return c.GetFsError(err)
	}

	logger.CommandLog(rmdirLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1)
	return nil
}

// Rename renames (moves) fsSourcePath to fsTargetPath
func (c *BaseConnection) Rename(fsSourcePath, fsTargetPath, virtualSourcePath, virtualTargetPath string) error {
	if c.User.IsMappedPath(fsSourcePath) {
		c.Log(logger.LevelWarn, "renaming a directory mapped as virtual folder is not allowed: %#v", fsSourcePath)
		return c.GetPermissionDeniedError()
	}
	if c.User.IsMappedPath(fsTargetPath) {
		c.Log(logger.LevelWarn, "renaming to a directory mapped as virtual folder is not allowed: %#v", fsTargetPath)
		return c.GetPermissionDeniedError()
	}
	srcInfo, err := c.Fs.Lstat(fsSourcePath)
	if err != nil {
		return c.GetFsError(err)
	}
	if !c.isRenamePermitted(fsSourcePath, virtualSourcePath, virtualTargetPath, srcInfo) {
		return c.GetPermissionDeniedError()
	}
	initialSize := int64(-1)
	if dstInfo, err := c.Fs.Lstat(fsTargetPath); err == nil {
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
			c.Log(logger.LevelDebug, "renaming is not allowed, %#v -> %#v. Target exists but the user "+
				"has no overwrite permission", virtualSourcePath, virtualTargetPath)
			return c.GetPermissionDeniedError()
		}
	}
	if srcInfo.IsDir() {
		if c.User.HasVirtualFoldersInside(virtualSourcePath) {
			c.Log(logger.LevelDebug, "renaming the folder %#v is not supported: it has virtual folders inside it",
				virtualSourcePath)
			return c.GetOpUnsupportedError()
		}
		if err = c.checkRecursiveRenameDirPermissions(fsSourcePath, fsTargetPath); err != nil {
			c.Log(logger.LevelDebug, "error checking recursive permissions before renaming %#v: %+v", fsSourcePath, err)
			return c.GetFsError(err)
		}
	}
	if !c.hasSpaceForRename(virtualSourcePath, virtualTargetPath, initialSize, fsSourcePath) {
		c.Log(logger.LevelInfo, "denying cross rename due to space limit")
		return c.GetGenericError(ErrQuotaExceeded)
	}
	if err := c.Fs.Rename(fsSourcePath, fsTargetPath); err != nil {
		c.Log(logger.LevelWarn, "failed to rename %#v -> %#v: %+v", fsSourcePath, fsTargetPath, err)
		return c.GetFsError(err)
	}
	if dataprovider.GetQuotaTracking() > 0 {
		c.updateQuotaAfterRename(virtualSourcePath, virtualTargetPath, fsTargetPath, initialSize) //nolint:errcheck
	}
	logger.CommandLog(renameLogSender, fsSourcePath, fsTargetPath, c.User.Username, "", c.ID, c.protocol, -1, -1,
		"", "", "", -1)
	action := newActionNotification(&c.User, operationRename, fsSourcePath, fsTargetPath, "", c.protocol, 0, nil)
	// the returned error is used in test cases only, we already log the error inside action.execute
	go actionHandler.Handle(action) // nolint:errcheck

	return nil
}

// CreateSymlink creates fsTargetPath as a symbolic link to fsSourcePath
func (c *BaseConnection) CreateSymlink(fsSourcePath, fsTargetPath, virtualSourcePath, virtualTargetPath string) error {
	if c.Fs.GetRelativePath(fsSourcePath) == "/" {
		c.Log(logger.LevelWarn, "symlinking root dir is not allowed")
		return c.GetPermissionDeniedError()
	}
	if c.User.IsVirtualFolder(virtualTargetPath) {
		c.Log(logger.LevelWarn, "symlinking a virtual folder is not allowed")
		return c.GetPermissionDeniedError()
	}
	if !c.User.HasPerm(dataprovider.PermCreateSymlinks, path.Dir(virtualTargetPath)) {
		return c.GetPermissionDeniedError()
	}
	if c.isCrossFoldersRequest(virtualSourcePath, virtualTargetPath) {
		c.Log(logger.LevelWarn, "cross folder symlink is not supported, src: %v dst: %v", virtualSourcePath, virtualTargetPath)
		return c.GetOpUnsupportedError()
	}
	if c.User.IsMappedPath(fsSourcePath) {
		c.Log(logger.LevelWarn, "symlinking a directory mapped as virtual folder is not allowed: %#v", fsSourcePath)
		return c.GetPermissionDeniedError()
	}
	if c.User.IsMappedPath(fsTargetPath) {
		c.Log(logger.LevelWarn, "symlinking to a directory mapped as virtual folder is not allowed: %#v", fsTargetPath)
		return c.GetPermissionDeniedError()
	}
	if err := c.Fs.Symlink(fsSourcePath, fsTargetPath); err != nil {
		c.Log(logger.LevelWarn, "failed to create symlink %#v -> %#v: %+v", fsSourcePath, fsTargetPath, err)
		return c.GetFsError(err)
	}
	logger.CommandLog(symlinkLogSender, fsSourcePath, fsTargetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1)
	return nil
}

func (c *BaseConnection) getPathForSetStatPerms(fsPath, virtualPath string) string {
	pathForPerms := virtualPath
	if fi, err := c.Fs.Lstat(fsPath); err == nil {
		if fi.IsDir() {
			pathForPerms = path.Dir(virtualPath)
		}
	}
	return pathForPerms
}

// DoStat execute a Stat if mode = 0, Lstat if mode = 1
func (c *BaseConnection) DoStat(fsPath string, mode int) (os.FileInfo, error) {
	var info os.FileInfo
	var err error
	if mode == 1 {
		info, err = c.Fs.Lstat(c.getRealFsPath(fsPath))
	} else {
		info, err = c.Fs.Stat(c.getRealFsPath(fsPath))
	}
	if err == nil && vfs.IsCryptOsFs(c.Fs) {
		info = c.Fs.(*vfs.CryptFs).ConvertFileInfo(info)
	}
	return info, err
}

func (c *BaseConnection) ignoreSetStat() bool {
	if Config.SetstatMode == 1 {
		return true
	}
	if Config.SetstatMode == 2 && !vfs.IsLocalOsFs(c.Fs) {
		return true
	}
	return false
}

func (c *BaseConnection) handleChmod(fsPath, pathForPerms string, attributes *StatAttributes) error {
	if !c.User.HasPerm(dataprovider.PermChmod, pathForPerms) {
		return c.GetPermissionDeniedError()
	}
	if c.ignoreSetStat() {
		return nil
	}
	if err := c.Fs.Chmod(c.getRealFsPath(fsPath), attributes.Mode); err != nil {
		c.Log(logger.LevelWarn, "failed to chmod path %#v, mode: %v, err: %+v", fsPath, attributes.Mode.String(), err)
		return c.GetFsError(err)
	}
	logger.CommandLog(chmodLogSender, fsPath, "", c.User.Username, attributes.Mode.String(), c.ID, c.protocol,
		-1, -1, "", "", "", -1)
	return nil
}

func (c *BaseConnection) handleChown(fsPath, pathForPerms string, attributes *StatAttributes) error {
	if !c.User.HasPerm(dataprovider.PermChown, pathForPerms) {
		return c.GetPermissionDeniedError()
	}
	if c.ignoreSetStat() {
		return nil
	}
	if err := c.Fs.Chown(c.getRealFsPath(fsPath), attributes.UID, attributes.GID); err != nil {
		c.Log(logger.LevelWarn, "failed to chown path %#v, uid: %v, gid: %v, err: %+v", fsPath, attributes.UID,
			attributes.GID, err)
		return c.GetFsError(err)
	}
	logger.CommandLog(chownLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, attributes.UID, attributes.GID,
		"", "", "", -1)
	return nil
}

func (c *BaseConnection) handleChtimes(fsPath, pathForPerms string, attributes *StatAttributes) error {
	if !c.User.HasPerm(dataprovider.PermChtimes, pathForPerms) {
		return c.GetPermissionDeniedError()
	}
	if c.ignoreSetStat() {
		return nil
	}
	if err := c.Fs.Chtimes(c.getRealFsPath(fsPath), attributes.Atime, attributes.Mtime); err != nil {
		c.Log(logger.LevelWarn, "failed to chtimes for path %#v, access time: %v, modification time: %v, err: %+v",
			fsPath, attributes.Atime, attributes.Mtime, err)
		return c.GetFsError(err)
	}
	accessTimeString := attributes.Atime.Format(chtimesFormat)
	modificationTimeString := attributes.Mtime.Format(chtimesFormat)
	logger.CommandLog(chtimesLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1,
		accessTimeString, modificationTimeString, "", -1)
	return nil
}

// SetStat set StatAttributes for the specified fsPath
func (c *BaseConnection) SetStat(fsPath, virtualPath string, attributes *StatAttributes) error {
	pathForPerms := c.getPathForSetStatPerms(fsPath, virtualPath)

	if attributes.Flags&StatAttrPerms != 0 {
		return c.handleChmod(fsPath, pathForPerms, attributes)
	}

	if attributes.Flags&StatAttrUIDGID != 0 {
		return c.handleChown(fsPath, pathForPerms, attributes)
	}

	if attributes.Flags&StatAttrTimes != 0 {
		return c.handleChtimes(fsPath, pathForPerms, attributes)
	}

	if attributes.Flags&StatAttrSize != 0 {
		if !c.User.HasPerm(dataprovider.PermOverwrite, pathForPerms) {
			return c.GetPermissionDeniedError()
		}

		if err := c.truncateFile(fsPath, virtualPath, attributes.Size); err != nil {
			c.Log(logger.LevelWarn, "failed to truncate path %#v, size: %v, err: %+v", fsPath, attributes.Size, err)
			return c.GetFsError(err)
		}
		logger.CommandLog(truncateLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", attributes.Size)
	}

	return nil
}

func (c *BaseConnection) truncateFile(fsPath, virtualPath string, size int64) error {
	// check first if we have an open transfer for the given path and try to truncate the file already opened
	// if we found no transfer we truncate by path.
	var initialSize int64
	var err error
	initialSize, err = c.truncateOpenHandle(fsPath, size)
	if err == errNoTransfer {
		c.Log(logger.LevelDebug, "file path %#v not found in active transfers, execute trucate by path", fsPath)
		var info os.FileInfo
		info, err = c.Fs.Stat(fsPath)
		if err != nil {
			return err
		}
		initialSize = info.Size()
		err = c.Fs.Truncate(fsPath, size)
	}
	if err == nil && vfs.IsLocalOsFs(c.Fs) {
		sizeDiff := initialSize - size
		vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(virtualPath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(vfolder.BaseVirtualFolder, 0, -sizeDiff, false) //nolint:errcheck
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(c.User, 0, -sizeDiff, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(c.User, 0, -sizeDiff, false) //nolint:errcheck
		}
	}
	return err
}

func (c *BaseConnection) checkRecursiveRenameDirPermissions(sourcePath, targetPath string) error {
	dstPerms := []string{
		dataprovider.PermCreateDirs,
		dataprovider.PermUpload,
		dataprovider.PermCreateSymlinks,
	}

	err := c.Fs.Walk(sourcePath, func(walkedPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		dstPath := strings.Replace(walkedPath, sourcePath, targetPath, 1)
		virtualSrcPath := c.Fs.GetRelativePath(walkedPath)
		virtualDstPath := c.Fs.GetRelativePath(dstPath)
		// walk scans the directory tree in order, checking the parent directory permissions we are sure that all contents
		// inside the parent path was checked. If the current dir has no subdirs with defined permissions inside it
		// and it has all the possible permissions we can stop scanning
		if !c.User.HasPermissionsInside(path.Dir(virtualSrcPath)) && !c.User.HasPermissionsInside(path.Dir(virtualDstPath)) {
			if c.User.HasPerm(dataprovider.PermRename, path.Dir(virtualSrcPath)) &&
				c.User.HasPerm(dataprovider.PermRename, path.Dir(virtualDstPath)) {
				return ErrSkipPermissionsCheck
			}
			if c.User.HasPerm(dataprovider.PermDelete, path.Dir(virtualSrcPath)) &&
				c.User.HasPerms(dstPerms, path.Dir(virtualDstPath)) {
				return ErrSkipPermissionsCheck
			}
		}
		if !c.isRenamePermitted(walkedPath, virtualSrcPath, virtualDstPath, info) {
			c.Log(logger.LevelInfo, "rename %#v -> %#v is not allowed, virtual destination path: %#v",
				walkedPath, dstPath, virtualDstPath)
			return os.ErrPermission
		}
		return nil
	})
	if err == ErrSkipPermissionsCheck {
		err = nil
	}
	return err
}

func (c *BaseConnection) isRenamePermitted(fsSourcePath, virtualSourcePath, virtualTargetPath string, fi os.FileInfo) bool {
	if c.Fs.GetRelativePath(fsSourcePath) == "/" {
		c.Log(logger.LevelWarn, "renaming root dir is not allowed")
		return false
	}
	if c.User.IsVirtualFolder(virtualSourcePath) || c.User.IsVirtualFolder(virtualTargetPath) {
		c.Log(logger.LevelWarn, "renaming a virtual folder is not allowed")
		return false
	}
	if !c.User.IsFileAllowed(virtualSourcePath) || !c.User.IsFileAllowed(virtualTargetPath) {
		if fi != nil && fi.Mode().IsRegular() {
			c.Log(logger.LevelDebug, "renaming file is not allowed, source: %#v target: %#v",
				virtualSourcePath, virtualTargetPath)
			return false
		}
	}
	if c.User.HasPerm(dataprovider.PermRename, path.Dir(virtualSourcePath)) &&
		c.User.HasPerm(dataprovider.PermRename, path.Dir(virtualTargetPath)) {
		return true
	}
	if !c.User.HasPerm(dataprovider.PermDelete, path.Dir(virtualSourcePath)) {
		return false
	}
	if fi != nil {
		if fi.IsDir() {
			return c.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(virtualTargetPath))
		} else if fi.Mode()&os.ModeSymlink != 0 {
			return c.User.HasPerm(dataprovider.PermCreateSymlinks, path.Dir(virtualTargetPath))
		}
	}
	return c.User.HasPerm(dataprovider.PermUpload, path.Dir(virtualTargetPath))
}

func (c *BaseConnection) hasSpaceForRename(virtualSourcePath, virtualTargetPath string, initialSize int64,
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
		if sourceFolder.MappedPath == dstFolder.MappedPath {
			// rename inside the same virtual folder
			return true
		}
	}
	if errSrc != nil && dstFolder.IsIncludedInUserQuota() {
		// rename between user root dir and a virtual folder included in user quota
		return true
	}
	quotaResult := c.HasSpace(true, virtualTargetPath)
	return c.hasSpaceForCrossRename(quotaResult, initialSize, fsSourcePath)
}

// hasSpaceForCrossRename checks the quota after a rename between different folders
func (c *BaseConnection) hasSpaceForCrossRename(quotaResult vfs.QuotaCheckResult, initialSize int64, sourcePath string) bool {
	if !quotaResult.HasSpace && initialSize == -1 {
		// we are over quota and this is not a file replace
		return false
	}
	fi, err := c.Fs.Lstat(sourcePath)
	if err != nil {
		c.Log(logger.LevelWarn, "cross rename denied, stat error for path %#v: %v", sourcePath, err)
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
		filesDiff, sizeDiff, err = c.Fs.GetDirSize(sourcePath)
		if err != nil {
			c.Log(logger.LevelWarn, "cross rename denied, error getting size for directory %#v: %v", sourcePath, err)
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
func (c *BaseConnection) GetMaxWriteSize(quotaResult vfs.QuotaCheckResult, isResume bool, fileSize int64) (int64, error) {
	maxWriteSize := quotaResult.GetRemainingSize()

	if isResume {
		if !c.Fs.IsUploadResumeSupported() {
			return 0, c.GetOpUnsupportedError()
		}
		if c.User.Filters.MaxUploadFileSize > 0 && c.User.Filters.MaxUploadFileSize <= fileSize {
			return 0, ErrQuotaExceeded
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

// HasSpace checks user's quota usage
func (c *BaseConnection) HasSpace(checkFiles bool, requestPath string) vfs.QuotaCheckResult {
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
		return result
	}
	var err error
	var vfolder vfs.VirtualFolder
	vfolder, err = c.User.GetVirtualFolderForPath(path.Dir(requestPath))
	if err == nil && !vfolder.IsIncludedInUserQuota() {
		if vfolder.HasNoQuotaRestrictions(checkFiles) {
			return result
		}
		result.QuotaSize = vfolder.QuotaSize
		result.QuotaFiles = vfolder.QuotaFiles
		result.UsedFiles, result.UsedSize, err = dataprovider.GetUsedVirtualFolderQuota(vfolder.MappedPath)
	} else {
		if c.User.HasNoQuotaRestrictions(checkFiles) {
			return result
		}
		result.QuotaSize = c.User.QuotaSize
		result.QuotaFiles = c.User.QuotaFiles
		result.UsedFiles, result.UsedSize, err = dataprovider.GetUsedQuota(c.User.Username)
	}
	if err != nil {
		c.Log(logger.LevelWarn, "error getting used quota for %#v request path %#v: %v", c.User.Username, requestPath, err)
		result.HasSpace = false
		return result
	}
	result.AllowedFiles = result.QuotaFiles - result.UsedFiles
	result.AllowedSize = result.QuotaSize - result.UsedSize
	if (checkFiles && result.QuotaFiles > 0 && result.UsedFiles >= result.QuotaFiles) ||
		(result.QuotaSize > 0 && result.UsedSize >= result.QuotaSize) {
		c.Log(logger.LevelDebug, "quota exceed for user %#v, request path %#v, num files: %v/%v, size: %v/%v check files: %v",
			c.User.Username, requestPath, result.UsedFiles, result.QuotaFiles, result.UsedSize, result.QuotaSize, checkFiles)
		result.HasSpace = false
		return result
	}
	return result
}

func (c *BaseConnection) isCrossFoldersRequest(virtualSourcePath, virtualTargetPath string) bool {
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(virtualSourcePath)
	dstFolder, errDst := c.User.GetVirtualFolderForPath(virtualTargetPath)
	if errSrc != nil && errDst != nil {
		return false
	}
	if errSrc == nil && errDst == nil {
		return sourceFolder.MappedPath != dstFolder.MappedPath
	}
	return true
}

func (c *BaseConnection) updateQuotaMoveBetweenVFolders(sourceFolder, dstFolder vfs.VirtualFolder, initialSize,
	filesSize int64, numFiles int) {
	if sourceFolder.MappedPath == dstFolder.MappedPath {
		// both files are inside the same virtual folder
		if initialSize != -1 {
			dataprovider.UpdateVirtualFolderQuota(dstFolder.BaseVirtualFolder, -numFiles, -initialSize, false) //nolint:errcheck
			if dstFolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(c.User, -numFiles, -initialSize, false) //nolint:errcheck
			}
		}
		return
	}
	// files are inside different virtual folders
	dataprovider.UpdateVirtualFolderQuota(sourceFolder.BaseVirtualFolder, -numFiles, -filesSize, false) //nolint:errcheck
	if sourceFolder.IsIncludedInUserQuota() {
		dataprovider.UpdateUserQuota(c.User, -numFiles, -filesSize, false) //nolint:errcheck
	}
	if initialSize == -1 {
		dataprovider.UpdateVirtualFolderQuota(dstFolder.BaseVirtualFolder, numFiles, filesSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(c.User, numFiles, filesSize, false) //nolint:errcheck
		}
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateVirtualFolderQuota(dstFolder.BaseVirtualFolder, 0, filesSize-initialSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(c.User, 0, filesSize-initialSize, false) //nolint:errcheck
		}
	}
}

func (c *BaseConnection) updateQuotaMoveFromVFolder(sourceFolder vfs.VirtualFolder, initialSize, filesSize int64, numFiles int) {
	// move between a virtual folder and the user home dir
	dataprovider.UpdateVirtualFolderQuota(sourceFolder.BaseVirtualFolder, -numFiles, -filesSize, false) //nolint:errcheck
	if sourceFolder.IsIncludedInUserQuota() {
		dataprovider.UpdateUserQuota(c.User, -numFiles, -filesSize, false) //nolint:errcheck
	}
	if initialSize == -1 {
		dataprovider.UpdateUserQuota(c.User, numFiles, filesSize, false) //nolint:errcheck
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateUserQuota(c.User, 0, filesSize-initialSize, false) //nolint:errcheck
	}
}

func (c *BaseConnection) updateQuotaMoveToVFolder(dstFolder vfs.VirtualFolder, initialSize, filesSize int64, numFiles int) {
	// move between the user home dir and a virtual folder
	dataprovider.UpdateUserQuota(c.User, -numFiles, -filesSize, false) //nolint:errcheck
	if initialSize == -1 {
		dataprovider.UpdateVirtualFolderQuota(dstFolder.BaseVirtualFolder, numFiles, filesSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(c.User, numFiles, filesSize, false) //nolint:errcheck
		}
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateVirtualFolderQuota(dstFolder.BaseVirtualFolder, 0, filesSize-initialSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(c.User, 0, filesSize-initialSize, false) //nolint:errcheck
		}
	}
}

func (c *BaseConnection) updateQuotaAfterRename(virtualSourcePath, virtualTargetPath, targetPath string, initialSize int64) error {
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
			// we cannot have a directory here
			dataprovider.UpdateUserQuota(c.User, -1, -initialSize, false) //nolint:errcheck
		}
		return nil
	}

	filesSize := int64(0)
	numFiles := 1
	if fi, err := c.Fs.Stat(targetPath); err == nil {
		if fi.Mode().IsDir() {
			numFiles, filesSize, err = c.Fs.GetDirSize(targetPath)
			if err != nil {
				c.Log(logger.LevelWarn, "failed to update quota after rename, error scanning moved folder %#v: %v",
					targetPath, err)
				return err
			}
		} else {
			filesSize = fi.Size()
		}
	} else {
		c.Log(logger.LevelWarn, "failed to update quota after rename, file %#v stat error: %+v", targetPath, err)
		return err
	}
	if errSrc == nil && errDst == nil {
		c.updateQuotaMoveBetweenVFolders(sourceFolder, dstFolder, initialSize, filesSize, numFiles)
	}
	if errSrc == nil && errDst != nil {
		c.updateQuotaMoveFromVFolder(sourceFolder, initialSize, filesSize, numFiles)
	}
	if errSrc != nil && errDst == nil {
		c.updateQuotaMoveToVFolder(dstFolder, initialSize, filesSize, numFiles)
	}
	return nil
}

// GetPermissionDeniedError returns an appropriate permission denied error for the connection protocol
func (c *BaseConnection) GetPermissionDeniedError() error {
	switch c.protocol {
	case ProtocolSFTP:
		return sftp.ErrSSHFxPermissionDenied
	case ProtocolWebDAV:
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
	case ProtocolWebDAV:
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

// GetGenericError returns an appropriate generic error for the connection protocol
func (c *BaseConnection) GetGenericError(err error) error {
	switch c.protocol {
	case ProtocolSFTP:
		return sftp.ErrSSHFxFailure
	default:
		if err == ErrPermissionDenied || err == ErrNotExist || err == ErrOpUnsupported || err == ErrQuotaExceeded {
			return err
		}
		return ErrGenericFailure
	}
}

// GetFsError converts a filesystem error to a protocol error
func (c *BaseConnection) GetFsError(err error) error {
	if c.Fs.IsNotExist(err) {
		return c.GetNotExistError()
	} else if c.Fs.IsPermission(err) {
		return c.GetPermissionDeniedError()
	} else if c.Fs.IsNotSupported(err) {
		return c.GetOpUnsupportedError()
	} else if err != nil {
		return c.GetGenericError(err)
	}
	return nil
}
