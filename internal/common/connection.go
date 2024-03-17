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

package common

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/pkg/sftp"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

// BaseConnection defines common fields for a connection using any supported protocol
type BaseConnection struct {
	// last activity for this connection.
	// Since this field is accessed atomically we put it as first element of the struct to achieve 64 bit alignment
	lastActivity atomic.Int64
	uploadDone   atomic.Bool
	downloadDone atomic.Bool
	// unique ID for a transfer.
	// This field is accessed atomically so we put it at the beginning of the struct to achieve 64 bit alignment
	transferID atomic.Int64
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
	if util.Contains(supportedProtocols, protocol) {
		connID = fmt.Sprintf("%s_%s", protocol, id)
	}
	user.UploadBandwidth, user.DownloadBandwidth = user.GetBandwidthForIP(util.GetIPFromRemoteAddress(remoteAddr), connID)
	c := &BaseConnection{
		ID:         connID,
		User:       user,
		startTime:  time.Now(),
		protocol:   protocol,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	c.transferID.Store(0)
	c.lastActivity.Store(time.Now().UnixNano())

	return c
}

// Log outputs a log entry to the configured logger
func (c *BaseConnection) Log(level logger.LogLevel, format string, v ...any) {
	logger.Log(level, c.protocol, c.ID, format, v...)
}

// GetTransferID returns an unique transfer ID for this connection
func (c *BaseConnection) GetTransferID() int64 {
	return c.transferID.Add(1)
}

// GetID returns the connection ID
func (c *BaseConnection) GetID() string {
	return c.ID
}

// GetUsername returns the authenticated username associated with this connection if any
func (c *BaseConnection) GetUsername() string {
	return c.User.Username
}

// GetRole returns the role for the user associated with this connection
func (c *BaseConnection) GetRole() string {
	return c.User.Role
}

// GetMaxSessions returns the maximum number of concurrent sessions allowed
func (c *BaseConnection) GetMaxSessions() int {
	return c.User.MaxSessions
}

// isAccessAllowed returns true if the user's access conditions are met
func (c *BaseConnection) isAccessAllowed() bool {
	if err := c.User.CheckLoginConditions(); err != nil {
		return false
	}
	return true
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
	if util.Contains(supportedProtocols, c.protocol) {
		c.ID = fmt.Sprintf("%v_%v", c.protocol, c.ID)
	}
}

// GetConnectionTime returns the initial connection time
func (c *BaseConnection) GetConnectionTime() time.Time {
	return c.startTime
}

// UpdateLastActivity updates last activity for this connection
func (c *BaseConnection) UpdateLastActivity() {
	c.lastActivity.Store(time.Now().UnixNano())
}

// GetLastActivity returns the last connection activity
func (c *BaseConnection) GetLastActivity() time.Time {
	return time.Unix(0, c.lastActivity.Load())
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
		if p := t.GetRealFsPath(fsPath); p != "" {
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
func (c *BaseConnection) ListDir(virtualPath string) (*DirListerAt, error) {
	if !c.User.HasPerm(dataprovider.PermListItems, virtualPath) {
		return nil, c.GetPermissionDeniedError()
	}
	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return nil, err
	}
	lister, err := fs.ReadDir(fsPath)
	if err != nil {
		c.Log(logger.LevelDebug, "error listing directory: %+v", err)
		return nil, c.GetFsError(fs, err)
	}
	return &DirListerAt{
		virtualPath: virtualPath,
		user:        &c.User,
		info:        c.User.GetVirtualFoldersInfo(virtualPath),
		id:          c.ID,
		protocol:    c.protocol,
		lister:      lister,
	}, nil
}

// CheckParentDirs tries to create the specified directory and any missing parent dirs
func (c *BaseConnection) CheckParentDirs(virtualPath string) error {
	fs, err := c.User.GetFilesystemForPath(virtualPath, c.GetID())
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
		fs, err = c.User.GetFilesystemForPath(dirs[idx], c.GetID())
		if err != nil {
			return err
		}
		if fs.HasVirtualFolders() {
			continue
		}
		if err = c.createDirIfMissing(dirs[idx]); err != nil {
			return fmt.Errorf("unable to check/create missing parent dir %q for virtual path %q: %w",
				dirs[idx], virtualPath, err)
		}
	}
	return nil
}

// GetCreateChecks returns the checks for creating new files
func (c *BaseConnection) GetCreateChecks(virtualPath string, isNewFile bool, isResume bool) int {
	result := 0
	if !isNewFile {
		if isResume {
			result += vfs.CheckResume
		}
		return result
	}
	if !c.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(virtualPath)) {
		result += vfs.CheckParentDir
		return result
	}
	return result
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
		c.Log(logger.LevelWarn, "mkdir not allowed %q is a virtual folder", virtualPath)
		return c.GetPermissionDeniedError()
	}
	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return err
	}
	startTime := time.Now()
	if err := fs.Mkdir(fsPath); err != nil {
		c.Log(logger.LevelError, "error creating dir: %q error: %+v", fsPath, err)
		return c.GetFsError(fs, err)
	}
	vfs.SetPathPermissions(fs, fsPath, c.User.GetUID(), c.User.GetGID())
	elapsed := time.Since(startTime).Nanoseconds() / 1000000

	logger.CommandLog(mkdirLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1,
		c.localAddr, c.remoteAddr, elapsed)
	ExecuteActionNotification(c, operationMkdir, fsPath, virtualPath, "", "", "", 0, nil, elapsed, nil) //nolint:errcheck
	return nil
}

// IsRemoveFileAllowed returns an error if removing this file is not allowed
func (c *BaseConnection) IsRemoveFileAllowed(virtualPath string) error {
	if !c.User.HasAnyPerm([]string{dataprovider.PermDeleteFiles, dataprovider.PermDelete}, path.Dir(virtualPath)) {
		return c.GetPermissionDeniedError()
	}
	if ok, policy := c.User.IsFileAllowed(virtualPath); !ok {
		c.Log(logger.LevelDebug, "removing file %q is not allowed", virtualPath)
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
	status, err := ExecutePreAction(c, operationPreDelete, fsPath, virtualPath, size, 0)
	if err != nil {
		c.Log(logger.LevelDebug, "delete for file %q denied by pre action: %v", virtualPath, err)
		return c.GetPermissionDeniedError()
	}
	updateQuota := true
	startTime := time.Now()
	if err := fs.Remove(fsPath, false); err != nil {
		if status > 0 && fs.IsNotExist(err) {
			// file removed in the pre-action, if the file was deleted from the EventManager the quota is already updated
			c.Log(logger.LevelDebug, "file deleted from the hook, status: %d", status)
			updateQuota = (status == 1)
		} else {
			c.Log(logger.LevelError, "failed to remove file/symlink %q: %+v", fsPath, err)
			return c.GetFsError(fs, err)
		}
	}
	elapsed := time.Since(startTime).Nanoseconds() / 1000000

	logger.CommandLog(removeLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1,
		c.localAddr, c.remoteAddr, elapsed)
	if updateQuota && info.Mode()&os.ModeSymlink == 0 {
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
	ExecuteActionNotification(c, operationDelete, fsPath, virtualPath, "", "", "", size, nil, elapsed, nil) //nolint:errcheck
	return nil
}

// IsRemoveDirAllowed returns an error if removing this directory is not allowed
func (c *BaseConnection) IsRemoveDirAllowed(fs vfs.Fs, fsPath, virtualPath string) error {
	if virtualPath == "/" || fs.GetRelativePath(fsPath) == "/" {
		c.Log(logger.LevelWarn, "removing root dir is not allowed")
		return c.GetPermissionDeniedError()
	}
	if c.User.IsVirtualFolder(virtualPath) {
		c.Log(logger.LevelWarn, "removing a virtual folder is not allowed: %q", virtualPath)
		return fmt.Errorf("removing virtual folders is not allowed: %w", c.GetPermissionDeniedError())
	}
	if c.User.HasVirtualFoldersInside(virtualPath) {
		c.Log(logger.LevelWarn, "removing a directory with a virtual folder inside is not allowed: %q", virtualPath)
		return fmt.Errorf("cannot remove directory %q with virtual folders inside: %w", virtualPath, c.GetOpUnsupportedError())
	}
	if c.User.IsMappedPath(fsPath) {
		c.Log(logger.LevelWarn, "removing a directory mapped as virtual folder is not allowed: %q", fsPath)
		return fmt.Errorf("removing the directory %q mapped as virtual folder is not allowed: %w",
			virtualPath, c.GetPermissionDeniedError())
	}
	if !c.User.HasAnyPerm([]string{dataprovider.PermDeleteDirs, dataprovider.PermDelete}, path.Dir(virtualPath)) {
		return c.GetPermissionDeniedError()
	}
	if ok, policy := c.User.IsFileAllowed(virtualPath); !ok {
		c.Log(logger.LevelDebug, "removing directory %q is not allowed", virtualPath)
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
		c.Log(logger.LevelError, "failed to remove a dir %q: stat error: %+v", fsPath, err)
		return c.GetFsError(fs, err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		c.Log(logger.LevelError, "cannot remove %q is not a directory", fsPath)
		return c.GetGenericError(nil)
	}

	startTime := time.Now()
	if err := fs.Remove(fsPath, true); err != nil {
		c.Log(logger.LevelError, "failed to remove directory %q: %+v", fsPath, err)
		return c.GetFsError(fs, err)
	}
	elapsed := time.Since(startTime).Nanoseconds() / 1000000

	logger.CommandLog(rmdirLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "", -1,
		c.localAddr, c.remoteAddr, elapsed)
	ExecuteActionNotification(c, operationRmdir, fsPath, virtualPath, "", "", "", 0, nil, elapsed, nil) //nolint:errcheck
	return nil
}

func (c *BaseConnection) doRecursiveRemoveDirEntry(virtualPath string, info os.FileInfo, recursion int) error {
	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return err
	}
	return c.doRecursiveRemove(fs, fsPath, virtualPath, info, recursion)
}

func (c *BaseConnection) doRecursiveRemove(fs vfs.Fs, fsPath, virtualPath string, info os.FileInfo, recursion int) error {
	if info.IsDir() {
		if recursion >= util.MaxRecursion {
			c.Log(logger.LevelError, "recursive rename failed, recursion too depth: %d", recursion)
			return util.ErrRecursionTooDeep
		}
		recursion++
		lister, err := c.ListDir(virtualPath)
		if err != nil {
			return fmt.Errorf("unable to get lister for dir %q: %w", virtualPath, err)
		}
		defer lister.Close()

		for {
			entries, err := lister.Next(vfs.ListerBatchSize)
			finished := errors.Is(err, io.EOF)
			if err != nil && !finished {
				return fmt.Errorf("unable to get content for dir %q: %w", virtualPath, err)
			}
			for _, fi := range entries {
				targetPath := path.Join(virtualPath, fi.Name())
				if err := c.doRecursiveRemoveDirEntry(targetPath, fi, recursion); err != nil {
					return err
				}
			}
			if finished {
				lister.Close()
				break
			}
		}
		return c.RemoveDir(virtualPath)
	}
	return c.RemoveFile(fs, fsPath, virtualPath, info)
}

// RemoveAll removes the specified path and any children it contains
func (c *BaseConnection) RemoveAll(virtualPath string) error {
	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return err
	}

	fi, err := fs.Lstat(fsPath)
	if err != nil {
		c.Log(logger.LevelDebug, "failed to remove path %q: stat error: %+v", fsPath, err)
		return c.GetFsError(fs, err)
	}
	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		if err := c.IsRemoveDirAllowed(fs, fsPath, virtualPath); err != nil {
			return err
		}
		return c.doRecursiveRemove(fs, fsPath, virtualPath, fi, 0)
	}
	return c.RemoveFile(fs, fsPath, virtualPath, fi)
}

func (c *BaseConnection) checkCopy(srcInfo, dstInfo os.FileInfo, virtualSource, virtualTarget string) error {
	_, fsSourcePath, err := c.GetFsAndResolvedPath(virtualSource)
	if err != nil {
		return err
	}
	_, fsTargetPath, err := c.GetFsAndResolvedPath(virtualTarget)
	if err != nil {
		return err
	}
	if srcInfo.IsDir() {
		if dstInfo != nil && !dstInfo.IsDir() {
			return fmt.Errorf("cannot overwrite file %q with dir %q: %w", virtualTarget, virtualSource, c.GetOpUnsupportedError())
		}
		if util.IsDirOverlapped(virtualSource, virtualTarget, true, "/") {
			return fmt.Errorf("nested copy %q => %q is not supported: %w", virtualSource, virtualTarget, c.GetOpUnsupportedError())
		}
		if util.IsDirOverlapped(fsSourcePath, fsTargetPath, true, c.User.FsConfig.GetPathSeparator()) {
			c.Log(logger.LevelWarn, "nested fs copy %q => %q not allowed", fsSourcePath, fsTargetPath)
			return fmt.Errorf("nested fs copy is not supported: %w", c.GetOpUnsupportedError())
		}
		return nil
	}
	if dstInfo != nil && dstInfo.IsDir() {
		return fmt.Errorf("cannot overwrite file %q with dir %q: %w", virtualSource, virtualTarget, c.GetOpUnsupportedError())
	}
	if fsSourcePath == fsTargetPath {
		return fmt.Errorf("the copy source and target cannot be the same: %w", c.GetOpUnsupportedError())
	}
	return nil
}

func (c *BaseConnection) copyFile(virtualSourcePath, virtualTargetPath string, srcSize int64) error {
	if !c.User.HasPerm(dataprovider.PermCopy, virtualSourcePath) || !c.User.HasPerm(dataprovider.PermCopy, virtualTargetPath) {
		return c.GetPermissionDeniedError()
	}
	if ok, _ := c.User.IsFileAllowed(virtualTargetPath); !ok {
		return fmt.Errorf("file %q is not allowed: %w", virtualTargetPath, c.GetPermissionDeniedError())
	}
	if c.IsSameResource(virtualSourcePath, virtualTargetPath) {
		fs, fsTargetPath, err := c.GetFsAndResolvedPath(virtualTargetPath)
		if err != nil {
			return err
		}
		if copier, ok := fs.(vfs.FsFileCopier); ok {
			_, fsSourcePath, err := c.GetFsAndResolvedPath(virtualSourcePath)
			if err != nil {
				return err
			}
			startTime := time.Now()
			numFiles, sizeDiff, err := copier.CopyFile(fsSourcePath, fsTargetPath, srcSize)
			elapsed := time.Since(startTime).Nanoseconds() / 1000000
			updateUserQuotaAfterFileWrite(c, virtualTargetPath, numFiles, sizeDiff)
			logger.CommandLog(copyLogSender, fsSourcePath, fsTargetPath, c.User.Username, "", c.ID, c.protocol, -1, -1,
				"", "", "", srcSize, c.localAddr, c.remoteAddr, elapsed)
			ExecuteActionNotification(c, operationCopy, fsSourcePath, virtualSourcePath, fsTargetPath, virtualTargetPath, "", srcSize, err, elapsed, nil) //nolint:errcheck
			return err
		}
	}

	reader, rCancelFn, err := getFileReader(c, virtualSourcePath)
	if err != nil {
		return fmt.Errorf("unable to get reader for path %q: %w", virtualSourcePath, err)
	}
	defer rCancelFn()
	defer reader.Close()

	writer, numFiles, truncatedSize, wCancelFn, err := getFileWriter(c, virtualTargetPath, srcSize)
	if err != nil {
		return fmt.Errorf("unable to get writer for path %q: %w", virtualTargetPath, err)
	}
	defer wCancelFn()

	startTime := time.Now()
	_, err = io.Copy(writer, reader)
	return closeWriterAndUpdateQuota(writer, c, virtualSourcePath, virtualTargetPath, numFiles, truncatedSize,
		err, operationCopy, startTime)
}

func (c *BaseConnection) doRecursiveCopy(virtualSourcePath, virtualTargetPath string, srcInfo os.FileInfo,
	createTargetDir bool, recursion int,
) error {
	if srcInfo.IsDir() {
		if recursion >= util.MaxRecursion {
			c.Log(logger.LevelError, "recursive copy failed, recursion too depth: %d", recursion)
			return util.ErrRecursionTooDeep
		}
		recursion++
		if createTargetDir {
			if err := c.CreateDir(virtualTargetPath, false); err != nil {
				return fmt.Errorf("unable to create directory %q: %w", virtualTargetPath, err)
			}
		}
		lister, err := c.ListDir(virtualSourcePath)
		if err != nil {
			return fmt.Errorf("unable to get lister for dir %q: %w", virtualSourcePath, err)
		}
		defer lister.Close()

		for {
			entries, err := lister.Next(vfs.ListerBatchSize)
			finished := errors.Is(err, io.EOF)
			if err != nil && !finished {
				return fmt.Errorf("unable to get contents for dir %q: %w", virtualSourcePath, err)
			}
			if err := c.recursiveCopyEntries(virtualSourcePath, virtualTargetPath, entries, recursion); err != nil {
				return err
			}
			if finished {
				return nil
			}
		}
	}
	if !srcInfo.Mode().IsRegular() {
		c.Log(logger.LevelInfo, "skipping copy for non regular file %q", virtualSourcePath)
		return nil
	}

	return c.copyFile(virtualSourcePath, virtualTargetPath, srcInfo.Size())
}

func (c *BaseConnection) recursiveCopyEntries(virtualSourcePath, virtualTargetPath string, entries []os.FileInfo, recursion int) error {
	for _, info := range entries {
		sourcePath := path.Join(virtualSourcePath, info.Name())
		targetPath := path.Join(virtualTargetPath, info.Name())
		targetInfo, err := c.DoStat(targetPath, 1, false)
		if err == nil {
			if info.IsDir() && targetInfo.IsDir() {
				c.Log(logger.LevelDebug, "target copy dir %q already exists", targetPath)
				continue
			}
		}
		if err != nil && !c.IsNotExistError(err) {
			return err
		}
		if err := c.checkCopy(info, targetInfo, sourcePath, targetPath); err != nil {
			return err
		}
		if err := c.doRecursiveCopy(sourcePath, targetPath, info, true, recursion); err != nil {
			if c.IsNotExistError(err) {
				c.Log(logger.LevelInfo, "skipping copy for source path %q: %v", sourcePath, err)
				continue
			}
			return err
		}
	}
	return nil
}

// Copy virtualSourcePath to virtualTargetPath
func (c *BaseConnection) Copy(virtualSourcePath, virtualTargetPath string) error {
	copyFromSource := strings.HasSuffix(virtualSourcePath, "/")
	copyInTarget := strings.HasSuffix(virtualTargetPath, "/")
	virtualSourcePath = path.Clean(virtualSourcePath)
	virtualTargetPath = path.Clean(virtualTargetPath)
	if virtualSourcePath == virtualTargetPath {
		return fmt.Errorf("the copy source and target cannot be the same: %w", c.GetOpUnsupportedError())
	}
	srcInfo, err := c.DoStat(virtualSourcePath, 1, false)
	if err != nil {
		return err
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("copying symlinks is not supported: %w", c.GetOpUnsupportedError())
	}
	dstInfo, err := c.DoStat(virtualTargetPath, 1, false)
	if err == nil && !copyFromSource {
		copyInTarget = dstInfo.IsDir()
	}
	if err != nil && !c.IsNotExistError(err) {
		return err
	}
	destPath := virtualTargetPath
	if copyInTarget {
		destPath = path.Join(virtualTargetPath, path.Base(virtualSourcePath))
		dstInfo, err = c.DoStat(destPath, 1, false)
		if err != nil && !c.IsNotExistError(err) {
			return err
		}
	}
	createTargetDir := true
	if dstInfo != nil && dstInfo.IsDir() {
		createTargetDir = false
	}
	if err := c.checkCopy(srcInfo, dstInfo, virtualSourcePath, destPath); err != nil {
		return err
	}
	if err := c.CheckParentDirs(path.Dir(destPath)); err != nil {
		return err
	}
	done := make(chan bool)
	defer close(done)
	go keepConnectionAlive(c, done, 2*time.Minute)

	return c.doRecursiveCopy(virtualSourcePath, destPath, srcInfo, createTargetDir, 0)
}

// Rename renames (moves) virtualSourcePath to virtualTargetPath
func (c *BaseConnection) Rename(virtualSourcePath, virtualTargetPath string) error {
	return c.renameInternal(virtualSourcePath, virtualTargetPath, false)
}

func (c *BaseConnection) renameInternal(virtualSourcePath, virtualTargetPath string, checkParentDestination bool) error {
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
	startTime := time.Now()
	srcInfo, err := fsSrc.Lstat(fsSourcePath)
	if err != nil {
		return c.GetFsError(fsSrc, err)
	}
	if !c.isRenamePermitted(fsSrc, fsDst, fsSourcePath, fsTargetPath, virtualSourcePath, virtualTargetPath, srcInfo) {
		return c.GetPermissionDeniedError()
	}
	initialSize := int64(-1)
	if dstInfo, err := fsDst.Lstat(fsTargetPath); err == nil {
		checkParentDestination = false
		if dstInfo.IsDir() {
			c.Log(logger.LevelWarn, "attempted to rename %q overwriting an existing directory %q",
				fsSourcePath, fsTargetPath)
			return c.GetOpUnsupportedError()
		}
		// we are overwriting an existing file/symlink
		if dstInfo.Mode().IsRegular() {
			initialSize = dstInfo.Size()
		}
		if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(virtualTargetPath)) {
			c.Log(logger.LevelDebug, "renaming %q -> %q is not allowed. Target exists but the user %q"+
				"has no overwrite permission", virtualSourcePath, virtualTargetPath, c.User.Username)
			return c.GetPermissionDeniedError()
		}
	}
	if srcInfo.IsDir() {
		if err := c.checkFolderRename(fsSrc, fsDst, fsSourcePath, fsTargetPath, virtualSourcePath, virtualTargetPath, srcInfo); err != nil {
			return err
		}
	}
	if !c.hasSpaceForRename(fsSrc, virtualSourcePath, virtualTargetPath, initialSize, fsSourcePath) {
		c.Log(logger.LevelInfo, "denying cross rename due to space limit")
		return c.GetGenericError(ErrQuotaExceeded)
	}
	if checkParentDestination {
		c.CheckParentDirs(path.Dir(virtualTargetPath)) //nolint:errcheck
	}
	done := make(chan bool)
	defer close(done)
	go keepConnectionAlive(c, done, 2*time.Minute)

	files, size, err := fsDst.Rename(fsSourcePath, fsTargetPath)
	if err != nil {
		c.Log(logger.LevelError, "failed to rename %q -> %q: %+v", fsSourcePath, fsTargetPath, err)
		return c.GetFsError(fsSrc, err)
	}
	vfs.SetPathPermissions(fsDst, fsTargetPath, c.User.GetUID(), c.User.GetGID())
	elapsed := time.Since(startTime).Nanoseconds() / 1000000
	c.updateQuotaAfterRename(fsDst, virtualSourcePath, virtualTargetPath, fsTargetPath, initialSize, files, size) //nolint:errcheck
	logger.CommandLog(renameLogSender, fsSourcePath, fsTargetPath, c.User.Username, "", c.ID, c.protocol, -1, -1,
		"", "", "", -1, c.localAddr, c.remoteAddr, elapsed)
	ExecuteActionNotification(c, operationRename, fsSourcePath, virtualSourcePath, fsTargetPath, //nolint:errcheck
		virtualTargetPath, "", 0, nil, elapsed, nil)

	return nil
}

// CreateSymlink creates fsTargetPath as a symbolic link to fsSourcePath
func (c *BaseConnection) CreateSymlink(virtualSourcePath, virtualTargetPath string) error {
	var relativePath string
	if !path.IsAbs(virtualSourcePath) {
		relativePath = virtualSourcePath
		virtualSourcePath = path.Join(path.Dir(virtualTargetPath), relativePath)
		c.Log(logger.LevelDebug, "link relative path %q resolved as %q, target path %q",
			relativePath, virtualSourcePath, virtualTargetPath)
	}
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
		c.Log(logger.LevelError, "symlink source path %q is not allowed", virtualSourcePath)
		return c.GetNotExistError()
	}
	if ok, _ = c.User.IsFileAllowed(virtualTargetPath); !ok {
		c.Log(logger.LevelError, "symlink target path %q is not allowed", virtualTargetPath)
		return c.GetPermissionDeniedError()
	}
	if relativePath != "" {
		fsSourcePath = relativePath
	}
	startTime := time.Now()
	if err := fs.Symlink(fsSourcePath, fsTargetPath); err != nil {
		c.Log(logger.LevelError, "failed to create symlink %q -> %q: %+v", fsSourcePath, fsTargetPath, err)
		return c.GetFsError(fs, err)
	}
	elapsed := time.Since(startTime).Nanoseconds() / 1000000
	logger.CommandLog(symlinkLogSender, fsSourcePath, fsTargetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "",
		"", "", -1, c.localAddr, c.remoteAddr, elapsed)
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

func (c *BaseConnection) doStatInternal(virtualPath string, mode int, checkFilePatterns,
	convertResult bool,
) (os.FileInfo, error) {
	// for some vfs we don't create intermediary folders so we cannot simply check
	// if virtualPath is a virtual folder. Allowing stat for hidden virtual folders
	// is by purpose.
	vfolders := c.User.GetVirtualFoldersInPath(path.Dir(virtualPath))
	if _, ok := vfolders[virtualPath]; ok {
		return vfs.NewFileInfo(virtualPath, true, 0, time.Unix(0, 0), false), nil
	}
	if checkFilePatterns && virtualPath != "/" {
		ok, policy := c.User.IsFileAllowed(virtualPath)
		if !ok && policy == sdk.DenyPolicyHide {
			return nil, c.GetNotExistError()
		}
	}

	var info os.FileInfo

	fs, fsPath, err := c.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return nil, err
	}

	if mode == 1 {
		info, err = fs.Lstat(c.getRealFsPath(fsPath))
	} else {
		info, err = fs.Stat(c.getRealFsPath(fsPath))
	}
	if err != nil {
		if !fs.IsNotExist(err) {
			c.Log(logger.LevelWarn, "stat error for path %q: %+v", virtualPath, err)
		}
		return nil, c.GetFsError(fs, err)
	}
	if convertResult && vfs.IsCryptOsFs(fs) {
		info = fs.(*vfs.CryptFs).ConvertFileInfo(info)
	}
	return info, nil
}

// DoStat execute a Stat if mode = 0, Lstat if mode = 1
func (c *BaseConnection) DoStat(virtualPath string, mode int, checkFilePatterns bool) (os.FileInfo, error) {
	return c.doStatInternal(virtualPath, mode, checkFilePatterns, true)
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
	startTime := time.Now()
	if err := fs.Chmod(c.getRealFsPath(fsPath), attributes.Mode); err != nil {
		c.Log(logger.LevelError, "failed to chmod path %q, mode: %v, err: %+v", fsPath, attributes.Mode.String(), err)
		return c.GetFsError(fs, err)
	}
	elapsed := time.Since(startTime).Nanoseconds() / 1000000
	logger.CommandLog(chmodLogSender, fsPath, "", c.User.Username, attributes.Mode.String(), c.ID, c.protocol,
		-1, -1, "", "", "", -1, c.localAddr, c.remoteAddr, elapsed)
	return nil
}

func (c *BaseConnection) handleChown(fs vfs.Fs, fsPath, pathForPerms string, attributes *StatAttributes) error {
	if !c.User.HasPerm(dataprovider.PermChown, pathForPerms) {
		return c.GetPermissionDeniedError()
	}
	if c.ignoreSetStat(fs) {
		return nil
	}
	startTime := time.Now()
	if err := fs.Chown(c.getRealFsPath(fsPath), attributes.UID, attributes.GID); err != nil {
		c.Log(logger.LevelError, "failed to chown path %q, uid: %v, gid: %v, err: %+v", fsPath, attributes.UID,
			attributes.GID, err)
		return c.GetFsError(fs, err)
	}
	elapsed := time.Since(startTime).Nanoseconds() / 1000000
	logger.CommandLog(chownLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, attributes.UID, attributes.GID,
		"", "", "", -1, c.localAddr, c.remoteAddr, elapsed)
	return nil
}

func (c *BaseConnection) handleChtimes(fs vfs.Fs, fsPath, pathForPerms string, attributes *StatAttributes) error {
	if !c.User.HasPerm(dataprovider.PermChtimes, pathForPerms) {
		return c.GetPermissionDeniedError()
	}
	if Config.SetstatMode == 1 {
		return nil
	}
	startTime := time.Now()
	isUploading := c.setTimes(fsPath, attributes.Atime, attributes.Mtime)
	if err := fs.Chtimes(c.getRealFsPath(fsPath), attributes.Atime, attributes.Mtime, isUploading); err != nil {
		c.setTimes(fsPath, time.Time{}, time.Time{})
		if errors.Is(err, vfs.ErrVfsUnsupported) && Config.SetstatMode == 2 {
			return nil
		}
		c.Log(logger.LevelError, "failed to chtimes for path %q, access time: %v, modification time: %v, err: %+v",
			fsPath, attributes.Atime, attributes.Mtime, err)
		return c.GetFsError(fs, err)
	}
	elapsed := time.Since(startTime).Nanoseconds() / 1000000
	accessTimeString := attributes.Atime.Format(chtimesFormat)
	modificationTimeString := attributes.Mtime.Format(chtimesFormat)
	logger.CommandLog(chtimesLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1,
		accessTimeString, modificationTimeString, "", -1, c.localAddr, c.remoteAddr, elapsed)
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
		startTime := time.Now()
		if err = c.truncateFile(fs, fsPath, virtualPath, attributes.Size); err != nil {
			c.Log(logger.LevelError, "failed to truncate path %q, size: %v, err: %+v", fsPath, attributes.Size, err)
			return c.GetFsError(fs, err)
		}
		elapsed := time.Since(startTime).Nanoseconds() / 1000000
		logger.CommandLog(truncateLogSender, fsPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "",
			"", attributes.Size, c.localAddr, c.remoteAddr, elapsed)
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
		c.Log(logger.LevelDebug, "file path %q not found in active transfers, execute trucate by path", fsPath)
		var info os.FileInfo
		info, err = fs.Stat(fsPath)
		if err != nil {
			return err
		}
		initialSize = info.Size()
		err = fs.Truncate(fsPath, size)
	}
	if err == nil && vfs.HasTruncateSupport(fs) {
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

func (c *BaseConnection) checkRecursiveRenameDirPermissions(fsSrc, fsDst vfs.Fs, sourcePath, targetPath,
	virtualSourcePath, virtualTargetPath string, fi os.FileInfo,
) error {
	if !c.User.HasPermissionsInside(virtualSourcePath) &&
		!c.User.HasPermissionsInside(virtualTargetPath) {
		if !c.isRenamePermitted(fsSrc, fsDst, sourcePath, targetPath, virtualSourcePath, virtualTargetPath, fi) {
			c.Log(logger.LevelInfo, "rename %q -> %q is not allowed, virtual destination path: %q",
				sourcePath, targetPath, virtualTargetPath)
			return c.GetPermissionDeniedError()
		}
		// if all rename permissions are granted we have finished, otherwise we have to walk
		// because we could have the rename dir permission but not the rename file and the dir to
		// rename could contain files
		if c.User.HasPermsRenameAll(path.Dir(virtualSourcePath)) && c.User.HasPermsRenameAll(path.Dir(virtualTargetPath)) {
			return nil
		}
	}

	return fsSrc.Walk(sourcePath, func(walkedPath string, info os.FileInfo, err error) error {
		if err != nil {
			return c.GetFsError(fsSrc, err)
		}
		if walkedPath != sourcePath && !vfs.IsRenameAtomic(fsSrc) && Config.RenameMode == 0 {
			c.Log(logger.LevelInfo, "cannot rename non empty directory %q on this filesystem", virtualSourcePath)
			return c.GetOpUnsupportedError()
		}
		dstPath := strings.Replace(walkedPath, sourcePath, targetPath, 1)
		virtualSrcPath := fsSrc.GetRelativePath(walkedPath)
		virtualDstPath := fsDst.GetRelativePath(dstPath)
		if !c.isRenamePermitted(fsSrc, fsDst, walkedPath, dstPath, virtualSrcPath, virtualDstPath, info) {
			c.Log(logger.LevelInfo, "rename %q -> %q is not allowed, virtual destination path: %q",
				walkedPath, dstPath, virtualDstPath)
			return c.GetPermissionDeniedError()
		}
		return nil
	})
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

func (c *BaseConnection) checkFolderRename(fsSrc, fsDst vfs.Fs, fsSourcePath, fsTargetPath, virtualSourcePath,
	virtualTargetPath string, fi os.FileInfo) error {
	if util.IsDirOverlapped(virtualSourcePath, virtualTargetPath, true, "/") {
		c.Log(logger.LevelDebug, "renaming the folder %q->%q is not supported: nested folders",
			virtualSourcePath, virtualTargetPath)
		return fmt.Errorf("nested rename %q => %q is not supported: %w",
			virtualSourcePath, virtualTargetPath, c.GetOpUnsupportedError())
	}
	if util.IsDirOverlapped(fsSourcePath, fsTargetPath, true, c.User.FsConfig.GetPathSeparator()) {
		c.Log(logger.LevelDebug, "renaming the folder %q->%q is not supported: nested fs folders",
			fsSourcePath, fsTargetPath)
		return fmt.Errorf("nested fs rename %q => %q is not supported: %w",
			fsSourcePath, fsTargetPath, c.GetOpUnsupportedError())
	}
	if c.User.HasVirtualFoldersInside(virtualSourcePath) {
		c.Log(logger.LevelDebug, "renaming the folder %q is not supported: it has virtual folders inside it",
			virtualSourcePath)
		return fmt.Errorf("folder %q has virtual folders inside it: %w", virtualSourcePath, c.GetOpUnsupportedError())
	}
	if c.User.HasVirtualFoldersInside(virtualTargetPath) {
		c.Log(logger.LevelDebug, "renaming the folder %q is not supported, the target %q has virtual folders inside it",
			virtualSourcePath, virtualTargetPath)
		return fmt.Errorf("folder %q has virtual folders inside it: %w", virtualTargetPath, c.GetOpUnsupportedError())
	}
	if err := c.checkRecursiveRenameDirPermissions(fsSrc, fsDst, fsSourcePath, fsTargetPath,
		virtualSourcePath, virtualTargetPath, fi); err != nil {
		c.Log(logger.LevelDebug, "error checking recursive permissions before renaming %q: %+v", fsSourcePath, err)
		return err
	}
	return nil
}

func (c *BaseConnection) isRenamePermitted(fsSrc, fsDst vfs.Fs, fsSourcePath, fsTargetPath, virtualSourcePath,
	virtualTargetPath string, fi os.FileInfo,
) bool {
	if !c.IsSameResource(virtualSourcePath, virtualTargetPath) {
		c.Log(logger.LevelInfo, "rename %q->%q is not allowed: the paths must be on the same resource",
			virtualSourcePath, virtualTargetPath)
		return false
	}
	if c.User.IsMappedPath(fsSourcePath) && vfs.IsLocalOrCryptoFs(fsSrc) {
		c.Log(logger.LevelWarn, "renaming a directory mapped as virtual folder is not allowed: %q", fsSourcePath)
		return false
	}
	if c.User.IsMappedPath(fsTargetPath) && vfs.IsLocalOrCryptoFs(fsDst) {
		c.Log(logger.LevelWarn, "renaming to a directory mapped as virtual folder is not allowed: %q", fsTargetPath)
		return false
	}
	if virtualSourcePath == "/" || virtualTargetPath == "/" || fsSrc.GetRelativePath(fsSourcePath) == "/" {
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
		c.Log(logger.LevelDebug, "renaming source: %q to target: %q not allowed", virtualSourcePath,
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
	if errDst != nil && sourceFolder.IsIncludedInUserQuota() {
		// rename between a virtual folder included in user quota and the user root dir
		return true
	}
	quotaResult, _ := c.HasSpace(true, false, virtualTargetPath)
	if quotaResult.HasSpace && quotaResult.QuotaSize == 0 && quotaResult.QuotaFiles == 0 {
		// no quota restrictions
		return true
	}
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
		c.Log(logger.LevelError, "cross rename denied, stat error for path %q: %v", sourcePath, err)
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
			c.Log(logger.LevelError, "cross rename denied, error getting size for directory %q: %v", sourcePath, err)
			return false
		}
	}
	if !quotaResult.HasSpace && initialSize != -1 {
		// we are over quota but we are overwriting an existing file so we check if the quota size after the rename is ok
		if quotaResult.QuotaSize == 0 {
			return true
		}
		c.Log(logger.LevelDebug, "cross rename overwrite, source %q, used size %d, size to add %d",
			sourcePath, quotaResult.UsedSize, sizeDiff)
		quotaResult.UsedSize += sizeDiff
		return quotaResult.GetRemainingSize() >= 0
	}
	if quotaResult.QuotaFiles > 0 {
		remainingFiles := quotaResult.GetRemainingFiles()
		c.Log(logger.LevelDebug, "cross rename, source %q remaining file %d to add %d", sourcePath,
			remainingFiles, filesDiff)
		if remainingFiles < filesDiff {
			return false
		}
	}
	if quotaResult.QuotaSize > 0 {
		remainingSize := quotaResult.GetRemainingSize()
		c.Log(logger.LevelDebug, "cross rename, source %q remaining size %d to add %d", sourcePath,
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
	ul, dl, total := c.User.GetDataTransferLimits()
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
		c.Log(logger.LevelError, "error getting used quota for %q: %v", c.User.Username, err)
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
		c.Log(logger.LevelError, "error getting used quota for %q request path %q: %v", c.User.Username, requestPath, err)
		result.HasSpace = false
		return result, transferQuota
	}
	result.AllowedFiles = result.QuotaFiles - result.UsedFiles
	result.AllowedSize = result.QuotaSize - result.UsedSize
	if (checkFiles && result.QuotaFiles > 0 && result.UsedFiles >= result.QuotaFiles) ||
		(result.QuotaSize > 0 && result.UsedSize >= result.QuotaSize) {
		c.Log(logger.LevelDebug, "quota exceed for user %q, request path %q, num files: %d/%d, size: %d/%d check files: %t",
			c.User.Username, requestPath, result.UsedFiles, result.QuotaFiles, result.UsedSize, result.QuotaSize, checkFiles)
		result.HasSpace = false
		return result, transferQuota
	}
	return result, transferQuota
}

// IsSameResource returns true if source and target paths are on the same resource
func (c *BaseConnection) IsSameResource(virtualSourcePath, virtualTargetPath string) bool {
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(virtualSourcePath)
	dstFolder, errDst := c.User.GetVirtualFolderForPath(virtualTargetPath)
	if errSrc != nil && errDst != nil {
		return true
	}
	if errSrc == nil && errDst == nil {
		if sourceFolder.Name == dstFolder.Name {
			return true
		}
		// we have different folders, check if they point to the same resource
		return sourceFolder.FsConfig.IsSameResource(dstFolder.FsConfig)
	}
	if errSrc == nil {
		return sourceFolder.FsConfig.IsSameResource(c.User.FsConfig)
	}
	return dstFolder.FsConfig.IsSameResource(c.User.FsConfig)
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

func (c *BaseConnection) updateQuotaAfterRename(fs vfs.Fs, virtualSourcePath, virtualTargetPath, targetPath string,
	initialSize int64, numFiles int, filesSize int64,
) error {
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

	if filesSize == -1 {
		// fs.Rename didn't return the affected files/sizes, we need to calculate them
		numFiles = 1
		if fi, err := fs.Stat(targetPath); err == nil {
			if fi.Mode().IsDir() {
				numFiles, filesSize, err = fs.GetDirSize(targetPath)
				if err != nil {
					c.Log(logger.LevelError, "failed to update quota after rename, error scanning moved folder %q: %+v",
						targetPath, err)
					return err
				}
			} else {
				filesSize = fi.Size()
			}
		} else {
			c.Log(logger.LevelError, "failed to update quota after renaming, file %q stat error: %+v", targetPath, err)
			return err
		}
		c.Log(logger.LevelDebug, "calculated renamed files: %d, size: %d bytes", numFiles, filesSize)
	} else {
		c.Log(logger.LevelDebug, "returned renamed files: %d, size: %d bytes", numFiles, filesSize)
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
	return getPermissionDeniedError(c.protocol)
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
		if err == ErrShuttingDown {
			return fmt.Errorf("%w: %v", sftp.ErrSSHFxFailure, err.Error())
		}
		if err != nil {
			if e, ok := err.(*os.PathError); ok {
				c.Log(logger.LevelError, "generic path error: %+v", e)
				return fmt.Errorf("%w: %v %v", sftp.ErrSSHFxFailure, e.Op, e.Err.Error())
			}
			c.Log(logger.LevelError, "generic error: %+v", err)
			return fmt.Errorf("%w: %v", sftp.ErrSSHFxFailure, ErrGenericFailure.Error())
		}
		return sftp.ErrSSHFxFailure
	default:
		if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrNotExist) || errors.Is(err, ErrOpUnsupported) ||
			errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrReadQuotaExceeded) ||
			errors.Is(err, vfs.ErrStorageSizeUnavailable) || errors.Is(err, ErrShuttingDown) {
			return err
		}
		c.Log(logger.LevelError, "generic error: %+v", err)
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

func (c *BaseConnection) getNotificationStatus(err error) int {
	if err == nil {
		return 1
	}
	if c.IsQuotaExceededError(err) {
		return 3
	}
	return 2
}

// GetFsAndResolvedPath returns the fs and the fs path matching virtualPath
func (c *BaseConnection) GetFsAndResolvedPath(virtualPath string) (vfs.Fs, string, error) {
	fs, err := c.User.GetFilesystemForPath(virtualPath, c.ID)
	if err != nil {
		if c.protocol == ProtocolWebDAV && strings.Contains(err.Error(), vfs.ErrSFTPLoop.Error()) {
			// if there is an SFTP loop we return a permission error, for WebDAV, so the problematic folder
			// will not be listed
			return nil, "", util.NewI18nError(c.GetPermissionDeniedError(), util.I18nError403Message)
		}
		return nil, "", c.GetGenericError(err)
	}

	if isShuttingDown.Load() {
		return nil, "", c.GetFsError(fs, ErrShuttingDown)
	}

	fsPath, err := fs.ResolvePath(virtualPath)
	if err != nil {
		return nil, "", c.GetFsError(fs, err)
	}

	return fs, fsPath, nil
}

// DirListerAt defines a directory lister implementing the ListAt method.
type DirListerAt struct {
	virtualPath string
	user        *dataprovider.User
	info        []os.FileInfo
	id          string
	protocol    string
	mu          sync.Mutex
	lister      vfs.DirLister
}

// Add adds the given os.FileInfo to the internal cache
func (l *DirListerAt) Add(fi os.FileInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.info = append(l.info, fi)
}

// ListAt implements sftp.ListerAt
func (l *DirListerAt) ListAt(f []os.FileInfo, _ int64) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(f) == 0 {
		return 0, errors.New("invalid ListAt destination, zero size")
	}
	if len(f) <= len(l.info) {
		files := make([]os.FileInfo, 0, len(f))
		for idx := len(l.info) - 1; idx >= 0; idx-- {
			files = append(files, l.info[idx])
			if len(files) == len(f) {
				l.info = l.info[:idx]
				n := copy(f, files)
				return n, nil
			}
		}
	}
	limit := len(f) - len(l.info)
	files, err := l.Next(limit)
	n := copy(f, files)
	return n, err
}

// Next reads the directory and returns a slice of up to n FileInfo values.
func (l *DirListerAt) Next(limit int) ([]os.FileInfo, error) {
	for {
		files, err := l.lister.Next(limit)
		if err != nil && !errors.Is(err, io.EOF) {
			logger.Debug(l.protocol, l.id, "error retrieving directory entries: %+v", err)
			return files, err
		}
		files = l.user.FilterListDir(files, l.virtualPath)
		if len(l.info) > 0 {
			for _, fi := range l.info {
				files = util.PrependFileInfo(files, fi)
			}
			l.info = nil
		}
		if err != nil || len(files) > 0 {
			return files, err
		}
	}
}

// Close closes the DirListerAt
func (l *DirListerAt) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.lister.Close()
}

func (l *DirListerAt) convertError(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func getPermissionDeniedError(protocol string) error {
	switch protocol {
	case ProtocolSFTP:
		return sftp.ErrSSHFxPermissionDenied
	case ProtocolWebDAV, ProtocolFTP, ProtocolHTTP, ProtocolOIDC, ProtocolHTTPShare, ProtocolDataRetention:
		return os.ErrPermission
	default:
		return ErrPermissionDenied
	}
}

func keepConnectionAlive(c *BaseConnection, done chan bool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			c.UpdateLastActivity()
		}
	}
}
