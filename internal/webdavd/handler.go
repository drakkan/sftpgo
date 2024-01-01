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

package webdavd

import (
	"context"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/drakkan/webdav"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

// Connection details for a WebDav connection.
type Connection struct {
	*common.BaseConnection
	request *http.Request
}

func (c *Connection) getModificationTime() time.Time {
	if c.request == nil {
		return time.Time{}
	}
	if val := c.request.Header.Get("X-OC-Mtime"); val != "" {
		if unixTime, err := strconv.ParseInt(val, 10, 64); err == nil {
			return time.Unix(unixTime, 0)
		}
	}
	return time.Time{}
}

// GetClientVersion returns the connected client's version.
func (c *Connection) GetClientVersion() string {
	if c.request != nil {
		return c.request.UserAgent()
	}
	return ""
}

// GetLocalAddress returns local connection address
func (c *Connection) GetLocalAddress() string {
	return util.GetHTTPLocalAddress(c.request)
}

// GetRemoteAddress returns the connected client's address
func (c *Connection) GetRemoteAddress() string {
	if c.request != nil {
		return c.request.RemoteAddr
	}
	return ""
}

// Disconnect closes the active transfer
func (c *Connection) Disconnect() error {
	return c.SignalTransfersAbort()
}

// GetCommand returns the request method
func (c *Connection) GetCommand() string {
	if c.request != nil {
		return strings.ToUpper(c.request.Method)
	}
	return ""
}

// Mkdir creates a directory using the connection filesystem
func (c *Connection) Mkdir(_ context.Context, name string, _ os.FileMode) error {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	return c.CreateDir(name, true)
}

// Rename renames a file or a directory
func (c *Connection) Rename(_ context.Context, oldName, newName string) error {
	c.UpdateLastActivity()

	oldName = util.CleanPath(oldName)
	newName = util.CleanPath(newName)

	err := c.BaseConnection.Rename(oldName, newName)
	if err == nil {
		if mtime := c.getModificationTime(); !mtime.IsZero() {
			attrs := &common.StatAttributes{
				Flags: common.StatAttrTimes,
				Atime: mtime,
				Mtime: mtime,
			}
			setStatErr := c.SetStat(newName, attrs)
			c.Log(logger.LevelDebug, "mtime header found for %q, value: %s, err: %v", newName, mtime, setStatErr)
		}
	}
	return err
}

// Stat returns a FileInfo describing the named file/directory, or an error,
// if any happens
func (c *Connection) Stat(_ context.Context, name string) (os.FileInfo, error) {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	fi, err := c.DoStat(name, 0, true)
	if err != nil {
		return nil, err
	}
	return fi, err
}

// RemoveAll removes path and any children it contains.
// If the path does not exist, RemoveAll returns nil (no error).
func (c *Connection) RemoveAll(_ context.Context, name string) error {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	return c.BaseConnection.RemoveAll(name)
}

// OpenFile opens the named file with specified flag.
// This method is used for uploads and downloads but also for Stat and Readdir
func (c *Connection) OpenFile(_ context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return nil, err
	}

	if flag == os.O_RDONLY || c.request.Method == "PROPPATCH" {
		// Download, Stat, Readdir or simply open/close
		return c.getFile(fs, p, name)
	}
	return c.putFile(fs, p, name)
}

func (c *Connection) getFile(fs vfs.Fs, fsPath, virtualPath string) (webdav.File, error) {
	var cancelFn func()

	// we open the file when we receive the first read so we only open the file if necessary
	baseTransfer := common.NewBaseTransfer(nil, c.BaseConnection, cancelFn, fsPath, fsPath, virtualPath,
		common.TransferDownload, 0, 0, 0, 0, false, fs, c.GetTransferQuota())

	return newWebDavFile(baseTransfer, nil, nil), nil
}

func (c *Connection) putFile(fs vfs.Fs, fsPath, virtualPath string) (webdav.File, error) {
	if ok, _ := c.User.IsFileAllowed(virtualPath); !ok {
		c.Log(logger.LevelWarn, "writing file %q is not allowed", virtualPath)
		return nil, c.GetPermissionDeniedError()
	}

	filePath := fsPath
	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		filePath = fs.GetAtomicUploadPath(fsPath)
	}

	stat, statErr := fs.Lstat(fsPath)
	if (statErr == nil && stat.Mode()&os.ModeSymlink != 0) || fs.IsNotExist(statErr) {
		if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(virtualPath)) {
			return nil, c.GetPermissionDeniedError()
		}
		return c.handleUploadToNewFile(fs, fsPath, filePath, virtualPath)
	}

	if statErr != nil {
		c.Log(logger.LevelError, "error performing file stat %q: %+v", fsPath, statErr)
		return nil, c.GetFsError(fs, statErr)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelError, "attempted to open a directory for writing to: %q", fsPath)
		return nil, c.GetOpUnsupportedError()
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(virtualPath)) {
		return nil, c.GetPermissionDeniedError()
	}

	return c.handleUploadToExistingFile(fs, fsPath, filePath, stat.Size(), virtualPath)
}

func (c *Connection) handleUploadToNewFile(fs vfs.Fs, resolvedPath, filePath, requestPath string) (webdav.File, error) {
	diskQuota, transferQuota := c.HasSpace(true, false, requestPath)
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, common.ErrQuotaExceeded
	}
	if _, err := common.ExecutePreAction(c.BaseConnection, common.OperationPreUpload, resolvedPath, requestPath, 0, 0); err != nil {
		c.Log(logger.LevelDebug, "upload for file %q denied by pre action: %v", requestPath, err)
		return nil, c.GetPermissionDeniedError()
	}
	file, w, cancelFn, err := fs.Create(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, c.GetCreateChecks(requestPath, true, false))
	if err != nil {
		c.Log(logger.LevelError, "error creating file %q: %+v", resolvedPath, err)
		return nil, c.GetFsError(fs, err)
	}

	vfs.SetPathPermissions(fs, filePath, c.User.GetUID(), c.User.GetGID())

	// we can get an error only for resume
	maxWriteSize, _ := c.GetMaxWriteSize(diskQuota, false, 0, fs.IsUploadResumeSupported())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, 0, 0, maxWriteSize, 0, true, fs, transferQuota)
	mtime := c.getModificationTime()
	baseTransfer.SetTimes(resolvedPath, mtime, mtime)

	return newWebDavFile(baseTransfer, w, nil), nil
}

func (c *Connection) handleUploadToExistingFile(fs vfs.Fs, resolvedPath, filePath string, fileSize int64,
	requestPath string,
) (webdav.File, error) {
	var err error
	diskQuota, transferQuota := c.HasSpace(false, false, requestPath)
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, common.ErrQuotaExceeded
	}
	if _, err := common.ExecutePreAction(c.BaseConnection, common.OperationPreUpload, resolvedPath, requestPath,
		fileSize, os.O_TRUNC); err != nil {
		c.Log(logger.LevelDebug, "upload for file %q denied by pre action: %v", requestPath, err)
		return nil, c.GetPermissionDeniedError()
	}

	// if there is a size limit remaining size cannot be 0 here, since quotaResult.HasSpace
	// will return false in this case and we deny the upload before
	maxWriteSize, _ := c.GetMaxWriteSize(diskQuota, false, fileSize, fs.IsUploadResumeSupported())

	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		_, _, err = fs.Rename(resolvedPath, filePath)
		if err != nil {
			c.Log(logger.LevelError, "error renaming existing file for atomic upload, source: %q, dest: %q, err: %+v",
				resolvedPath, filePath, err)
			return nil, c.GetFsError(fs, err)
		}
	}

	file, w, cancelFn, err := fs.Create(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, c.GetCreateChecks(requestPath, false, false))
	if err != nil {
		c.Log(logger.LevelError, "error creating file %q: %+v", resolvedPath, err)
		return nil, c.GetFsError(fs, err)
	}
	initialSize := int64(0)
	truncatedSize := int64(0) // bytes truncated and not included in quota
	if vfs.HasTruncateSupport(fs) {
		vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(requestPath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(&vfolder.BaseVirtualFolder, 0, -fileSize, false) //nolint:errcheck
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(&c.User, 0, -fileSize, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(&c.User, 0, -fileSize, false) //nolint:errcheck
		}
	} else {
		initialSize = fileSize
		truncatedSize = fileSize
	}

	vfs.SetPathPermissions(fs, filePath, c.User.GetUID(), c.User.GetGID())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, 0, initialSize, maxWriteSize, truncatedSize, false, fs, transferQuota)
	mtime := c.getModificationTime()
	baseTransfer.SetTimes(resolvedPath, mtime, mtime)

	return newWebDavFile(baseTransfer, w, nil), nil
}
