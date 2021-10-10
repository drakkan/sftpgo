package httpd

import (
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

// Connection details for a HTTP connection used to inteact with an SFTPGo filesystem
type Connection struct {
	*common.BaseConnection
	request *http.Request
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
func (c *Connection) Disconnect() (err error) {
	return c.SignalTransfersAbort()
}

// GetCommand returns the request method
func (c *Connection) GetCommand() string {
	if c.request != nil {
		return strings.ToUpper(c.request.Method)
	}
	return ""
}

// Stat returns a FileInfo describing the named file/directory, or an error,
// if any happens
func (c *Connection) Stat(name string, mode int) (os.FileInfo, error) {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	fi, err := c.DoStat(name, mode)
	if err != nil {
		c.Log(logger.LevelDebug, "error running stat on path %#v: %+v", name, err)
		return nil, err
	}
	return fi, err
}

// ReadDir returns a list of directory entries
func (c *Connection) ReadDir(name string) ([]os.FileInfo, error) {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	return c.ListDir(name)
}

func (c *Connection) getFileReader(name string, offset int64, method string) (io.ReadCloser, error) {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	if !c.User.HasPerm(dataprovider.PermDownload, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	if !c.User.IsFileAllowed(name) {
		c.Log(logger.LevelWarn, "reading file %#v is not allowed", name)
		return nil, c.GetPermissionDeniedError()
	}

	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return nil, err
	}

	if method != http.MethodHead {
		if err := common.ExecutePreAction(&c.User, common.OperationPreDownload, p, name, c.GetProtocol(), c.GetRemoteIP(), 0, 0); err != nil {
			c.Log(logger.LevelDebug, "download for file %#v denied by pre action: %v", name, err)
			return nil, c.GetPermissionDeniedError()
		}
	}

	file, r, cancelFn, err := fs.Open(p, offset)
	if err != nil {
		c.Log(logger.LevelWarn, "could not open file %#v for reading: %+v", p, err)
		return nil, c.GetFsError(fs, err)
	}

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, p, p, name, common.TransferDownload,
		0, 0, 0, false, fs)
	return newHTTPDFile(baseTransfer, nil, r), nil
}

func (c *Connection) getFileWriter(name string) (io.WriteCloser, error) {
	c.UpdateLastActivity()

	if !c.User.IsFileAllowed(name) {
		c.Log(logger.LevelWarn, "writing file %#v is not allowed", name)
		return nil, c.GetPermissionDeniedError()
	}

	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return nil, err
	}
	filePath := p
	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		filePath = fs.GetAtomicUploadPath(p)
	}

	stat, statErr := fs.Lstat(p)
	if (statErr == nil && stat.Mode()&os.ModeSymlink != 0) || fs.IsNotExist(statErr) {
		if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(name)) {
			return nil, c.GetPermissionDeniedError()
		}
		return c.handleUploadFile(fs, p, filePath, name, true, 0)
	}

	if statErr != nil {
		c.Log(logger.LevelError, "error performing file stat %#v: %+v", p, statErr)
		return nil, c.GetFsError(fs, statErr)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelWarn, "attempted to open a directory for writing to: %#v", p)
		return nil, c.GetOpUnsupportedError()
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		err = fs.Rename(p, filePath)
		if err != nil {
			c.Log(logger.LevelWarn, "error renaming existing file for atomic upload, source: %#v, dest: %#v, err: %+v",
				p, filePath, err)
			return nil, c.GetFsError(fs, err)
		}
	}

	return c.handleUploadFile(fs, p, filePath, name, false, stat.Size())
}

func (c *Connection) handleUploadFile(fs vfs.Fs, resolvedPath, filePath, requestPath string, isNewFile bool, fileSize int64) (io.WriteCloser, error) {
	quotaResult := c.HasSpace(isNewFile, false, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, common.ErrQuotaExceeded
	}
	err := common.ExecutePreAction(&c.User, common.OperationPreUpload, resolvedPath, requestPath, c.GetProtocol(), c.GetRemoteIP(), fileSize, os.O_TRUNC)
	if err != nil {
		c.Log(logger.LevelDebug, "upload for file %#v denied by pre action: %v", requestPath, err)
		return nil, c.GetPermissionDeniedError()
	}

	maxWriteSize, _ := c.GetMaxWriteSize(quotaResult, false, fileSize, fs.IsUploadResumeSupported())

	file, w, cancelFn, err := fs.Create(filePath, 0)
	if err != nil {
		c.Log(logger.LevelWarn, "error opening existing file, source: %#v, err: %+v", filePath, err)
		return nil, c.GetFsError(fs, err)
	}

	initialSize := int64(0)
	if !isNewFile {
		if vfs.IsLocalOrSFTPFs(fs) {
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
		}
		if maxWriteSize > 0 {
			maxWriteSize += fileSize
		}
	}

	vfs.SetPathPermissions(fs, filePath, c.User.GetUID(), c.User.GetGID())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, 0, initialSize, maxWriteSize, isNewFile, fs)
	return newHTTPDFile(baseTransfer, w, nil), nil
}
