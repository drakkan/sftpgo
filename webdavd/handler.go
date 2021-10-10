package webdavd

import (
	"context"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/eikenb/pipeat"
	"golang.org/x/net/webdav"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

// Connection details for a WebDav connection.
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
func (c *Connection) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	return c.CreateDir(name)
}

// Rename renames a file or a directory
func (c *Connection) Rename(ctx context.Context, oldName, newName string) error {
	c.UpdateLastActivity()

	oldName = util.CleanPath(oldName)
	newName = util.CleanPath(newName)

	return c.BaseConnection.Rename(oldName, newName)
}

// Stat returns a FileInfo describing the named file/directory, or an error,
// if any happens
func (c *Connection) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	fi, err := c.DoStat(name, 0)
	if err != nil {
		c.Log(logger.LevelDebug, "error running stat on path %#v: %+v", name, err)
		return nil, err
	}
	return fi, err
}

// RemoveAll removes path and any children it contains.
// If the path does not exist, RemoveAll returns nil (no error).
func (c *Connection) RemoveAll(ctx context.Context, name string) error {
	c.UpdateLastActivity()

	name = util.CleanPath(name)
	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return err
	}

	var fi os.FileInfo
	if fi, err = fs.Lstat(p); err != nil {
		c.Log(logger.LevelDebug, "failed to remove a file %#v: stat error: %+v", p, err)
		return c.GetFsError(fs, err)
	}

	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		return c.removeDirTree(fs, p, name)
	}
	return c.RemoveFile(fs, p, name, fi)
}

// OpenFile opens the named file with specified flag.
// This method is used for uploads and downloads but also for Stat and Readdir
func (c *Connection) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
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
	var err error
	var file vfs.File
	var r *pipeat.PipeReaderAt
	var cancelFn func()

	// for cloud fs we open the file when we receive the first read to avoid to download the first part of
	// the file if it was opened only to do a stat or a readdir and so it is not a real download
	if vfs.IsLocalOrUnbufferedSFTPFs(fs) {
		file, r, cancelFn, err = fs.Open(fsPath, 0)
		if err != nil {
			c.Log(logger.LevelWarn, "could not open file %#v for reading: %+v", fsPath, err)
			return nil, c.GetFsError(fs, err)
		}
	}

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, fsPath, fsPath, virtualPath, common.TransferDownload,
		0, 0, 0, false, fs)

	return newWebDavFile(baseTransfer, nil, r), nil
}

func (c *Connection) putFile(fs vfs.Fs, fsPath, virtualPath string) (webdav.File, error) {
	if !c.User.IsFileAllowed(virtualPath) {
		c.Log(logger.LevelWarn, "writing file %#v is not allowed", virtualPath)
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
		c.Log(logger.LevelError, "error performing file stat %#v: %+v", fsPath, statErr)
		return nil, c.GetFsError(fs, statErr)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelWarn, "attempted to open a directory for writing to: %#v", fsPath)
		return nil, c.GetOpUnsupportedError()
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(virtualPath)) {
		return nil, c.GetPermissionDeniedError()
	}

	return c.handleUploadToExistingFile(fs, fsPath, filePath, stat.Size(), virtualPath)
}

func (c *Connection) handleUploadToNewFile(fs vfs.Fs, resolvedPath, filePath, requestPath string) (webdav.File, error) {
	quotaResult := c.HasSpace(true, false, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, common.ErrQuotaExceeded
	}
	if err := common.ExecutePreAction(&c.User, common.OperationPreUpload, resolvedPath, requestPath, c.GetProtocol(), c.GetRemoteIP(), 0, 0); err != nil {
		c.Log(logger.LevelDebug, "upload for file %#v denied by pre action: %v", requestPath, err)
		return nil, c.GetPermissionDeniedError()
	}
	file, w, cancelFn, err := fs.Create(filePath, 0)
	if err != nil {
		c.Log(logger.LevelWarn, "error creating file %#v: %+v", resolvedPath, err)
		return nil, c.GetFsError(fs, err)
	}

	vfs.SetPathPermissions(fs, filePath, c.User.GetUID(), c.User.GetGID())

	// we can get an error only for resume
	maxWriteSize, _ := c.GetMaxWriteSize(quotaResult, false, 0, fs.IsUploadResumeSupported())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, 0, 0, maxWriteSize, true, fs)

	return newWebDavFile(baseTransfer, w, nil), nil
}

func (c *Connection) handleUploadToExistingFile(fs vfs.Fs, resolvedPath, filePath string, fileSize int64,
	requestPath string) (webdav.File, error) {
	var err error
	quotaResult := c.HasSpace(false, false, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, common.ErrQuotaExceeded
	}
	if err := common.ExecutePreAction(&c.User, common.OperationPreUpload, resolvedPath, requestPath, c.GetProtocol(), c.GetRemoteIP(),
		fileSize, os.O_TRUNC); err != nil {
		c.Log(logger.LevelDebug, "upload for file %#v denied by pre action: %v", requestPath, err)
		return nil, c.GetPermissionDeniedError()
	}

	// if there is a size limit remaining size cannot be 0 here, since quotaResult.HasSpace
	// will return false in this case and we deny the upload before
	maxWriteSize, _ := c.GetMaxWriteSize(quotaResult, false, fileSize, fs.IsUploadResumeSupported())

	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		err = fs.Rename(resolvedPath, filePath)
		if err != nil {
			c.Log(logger.LevelWarn, "error renaming existing file for atomic upload, source: %#v, dest: %#v, err: %+v",
				resolvedPath, filePath, err)
			return nil, c.GetFsError(fs, err)
		}
	}

	file, w, cancelFn, err := fs.Create(filePath, 0)
	if err != nil {
		c.Log(logger.LevelWarn, "error creating file %#v: %+v", resolvedPath, err)
		return nil, c.GetFsError(fs, err)
	}
	initialSize := int64(0)
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

	vfs.SetPathPermissions(fs, filePath, c.User.GetUID(), c.User.GetGID())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, 0, initialSize, maxWriteSize, false, fs)

	return newWebDavFile(baseTransfer, w, nil), nil
}

type objectMapping struct {
	fsPath      string
	virtualPath string
	info        os.FileInfo
}

func (c *Connection) removeDirTree(fs vfs.Fs, fsPath, virtualPath string) error {
	var dirsToRemove []objectMapping
	var filesToRemove []objectMapping

	err := fs.Walk(fsPath, func(walkedPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		obj := objectMapping{
			fsPath:      walkedPath,
			virtualPath: fs.GetRelativePath(walkedPath),
			info:        info,
		}
		if info.IsDir() {
			err = c.IsRemoveDirAllowed(fs, obj.fsPath, obj.virtualPath)
			isDuplicated := false
			for _, d := range dirsToRemove {
				if d.fsPath == obj.fsPath {
					isDuplicated = true
					break
				}
			}
			if !isDuplicated {
				dirsToRemove = append(dirsToRemove, obj)
			}
		} else {
			err = c.IsRemoveFileAllowed(obj.virtualPath)
			filesToRemove = append(filesToRemove, obj)
		}
		if err != nil {
			c.Log(logger.LevelDebug, "unable to remove dir tree, object %#v->%#v cannot be removed: %v",
				virtualPath, fsPath, err)
			return err
		}

		return nil
	})
	if err != nil {
		c.Log(logger.LevelWarn, "failed to remove dir tree %#v->%#v: error: %+v", virtualPath, fsPath, err)
		return err
	}

	for _, fileObj := range filesToRemove {
		err = c.RemoveFile(fs, fileObj.fsPath, fileObj.virtualPath, fileObj.info)
		if err != nil {
			c.Log(logger.LevelDebug, "unable to remove dir tree, error removing file %#v->%#v: %v",
				fileObj.virtualPath, fileObj.fsPath, err)
			return err
		}
	}

	for _, dirObj := range c.orderDirsToRemove(fs, dirsToRemove) {
		err = c.RemoveDir(dirObj.virtualPath)
		if err != nil {
			c.Log(logger.LevelDebug, "unable to remove dir tree, error removing directory %#v->%#v: %v",
				dirObj.virtualPath, dirObj.fsPath, err)
			return err
		}
	}

	return err
}

// order directories so that the empty ones will be at slice start
func (c *Connection) orderDirsToRemove(fs vfs.Fs, dirsToRemove []objectMapping) []objectMapping {
	orderedDirs := make([]objectMapping, 0, len(dirsToRemove))
	removedDirs := make([]string, 0, len(dirsToRemove))

	pathSeparator := "/"
	if vfs.IsLocalOsFs(fs) {
		pathSeparator = string(os.PathSeparator)
	}

	for len(orderedDirs) < len(dirsToRemove) {
		for idx, d := range dirsToRemove {
			if util.IsStringInSlice(d.fsPath, removedDirs) {
				continue
			}
			isEmpty := true
			for idx1, d1 := range dirsToRemove {
				if idx == idx1 {
					continue
				}
				if util.IsStringInSlice(d1.fsPath, removedDirs) {
					continue
				}
				if strings.HasPrefix(d1.fsPath, d.fsPath+pathSeparator) {
					isEmpty = false
					break
				}
			}
			if isEmpty {
				orderedDirs = append(orderedDirs, d)
				removedDirs = append(removedDirs, d.fsPath)
			}
		}
	}

	return orderedDirs
}
