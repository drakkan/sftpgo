package ftpd

import (
	"errors"
	"os"
	"path"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
)

var (
	errNotImplemented = errors.New("Not implemented")
)

// Connection details for an FTP connection.
// It implements common.ActiveConnection and ftpserver.ClientDriver interfaces
type Connection struct {
	*common.BaseConnection
	clientContext ftpserver.ClientContext
}

// GetClientVersion returns the connected client's version.
// It returns "Unknown" if the client does not advertise its
// version
func (c *Connection) GetClientVersion() string {
	version := c.clientContext.GetClientVersion()
	if len(version) > 0 {
		return version
	}
	return "Unknown"
}

// GetRemoteAddress return the connected client's address
func (c *Connection) GetRemoteAddress() string {
	return c.clientContext.RemoteAddr().String()
}

// Disconnect disconnects the client
func (c *Connection) Disconnect() error {
	return c.clientContext.Close(ftpserver.StatusServiceNotAvailable, "connection closed")
}

// GetCommand returns an empty string
func (c *Connection) GetCommand() string {
	return ""
}

// Create is not implemented we use ClientDriverExtentionFileTransfer
func (c *Connection) Create(name string) (afero.File, error) {
	return nil, errNotImplemented
}

// Mkdir creates a directory using the connection filesystem
func (c *Connection) Mkdir(name string, perm os.FileMode) error {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return c.GetFsError(err)
	}
	return c.CreateDir(p, name)
}

// MkdirAll is not implemented, we don't need it
func (c *Connection) MkdirAll(path string, perm os.FileMode) error {
	return errNotImplemented
}

// Open is not implemented we use ClientDriverExtentionFileTransfer and ClientDriverExtensionFileList
func (c *Connection) Open(name string) (afero.File, error) {
	return nil, errNotImplemented
}

// OpenFile is not implemented we use ClientDriverExtentionFileTransfer
func (c *Connection) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	return nil, errNotImplemented
}

// Remove removes a file.
// We implements ClientDriverExtensionRemoveDir for directories
func (c *Connection) Remove(name string) error {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return c.GetFsError(err)
	}

	var fi os.FileInfo
	if fi, err = c.Fs.Lstat(p); err != nil {
		c.Log(logger.LevelWarn, "failed to remove a file %#v: stat error: %+v", p, err)
		return c.GetFsError(err)
	}

	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		c.Log(logger.LevelDebug, "cannot remove %#v is not a file/symlink", p)
		return c.GetGenericError(nil)
	}
	return c.RemoveFile(p, name, fi)
}

// RemoveAll is not implemented, we don't need it
func (c *Connection) RemoveAll(path string) error {
	return errNotImplemented
}

// Rename renames a file or a directory
func (c *Connection) Rename(oldname, newname string) error {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(oldname)
	if err != nil {
		return c.GetFsError(err)
	}
	t, err := c.Fs.ResolvePath(newname)
	if err != nil {
		return c.GetFsError(err)
	}

	if err = c.BaseConnection.Rename(p, t, oldname, newname); err != nil {
		return err
	}

	vfs.SetPathPermissions(c.Fs, t, c.User.GetUID(), c.User.GetGID())
	return nil
}

// Stat returns a FileInfo describing the named file/directory, or an error,
// if any happens
func (c *Connection) Stat(name string) (os.FileInfo, error) {
	c.UpdateLastActivity()

	if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return nil, c.GetFsError(err)
	}
	fi, err := c.DoStat(p, 0)
	if err != nil {
		c.Log(logger.LevelDebug, "error running stat on path %#v: %+v", p, err)
		return nil, c.GetFsError(err)
	}
	return fi, nil
}

// Name returns the name of this connection
func (c *Connection) Name() string {
	return c.GetID()
}

// Chmod changes the mode of the named file/directory
func (c *Connection) Chmod(name string, mode os.FileMode) error {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return c.GetFsError(err)
	}
	attrs := common.StatAttributes{
		Flags: common.StatAttrPerms,
		Mode:  mode,
	}
	return c.SetStat(p, name, &attrs)
}

// Chtimes changes the access and modification times of the named file
func (c *Connection) Chtimes(name string, atime time.Time, mtime time.Time) error {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return c.GetFsError(err)
	}
	attrs := common.StatAttributes{
		Flags: common.StatAttrTimes,
		Atime: atime,
		Mtime: mtime,
	}
	return c.SetStat(p, name, &attrs)
}

// AllocateSpace implements ClientDriverExtensionAllocate
func (c *Connection) AllocateSpace(size int) error {
	c.UpdateLastActivity()
	// check the max allowed file size first
	if c.User.Filters.MaxUploadFileSize > 0 && int64(size) > c.User.Filters.MaxUploadFileSize {
		return common.ErrQuotaExceeded
	}

	// we don't have a path here so we check home dir and any virtual folders
	// we return no error if there is space in any folder
	folders := []string{"/"}
	for _, v := range c.User.VirtualFolders {
		// the space is checked for the parent folder
		folders = append(folders, path.Join(v.VirtualPath, "fakefile.txt"))
	}
	for _, f := range folders {
		quotaResult := c.HasSpace(false, f)
		if quotaResult.HasSpace {
			if quotaResult.QuotaSize == 0 {
				// unlimited size is allowed
				return nil
			}
			if quotaResult.GetRemainingSize() > int64(size) {
				return nil
			}
		}
	}
	return common.ErrQuotaExceeded
}

// RemoveDir implements ClientDriverExtensionRemoveDir
func (c *Connection) RemoveDir(name string) error {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return c.GetFsError(err)
	}

	return c.BaseConnection.RemoveDir(p, name)
}

// Symlink implements ClientDriverExtensionSymlink
func (c *Connection) Symlink(oldname, newname string) error {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(oldname)
	if err != nil {
		return c.GetFsError(err)
	}
	t, err := c.Fs.ResolvePath(newname)
	if err != nil {
		return c.GetFsError(err)
	}

	return c.BaseConnection.CreateSymlink(p, t, oldname, newname)
}

// ReadDir implements ClientDriverExtensionFilelist
func (c *Connection) ReadDir(name string) ([]os.FileInfo, error) {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return nil, c.GetFsError(err)
	}
	return c.ListDir(p, name)
}

// GetHandle implements ClientDriverExtentionFileTransfer
func (c *Connection) GetHandle(name string, flags int, offset int64) (ftpserver.FileTransfer, error) {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return nil, c.GetFsError(err)
	}
	if flags&os.O_WRONLY != 0 {
		return c.uploadFile(p, name, flags)
	}
	return c.downloadFile(p, name, offset)
}

func (c *Connection) downloadFile(fsPath, ftpPath string, offset int64) (ftpserver.FileTransfer, error) {
	if !c.User.HasPerm(dataprovider.PermDownload, path.Dir(ftpPath)) {
		return nil, c.GetPermissionDeniedError()
	}

	if !c.User.IsFileAllowed(ftpPath) {
		c.Log(logger.LevelWarn, "reading file %#v is not allowed", ftpPath)
		return nil, c.GetPermissionDeniedError()
	}

	file, r, cancelFn, err := c.Fs.Open(fsPath, offset)
	if err != nil {
		c.Log(logger.LevelWarn, "could not open file %#v for reading: %+v", fsPath, err)
		return nil, c.GetFsError(err)
	}

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, fsPath, ftpPath, common.TransferDownload,
		0, 0, 0, false, c.Fs)
	t := newTransfer(baseTransfer, nil, r, offset)

	return t, nil
}

func (c *Connection) uploadFile(fsPath, ftpPath string, flags int) (ftpserver.FileTransfer, error) {
	if !c.User.IsFileAllowed(ftpPath) {
		c.Log(logger.LevelWarn, "writing file %#v is not allowed", ftpPath)
		return nil, c.GetPermissionDeniedError()
	}

	filePath := fsPath
	if common.Config.IsAtomicUploadEnabled() && c.Fs.IsAtomicUploadSupported() {
		filePath = c.Fs.GetAtomicUploadPath(fsPath)
	}

	stat, statErr := c.Fs.Lstat(fsPath)
	if (statErr == nil && stat.Mode()&os.ModeSymlink != 0) || c.Fs.IsNotExist(statErr) {
		if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(ftpPath)) {
			return nil, c.GetPermissionDeniedError()
		}
		return c.handleFTPUploadToNewFile(fsPath, filePath, ftpPath)
	}

	if statErr != nil {
		c.Log(logger.LevelError, "error performing file stat %#v: %+v", fsPath, statErr)
		return nil, c.GetFsError(statErr)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelWarn, "attempted to open a directory for writing to: %#v", fsPath)
		return nil, c.GetOpUnsupportedError()
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(ftpPath)) {
		return nil, c.GetPermissionDeniedError()
	}

	return c.handleFTPUploadToExistingFile(flags, fsPath, filePath, stat.Size(), ftpPath)
}

func (c *Connection) handleFTPUploadToNewFile(resolvedPath, filePath, requestPath string) (ftpserver.FileTransfer, error) {
	quotaResult := c.HasSpace(true, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, common.ErrQuotaExceeded
	}
	file, w, cancelFn, err := c.Fs.Create(filePath, 0)
	if err != nil {
		c.Log(logger.LevelWarn, "error creating file %#v: %+v", resolvedPath, err)
		return nil, c.GetFsError(err)
	}

	vfs.SetPathPermissions(c.Fs, filePath, c.User.GetUID(), c.User.GetGID())

	// we can get an error only for resume
	maxWriteSize, _ := c.GetMaxWriteSize(quotaResult, false, 0)

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, requestPath,
		common.TransferUpload, 0, 0, maxWriteSize, true, c.Fs)
	t := newTransfer(baseTransfer, w, nil, 0)

	return t, nil
}

func (c *Connection) handleFTPUploadToExistingFile(flags int, resolvedPath, filePath string, fileSize int64,
	requestPath string) (ftpserver.FileTransfer, error) {
	var err error
	quotaResult := c.HasSpace(false, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, common.ErrQuotaExceeded
	}
	minWriteOffset := int64(0)
	// ftpserverlib set os.O_WRONLY | os.O_APPEND for APPE
	// and os.O_WRONLY | os.O_CREATE for REST. If is not APPE
	// and REST = 0 then os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	// so if we don't have O_TRUC is a resume
	isResume := flags&os.O_TRUNC == 0
	// if there is a size limit remaining size cannot be 0 here, since quotaResult.HasSpace
	// will return false in this case and we deny the upload before
	maxWriteSize, err := c.GetMaxWriteSize(quotaResult, isResume, fileSize)
	if err != nil {
		c.Log(logger.LevelDebug, "unable to get max write size: %v", err)
		return nil, err
	}

	if common.Config.IsAtomicUploadEnabled() && c.Fs.IsAtomicUploadSupported() {
		err = c.Fs.Rename(resolvedPath, filePath)
		if err != nil {
			c.Log(logger.LevelWarn, "error renaming existing file for atomic upload, source: %#v, dest: %#v, err: %+v",
				resolvedPath, filePath, err)
			return nil, c.GetFsError(err)
		}
	}

	file, w, cancelFn, err := c.Fs.Create(filePath, flags)
	if err != nil {
		c.Log(logger.LevelWarn, "error opening existing file, flags: %v, source: %#v, err: %+v", flags, filePath, err)
		return nil, c.GetFsError(err)
	}

	initialSize := int64(0)
	if isResume {
		c.Log(logger.LevelDebug, "upload resume requested, file path: %#v initial size: %v", filePath, fileSize)
		minWriteOffset = fileSize
		initialSize = fileSize
	} else {
		if vfs.IsLocalOsFs(c.Fs) {
			vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(requestPath))
			if err == nil {
				dataprovider.UpdateVirtualFolderQuota(vfolder.BaseVirtualFolder, 0, -fileSize, false) //nolint:errcheck
				if vfolder.IsIncludedInUserQuota() {
					dataprovider.UpdateUserQuota(c.User, 0, -fileSize, false) //nolint:errcheck
				}
			} else {
				dataprovider.UpdateUserQuota(c.User, 0, -fileSize, false) //nolint:errcheck
			}
		} else {
			initialSize = fileSize
		}
	}

	vfs.SetPathPermissions(c.Fs, filePath, c.User.GetUID(), c.User.GetGID())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, requestPath,
		common.TransferUpload, minWriteOffset, initialSize, maxWriteSize, false, c.Fs)
	t := newTransfer(baseTransfer, w, nil, 0)

	return t, nil
}
