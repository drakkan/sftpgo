package ftpd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

var (
	errNotImplemented   = errors.New("not implemented")
	errCOMBNotSupported = errors.New("COMB is not supported for this filesystem")
)

// Connection details for an FTP connection.
// It implements common.ActiveConnection and ftpserver.ClientDriver interfaces
type Connection struct {
	*common.BaseConnection
	clientContext ftpserver.ClientContext
}

func (c *Connection) getFTPMode() string {
	if c.clientContext == nil {
		return ""
	}
	switch c.clientContext.GetLastDataChannel() {
	case ftpserver.DataChannelActive:
		return "active"
	case ftpserver.DataChannelPassive:
		return "passive"
	}
	return ""
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

// GetLocalAddress returns local connection address
func (c *Connection) GetLocalAddress() string {
	return c.clientContext.LocalAddr().String()
}

// GetRemoteAddress returns the connected client's address
func (c *Connection) GetRemoteAddress() string {
	return c.clientContext.RemoteAddr().String()
}

// Disconnect disconnects the client
func (c *Connection) Disconnect() error {
	return c.clientContext.Close()
}

// GetCommand returns the last received FTP command
func (c *Connection) GetCommand() string {
	return c.clientContext.GetLastCommand()
}

// Create is not implemented we use ClientDriverExtentionFileTransfer
func (c *Connection) Create(name string) (afero.File, error) {
	return nil, errNotImplemented
}

// Mkdir creates a directory using the connection filesystem
func (c *Connection) Mkdir(name string, perm os.FileMode) error {
	c.UpdateLastActivity()

	return c.CreateDir(name, true)
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

	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return err
	}

	var fi os.FileInfo
	if fi, err = fs.Lstat(p); err != nil {
		c.Log(logger.LevelError, "failed to remove file %#v: stat error: %+v", p, err)
		return c.GetFsError(fs, err)
	}

	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		c.Log(logger.LevelError, "cannot remove %#v is not a file/symlink", p)
		return c.GetGenericError(nil)
	}
	return c.RemoveFile(fs, p, name, fi)
}

// RemoveAll is not implemented, we don't need it
func (c *Connection) RemoveAll(path string) error {
	return errNotImplemented
}

// Rename renames a file or a directory
func (c *Connection) Rename(oldname, newname string) error {
	c.UpdateLastActivity()

	return c.BaseConnection.Rename(oldname, newname)
}

// Stat returns a FileInfo describing the named file/directory, or an error,
// if any happens
func (c *Connection) Stat(name string) (os.FileInfo, error) {
	c.UpdateLastActivity()

	if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	fi, err := c.DoStat(name, 0, true)
	if err != nil {
		return nil, err
	}
	return fi, nil
}

// Name returns the name of this connection
func (c *Connection) Name() string {
	return c.GetID()
}

// Chown changes the uid and gid of the named file
func (c *Connection) Chown(name string, uid, gid int) error {
	c.UpdateLastActivity()

	return common.ErrOpUnsupported
	/*p, err := c.Fs.ResolvePath(name)
	if err != nil {
		return c.GetFsError(err)
	}
	attrs := common.StatAttributes{
		Flags: common.StatAttrUIDGID,
		UID:   uid,
		GID:   gid,
	}

	return c.SetStat(p, name, &attrs)*/
}

// Chmod changes the mode of the named file/directory
func (c *Connection) Chmod(name string, mode os.FileMode) error {
	c.UpdateLastActivity()

	attrs := common.StatAttributes{
		Flags: common.StatAttrPerms,
		Mode:  mode,
	}
	return c.SetStat(name, &attrs)
}

// Chtimes changes the access and modification times of the named file
func (c *Connection) Chtimes(name string, atime time.Time, mtime time.Time) error {
	c.UpdateLastActivity()

	attrs := common.StatAttributes{
		Flags: common.StatAttrTimes,
		Atime: atime,
		Mtime: mtime,
	}
	return c.SetStat(name, &attrs)
}

// GetAvailableSpace implements ClientDriverExtensionAvailableSpace interface
func (c *Connection) GetAvailableSpace(dirName string) (int64, error) {
	c.UpdateLastActivity()

	diskQuota, transferQuota := c.HasSpace(false, false, path.Join(dirName, "fakefile.txt"))
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() {
		return 0, nil
	}

	if diskQuota.AllowedSize == 0 && transferQuota.AllowedULSize == 0 && transferQuota.AllowedTotalSize == 0 {
		// no quota restrictions
		if c.User.Filters.MaxUploadFileSize > 0 {
			return c.User.Filters.MaxUploadFileSize, nil
		}

		fs, p, err := c.GetFsAndResolvedPath(dirName)
		if err != nil {
			return 0, err
		}

		statVFS, err := fs.GetAvailableDiskSize(p)
		if err != nil {
			return 0, c.GetFsError(fs, err)
		}
		return int64(statVFS.FreeSpace()), nil
	}

	allowedDiskSize := diskQuota.AllowedSize
	allowedUploadSize := transferQuota.AllowedULSize
	if transferQuota.AllowedTotalSize > 0 {
		allowedUploadSize = transferQuota.AllowedTotalSize
	}
	allowedSize := allowedDiskSize
	if allowedSize == 0 {
		allowedSize = allowedUploadSize
	} else {
		if allowedUploadSize > 0 && allowedUploadSize < allowedSize {
			allowedSize = allowedUploadSize
		}
	}
	// the available space is the minimum between MaxUploadFileSize, if setted,
	// and quota allowed size
	if c.User.Filters.MaxUploadFileSize > 0 {
		if c.User.Filters.MaxUploadFileSize < allowedSize {
			return c.User.Filters.MaxUploadFileSize, nil
		}
	}

	return allowedSize, nil
}

// AllocateSpace implements ClientDriverExtensionAllocate interface
func (c *Connection) AllocateSpace(size int) error {
	c.UpdateLastActivity()
	// we treat ALLO as NOOP see RFC 959
	return nil
}

// RemoveDir implements ClientDriverExtensionRemoveDir
func (c *Connection) RemoveDir(name string) error {
	c.UpdateLastActivity()

	return c.BaseConnection.RemoveDir(name)
}

// Symlink implements ClientDriverExtensionSymlink
func (c *Connection) Symlink(oldname, newname string) error {
	c.UpdateLastActivity()

	return c.BaseConnection.CreateSymlink(oldname, newname)
}

// ReadDir implements ClientDriverExtensionFilelist
func (c *Connection) ReadDir(name string) ([]os.FileInfo, error) {
	c.UpdateLastActivity()

	files, err := c.ListDir(name)
	if err != nil {
		return files, err
	}
	if name != "/" {
		files = util.PrependFileInfo(files, vfs.NewFileInfo("..", true, 0, time.Now(), false))
	}
	files = util.PrependFileInfo(files, vfs.NewFileInfo(".", true, 0, time.Now(), false))
	return files, nil
}

// GetHandle implements ClientDriverExtentionFileTransfer
func (c *Connection) GetHandle(name string, flags int, offset int64) (ftpserver.FileTransfer, error) {
	c.UpdateLastActivity()

	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return nil, err
	}

	if c.GetCommand() == "COMB" && !vfs.IsLocalOsFs(fs) {
		return nil, errCOMBNotSupported
	}

	if flags&os.O_WRONLY != 0 {
		return c.uploadFile(fs, p, name, flags)
	}
	return c.downloadFile(fs, p, name, offset)
}

func (c *Connection) downloadFile(fs vfs.Fs, fsPath, ftpPath string, offset int64) (ftpserver.FileTransfer, error) {
	if !c.User.HasPerm(dataprovider.PermDownload, path.Dir(ftpPath)) {
		return nil, c.GetPermissionDeniedError()
	}
	transferQuota := c.GetTransferQuota()
	if !transferQuota.HasDownloadSpace() {
		c.Log(logger.LevelInfo, "denying file read due to quota limits")
		return nil, c.GetReadQuotaExceededError()
	}

	if ok, policy := c.User.IsFileAllowed(ftpPath); !ok {
		c.Log(logger.LevelWarn, "reading file %#v is not allowed", ftpPath)
		return nil, c.GetErrorForDeniedFile(policy)
	}

	if err := common.ExecutePreAction(c.BaseConnection, common.OperationPreDownload, fsPath, ftpPath, 0, 0); err != nil {
		c.Log(logger.LevelDebug, "download for file %#v denied by pre action: %v", ftpPath, err)
		return nil, c.GetPermissionDeniedError()
	}

	file, r, cancelFn, err := fs.Open(fsPath, offset)
	if err != nil {
		c.Log(logger.LevelError, "could not open file %#v for reading: %+v", fsPath, err)
		return nil, c.GetFsError(fs, err)
	}

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, fsPath, fsPath, ftpPath,
		common.TransferDownload, 0, 0, 0, 0, false, fs, transferQuota)
	baseTransfer.SetFtpMode(c.getFTPMode())
	t := newTransfer(baseTransfer, nil, r, offset)

	return t, nil
}

func (c *Connection) uploadFile(fs vfs.Fs, fsPath, ftpPath string, flags int) (ftpserver.FileTransfer, error) {
	if ok, _ := c.User.IsFileAllowed(ftpPath); !ok {
		c.Log(logger.LevelWarn, "writing file %#v is not allowed", ftpPath)
		return nil, ftpserver.ErrFileNameNotAllowed
	}

	filePath := fsPath
	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		filePath = fs.GetAtomicUploadPath(fsPath)
	}

	stat, statErr := fs.Lstat(fsPath)
	if (statErr == nil && stat.Mode()&os.ModeSymlink != 0) || fs.IsNotExist(statErr) {
		if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(ftpPath)) {
			return nil, fmt.Errorf("%w, no upload permission", ftpserver.ErrFileNameNotAllowed)
		}
		return c.handleFTPUploadToNewFile(fs, flags, fsPath, filePath, ftpPath)
	}

	if statErr != nil {
		c.Log(logger.LevelError, "error performing file stat %#v: %+v", fsPath, statErr)
		return nil, c.GetFsError(fs, statErr)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelError, "attempted to open a directory for writing to: %#v", fsPath)
		return nil, c.GetOpUnsupportedError()
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(ftpPath)) {
		return nil, fmt.Errorf("%w, no overwrite permission", ftpserver.ErrFileNameNotAllowed)
	}

	return c.handleFTPUploadToExistingFile(fs, flags, fsPath, filePath, stat.Size(), ftpPath)
}

func (c *Connection) handleFTPUploadToNewFile(fs vfs.Fs, flags int, resolvedPath, filePath, requestPath string) (ftpserver.FileTransfer, error) {
	diskQuota, transferQuota := c.HasSpace(true, false, requestPath)
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, ftpserver.ErrStorageExceeded
	}
	if err := common.ExecutePreAction(c.BaseConnection, common.OperationPreUpload, resolvedPath, requestPath, 0, 0); err != nil {
		c.Log(logger.LevelDebug, "upload for file %#v denied by pre action: %v", requestPath, err)
		return nil, fmt.Errorf("%w, denied by pre-upload action", ftpserver.ErrFileNameNotAllowed)
	}
	file, w, cancelFn, err := fs.Create(filePath, flags)
	if err != nil {
		c.Log(logger.LevelError, "error creating file %#v, flags %v: %+v", resolvedPath, flags, err)
		return nil, c.GetFsError(fs, err)
	}

	vfs.SetPathPermissions(fs, filePath, c.User.GetUID(), c.User.GetGID())

	// we can get an error only for resume
	maxWriteSize, _ := c.GetMaxWriteSize(diskQuota, false, 0, fs.IsUploadResumeSupported())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, 0, 0, maxWriteSize, 0, true, fs, transferQuota)
	baseTransfer.SetFtpMode(c.getFTPMode())
	t := newTransfer(baseTransfer, w, nil, 0)

	return t, nil
}

func (c *Connection) handleFTPUploadToExistingFile(fs vfs.Fs, flags int, resolvedPath, filePath string, fileSize int64,
	requestPath string) (ftpserver.FileTransfer, error) {
	var err error
	diskQuota, transferQuota := c.HasSpace(false, false, requestPath)
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, ftpserver.ErrStorageExceeded
	}
	minWriteOffset := int64(0)
	// ftpserverlib sets:
	// - os.O_WRONLY | os.O_APPEND for APPE and COMB
	// - os.O_WRONLY | os.O_CREATE for REST.
	// - os.O_WRONLY | os.O_CREATE | os.O_TRUNC if the command is not APPE and REST = 0
	// so if we don't have O_TRUNC is a resume.
	isResume := flags&os.O_TRUNC == 0
	// if there is a size limit remaining size cannot be 0 here, since quotaResult.HasSpace
	// will return false in this case and we deny the upload before
	maxWriteSize, err := c.GetMaxWriteSize(diskQuota, isResume, fileSize, fs.IsUploadResumeSupported())
	if err != nil {
		c.Log(logger.LevelDebug, "unable to get max write size: %v", err)
		return nil, err
	}
	if err := common.ExecutePreAction(c.BaseConnection, common.OperationPreUpload, resolvedPath, requestPath, fileSize, flags); err != nil {
		c.Log(logger.LevelDebug, "upload for file %#v denied by pre action: %v", requestPath, err)
		return nil, fmt.Errorf("%w, denied by pre-upload action", ftpserver.ErrFileNameNotAllowed)
	}

	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		err = fs.Rename(resolvedPath, filePath)
		if err != nil {
			c.Log(logger.LevelError, "error renaming existing file for atomic upload, source: %#v, dest: %#v, err: %+v",
				resolvedPath, filePath, err)
			return nil, c.GetFsError(fs, err)
		}
	}

	file, w, cancelFn, err := fs.Create(filePath, flags)
	if err != nil {
		c.Log(logger.LevelError, "error opening existing file, flags: %v, source: %#v, err: %+v", flags, filePath, err)
		return nil, c.GetFsError(fs, err)
	}

	initialSize := int64(0)
	truncatedSize := int64(0) // bytes truncated and not included in quota
	if isResume {
		c.Log(logger.LevelDebug, "resuming upload requested, file path: %#v initial size: %v", filePath, fileSize)
		minWriteOffset = fileSize
		initialSize = fileSize
		if vfs.IsSFTPFs(fs) && fs.IsUploadResumeSupported() {
			// we need this since we don't allow resume with wrong offset, we should fix this in pkg/sftp
			file.Seek(initialSize, io.SeekStart) //nolint:errcheck // for sftp seek simply set the offset
		}
	} else {
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
			truncatedSize = fileSize
		}
	}

	vfs.SetPathPermissions(fs, filePath, c.User.GetUID(), c.User.GetGID())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, minWriteOffset, initialSize, maxWriteSize, truncatedSize, false, fs, transferQuota)
	baseTransfer.SetFtpMode(c.getFTPMode())
	t := newTransfer(baseTransfer, w, nil, 0)

	return t, nil
}
