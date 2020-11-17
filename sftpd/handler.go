package sftpd

import (
	"io"
	"net"
	"os"
	"path"
	"time"

	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
)

// Connection details for an authenticated user
type Connection struct {
	*common.BaseConnection
	// client's version string
	ClientVersion string
	// Remote address for this connection
	RemoteAddr net.Addr
	channel    io.ReadWriteCloser
	command    string
}

// GetClientVersion returns the connected client's version
func (c *Connection) GetClientVersion() string {
	return c.ClientVersion
}

// GetRemoteAddress return the connected client's address
func (c *Connection) GetRemoteAddress() string {
	return c.RemoteAddr.String()
}

// GetCommand returns the SSH command, if any
func (c *Connection) GetCommand() string {
	return c.command
}

// Fileread creates a reader for a file on the system and returns the reader back.
func (c *Connection) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	c.UpdateLastActivity()

	if !c.User.HasPerm(dataprovider.PermDownload, path.Dir(request.Filepath)) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	if !c.User.IsFileAllowed(request.Filepath) {
		c.Log(logger.LevelWarn, "reading file %#v is not allowed", request.Filepath)
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	p, err := c.Fs.ResolvePath(request.Filepath)
	if err != nil {
		return nil, c.GetFsError(err)
	}

	file, r, cancelFn, err := c.Fs.Open(p, 0)
	if err != nil {
		c.Log(logger.LevelWarn, "could not open file %#v for reading: %+v", p, err)
		return nil, c.GetFsError(err)
	}

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, p, request.Filepath, common.TransferDownload,
		0, 0, 0, false, c.Fs)
	t := newTransfer(baseTransfer, nil, r, nil)

	return t, nil
}

// OpenFile implements OpenFileWriter interface
func (c *Connection) OpenFile(request *sftp.Request) (sftp.WriterAtReaderAt, error) {
	return c.handleFilewrite(request)
}

// Filewrite handles the write actions for a file on the system.
func (c *Connection) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	return c.handleFilewrite(request)
}

func (c *Connection) handleFilewrite(request *sftp.Request) (sftp.WriterAtReaderAt, error) {
	c.UpdateLastActivity()

	if !c.User.IsFileAllowed(request.Filepath) {
		c.Log(logger.LevelWarn, "writing file %#v is not allowed", request.Filepath)
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	p, err := c.Fs.ResolvePath(request.Filepath)
	if err != nil {
		return nil, c.GetFsError(err)
	}

	filePath := p
	if common.Config.IsAtomicUploadEnabled() && c.Fs.IsAtomicUploadSupported() {
		filePath = c.Fs.GetAtomicUploadPath(p)
	}

	var errForRead error
	if !vfs.IsLocalOsFs(c.Fs) && request.Pflags().Read {
		// read and write mode is only supported for local filesystem
		errForRead = sftp.ErrSSHFxOpUnsupported
	}
	if !c.User.HasPerm(dataprovider.PermDownload, path.Dir(request.Filepath)) {
		// we can try to read only for local fs here, see above.
		// os.ErrPermission will become sftp.ErrSSHFxPermissionDenied when sent to
		// the client
		errForRead = os.ErrPermission
	}

	stat, statErr := c.Fs.Lstat(p)
	if (statErr == nil && stat.Mode()&os.ModeSymlink != 0) || c.Fs.IsNotExist(statErr) {
		if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(request.Filepath)) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		return c.handleSFTPUploadToNewFile(p, filePath, request.Filepath, errForRead)
	}

	if statErr != nil {
		c.Log(logger.LevelError, "error performing file stat %#v: %+v", p, statErr)
		return nil, c.GetFsError(statErr)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelWarn, "attempted to open a directory for writing to: %#v", p)
		return nil, sftp.ErrSSHFxOpUnsupported
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(request.Filepath)) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	return c.handleSFTPUploadToExistingFile(request.Pflags(), p, filePath, stat.Size(), request.Filepath, errForRead)
}

// Filecmd hander for basic SFTP system calls related to files, but not anything to do with reading
// or writing to those files.
func (c *Connection) Filecmd(request *sftp.Request) error {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(request.Filepath)
	if err != nil {
		return c.GetFsError(err)
	}
	target, err := c.getSFTPCmdTargetPath(request.Target)
	if err != nil {
		return c.GetFsError(err)
	}

	c.Log(logger.LevelDebug, "new cmd, method: %v, sourcePath: %#v, targetPath: %#v", request.Method, p, target)

	switch request.Method {
	case "Setstat":
		return c.handleSFTPSetstat(p, request)
	case "Rename":
		if err = c.Rename(p, target, request.Filepath, request.Target); err != nil {
			return err
		}
	case "Rmdir":
		return c.RemoveDir(p, request.Filepath)
	case "Mkdir":
		err = c.CreateDir(p, request.Filepath)
		if err != nil {
			return err
		}
	case "Symlink":
		if err = c.CreateSymlink(p, target, request.Filepath, request.Target); err != nil {
			return err
		}
	case "Remove":
		return c.handleSFTPRemove(p, request)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}

	return sftp.ErrSSHFxOk
}

// Filelist is the handler for SFTP filesystem list calls. This will handle calls to list the contents of
// a directory as well as perform file/folder stat calls.
func (c *Connection) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	c.UpdateLastActivity()
	p, err := c.Fs.ResolvePath(request.Filepath)
	if err != nil {
		return nil, c.GetFsError(err)
	}

	switch request.Method {
	case "List":
		files, err := c.ListDir(p, request.Filepath)
		if err != nil {
			return nil, err
		}
		return listerAt(files), nil
	case "Stat":
		if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(request.Filepath)) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		s, err := c.DoStat(p, 0)
		if err != nil {
			c.Log(logger.LevelDebug, "error running stat on path %#v: %+v", p, err)
			return nil, c.GetFsError(err)
		}

		return listerAt([]os.FileInfo{s}), nil
	case "Readlink":
		if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(request.Filepath)) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		s, err := c.Fs.Readlink(p)
		if err != nil {
			c.Log(logger.LevelDebug, "error running readlink on path %#v: %+v", p, err)
			return nil, c.GetFsError(err)
		}

		if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(s)) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		return listerAt([]os.FileInfo{vfs.NewFileInfo(s, false, 0, time.Now(), true)}), nil

	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

// Lstat implements LstatFileLister interface
func (c *Connection) Lstat(request *sftp.Request) (sftp.ListerAt, error) {
	c.UpdateLastActivity()

	p, err := c.Fs.ResolvePath(request.Filepath)
	if err != nil {
		return nil, c.GetFsError(err)
	}

	if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(request.Filepath)) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	s, err := c.DoStat(p, 1)
	if err != nil {
		c.Log(logger.LevelDebug, "error running lstat on path %#v: %+v", p, err)
		return nil, c.GetFsError(err)
	}

	return listerAt([]os.FileInfo{s}), nil
}

func (c *Connection) getSFTPCmdTargetPath(requestTarget string) (string, error) {
	var target string
	// If a target is provided in this request validate that it is going to the correct
	// location for the server. If it is not, return an error
	if len(requestTarget) > 0 {
		var err error
		target, err = c.Fs.ResolvePath(requestTarget)
		if err != nil {
			return target, err
		}
	}
	return target, nil
}

func (c *Connection) handleSFTPSetstat(filePath string, request *sftp.Request) error {
	attrs := common.StatAttributes{
		Flags: 0,
	}
	if request.AttrFlags().Permissions {
		attrs.Flags |= common.StatAttrPerms
		attrs.Mode = request.Attributes().FileMode()
	}
	if request.AttrFlags().UidGid {
		attrs.Flags |= common.StatAttrUIDGID
		attrs.UID = int(request.Attributes().UID)
		attrs.GID = int(request.Attributes().GID)
	}
	if request.AttrFlags().Acmodtime {
		attrs.Flags |= common.StatAttrTimes
		attrs.Atime = time.Unix(int64(request.Attributes().Atime), 0)
		attrs.Mtime = time.Unix(int64(request.Attributes().Mtime), 0)
	}
	if request.AttrFlags().Size {
		attrs.Flags |= common.StatAttrSize
		attrs.Size = int64(request.Attributes().Size)
	}

	return c.SetStat(filePath, request.Filepath, &attrs)
}

func (c *Connection) handleSFTPRemove(filePath string, request *sftp.Request) error {
	var fi os.FileInfo
	var err error
	if fi, err = c.Fs.Lstat(filePath); err != nil {
		c.Log(logger.LevelWarn, "failed to remove a file %#v: stat error: %+v", filePath, err)
		return c.GetFsError(err)
	}
	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		c.Log(logger.LevelDebug, "cannot remove %#v is not a file/symlink", filePath)
		return sftp.ErrSSHFxFailure
	}

	return c.RemoveFile(filePath, request.Filepath, fi)
}

func (c *Connection) handleSFTPUploadToNewFile(resolvedPath, filePath, requestPath string, errForRead error) (sftp.WriterAtReaderAt, error) {
	quotaResult := c.HasSpace(true, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, sftp.ErrSSHFxFailure
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
	t := newTransfer(baseTransfer, w, nil, errForRead)

	return t, nil
}

func (c *Connection) handleSFTPUploadToExistingFile(pflags sftp.FileOpenFlags, resolvedPath, filePath string,
	fileSize int64, requestPath string, errForRead error) (sftp.WriterAtReaderAt, error) {
	var err error
	quotaResult := c.HasSpace(false, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, sftp.ErrSSHFxFailure
	}

	minWriteOffset := int64(0)
	osFlags := getOSOpenFlags(pflags)
	isTruncate := osFlags&os.O_TRUNC != 0
	isResume := pflags.Append && !isTruncate

	// if there is a size limit the remaining size cannot be 0 here, since quotaResult.HasSpace
	// will return false in this case and we deny the upload before.
	// For Cloud FS GetMaxWriteSize will return unsupported operation
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

	file, w, cancelFn, err := c.Fs.Create(filePath, osFlags)
	if err != nil {
		c.Log(logger.LevelWarn, "error opening existing file, flags: %v, source: %#v, err: %+v", pflags, filePath, err)
		return nil, c.GetFsError(err)
	}

	initialSize := int64(0)
	if isResume {
		c.Log(logger.LevelDebug, "upload resume requested, file path %#v initial size: %v", filePath, fileSize)
		minWriteOffset = fileSize
		initialSize = fileSize
	} else {
		if vfs.IsLocalOsFs(c.Fs) && isTruncate {
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
	t := newTransfer(baseTransfer, w, nil, errForRead)

	return t, nil
}

// Disconnect disconnects the client closing the network connection
func (c *Connection) Disconnect() error {
	return c.channel.Close()
}

func getOSOpenFlags(requestFlags sftp.FileOpenFlags) (flags int) {
	var osFlags int
	if requestFlags.Read && requestFlags.Write {
		osFlags |= os.O_RDWR
	} else if requestFlags.Write {
		osFlags |= os.O_WRONLY
	}
	// we ignore Append flag since pkg/sftp use WriteAt that cannot work with os.O_APPEND
	/*if requestFlags.Append {
		osFlags |= os.O_APPEND
	}*/
	if requestFlags.Creat {
		osFlags |= os.O_CREATE
	}
	if requestFlags.Trunc {
		osFlags |= os.O_TRUNC
	}
	if requestFlags.Excl {
		osFlags |= os.O_EXCL
	}
	return osFlags
}
