package sftpd

import (
	"io"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
)

// Connection details for an authenticated user
type Connection struct {
	// Unique identifier for the connection
	ID string
	// logged in user's details
	User dataprovider.User
	// client's version string
	ClientVersion string
	// Remote address for this connection
	RemoteAddr net.Addr
	// start time for this connection
	StartTime time.Time
	// last activity for this connection
	lastActivity time.Time
	protocol     string
	netConn      net.Conn
	channel      ssh.Channel
	command      string
	fs           vfs.Fs
}

// Log outputs a log entry to the configured logger
func (c Connection) Log(level logger.LogLevel, sender string, format string, v ...interface{}) {
	logger.Log(level, sender, c.ID, format, v...)
}

// Fileread creates a reader for a file on the system and returns the reader back.
func (c Connection) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	updateConnectionActivity(c.ID)

	if !c.User.HasPerm(dataprovider.PermDownload, path.Dir(request.Filepath)) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	if !c.User.IsFileAllowed(request.Filepath) {
		c.Log(logger.LevelWarn, logSender, "reading file %#v is not allowed", request.Filepath)
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	p, err := c.fs.ResolvePath(request.Filepath)
	if err != nil {
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	file, r, cancelFn, err := c.fs.Open(p)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "could not open file %#v for reading: %+v", p, err)
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	c.Log(logger.LevelDebug, logSender, "fileread requested for path: %#v", p)

	transfer := Transfer{
		file:           file,
		readerAt:       r,
		writerAt:       nil,
		cancelFn:       cancelFn,
		path:           p,
		start:          time.Now(),
		bytesSent:      0,
		bytesReceived:  0,
		user:           c.User,
		connectionID:   c.ID,
		transferType:   transferDownload,
		lastActivity:   time.Now(),
		isNewFile:      false,
		protocol:       c.protocol,
		transferError:  nil,
		isFinished:     false,
		minWriteOffset: 0,
		requestPath:    request.Filepath,
		lock:           new(sync.Mutex),
	}
	addTransfer(&transfer)
	return &transfer, nil
}

// Filewrite handles the write actions for a file on the system.
func (c Connection) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	updateConnectionActivity(c.ID)

	if !c.User.IsFileAllowed(request.Filepath) {
		c.Log(logger.LevelWarn, logSender, "writing file %#v is not allowed", request.Filepath)
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	p, err := c.fs.ResolvePath(request.Filepath)
	if err != nil {
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	filePath := p
	if isAtomicUploadEnabled() && c.fs.IsAtomicUploadSupported() {
		filePath = c.fs.GetAtomicUploadPath(p)
	}

	stat, statErr := c.fs.Lstat(p)
	if (statErr == nil && stat.Mode()&os.ModeSymlink == os.ModeSymlink) || c.fs.IsNotExist(statErr) {
		if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(request.Filepath)) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		return c.handleSFTPUploadToNewFile(p, filePath, request.Filepath)
	}

	if statErr != nil {
		c.Log(logger.LevelError, logSender, "error performing file stat %#v: %+v", p, statErr)
		return nil, vfs.GetSFTPError(c.fs, statErr)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelWarn, logSender, "attempted to open a directory for writing to: %#v", p)
		return nil, sftp.ErrSSHFxOpUnsupported
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(request.Filepath)) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	return c.handleSFTPUploadToExistingFile(request.Pflags(), p, filePath, stat.Size(), request.Filepath)
}

// Filecmd hander for basic SFTP system calls related to files, but not anything to do with reading
// or writing to those files.
func (c Connection) Filecmd(request *sftp.Request) error {
	updateConnectionActivity(c.ID)

	p, err := c.fs.ResolvePath(request.Filepath)
	if err != nil {
		return vfs.GetSFTPError(c.fs, err)
	}
	target, err := c.getSFTPCmdTargetPath(request.Target)
	if err != nil {
		return err
	}

	c.Log(logger.LevelDebug, logSender, "new cmd, method: %v, sourcePath: %#v, targetPath: %#v", request.Method,
		p, target)

	switch request.Method {
	case "Setstat":
		return c.handleSFTPSetstat(p, request)
	case "Rename":
		if err = c.handleSFTPRename(p, target, request); err != nil {
			return err
		}
	case "Rmdir":
		return c.handleSFTPRmdir(p, request)
	case "Mkdir":
		err = c.handleSFTPMkdir(p, request)
		if err != nil {
			return err
		}
	case "Symlink":
		if err = c.handleSFTPSymlink(p, target, request); err != nil {
			return err
		}
	case "Remove":
		return c.handleSFTPRemove(p, request)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}

	var fileLocation = p
	if target != "" {
		fileLocation = target
	}

	// we return if we remove a file or a dir so source path or target path always exists here
	vfs.SetPathPermissions(c.fs, fileLocation, c.User.GetUID(), c.User.GetGID())

	return sftp.ErrSSHFxOk
}

// Filelist is the handler for SFTP filesystem list calls. This will handle calls to list the contents of
// a directory as well as perform file/folder stat calls.
func (c Connection) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	updateConnectionActivity(c.ID)
	p, err := c.fs.ResolvePath(request.Filepath)
	if err != nil {
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	switch request.Method {
	case "List":
		if !c.User.HasPerm(dataprovider.PermListItems, request.Filepath) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		c.Log(logger.LevelDebug, logSender, "requested list file for dir: %#v", p)
		files, err := c.fs.ReadDir(p)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error listing directory: %+v", err)
			return nil, vfs.GetSFTPError(c.fs, err)
		}

		return listerAt(c.User.AddVirtualDirs(files, request.Filepath)), nil
	case "Stat":
		if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(request.Filepath)) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		c.Log(logger.LevelDebug, logSender, "requested stat for path: %#v", p)
		s, err := c.fs.Stat(p)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error running stat on path: %+v", err)
			return nil, vfs.GetSFTPError(c.fs, err)
		}

		return listerAt([]os.FileInfo{s}), nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

func (c Connection) getSFTPCmdTargetPath(requestTarget string) (string, error) {
	var target string
	// If a target is provided in this request validate that it is going to the correct
	// location for the server. If it is not, return an error
	if len(requestTarget) > 0 {
		var err error
		target, err = c.fs.ResolvePath(requestTarget)
		if err != nil {
			return target, vfs.GetSFTPError(c.fs, err)
		}
	}
	return target, nil
}

func (c Connection) handleSFTPSetstat(filePath string, request *sftp.Request) error {
	if setstatMode == 1 {
		return nil
	}
	pathForPerms := request.Filepath
	if fi, err := c.fs.Lstat(filePath); err == nil {
		if fi.IsDir() {
			pathForPerms = path.Dir(request.Filepath)
		}
	}
	attrFlags := request.AttrFlags()
	if attrFlags.Permissions {
		if !c.User.HasPerm(dataprovider.PermChmod, pathForPerms) {
			return sftp.ErrSSHFxPermissionDenied
		}
		fileMode := request.Attributes().FileMode()
		if err := c.fs.Chmod(filePath, fileMode); err != nil {
			c.Log(logger.LevelWarn, logSender, "failed to chmod path %#v, mode: %v, err: %+v", filePath, fileMode.String(), err)
			return vfs.GetSFTPError(c.fs, err)
		}
		logger.CommandLog(chmodLogSender, filePath, "", c.User.Username, fileMode.String(), c.ID, c.protocol, -1, -1, "", "", "")
		return nil
	} else if attrFlags.UidGid {
		if !c.User.HasPerm(dataprovider.PermChown, pathForPerms) {
			return sftp.ErrSSHFxPermissionDenied
		}
		uid := int(request.Attributes().UID)
		gid := int(request.Attributes().GID)
		if err := c.fs.Chown(filePath, uid, gid); err != nil {
			c.Log(logger.LevelWarn, logSender, "failed to chown path %#v, uid: %v, gid: %v, err: %+v", filePath, uid, gid, err)
			return vfs.GetSFTPError(c.fs, err)
		}
		logger.CommandLog(chownLogSender, filePath, "", c.User.Username, "", c.ID, c.protocol, uid, gid, "", "", "")
		return nil
	} else if attrFlags.Acmodtime {
		if !c.User.HasPerm(dataprovider.PermChtimes, pathForPerms) {
			return sftp.ErrSSHFxPermissionDenied
		}
		dateFormat := "2006-01-02T15:04:05" // YYYY-MM-DDTHH:MM:SS
		accessTime := time.Unix(int64(request.Attributes().Atime), 0)
		modificationTime := time.Unix(int64(request.Attributes().Mtime), 0)
		accessTimeString := accessTime.Format(dateFormat)
		modificationTimeString := modificationTime.Format(dateFormat)
		if err := c.fs.Chtimes(filePath, accessTime, modificationTime); err != nil {
			c.Log(logger.LevelWarn, logSender, "failed to chtimes for path %#v, access time: %v, modification time: %v, err: %+v",
				filePath, accessTime, modificationTime, err)
			return vfs.GetSFTPError(c.fs, err)
		}
		logger.CommandLog(chtimesLogSender, filePath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, accessTimeString,
			modificationTimeString, "")
		return nil
	}
	return nil
}

func (c Connection) handleSFTPRename(sourcePath, targetPath string, request *sftp.Request) error {
	if !c.isRenamePermitted(sourcePath, request) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.User.IsMappedPath(sourcePath) {
		c.Log(logger.LevelWarn, logSender, "renaming a directory mapped as virtual folder is not allowed: %#v", sourcePath)
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.User.IsMappedPath(targetPath) {
		c.Log(logger.LevelWarn, logSender, "renaming to a directory mapped as virtual folder is not allowed: %#v", targetPath)
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.User.HasVirtualFoldersInside(request.Filepath) {
		if fi, err := c.fs.Stat(sourcePath); err == nil {
			if fi.IsDir() {
				c.Log(logger.LevelDebug, logSender, "renaming the folder %#v is not supported: it has virtual folders inside it",
					request.Filepath)
				return sftp.ErrSSHFxOpUnsupported
			}
		}
	}
	initialSize := int64(-1)
	if fi, err := c.fs.Lstat(targetPath); err == nil {
		if fi.IsDir() {
			c.Log(logger.LevelWarn, logSender, "attempted to rename %#v overwriting an existing directory %#v", sourcePath, targetPath)
			return sftp.ErrSSHFxOpUnsupported
		}
		// we are overwriting an existing file/symlink
		if fi.Mode().IsRegular() {
			initialSize = fi.Size()
		}
		if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(request.Target)) {
			c.Log(logger.LevelDebug, logSender, "renaming is not allowed, source: %#v target: %#v. "+
				"Target exists but the user has no overwrite permission", request.Filepath, request.Target)
			return sftp.ErrSSHFxPermissionDenied
		}
	}
	if !c.hasSpaceForRename(request, initialSize, sourcePath) {
		c.Log(logger.LevelInfo, logSender, "denying cross rename due to space limit")
		return sftp.ErrSSHFxFailure
	}
	if err := c.fs.Rename(sourcePath, targetPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to rename %#v -> %#v: %+v", sourcePath, targetPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}
	if dataprovider.GetQuotaTracking() > 0 {
		c.updateQuotaAfterRename(request, targetPath, initialSize) //nolint:errcheck
	}
	logger.CommandLog(renameLogSender, sourcePath, targetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	// the returned error is used in test cases only, we already log the error inside executeAction
	go executeAction(newActionNotification(c.User, operationRename, sourcePath, targetPath, "", 0, nil)) //nolint:errcheck
	return nil
}

func (c Connection) handleSFTPRmdir(dirPath string, request *sftp.Request) error {
	if c.fs.GetRelativePath(dirPath) == "/" {
		c.Log(logger.LevelWarn, logSender, "removing root dir is not allowed")
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.User.IsVirtualFolder(request.Filepath) {
		c.Log(logger.LevelWarn, logSender, "removing a virtual folder is not allowed: %#v", request.Filepath)
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.User.HasVirtualFoldersInside(request.Filepath) {
		c.Log(logger.LevelWarn, logSender, "removing a directory with a virtual folder inside is not allowed: %#v", request.Filepath)
		return sftp.ErrSSHFxOpUnsupported
	}
	if c.User.IsMappedPath(dirPath) {
		c.Log(logger.LevelWarn, logSender, "removing a directory mapped as virtual folder is not allowed: %#v", dirPath)
		return sftp.ErrSSHFxPermissionDenied
	}
	if !c.User.HasPerm(dataprovider.PermDelete, path.Dir(request.Filepath)) {
		return sftp.ErrSSHFxPermissionDenied
	}

	var fi os.FileInfo
	var err error
	if fi, err = c.fs.Lstat(dirPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove a dir %#v: stat error: %+v", dirPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		c.Log(logger.LevelDebug, logSender, "cannot remove %#v is not a directory", dirPath)
		return sftp.ErrSSHFxFailure
	}

	if err = c.fs.Remove(dirPath, true); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove directory %#v: %+v", dirPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}

	logger.CommandLog(rmdirLogSender, dirPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	return sftp.ErrSSHFxOk
}

func (c Connection) handleSFTPSymlink(sourcePath string, targetPath string, request *sftp.Request) error {
	if c.fs.GetRelativePath(sourcePath) == "/" {
		c.Log(logger.LevelWarn, logSender, "symlinking root dir is not allowed")
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.User.IsVirtualFolder(request.Target) {
		c.Log(logger.LevelWarn, logSender, "symlinking a virtual folder is not allowed")
		return sftp.ErrSSHFxPermissionDenied
	}
	if !c.User.HasPerm(dataprovider.PermCreateSymlinks, path.Dir(request.Target)) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.isCrossFoldersRequest(request) {
		c.Log(logger.LevelWarn, logSender, "cross folder symlink is not supported, src: %v dst: %v", request.Filepath, request.Target)
		return sftp.ErrSSHFxFailure
	}
	if c.User.IsMappedPath(sourcePath) {
		c.Log(logger.LevelWarn, logSender, "symlinking a directory mapped as virtual folder is not allowed: %#v", sourcePath)
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.User.IsMappedPath(targetPath) {
		c.Log(logger.LevelWarn, logSender, "symlinking to a directory mapped as virtual folder is not allowed: %#v", targetPath)
		return sftp.ErrSSHFxPermissionDenied
	}
	if err := c.fs.Symlink(sourcePath, targetPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to create symlink %#v -> %#v: %+v", sourcePath, targetPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}
	logger.CommandLog(symlinkLogSender, sourcePath, targetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	return nil
}

func (c Connection) handleSFTPMkdir(dirPath string, request *sftp.Request) error {
	if !c.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(request.Filepath)) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if c.User.IsVirtualFolder(request.Filepath) {
		c.Log(logger.LevelWarn, logSender, "mkdir not allowed %#v is virtual folder is not allowed", request.Filepath)
		return sftp.ErrSSHFxPermissionDenied
	}
	if err := c.fs.Mkdir(dirPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "error creating missing dir: %#v error: %+v", dirPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}
	vfs.SetPathPermissions(c.fs, dirPath, c.User.GetUID(), c.User.GetGID())

	logger.CommandLog(mkdirLogSender, dirPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	return nil
}

func (c Connection) handleSFTPRemove(filePath string, request *sftp.Request) error {
	if !c.User.HasPerm(dataprovider.PermDelete, path.Dir(request.Filepath)) {
		return sftp.ErrSSHFxPermissionDenied
	}

	var size int64
	var fi os.FileInfo
	var err error
	if fi, err = c.fs.Lstat(filePath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove a file %#v: stat error: %+v", filePath, err)
		return vfs.GetSFTPError(c.fs, err)
	}
	if fi.IsDir() && fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		c.Log(logger.LevelDebug, logSender, "cannot remove %#v is not a file/symlink", filePath)
		return sftp.ErrSSHFxFailure
	}

	if !c.User.IsFileAllowed(request.Filepath) {
		c.Log(logger.LevelDebug, logSender, "removing file %#v is not allowed", filePath)
		return sftp.ErrSSHFxPermissionDenied
	}

	size = fi.Size()
	actionErr := executeAction(newActionNotification(c.User, operationPreDelete, filePath, "", "", fi.Size(), nil))
	if actionErr == nil {
		c.Log(logger.LevelDebug, logSender, "remove for path %#v handled by pre-delete action", filePath)
	} else {
		if err := c.fs.Remove(filePath, false); err != nil {
			c.Log(logger.LevelWarn, logSender, "failed to remove a file/symlink %#v: %+v", filePath, err)
			return vfs.GetSFTPError(c.fs, err)
		}
	}

	logger.CommandLog(removeLogSender, filePath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(request.Filepath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(dataProvider, vfolder.BaseVirtualFolder, -1, -size, false) //nolint:errcheck
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(dataProvider, c.User, -1, -size, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(dataProvider, c.User, -1, -size, false) //nolint:errcheck
		}
	}
	if actionErr != nil {
		go executeAction(newActionNotification(c.User, operationDelete, filePath, "", "", fi.Size(), nil)) //nolint:errcheck
	}

	return sftp.ErrSSHFxOk
}

func (c Connection) handleSFTPUploadToNewFile(resolvedPath, filePath, requestPath string) (io.WriterAt, error) {
	quotaResult := c.hasSpace(true, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, logSender, "denying file write due to quota limits")
		return nil, sftp.ErrSSHFxFailure
	}

	file, w, cancelFn, err := c.fs.Create(filePath, 0)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "error creating file %#v: %+v", resolvedPath, err)
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	vfs.SetPathPermissions(c.fs, filePath, c.User.GetUID(), c.User.GetGID())

	transfer := Transfer{
		file:           file,
		writerAt:       w,
		readerAt:       nil,
		cancelFn:       cancelFn,
		path:           resolvedPath,
		start:          time.Now(),
		bytesSent:      0,
		bytesReceived:  0,
		user:           c.User,
		connectionID:   c.ID,
		transferType:   transferUpload,
		lastActivity:   time.Now(),
		isNewFile:      true,
		protocol:       c.protocol,
		transferError:  nil,
		isFinished:     false,
		minWriteOffset: 0,
		requestPath:    requestPath,
		lock:           new(sync.Mutex),
	}
	addTransfer(&transfer)
	return &transfer, nil
}

func (c Connection) handleSFTPUploadToExistingFile(pflags sftp.FileOpenFlags, resolvedPath, filePath string,
	fileSize int64, requestPath string) (io.WriterAt, error) {
	var err error
	quotaResult := c.hasSpace(false, requestPath)
	if !quotaResult.HasSpace {
		c.Log(logger.LevelInfo, logSender, "denying file write due to quota limits")
		return nil, sftp.ErrSSHFxFailure
	}

	minWriteOffset := int64(0)
	osFlags := getOSOpenFlags(pflags)

	if pflags.Append && osFlags&os.O_TRUNC == 0 && !c.fs.IsUploadResumeSupported() {
		c.Log(logger.LevelInfo, logSender, "upload resume requested for path: %#v but not supported in fs implementation", resolvedPath)
		return nil, sftp.ErrSSHFxOpUnsupported
	}

	if isAtomicUploadEnabled() && c.fs.IsAtomicUploadSupported() {
		err = c.fs.Rename(resolvedPath, filePath)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error renaming existing file for atomic upload, source: %#v, dest: %#v, err: %+v",
				resolvedPath, filePath, err)
			return nil, vfs.GetSFTPError(c.fs, err)
		}
	}

	file, w, cancelFn, err := c.fs.Create(filePath, osFlags)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "error opening existing file, flags: %v, source: %#v, err: %+v", pflags, filePath, err)
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	initialSize := int64(0)
	if pflags.Append && osFlags&os.O_TRUNC == 0 {
		c.Log(logger.LevelDebug, logSender, "upload resume requested, file path: %#v initial size: %v", filePath, fileSize)
		minWriteOffset = fileSize
	} else {
		if vfs.IsLocalOsFs(c.fs) {
			vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(requestPath))
			if err == nil {
				dataprovider.UpdateVirtualFolderQuota(dataProvider, vfolder.BaseVirtualFolder, 0, -fileSize, false) //nolint:errcheck
				if vfolder.IsIncludedInUserQuota() {
					dataprovider.UpdateUserQuota(dataProvider, c.User, 0, -fileSize, false) //nolint:errcheck
				}
			} else {
				dataprovider.UpdateUserQuota(dataProvider, c.User, 0, -fileSize, false) //nolint:errcheck
			}
		} else {
			initialSize = fileSize
		}
	}

	vfs.SetPathPermissions(c.fs, filePath, c.User.GetUID(), c.User.GetGID())

	transfer := Transfer{
		file:           file,
		writerAt:       w,
		readerAt:       nil,
		cancelFn:       cancelFn,
		path:           resolvedPath,
		start:          time.Now(),
		bytesSent:      0,
		bytesReceived:  0,
		user:           c.User,
		connectionID:   c.ID,
		transferType:   transferUpload,
		lastActivity:   time.Now(),
		isNewFile:      false,
		protocol:       c.protocol,
		transferError:  nil,
		isFinished:     false,
		minWriteOffset: minWriteOffset,
		initialSize:    initialSize,
		requestPath:    requestPath,
		lock:           new(sync.Mutex),
	}
	addTransfer(&transfer)
	return &transfer, nil
}

func (c Connection) hasSpaceForRename(request *sftp.Request, initialSize int64, sourcePath string) bool {
	if dataprovider.GetQuotaTracking() == 0 {
		return true
	}
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(path.Dir(request.Filepath))
	dstFolder, errDst := c.User.GetVirtualFolderForPath(path.Dir(request.Target))
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
	quotaResult := c.hasSpace(true, request.Target)
	if !quotaResult.HasSpace {
		if initialSize != -1 {
			// we are overquota but we are overwriting a file so we check the quota size
			quotaResult = c.hasSpace(false, request.Target)
			if quotaResult.HasSpace {
				// we have enough quota size
				return true
			}
			if fi, err := c.fs.Lstat(sourcePath); err == nil {
				if fi.Mode().IsRegular() {
					// we have space if we are overwriting a bigger file with a smaller one
					return initialSize >= fi.Size()
				}
			}
		}
		return false
	}
	return true
}

func (c Connection) hasSpace(checkFiles bool, requestPath string) vfs.QuotaCheckResult {
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
		result.UsedFiles, result.UsedSize, err = dataprovider.GetUsedVirtualFolderQuota(dataProvider, vfolder.MappedPath)
	} else {
		if c.User.HasNoQuotaRestrictions(checkFiles) {
			return result
		}
		result.QuotaSize = c.User.QuotaSize
		result.QuotaFiles = c.User.QuotaFiles
		result.UsedFiles, result.UsedSize, err = dataprovider.GetUsedQuota(dataProvider, c.User.Username)
	}
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "error getting used quota for %#v request path %#v: %v", c.User.Username, requestPath, err)
		result.HasSpace = false
		return result
	}
	result.AllowedFiles = result.QuotaFiles - result.UsedFiles
	result.AllowedSize = result.QuotaSize - result.UsedSize
	if (checkFiles && result.QuotaFiles > 0 && result.UsedFiles >= result.QuotaFiles) ||
		(result.QuotaSize > 0 && result.UsedSize >= result.QuotaSize) {
		c.Log(logger.LevelDebug, logSender, "quota exceed for user %#v, request path %#v, num files: %v/%v, size: %v/%v check files: %v",
			c.User.Username, requestPath, result.UsedFiles, result.QuotaFiles, result.UsedSize, result.QuotaSize, checkFiles)
		result.HasSpace = false
		return result
	}
	return result
}

func (c Connection) close() error {
	if c.channel != nil {
		err := c.channel.Close()
		c.Log(logger.LevelInfo, logSender, "channel close, err: %v", err)
	}
	return c.netConn.Close()
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

func (c Connection) isCrossFoldersRequest(request *sftp.Request) bool {
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(request.Filepath)
	dstFolder, errDst := c.User.GetVirtualFolderForPath(request.Target)
	if errSrc != nil && errDst != nil {
		return false
	}
	if errSrc == nil && errDst == nil {
		return sourceFolder.MappedPath != dstFolder.MappedPath
	}
	return true
}

func (c Connection) isRenamePermitted(sourcePath string, request *sftp.Request) bool {
	if c.fs.GetRelativePath(sourcePath) == "/" {
		c.Log(logger.LevelWarn, logSender, "renaming root dir is not allowed")
		return false
	}
	if c.User.IsVirtualFolder(request.Filepath) || c.User.IsVirtualFolder(request.Target) {
		c.Log(logger.LevelWarn, logSender, "renaming a virtual folder is not allowed")
		return false
	}
	if !c.User.IsFileAllowed(request.Filepath) || !c.User.IsFileAllowed(request.Target) {
		if fi, err := c.fs.Lstat(sourcePath); err == nil && fi.Mode().IsRegular() {
			c.Log(logger.LevelDebug, logSender, "renaming file is not allowed, source: %#v target: %#v", request.Filepath,
				request.Target)
			return false
		}
	}
	if !c.User.HasPerm(dataprovider.PermRename, path.Dir(request.Target)) &&
		(!c.User.HasPerm(dataprovider.PermDelete, path.Dir(request.Filepath)) ||
			!c.User.HasPerm(dataprovider.PermUpload, path.Dir(request.Target))) {
		return false
	}
	return true
}

func (c Connection) updateQuotaMoveBetweenVFolders(sourceFolder, dstFolder vfs.VirtualFolder, initialSize, filesSize int64, numFiles int) {
	if sourceFolder.MappedPath == dstFolder.MappedPath {
		// both files are inside the same virtual folder
		if initialSize != -1 {
			dataprovider.UpdateVirtualFolderQuota(dataProvider, dstFolder.BaseVirtualFolder, -numFiles, -initialSize, false) //nolint:errcheck
			if dstFolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(dataProvider, c.User, -numFiles, -initialSize, false) //nolint:errcheck
			}
		}
		return
	}
	// files are inside different virtual folders
	dataprovider.UpdateVirtualFolderQuota(dataProvider, sourceFolder.BaseVirtualFolder, -numFiles, -filesSize, false) //nolint:errcheck
	if sourceFolder.IsIncludedInUserQuota() {
		dataprovider.UpdateUserQuota(dataProvider, c.User, -numFiles, -filesSize, false) //nolint:errcheck
	}
	if initialSize == -1 {
		dataprovider.UpdateVirtualFolderQuota(dataProvider, dstFolder.BaseVirtualFolder, numFiles, filesSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(dataProvider, c.User, numFiles, filesSize, false) //nolint:errcheck
		}
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateVirtualFolderQuota(dataProvider, dstFolder.BaseVirtualFolder, 0, filesSize-initialSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(dataProvider, c.User, 0, filesSize-initialSize, false) //nolint:errcheck
		}
	}
}

func (c Connection) updateQuotaMoveFromVFolder(sourceFolder vfs.VirtualFolder, initialSize, filesSize int64, numFiles int) {
	// move between a virtual folder and the user home dir
	dataprovider.UpdateVirtualFolderQuota(dataProvider, sourceFolder.BaseVirtualFolder, -numFiles, -filesSize, false) //nolint:errcheck
	if sourceFolder.IsIncludedInUserQuota() {
		dataprovider.UpdateUserQuota(dataProvider, c.User, -numFiles, -filesSize, false) //nolint:errcheck
	}
	if initialSize == -1 {
		dataprovider.UpdateUserQuota(dataProvider, c.User, numFiles, filesSize, false) //nolint:errcheck
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateUserQuota(dataProvider, c.User, 0, filesSize-initialSize, false) //nolint:errcheck
	}
}

func (c Connection) updateQuotaMoveToVFolder(dstFolder vfs.VirtualFolder, initialSize, filesSize int64, numFiles int) {
	// move between the user home dir and a virtual folder
	dataprovider.UpdateUserQuota(dataProvider, c.User, -numFiles, -filesSize, false) //nolint:errcheck
	if initialSize == -1 {
		dataprovider.UpdateVirtualFolderQuota(dataProvider, dstFolder.BaseVirtualFolder, numFiles, filesSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(dataProvider, c.User, numFiles, filesSize, false) //nolint:errcheck
		}
	} else {
		// we cannot have a directory here, initialSize != -1 only for files
		dataprovider.UpdateVirtualFolderQuota(dataProvider, dstFolder.BaseVirtualFolder, 0, filesSize-initialSize, false) //nolint:errcheck
		if dstFolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(dataProvider, c.User, 0, filesSize-initialSize, false) //nolint:errcheck
		}
	}
}

func (c Connection) updateQuotaAfterRename(request *sftp.Request, targetPath string, initialSize int64) error {
	// we don't allow to overwrite an existing directory so targetPath can be:
	// - a new file, a symlink is as a new file here
	// - a file overwriting an existing one
	// - a new directory
	// initialSize != -1 only when overwriting files
	sourceFolder, errSrc := c.User.GetVirtualFolderForPath(path.Dir(request.Filepath))
	dstFolder, errDst := c.User.GetVirtualFolderForPath(path.Dir(request.Target))
	if errSrc != nil && errDst != nil {
		// both files are contained inside the user home dir
		if initialSize != -1 {
			// we cannot have a directory here
			dataprovider.UpdateUserQuota(dataProvider, c.User, -1, -initialSize, false) //nolint:errcheck
		}
		return nil
	}

	filesSize := int64(0)
	numFiles := 1
	if fi, err := c.fs.Stat(targetPath); err == nil {
		if fi.Mode().IsDir() {
			numFiles, filesSize, err = c.fs.GetDirSize(targetPath)
			if err != nil {
				logger.Warn(logSender, "", "failed to update quota after rename, error scanning moved folder %#v: %v", targetPath, err)
				return err
			}
		} else {
			filesSize = fi.Size()
		}
	} else {
		c.Log(logger.LevelWarn, logSender, "failed to update quota after rename, file %#v stat error: %+v", targetPath, err)
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
