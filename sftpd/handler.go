package sftpd

import (
	"io"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/vfs"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"

	"github.com/pkg/sftp"
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

	p, err := c.fs.ResolvePath(request.Filepath, c.User.GetHomeDir())
	if err != nil {
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	fi, err := c.fs.Stat(p)
	if err != nil {
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	file, r, cancelFn, err := c.fs.Open(p)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "could not open file %#v for reading: %v", p, err)
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
		expectedSize:   fi.Size(),
		lock:           new(sync.Mutex),
	}
	addTransfer(&transfer)
	return &transfer, nil
}

// Filewrite handles the write actions for a file on the system.
func (c Connection) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	updateConnectionActivity(c.ID)
	p, err := c.fs.ResolvePath(request.Filepath, c.User.GetHomeDir())
	if err != nil {
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	filePath := p
	if isAtomicUploadEnabled() && c.fs.IsAtomicUploadSupported() {
		filePath = c.fs.GetAtomicUploadPath(p)
	}

	stat, statErr := c.fs.Stat(p)
	if c.fs.IsNotExist(statErr) {
		if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(request.Filepath)) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		return c.handleSFTPUploadToNewFile(p, filePath)
	}

	if statErr != nil {
		c.Log(logger.LevelError, logSender, "error performing file stat %#v: %v", p, statErr)
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

	return c.handleSFTPUploadToExistingFile(request.Pflags(), p, filePath, stat.Size())
}

// Filecmd hander for basic SFTP system calls related to files, but not anything to do with reading
// or writing to those files.
func (c Connection) Filecmd(request *sftp.Request) error {
	updateConnectionActivity(c.ID)

	p, err := c.fs.ResolvePath(request.Filepath, c.User.GetHomeDir())
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
		break
	case "Rmdir":
		return c.handleSFTPRmdir(p, request)

	case "Mkdir":
		err = c.handleSFTPMkdir(p, request)
		if err != nil {
			return err
		}
		break
	case "Symlink":
		if err = c.handleSFTPSymlink(p, target, request); err != nil {
			return err
		}
		break
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
	p, err := c.fs.ResolvePath(request.Filepath, c.User.GetHomeDir())
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
			c.Log(logger.LevelWarn, logSender, "error listing directory: %#v", err)
			return nil, vfs.GetSFTPError(c.fs, err)
		}

		return listerAt(files), nil
	case "Stat":
		if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(request.Filepath)) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		c.Log(logger.LevelDebug, logSender, "requested stat for path: %#v", p)
		s, err := c.fs.Stat(p)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error running stat on path: %#v", err)
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
		target, err = c.fs.ResolvePath(requestTarget, c.User.GetHomeDir())
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
			c.Log(logger.LevelWarn, logSender, "failed to chmod path %#v, mode: %v, err: %v", filePath, fileMode.String(), err)
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
			c.Log(logger.LevelWarn, logSender, "failed to chown path %#v, uid: %v, gid: %v, err: %v", filePath, uid, gid, err)
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
			c.Log(logger.LevelWarn, logSender, "failed to chtimes for path %#v, access time: %v, modification time: %v, err: %v",
				filePath, accessTime, modificationTime, err)
			return vfs.GetSFTPError(c.fs, err)
		}
		logger.CommandLog(chtimesLogSender, filePath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, accessTimeString,
			modificationTimeString, "")
		return nil
	}
	return nil
}

func (c Connection) handleSFTPRename(sourcePath string, targetPath string, request *sftp.Request) error {
	if c.fs.GetRelativePath(sourcePath, c.User.GetHomeDir()) == "/" {
		c.Log(logger.LevelWarn, logSender, "renaming root dir is not allowed")
		return sftp.ErrSSHFxPermissionDenied
	}
	if !c.User.HasPerm(dataprovider.PermRename, path.Dir(request.Target)) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if err := c.fs.Rename(sourcePath, targetPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to rename file, source: %#v target: %#v: %v", sourcePath, targetPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}
	logger.CommandLog(renameLogSender, sourcePath, targetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	go executeAction(operationRename, c.User.Username, sourcePath, targetPath, "", 0)
	return nil
}

func (c Connection) handleSFTPRmdir(dirPath string, request *sftp.Request) error {
	if c.fs.GetRelativePath(dirPath, c.User.GetHomeDir()) == "/" {
		c.Log(logger.LevelWarn, logSender, "removing root dir is not allowed")
		return sftp.ErrSSHFxPermissionDenied
	}
	if !c.User.HasPerm(dataprovider.PermDelete, path.Dir(request.Filepath)) {
		return sftp.ErrSSHFxPermissionDenied
	}

	var fi os.FileInfo
	var err error
	if fi, err = c.fs.Lstat(dirPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove a dir %#v: stat error: %v", dirPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		c.Log(logger.LevelDebug, logSender, "cannot remove %#v is not a directory", dirPath)
		return sftp.ErrSSHFxFailure
	}

	if err = c.fs.Remove(dirPath, true); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove directory %#v: %v", dirPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}

	logger.CommandLog(rmdirLogSender, dirPath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	return sftp.ErrSSHFxOk
}

func (c Connection) handleSFTPSymlink(sourcePath string, targetPath string, request *sftp.Request) error {
	if c.fs.GetRelativePath(sourcePath, c.User.GetHomeDir()) == "/" {
		c.Log(logger.LevelWarn, logSender, "symlinking root dir is not allowed")
		return sftp.ErrSSHFxPermissionDenied
	}
	if !c.User.HasPerm(dataprovider.PermCreateSymlinks, path.Dir(request.Target)) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if err := c.fs.Symlink(sourcePath, targetPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to create symlink %#v -> %#v: %v", sourcePath, targetPath, err)
		return vfs.GetSFTPError(c.fs, err)
	}

	logger.CommandLog(symlinkLogSender, sourcePath, targetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	return nil
}

func (c Connection) handleSFTPMkdir(dirPath string, request *sftp.Request) error {
	if !c.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(request.Filepath)) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if err := c.fs.Mkdir(dirPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "error creating missing dir: %#v error: %v", dirPath, err)
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
		c.Log(logger.LevelWarn, logSender, "failed to remove a file %#v: stat error: %v", filePath, err)
		return vfs.GetSFTPError(c.fs, err)
	}
	if fi.IsDir() && fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		c.Log(logger.LevelDebug, logSender, "cannot remove %#v is not a file/symlink", filePath)
		return sftp.ErrSSHFxFailure
	}
	size = fi.Size()
	if err := c.fs.Remove(filePath, false); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove a file/symlink %#v: %v", filePath, err)
		return vfs.GetSFTPError(c.fs, err)
	}

	logger.CommandLog(removeLogSender, filePath, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "", "")
	if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		dataprovider.UpdateUserQuota(dataProvider, c.User, -1, -size, false)
	}
	go executeAction(operationDelete, c.User.Username, filePath, "", "", fi.Size())

	return sftp.ErrSSHFxOk
}

func (c Connection) handleSFTPUploadToNewFile(requestPath, filePath string) (io.WriterAt, error) {
	if !c.hasSpace(true) {
		c.Log(logger.LevelInfo, logSender, "denying file write due to space limit")
		return nil, sftp.ErrSSHFxFailure
	}

	file, w, cancelFn, err := c.fs.Create(filePath, 0)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "error creating file %#v: %v", requestPath, err)
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	vfs.SetPathPermissions(c.fs, filePath, c.User.GetUID(), c.User.GetGID())

	transfer := Transfer{
		file:           file,
		writerAt:       w,
		readerAt:       nil,
		cancelFn:       cancelFn,
		path:           requestPath,
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
		lock:           new(sync.Mutex),
	}
	addTransfer(&transfer)
	return &transfer, nil
}

func (c Connection) handleSFTPUploadToExistingFile(pflags sftp.FileOpenFlags, requestPath, filePath string,
	fileSize int64) (io.WriterAt, error) {
	var err error
	if !c.hasSpace(false) {
		c.Log(logger.LevelInfo, logSender, "denying file write due to space limit")
		return nil, sftp.ErrSSHFxFailure
	}

	minWriteOffset := int64(0)
	osFlags := getOSOpenFlags(pflags)

	if pflags.Append && osFlags&os.O_TRUNC == 0 && !c.fs.IsUploadResumeSupported() {
		c.Log(logger.LevelInfo, logSender, "upload resume requested for path: %#v but not supported in fs implementation",
			requestPath)
		return nil, sftp.ErrSSHFxOpUnsupported
	}

	if isAtomicUploadEnabled() && c.fs.IsAtomicUploadSupported() {
		err = c.fs.Rename(requestPath, filePath)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error renaming existing file for atomic upload, source: %#v, dest: %#v, err: %v",
				requestPath, filePath, err)
			return nil, vfs.GetSFTPError(c.fs, err)
		}
	}

	file, w, cancelFn, err := c.fs.Create(filePath, osFlags)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "error opening existing file, flags: %v, source: %#v, err: %v", pflags, filePath, err)
		return nil, vfs.GetSFTPError(c.fs, err)
	}

	if pflags.Append && osFlags&os.O_TRUNC == 0 {
		c.Log(logger.LevelDebug, logSender, "upload resume requested, file path: %#v initial size: %v", filePath, fileSize)
		minWriteOffset = fileSize
	} else {
		dataprovider.UpdateUserQuota(dataProvider, c.User, 0, -fileSize, false)
	}

	vfs.SetPathPermissions(c.fs, filePath, c.User.GetUID(), c.User.GetGID())

	transfer := Transfer{
		file:           file,
		writerAt:       w,
		readerAt:       nil,
		cancelFn:       cancelFn,
		path:           requestPath,
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
		lock:           new(sync.Mutex),
	}
	addTransfer(&transfer)
	return &transfer, nil
}

func (c Connection) hasSpace(checkFiles bool) bool {
	if (checkFiles && c.User.QuotaFiles > 0) || c.User.QuotaSize > 0 {
		numFile, size, err := dataprovider.GetUsedQuota(dataProvider, c.User.Username)
		if err != nil {
			if _, ok := err.(*dataprovider.MethodDisabledError); ok {
				c.Log(logger.LevelWarn, logSender, "quota enforcement not possible for user %#v: %v", c.User.Username, err)
				return true
			}
			c.Log(logger.LevelWarn, logSender, "error getting used quota for %#v: %v", c.User.Username, err)
			return false
		}
		if (checkFiles && c.User.QuotaFiles > 0 && numFile >= c.User.QuotaFiles) ||
			(c.User.QuotaSize > 0 && size >= c.User.QuotaSize) {
			c.Log(logger.LevelDebug, logSender, "quota exceed for user %#v, num files: %v/%v, size: %v/%v check files: %v",
				c.User.Username, numFile, c.User.QuotaFiles, size, c.User.QuotaSize, checkFiles)
			return false
		}
	}
	return true
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
