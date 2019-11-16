package sftpd

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/utils"
	"github.com/rs/xid"
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
	lock         *sync.Mutex
	netConn      net.Conn
	channel      ssh.Channel
}

// Log outputs a log entry to the configured logger
func (c Connection) Log(level logger.LogLevel, sender string, format string, v ...interface{}) {
	logger.Log(level, sender, c.ID, format, v...)
}

// Fileread creates a reader for a file on the system and returns the reader back.
func (c Connection) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	updateConnectionActivity(c.ID)

	if !c.User.HasPerm(dataprovider.PermDownload) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	p, err := c.buildPath(request.Filepath)
	if err != nil {
		return nil, getSFTPErrorFromOSError(err)
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if _, err := os.Stat(p); err != nil {
		return nil, getSFTPErrorFromOSError(err)
	}

	file, err := os.Open(p)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "could not open file %#v for reading: %v", p, err)
		return nil, getSFTPErrorFromOSError(err)
	}

	c.Log(logger.LevelDebug, logSender, "fileread requested for path: %#v", p)

	transfer := Transfer{
		file:           file,
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
	}
	addTransfer(&transfer)
	return &transfer, nil
}

// Filewrite handles the write actions for a file on the system.
func (c Connection) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	updateConnectionActivity(c.ID)
	if !c.User.HasPerm(dataprovider.PermUpload) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	p, err := c.buildPath(request.Filepath)
	if err != nil {
		return nil, getSFTPErrorFromOSError(err)
	}

	filePath := p
	if isAtomicUploadEnabled() {
		filePath = getUploadTempFilePath(p)
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	stat, statErr := os.Stat(p)
	// If the file doesn't exist we need to create it, as well as the directory pathway
	// leading up to where that file will be created.
	if os.IsNotExist(statErr) {
		return c.handleSFTPUploadToNewFile(p, filePath)
	}

	if statErr != nil {
		c.Log(logger.LevelError, logSender, "error performing file stat %#v: %v", p, statErr)
		return nil, getSFTPErrorFromOSError(err)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelWarn, logSender, "attempted to open a directory for writing to: %#v", p)
		return nil, sftp.ErrSSHFxOpUnsupported
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	return c.handleSFTPUploadToExistingFile(request.Pflags(), p, filePath, stat.Size())
}

// Filecmd hander for basic SFTP system calls related to files, but not anything to do with reading
// or writing to those files.
func (c Connection) Filecmd(request *sftp.Request) error {
	updateConnectionActivity(c.ID)

	p, err := c.buildPath(request.Filepath)
	if err != nil {
		return getSFTPErrorFromOSError(err)
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
		if err = c.handleSFTPRename(p, target); err != nil {
			return err
		}

		break
	case "Rmdir":
		return c.handleSFTPRmdir(p)

	case "Mkdir":
		err = c.handleSFTPMkdir(p)
		if err != nil {
			return err
		}

		break
	case "Symlink":
		if err = c.handleSFTPSymlink(p, target); err != nil {
			return err
		}

		break
	case "Remove":
		return c.handleSFTPRemove(p)

	default:
		return sftp.ErrSSHFxOpUnsupported
	}

	var fileLocation = p
	if target != "" {
		fileLocation = target
	}

	// we return if we remove a file or a dir so source path or target path always exists here
	utils.SetPathPermissions(fileLocation, c.User.GetUID(), c.User.GetGID())

	return sftp.ErrSSHFxOk
}

// Filelist is the handler for SFTP filesystem list calls. This will handle calls to list the contents of
// a directory as well as perform file/folder stat calls.
func (c Connection) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	updateConnectionActivity(c.ID)
	p, err := c.buildPath(request.Filepath)
	if err != nil {
		return nil, getSFTPErrorFromOSError(err)
	}

	switch request.Method {
	case "List":
		if !c.User.HasPerm(dataprovider.PermListItems) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		c.Log(logger.LevelDebug, logSender, "requested list file for dir: %#v", p)

		files, err := ioutil.ReadDir(p)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error listing directory: %#v", err)
			return nil, getSFTPErrorFromOSError(err)
		}

		return listerAt(files), nil
	case "Stat":
		if !c.User.HasPerm(dataprovider.PermListItems) {
			return nil, sftp.ErrSSHFxPermissionDenied
		}

		c.Log(logger.LevelDebug, logSender, "requested stat for path: %#v", p)
		s, err := os.Stat(p)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error running stat on path: %#v", err)
			return nil, getSFTPErrorFromOSError(err)
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
		target, err = c.buildPath(requestTarget)
		if err != nil {
			return target, getSFTPErrorFromOSError(err)
		}
	}
	return target, nil
}

func (c Connection) handleSFTPSetstat(path string, request *sftp.Request) error {
	if setstatMode == 1 {
		return nil
	}
	attrFlags := request.AttrFlags()
	if attrFlags.Permissions {
		if !c.User.HasPerm(dataprovider.PermChmod) {
			return sftp.ErrSSHFxPermissionDenied
		}
		fileMode := request.Attributes().FileMode()
		if err := os.Chmod(path, fileMode); err != nil {
			c.Log(logger.LevelWarn, logSender, "failed to chmod path %#v, mode: %v, err: %v", path, fileMode.String(), err)
			return getSFTPErrorFromOSError(err)
		}
		logger.CommandLog(chmodLogSender, path, "", c.User.Username, fileMode.String(), c.ID, c.protocol, -1, -1, "", "")
		return nil
	} else if attrFlags.UidGid {
		if !c.User.HasPerm(dataprovider.PermChown) {
			return sftp.ErrSSHFxPermissionDenied
		}
		uid := int(request.Attributes().UID)
		gid := int(request.Attributes().GID)
		if err := os.Chown(path, uid, gid); err != nil {
			c.Log(logger.LevelWarn, logSender, "failed to chown path %#v, uid: %v, gid: %v, err: %v", path, uid, gid, err)
			return getSFTPErrorFromOSError(err)
		}
		logger.CommandLog(chownLogSender, path, "", c.User.Username, "", c.ID, c.protocol, uid, gid, "", "")
		return nil
	} else if attrFlags.Acmodtime {
		if !c.User.HasPerm(dataprovider.PermChtimes) {
			return sftp.ErrSSHFxPermissionDenied
		}
		dateFormat := "2006-01-02T15:04:05" // YYYY-MM-DDTHH:MM:SS
		accessTime := time.Unix(int64(request.Attributes().Atime), 0)
		modificationTime := time.Unix(int64(request.Attributes().Mtime), 0)
		accessTimeString := accessTime.Format(dateFormat)
		modificationTimeString := modificationTime.Format(dateFormat)
		if err := os.Chtimes(path, accessTime, modificationTime); err != nil {
			c.Log(logger.LevelWarn, logSender, "failed to chtimes for path %#v, access time: %v, modification time: %v, err: %v",
				path, accessTime, modificationTime, err)
			return getSFTPErrorFromOSError(err)
		}
		logger.CommandLog(chtimesLogSender, path, "", c.User.Username, "", c.ID, c.protocol, -1, -1, accessTimeString,
			modificationTimeString)
		return nil
	}
	return nil
}

func (c Connection) handleSFTPRename(sourcePath string, targetPath string) error {
	if !c.User.HasPerm(dataprovider.PermRename) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if err := os.Rename(sourcePath, targetPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to rename file, source: %#v target: %#v: %v", sourcePath, targetPath, err)
		return getSFTPErrorFromOSError(err)
	}
	logger.CommandLog(renameLogSender, sourcePath, targetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "", "")
	go executeAction(operationRename, c.User.Username, sourcePath, targetPath)
	return nil
}

func (c Connection) handleSFTPRmdir(path string) error {
	if !c.User.HasPerm(dataprovider.PermDelete) {
		return sftp.ErrSSHFxPermissionDenied
	}

	var fi os.FileInfo
	var err error
	if fi, err = os.Lstat(path); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove a dir %#v: stat error: %v", path, err)
		return getSFTPErrorFromOSError(err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		c.Log(logger.LevelDebug, logSender, "cannot remove %#v is not a directory", path)
		return sftp.ErrSSHFxFailure
	}

	if err = os.Remove(path); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove directory %#v: %v", path, err)
		return getSFTPErrorFromOSError(err)
	}

	logger.CommandLog(rmdirLogSender, path, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "")
	return sftp.ErrSSHFxOk
}

func (c Connection) handleSFTPSymlink(sourcePath string, targetPath string) error {
	if !c.User.HasPerm(dataprovider.PermCreateSymlinks) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if err := os.Symlink(sourcePath, targetPath); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to create symlink %#v -> %#v: %v", sourcePath, targetPath, err)
		return getSFTPErrorFromOSError(err)
	}

	logger.CommandLog(symlinkLogSender, sourcePath, targetPath, c.User.Username, "", c.ID, c.protocol, -1, -1, "", "")
	return nil
}

func (c Connection) handleSFTPMkdir(path string) error {
	if !c.User.HasPerm(dataprovider.PermCreateDirs) {
		return sftp.ErrSSHFxPermissionDenied
	}
	if err := os.Mkdir(path, 0777); err != nil {
		c.Log(logger.LevelWarn, logSender, "error creating missing dir: %#v error: %v", path, err)
		return getSFTPErrorFromOSError(err)
	}
	utils.SetPathPermissions(path, c.User.GetUID(), c.User.GetGID())

	logger.CommandLog(mkdirLogSender, path, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "")
	return nil
}

func (c Connection) handleSFTPRemove(path string) error {
	if !c.User.HasPerm(dataprovider.PermDelete) {
		return sftp.ErrSSHFxPermissionDenied
	}

	var size int64
	var fi os.FileInfo
	var err error
	if fi, err = os.Lstat(path); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove a file %#v: stat error: %v", path, err)
		return getSFTPErrorFromOSError(err)
	}
	if fi.IsDir() && fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		c.Log(logger.LevelDebug, logSender, "cannot remove %#v is not a file/symlink", path)
		return sftp.ErrSSHFxFailure
	}
	size = fi.Size()
	if err := os.Remove(path); err != nil {
		c.Log(logger.LevelWarn, logSender, "failed to remove a file/symlink %#v: %v", path, err)
		return getSFTPErrorFromOSError(err)
	}

	logger.CommandLog(removeLogSender, path, "", c.User.Username, "", c.ID, c.protocol, -1, -1, "", "")
	if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
		dataprovider.UpdateUserQuota(dataProvider, c.User, -1, -size, false)
	}
	go executeAction(operationDelete, c.User.Username, path, "")

	return sftp.ErrSSHFxOk
}

func (c Connection) handleSFTPUploadToNewFile(requestPath, filePath string) (io.WriterAt, error) {
	if !c.hasSpace(true) {
		c.Log(logger.LevelInfo, logSender, "denying file write due to space limit")
		return nil, sftp.ErrSSHFxFailure
	}

	file, err := os.Create(filePath)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "error creating file %#v: %v", requestPath, err)
		return nil, getSFTPErrorFromOSError(err)
	}

	utils.SetPathPermissions(filePath, c.User.GetUID(), c.User.GetGID())

	transfer := Transfer{
		file:           file,
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

	if isAtomicUploadEnabled() {
		err = os.Rename(requestPath, filePath)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error renaming existing file for atomic upload, source: %#v, dest: %#v, err: %v",
				requestPath, filePath, err)
			return nil, getSFTPErrorFromOSError(err)
		}
	}
	// we use 0666 so the umask is applied
	file, err := os.OpenFile(filePath, osFlags, 0666)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "error opening existing file, flags: %v, source: %#v, err: %v", pflags, filePath, err)
		return nil, getSFTPErrorFromOSError(err)
	}

	if pflags.Append && osFlags&os.O_TRUNC == 0 {
		c.Log(logger.LevelDebug, logSender, "upload resume requested, file path: %#v initial size: %v", filePath, fileSize)
		minWriteOffset = fileSize
	} else {
		dataprovider.UpdateUserQuota(dataProvider, c.User, 0, -fileSize, false)
	}

	utils.SetPathPermissions(filePath, c.User.GetUID(), c.User.GetGID())

	transfer := Transfer{
		file:           file,
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
	}
	addTransfer(&transfer)
	return &transfer, nil
}

func (c Connection) hasSpace(checkFiles bool) bool {
	if (checkFiles && c.User.QuotaFiles > 0) || c.User.QuotaSize > 0 {
		numFile, size, err := dataprovider.GetUsedQuota(dataProvider, c.User.Username)
		if err != nil {
			if _, ok := err.(*dataprovider.MethodDisabledError); ok {
				c.Log(logger.LevelWarn, logSender, "quota enforcement not possible for user %v: %v", c.User.Username, err)
				return true
			}
			c.Log(logger.LevelWarn, logSender, "error getting used quota for %v: %v", c.User.Username, err)
			return false
		}
		if (checkFiles && c.User.QuotaFiles > 0 && numFile >= c.User.QuotaFiles) ||
			(c.User.QuotaSize > 0 && size >= c.User.QuotaSize) {
			c.Log(logger.LevelDebug, logSender, "quota exceed for user %v, num files: %v/%v, size: %v/%v check files: %v",
				c.User.Username, numFile, c.User.QuotaFiles, size, c.User.QuotaSize, checkFiles)
			return false
		}
	}
	return true
}

// Normalizes a directory we get from the SFTP request to ensure the user is not able to escape
// from their data directory. After normalization if the directory is still within their home
// path it is returned. If they managed to "escape" an error will be returned.
func (c Connection) buildPath(rawPath string) (string, error) {
	r := filepath.Clean(filepath.Join(c.User.HomeDir, rawPath))
	p, err := filepath.EvalSymlinks(r)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	} else if os.IsNotExist(err) {
		// The requested directory doesn't exist, so at this point we need to iterate up the
		// path chain until we hit a directory that _does_ exist and can be validated.
		_, err = c.findFirstExistingDir(r)
		if err != nil {
			c.Log(logger.LevelWarn, logSender, "error resolving not existent path: %#v", err)
		}
		return r, err
	}

	err = c.isSubDir(p)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "Invalid path resolution, dir: %#v outside user home: %#v err: %v", p, c.User.HomeDir, err)
	}
	return r, err
}

// iterate up the path chain until we hit a directory that does exist and can be validated.
// all nonexistent directories will be returned
func (c Connection) findNonexistentDirs(path string) ([]string, error) {
	results := []string{}
	cleanPath := filepath.Clean(path)
	parent := filepath.Dir(cleanPath)
	_, err := os.Stat(parent)

	for os.IsNotExist(err) {
		results = append(results, parent)
		parent = filepath.Dir(parent)
		_, err = os.Stat(parent)
	}
	if err != nil {
		return results, err
	}
	p, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return results, err
	}
	err = c.isSubDir(p)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "Error finding non existing dir: %v", err)
	}
	return results, err
}

// iterate up the path chain until we hit a directory that does exist and can be validated.
func (c Connection) findFirstExistingDir(path string) (string, error) {
	results, err := c.findNonexistentDirs(path)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "unable to find non existent dirs: %v", err)
		return "", err
	}
	var parent string
	if len(results) > 0 {
		lastMissingDir := results[len(results)-1]
		parent = filepath.Dir(lastMissingDir)
	} else {
		parent = c.User.GetHomeDir()
	}
	p, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	fileInfo, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("resolved path is not a dir: %#v", p)
	}
	err = c.isSubDir(p)
	return p, err
}

// checks if sub is a subpath of the user home dir.
// EvalSymlink must be used on sub before calling this method
func (c Connection) isSubDir(sub string) error {
	// home dir must exist and it is already a validated absolute path
	parent, err := filepath.EvalSymlinks(c.User.HomeDir)
	if err != nil {
		c.Log(logger.LevelWarn, logSender, "invalid home dir %#v: %v", c.User.HomeDir, err)
		return err
	}
	if !strings.HasPrefix(sub, parent) {
		c.Log(logger.LevelWarn, logSender, "dir %#v is not inside: %#v ", sub, parent)
		return fmt.Errorf("dir %#v is not inside: %#v", sub, parent)
	}
	return nil
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

func getUploadTempFilePath(path string) string {
	dir := filepath.Dir(path)
	guid := xid.New().String()
	return filepath.Join(dir, ".sftpgo-upload."+guid+"."+filepath.Base(path))
}

func getSFTPErrorFromOSError(err error) error {
	if os.IsNotExist(err) {
		return sftp.ErrSSHFxNoSuchFile
	} else if os.IsPermission(err) {
		return sftp.ErrSSHFxPermissionDenied
	} else if err != nil {
		return sftp.ErrSSHFxFailure
	}
	return nil
}
