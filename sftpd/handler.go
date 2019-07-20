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

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"golang.org/x/crypto/ssh"

	"github.com/pkg/sftp"
)

// Connection details for an authenticated user
type Connection struct {
	ID            string
	User          dataprovider.User
	ClientVersion string
	RemoteAddr    net.Addr
	StartTime     time.Time
	lastActivity  time.Time
	lock          *sync.Mutex
	sshConn       *ssh.ServerConn
	dataProvider  dataprovider.Provider
}

// Fileread creates a reader for a file on the system and returns the reader back.
func (c Connection) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	updateConnectionActivity(c.ID)

	if !c.User.HasPerm(dataprovider.PermDownload) {
		return nil, sftp.ErrSshFxPermissionDenied
	}

	p, err := c.buildPath(request.Filepath)
	if err != nil {
		return nil, sftp.ErrSshFxNoSuchFile
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if _, err := os.Stat(p); os.IsNotExist(err) {
		return nil, sftp.ErrSshFxNoSuchFile
	}

	file, err := os.Open(p)
	if err != nil {
		logger.Error(logSender, "could not open file \"%v\" for reading: %v", p, err)
		return nil, sftp.ErrSshFxFailure
	}

	logger.Debug(logSender, "fileread requested for path: \"%v\", user: %v", p, c.User.Username)

	transfer := Transfer{
		file:          file,
		path:          p,
		start:         time.Now(),
		bytesSent:     0,
		bytesReceived: 0,
		user:          c.User,
		connectionID:  c.ID,
		transferType:  transferDownload,
		isNewFile:     false,
	}
	addTransfer(&transfer)
	return &transfer, nil
}

// Filewrite handles the write actions for a file on the system.
func (c Connection) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	updateConnectionActivity(c.ID)
	if !c.User.HasPerm(dataprovider.PermUpload) {
		return nil, sftp.ErrSshFxPermissionDenied
	}

	p, err := c.buildPath(request.Filepath)
	if err != nil {
		return nil, sftp.ErrSshFxNoSuchFile
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	stat, statErr := os.Stat(p)
	// If the file doesn't exist we need to create it, as well as the directory pathway
	// leading up to where that file will be created.
	if os.IsNotExist(statErr) {
		if !c.hasSpace(true) {
			logger.Info(logSender, "denying file write due to space limit")
			return nil, sftp.ErrSshFxFailure
		}

		if _, err := os.Stat(filepath.Dir(p)); os.IsNotExist(err) {
			if !c.User.HasPerm(dataprovider.PermCreateDirs) {
				return nil, sftp.ErrSshFxPermissionDenied
			}
		}

		dirsToCreate, err := c.findNonexistentDirs(p)
		if err != nil {
			return nil, sftp.ErrSshFxFailure
		}

		last := len(dirsToCreate) - 1
		for i := range dirsToCreate {
			d := dirsToCreate[last-i]
			if err := os.Mkdir(d, 0777); err != nil {
				logger.Error(logSender, "error making path for file, dir: %v, path: %v", d, p)
				return nil, sftp.ErrSshFxFailure
			}
			utils.SetPathPermissions(d, c.User.GetUID(), c.User.GetGID())
		}

		file, err := os.Create(p)
		if err != nil {
			logger.Error(logSender, "error creating file %v: %v", p, err)
			return nil, sftp.ErrSshFxFailure
		}

		utils.SetPathPermissions(p, c.User.GetUID(), c.User.GetGID())

		logger.Debug(logSender, "file upload/replace started for path \"%v\" user: %v", p, c.User.Username)

		transfer := Transfer{
			file:          file,
			path:          p,
			start:         time.Now(),
			bytesSent:     0,
			bytesReceived: 0,
			user:          c.User,
			connectionID:  c.ID,
			transferType:  transferUpload,
			isNewFile:     true,
		}
		addTransfer(&transfer)
		return &transfer, nil
	}

	if statErr != nil {
		logger.Error("error performing file stat %v: %v", p, statErr)
		return nil, sftp.ErrSshFxFailure
	}

	if !c.hasSpace(false) {
		logger.Info(logSender, "denying file write due to space limit")
		return nil, sftp.ErrSshFxFailure
	}

	// Not sure this would ever happen, but lets not find out.
	if stat.IsDir() {
		logger.Warn("attempted to open a directory for writing to: %v", p)
		return nil, sftp.ErrSshFxOpUnsupported
	}

	var osFlags int
	trunc := false
	sftpFileOpenFlags := request.Pflags()
	if sftpFileOpenFlags.Read && sftpFileOpenFlags.Write {
		osFlags |= os.O_RDWR
	} else if sftpFileOpenFlags.Write {
		osFlags |= os.O_WRONLY
	}
	if sftpFileOpenFlags.Append {
		osFlags |= os.O_APPEND
	}
	if sftpFileOpenFlags.Creat {
		osFlags |= os.O_CREATE
	}
	if sftpFileOpenFlags.Trunc {
		osFlags |= os.O_TRUNC
		trunc = true
	}

	if !trunc {
		// see https://github.com/pkg/sftp/issues/295
		logger.Info(logSender, "upload resume is not supported, returning error")
		return nil, sftp.ErrSshFxOpUnsupported
	}

	// we use 0666 so the umask is applied
	file, err := os.OpenFile(p, osFlags, 0666)
	if err != nil {
		logger.Error(logSender, "error opening existing file, flags: %v, source: %v, err: %v", request.Flags, p, err)
		return nil, sftp.ErrSshFxFailure
	}

	if trunc {
		logger.Debug(logSender, "file truncation requested update quota for user %v", c.User.Username)
		dataprovider.UpdateUserQuota(dataProvider, c.User.Username, -1, -stat.Size(), false)
	}

	utils.SetPathPermissions(p, c.User.GetUID(), c.User.GetGID())

	logger.Debug(logSender, "file upload started for path \"%v\" user: %v", p, c.User.Username)

	transfer := Transfer{
		file:          file,
		path:          p,
		start:         time.Now(),
		bytesSent:     0,
		bytesReceived: 0,
		user:          c.User,
		connectionID:  c.ID,
		transferType:  transferUpload,
		isNewFile:     trunc,
	}
	addTransfer(&transfer)
	return &transfer, nil
}

// Filecmd hander for basic SFTP system calls related to files, but not anything to do with reading
// or writing to those files.
func (c Connection) Filecmd(request *sftp.Request) error {
	updateConnectionActivity(c.ID)

	p, err := c.buildPath(request.Filepath)
	if err != nil {
		return sftp.ErrSshFxNoSuchFile
	}

	var target string
	// If a target is provided in this request validate that it is going to the correct
	// location for the server. If it is not, return an operation unsupported error. This
	// is maybe not the best error response, but its not wrong either.
	if request.Target != "" {
		target, err = c.buildPath(request.Target)
		if err != nil {
			return sftp.ErrSshFxOpUnsupported
		}
	}

	logger.Debug(logSender, "new cmd, method: %v user: %v", request.Method, c.User.Username)

	switch request.Method {
	case "Setstat":
		return nil
	case "Rename":
		if !c.User.HasPerm(dataprovider.PermRename) {
			return sftp.ErrSshFxPermissionDenied
		}

		logger.CommandLog(sftpdRenameLogSender, p, target, c.User.Username, c.ID)
		if err := os.Rename(p, target); err != nil {
			logger.Error("failed to rename file, source: %v target: %v: %v", p, target, err)
			return sftp.ErrSshFxFailure
		}

		break
	case "Rmdir":
		if !c.User.HasPerm(dataprovider.PermDelete) {
			return sftp.ErrSshFxPermissionDenied
		}

		logger.CommandLog(sftpdRmdirLogSender, p, target, c.User.Username, c.ID)
		numFiles, size, err := utils.ScanDirContents(p)
		if err != nil {
			logger.Error("failed to remove directory %v, scanning error: %v", p, err)
			return sftp.ErrSshFxFailure
		}
		if err := os.RemoveAll(p); err != nil {
			logger.Error("failed to remove directory %v: %v", p, err)
			return sftp.ErrSshFxFailure
		}

		dataprovider.UpdateUserQuota(dataProvider, c.User.Username, -numFiles, -size, false)

		return sftp.ErrSshFxOk
	case "Mkdir":
		if !c.User.HasPerm(dataprovider.PermCreateDirs) {
			return sftp.ErrSshFxPermissionDenied
		}

		logger.CommandLog(sftpdMkdirLogSender, p, target, c.User.Username, c.ID)
		dirsToCreate, err := c.findNonexistentDirs(filepath.Join(p, "testfile"))
		if err != nil {
			return sftp.ErrSshFxFailure
		}

		last := len(dirsToCreate) - 1
		for i := range dirsToCreate {
			d := dirsToCreate[last-i]
			if err := os.Mkdir(d, 0777); err != nil {
				logger.Error(logSender, "error making path dir: %v, full path: %v", d, p)
				return sftp.ErrSshFxFailure
			}
			utils.SetPathPermissions(d, c.User.GetUID(), c.User.GetGID())
		}
		break
	case "Symlink":
		if !c.User.HasPerm(dataprovider.PermCreateSymlinks) {
			return sftp.ErrSshFxPermissionDenied
		}

		logger.CommandLog(sftpdSymlinkLogSender, p, target, c.User.Username, c.ID)
		if err := os.Symlink(p, target); err != nil {
			logger.Warn("failed to create symlink %v->%v: %v", p, target, err)
			return sftp.ErrSshFxFailure
		}

		break
	case "Remove":
		if !c.User.HasPerm(dataprovider.PermDelete) {
			return sftp.ErrSshFxPermissionDenied
		}

		logger.CommandLog(sftpdRemoveLogSender, p, target, c.User.Username, c.ID)
		var size int64
		var fi os.FileInfo
		if fi, err = os.Lstat(p); err != nil {
			logger.Error(logSender, "failed to remove a file %v: stat error: %v", p, err)
			return sftp.ErrSshFxFailure
		}
		size = fi.Size()
		if err := os.Remove(p); err != nil {
			logger.Error(logSender, "failed to remove a file %v: %v", p, err)
			return sftp.ErrSshFxFailure
		}

		if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
			dataprovider.UpdateUserQuota(dataProvider, c.User.Username, -1, -size, false)
		}

		return sftp.ErrSshFxOk
	default:
		return sftp.ErrSshFxOpUnsupported
	}

	var fileLocation = p
	if target != "" {
		fileLocation = target
	}

	utils.SetPathPermissions(fileLocation, c.User.GetUID(), c.User.GetGID())

	return sftp.ErrSshFxOk
}

// Filelist is the handler for SFTP filesystem list calls. This will handle calls to list the contents of
// a directory as well as perform file/folder stat calls.
func (c Connection) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	updateConnectionActivity(c.ID)
	p, err := c.buildPath(request.Filepath)
	if err != nil {
		return nil, sftp.ErrSshFxNoSuchFile
	}

	switch request.Method {
	case "List":
		if !c.User.HasPerm(dataprovider.PermListItems) {
			return nil, sftp.ErrSshFxPermissionDenied
		}

		logger.Debug(logSender, "requested list file for dir: %v user: %v", p, c.User.Username)

		files, err := ioutil.ReadDir(p)
		if err != nil {
			logger.Error(logSender, "error listing directory: %v", err)
			return nil, sftp.ErrSshFxFailure
		}

		return ListerAt(files), nil
	case "Stat":
		if !c.User.HasPerm(dataprovider.PermListItems) {
			return nil, sftp.ErrSshFxPermissionDenied
		}

		logger.Debug(logSender, "requested stat for file: %v user: %v", p, c.User.Username)
		s, err := os.Stat(p)
		if os.IsNotExist(err) {
			return nil, sftp.ErrSshFxNoSuchFile
		} else if err != nil {
			logger.Error(logSender, "error running STAT on file: %v", err)
			return nil, sftp.ErrSshFxFailure
		}

		return ListerAt([]os.FileInfo{s}), nil
	default:
		return nil, sftp.ErrSshFxOpUnsupported
	}
}

func (c Connection) hasSpace(checkFiles bool) bool {
	if (checkFiles && c.User.QuotaFiles > 0) || c.User.QuotaSize > 0 {
		numFile, size, err := dataprovider.GetUsedQuota(c.dataProvider, c.User.Username)
		if err != nil {
			if _, ok := err.(*dataprovider.MethodDisabledError); ok {
				logger.Warn(logSender, "quota enforcement not possibile for user %v: %v", c.User.Username, err)
				return true
			}
			logger.Warn(logSender, "error getting used quota for %v: %v", c.User.Username, err)
			return false
		}
		if (checkFiles && numFile >= c.User.QuotaFiles) || size >= c.User.QuotaSize {
			logger.Debug(logSender, "quota exceed for user %v, num files: %v/%v, size: %v/%v check files: %v",
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
			logger.Warn(logSender, "error resolving not existent path: %v", err)
		}
		return r, err
	}

	err = c.isSubDir(p)
	if err != nil {
		logger.Warn(logSender, "Invalid path resolution, dir: %v outside user home: %v err: %v", p, c.User.HomeDir, err)
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
		logger.Warn(logSender, "Error finding non existing dir: %v", err)
	}
	return results, err
}

// iterate up the path chain until we hit a directory that does exist and can be validated.
func (c Connection) findFirstExistingDir(path string) (string, error) {
	results, err := c.findNonexistentDirs(path)
	if err != nil {
		logger.Warn(logSender, "unable to find non existent dirs: %v", err)
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
		return "", fmt.Errorf("resolved path is not a dir: %v", p)
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
		logger.Warn(logSender, "invalid home dir %v: %v", c.User.HomeDir, err)
		return err
	}
	if !strings.HasPrefix(sub, parent) {
		logger.Warn(logSender, "dir %v is not inside: %v ", sub, parent)
		return fmt.Errorf("dir %v is not inside: %v", sub, parent)
	}
	return nil
}
