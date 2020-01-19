package vfs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/logger"
	"github.com/eikenb/pipeat"
	"github.com/rs/xid"
)

const (
	// osFsName is the name for the local Fs implementation
	osFsName = "osfs"
)

// OsFs is a Fs implementation that uses functions provided by the os package.
type OsFs struct {
	name         string
	connectionID string
}

// NewOsFs returns an OsFs object that allows to interact with local Os filesystem
func NewOsFs(connectionID string) Fs {
	return &OsFs{
		name:         osFsName,
		connectionID: connectionID}
}

// Name returns the name for the Fs implementation
func (fs OsFs) Name() string {
	return fs.name
}

// ConnectionID returns the SSH connection ID associated to this Fs implementation
func (fs OsFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (OsFs) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (OsFs) Lstat(name string) (os.FileInfo, error) {
	return os.Lstat(name)
}

// Open opens the named file for reading
func (OsFs) Open(name string) (*os.File, *pipeat.PipeReaderAt, func(), error) {
	f, err := os.Open(name)
	return f, nil, nil, err
}

// Create creates or opens the named file for writing
func (OsFs) Create(name string, flag int) (*os.File, *pipeat.PipeWriterAt, func(), error) {
	var err error
	var f *os.File
	if flag == 0 {
		f, err = os.Create(name)
	} else {
		f, err = os.OpenFile(name, flag, 0666)

	}
	return f, nil, nil, err
}

// Rename renames (moves) source to target
func (OsFs) Rename(source, target string) error {
	return os.Rename(source, target)
}

// Remove removes the named file or (empty) directory.
func (OsFs) Remove(name string, isDir bool) error {
	return os.Remove(name)
}

// Mkdir creates a new directory with the specified name and default permissions
func (OsFs) Mkdir(name string) error {
	return os.Mkdir(name, 0777)
}

// Symlink creates source as a symbolic link to target.
func (OsFs) Symlink(source, target string) error {
	return os.Symlink(source, target)
}

// Chown changes the numeric uid and gid of the named file.
func (OsFs) Chown(name string, uid int, gid int) error {
	return os.Chown(name, uid, gid)
}

// Chmod changes the mode of the named file to mode
func (OsFs) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(name, mode)
}

// Chtimes changes the access and modification times of the named file
func (OsFs) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(name, atime, mtime)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (OsFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	return ioutil.ReadDir(dirname)
}

// IsUploadResumeSupported returns true if upload resume is supported
func (OsFs) IsUploadResumeSupported() bool {
	return true
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (OsFs) IsAtomicUploadSupported() bool {
	return true
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (OsFs) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (OsFs) IsPermission(err error) bool {
	return os.IsPermission(err)
}

// CheckRootPath creates the specified root directory if it does not exists
func (fs OsFs) CheckRootPath(rootPath, username string, uid int, gid int) bool {
	var err error
	if _, err = fs.Stat(rootPath); fs.IsNotExist(err) {
		err = os.MkdirAll(rootPath, 0777)
		fsLog(fs, logger.LevelDebug, "root directory %#v for user %#v does not exist, try to create, mkdir error: %v",
			rootPath, username, err)
		if err == nil {
			SetPathPermissions(fs, rootPath, uid, gid)
		}
	}
	return (err == nil)
}

// ScanDirContents returns the number of files contained in a directory and
// their size
func (fs OsFs) ScanDirContents(dirPath string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	isDir, err := IsDirectory(fs, dirPath)
	if err == nil && isDir {
		err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info != nil && info.Mode().IsRegular() {
				size += info.Size()
				numFiles++
			}
			return err
		})
	}
	return numFiles, size, err
}

// GetAtomicUploadPath returns the path to use for an atomic upload
func (OsFs) GetAtomicUploadPath(name string) string {
	dir := filepath.Dir(name)
	guid := xid.New().String()
	return filepath.Join(dir, ".sftpgo-upload."+guid+"."+filepath.Base(name))
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTP users
func (OsFs) GetRelativePath(name, rootPath string) string {
	rel, err := filepath.Rel(rootPath, filepath.Clean(name))
	if err != nil {
		return ""
	}
	if rel == "." || strings.HasPrefix(rel, "..") {
		rel = ""
	}
	return "/" + filepath.ToSlash(rel)
}

// Join joins any number of path elements into a single path
func (OsFs) Join(elem ...string) string {
	return filepath.Join(elem...)
}

// ResolvePath returns the matching filesystem path for the specified sftp path
func (fs OsFs) ResolvePath(sftpPath, rootPath string) (string, error) {
	if !filepath.IsAbs(rootPath) {
		return "", fmt.Errorf("Invalid root path: %v", rootPath)
	}
	r := filepath.Clean(filepath.Join(rootPath, sftpPath))
	p, err := filepath.EvalSymlinks(r)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	} else if os.IsNotExist(err) {
		// The requested path doesn't exist, so at this point we need to iterate up the
		// path chain until we hit a directory that _does_ exist and can be validated.
		_, err = fs.findFirstExistingDir(r, rootPath)
		if err != nil {
			fsLog(fs, logger.LevelWarn, "error resolving not existent path: %#v", err)
		}
		return r, err
	}

	err = fs.isSubDir(p, rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "Invalid path resolution, dir: %#v outside user home: %#v err: %v", p, rootPath, err)
	}
	return r, err
}

func (fs *OsFs) findNonexistentDirs(path, rootPath string) ([]string, error) {
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
	err = fs.isSubDir(p, rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "error finding non existing dir: %v", err)
	}
	return results, err
}

func (fs *OsFs) findFirstExistingDir(path, rootPath string) (string, error) {
	results, err := fs.findNonexistentDirs(path, rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "unable to find non existent dirs: %v", err)
		return "", err
	}
	var parent string
	if len(results) > 0 {
		lastMissingDir := results[len(results)-1]
		parent = filepath.Dir(lastMissingDir)
	} else {
		parent = rootPath
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
	err = fs.isSubDir(p, rootPath)
	return p, err
}

func (fs *OsFs) isSubDir(sub, rootPath string) error {
	// rootPath must exist and it is already a validated absolute path
	parent, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "invalid home dir %#v: %v", rootPath, err)
		return err
	}
	if !strings.HasPrefix(sub, parent) {
		err = fmt.Errorf("path %#v is not inside: %#v", sub, parent)
		fsLog(fs, logger.LevelWarn, "error: %v ", err)
		return err
	}
	return nil
}
