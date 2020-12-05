package vfs

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const (
	// osFsName is the name for the local Fs implementation
	osFsName = "osfs"
)

// OsFs is a Fs implementation that uses functions provided by the os package.
type OsFs struct {
	name           string
	connectionID   string
	rootDir        string
	virtualFolders []VirtualFolder
}

// NewOsFs returns an OsFs object that allows to interact with local Os filesystem
func NewOsFs(connectionID, rootDir string, virtualFolders []VirtualFolder) Fs {
	return &OsFs{
		name:           osFsName,
		connectionID:   connectionID,
		rootDir:        rootDir,
		virtualFolders: virtualFolders,
	}
}

// Name returns the name for the Fs implementation
func (fs *OsFs) Name() string {
	return fs.name
}

// ConnectionID returns the SSH connection ID associated to this Fs implementation
func (fs *OsFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *OsFs) Stat(name string) (os.FileInfo, error) {
	fi, err := os.Stat(name)
	if err != nil {
		return fi, err
	}
	for _, v := range fs.virtualFolders {
		if v.MappedPath == name {
			info := NewFileInfo(v.VirtualPath, true, fi.Size(), fi.ModTime(), false)
			return info, nil
		}
	}
	return fi, err
}

// Lstat returns a FileInfo describing the named file
func (fs *OsFs) Lstat(name string) (os.FileInfo, error) {
	fi, err := os.Lstat(name)
	if err != nil {
		return fi, err
	}
	for _, v := range fs.virtualFolders {
		if v.MappedPath == name {
			info := NewFileInfo(v.VirtualPath, true, fi.Size(), fi.ModTime(), false)
			return info, nil
		}
	}
	return fi, err
}

// Open opens the named file for reading
func (*OsFs) Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error) {
	f, err := os.Open(name)
	return f, nil, nil, err
}

// Create creates or opens the named file for writing
func (*OsFs) Create(name string, flag int) (File, *PipeWriter, func(), error) {
	var err error
	var f *os.File
	if flag == 0 {
		f, err = os.Create(name)
	} else {
		f, err = os.OpenFile(name, flag, os.ModePerm)
	}
	return f, nil, nil, err
}

// Rename renames (moves) source to target
func (*OsFs) Rename(source, target string) error {
	return os.Rename(source, target)
}

// Remove removes the named file or (empty) directory.
func (*OsFs) Remove(name string, isDir bool) error {
	return os.Remove(name)
}

// Mkdir creates a new directory with the specified name and default permissions
func (*OsFs) Mkdir(name string) error {
	return os.Mkdir(name, os.ModePerm)
}

// Symlink creates source as a symbolic link to target.
func (*OsFs) Symlink(source, target string) error {
	return os.Symlink(source, target)
}

// Readlink returns the destination of the named symbolic link
// as absolute virtual path
func (fs *OsFs) Readlink(name string) (string, error) {
	p, err := os.Readlink(name)
	if err != nil {
		return p, err
	}
	return fs.GetRelativePath(p), err
}

// Chown changes the numeric uid and gid of the named file.
func (*OsFs) Chown(name string, uid int, gid int) error {
	return os.Chown(name, uid, gid)
}

// Chmod changes the mode of the named file to mode
func (*OsFs) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(name, mode)
}

// Chtimes changes the access and modification times of the named file
func (*OsFs) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(name, atime, mtime)
}

// Truncate changes the size of the named file
func (*OsFs) Truncate(name string, size int64) error {
	return os.Truncate(name, size)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (*OsFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	list, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	return list, nil
}

// IsUploadResumeSupported returns true if upload resume is supported
func (*OsFs) IsUploadResumeSupported() bool {
	return true
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (*OsFs) IsAtomicUploadSupported() bool {
	return true
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*OsFs) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*OsFs) IsPermission(err error) bool {
	return os.IsPermission(err)
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*OsFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the root directory if it does not exists
func (fs *OsFs) CheckRootPath(username string, uid int, gid int) bool {
	var err error
	if _, err = fs.Stat(fs.rootDir); fs.IsNotExist(err) {
		err = os.MkdirAll(fs.rootDir, os.ModePerm)
		fsLog(fs, logger.LevelDebug, "root directory %#v for user %#v does not exist, try to create, mkdir error: %v",
			fs.rootDir, username, err)
		if err == nil {
			SetPathPermissions(fs, fs.rootDir, uid, gid)
		}
	}
	// create any missing dirs to the defined virtual dirs
	for _, v := range fs.virtualFolders {
		p := filepath.Clean(filepath.Join(fs.rootDir, v.VirtualPath))
		err = fs.createMissingDirs(p, uid, gid)
		if err != nil {
			return false
		}
	}
	return (err == nil)
}

// ScanRootDirContents returns the number of files contained in the root
// directory and their size
func (fs *OsFs) ScanRootDirContents() (int, int64, error) {
	numFiles, size, err := fs.GetDirSize(fs.rootDir)
	for _, v := range fs.virtualFolders {
		if !v.IsIncludedInUserQuota() {
			continue
		}
		num, s, err := fs.GetDirSize(v.MappedPath)
		if err != nil {
			if fs.IsNotExist(err) {
				fsLog(fs, logger.LevelWarn, "unable to scan contents for non-existent mapped path: %#v", v.MappedPath)
				continue
			}
			return numFiles, size, err
		}
		numFiles += num
		size += s
	}
	return numFiles, size, err
}

// GetAtomicUploadPath returns the path to use for an atomic upload
func (*OsFs) GetAtomicUploadPath(name string) string {
	dir := filepath.Dir(name)
	guid := xid.New().String()
	return filepath.Join(dir, ".sftpgo-upload."+guid+"."+filepath.Base(name))
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTP users
func (fs *OsFs) GetRelativePath(name string) string {
	basePath := fs.rootDir
	virtualPath := "/"
	for _, v := range fs.virtualFolders {
		if strings.HasPrefix(name, v.MappedPath+string(os.PathSeparator)) ||
			filepath.Clean(name) == v.MappedPath {
			basePath = v.MappedPath
			virtualPath = v.VirtualPath
		}
	}
	rel, err := filepath.Rel(basePath, filepath.Clean(name))
	if err != nil {
		return ""
	}
	if rel == "." || strings.HasPrefix(rel, "..") {
		rel = ""
	}
	return path.Join(virtualPath, filepath.ToSlash(rel))
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root
func (*OsFs) Walk(root string, walkFn filepath.WalkFunc) error {
	return filepath.Walk(root, walkFn)
}

// Join joins any number of path elements into a single path
func (*OsFs) Join(elem ...string) string {
	return filepath.Join(elem...)
}

// ResolvePath returns the matching filesystem path for the specified sftp path
func (fs *OsFs) ResolvePath(sftpPath string) (string, error) {
	if !filepath.IsAbs(fs.rootDir) {
		return "", fmt.Errorf("Invalid root path: %v", fs.rootDir)
	}
	basePath, r := fs.GetFsPaths(sftpPath)
	p, err := filepath.EvalSymlinks(r)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	} else if os.IsNotExist(err) {
		// The requested path doesn't exist, so at this point we need to iterate up the
		// path chain until we hit a directory that _does_ exist and can be validated.
		_, err = fs.findFirstExistingDir(r, basePath)
		if err != nil {
			fsLog(fs, logger.LevelWarn, "error resolving non-existent path: %#v", err)
		}
		return r, err
	}

	err = fs.isSubDir(p, basePath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "Invalid path resolution, dir: %#v outside user home: %#v err: %v", p, fs.rootDir, err)
	}
	return r, err
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *OsFs) GetDirSize(dirname string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	isDir, err := IsDirectory(fs, dirname)
	if err == nil && isDir {
		err = filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
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

// HasVirtualFolders returns true if folders are emulated
func (*OsFs) HasVirtualFolders() bool {
	return false
}

// GetFsPaths returns the base path and filesystem path for the given sftpPath.
// base path is the root dir or matching the virtual folder dir for the sftpPath.
// file path is the filesystem path matching the sftpPath
func (fs *OsFs) GetFsPaths(sftpPath string) (string, string) {
	basePath := fs.rootDir
	virtualPath, mappedPath := fs.getMappedFolderForPath(sftpPath)
	if len(mappedPath) > 0 {
		basePath = mappedPath
		sftpPath = strings.TrimPrefix(utils.CleanPath(sftpPath), virtualPath)
	}
	r := filepath.Clean(filepath.Join(basePath, sftpPath))
	return basePath, r
}

// returns the path for the mapped folders or an empty string
func (fs *OsFs) getMappedFolderForPath(p string) (virtualPath, mappedPath string) {
	if len(fs.virtualFolders) == 0 {
		return
	}
	dirsForPath := utils.GetDirsForSFTPPath(p)
	// dirsForPath contains all the dirs for a given path in reverse order
	// for example if the path is: /1/2/3/4 it contains:
	// [ "/1/2/3/4", "/1/2/3", "/1/2", "/1", "/" ]
	// so the first match is the one we are interested to
	for _, val := range dirsForPath {
		for _, v := range fs.virtualFolders {
			if val == v.VirtualPath {
				return v.VirtualPath, v.MappedPath
			}
		}
	}
	return
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
		fsLog(fs, logger.LevelWarn, "invalid root path %#v: %v", rootPath, err)
		return err
	}
	if parent == sub {
		return nil
	}
	if len(sub) < len(parent) {
		err = fmt.Errorf("path %#v is not inside: %#v", sub, parent)
		fsLog(fs, logger.LevelWarn, "error: %v ", err)
		return err
	}
	if !strings.HasPrefix(sub, parent+string(os.PathSeparator)) {
		err = fmt.Errorf("path %#v is not inside: %#v", sub, parent)
		fsLog(fs, logger.LevelWarn, "error: %v ", err)
		return err
	}
	return nil
}

func (fs *OsFs) createMissingDirs(filePath string, uid, gid int) error {
	dirsToCreate, err := fs.findNonexistentDirs(filePath, fs.rootDir)
	if err != nil {
		return err
	}
	last := len(dirsToCreate) - 1
	for i := range dirsToCreate {
		d := dirsToCreate[last-i]
		if err := os.Mkdir(d, os.ModePerm); err != nil {
			fsLog(fs, logger.LevelError, "error creating missing dir: %#v", d)
			return err
		}
		SetPathPermissions(fs, d, uid, gid)
	}
	return nil
}

// GetMimeType returns the content type
func (fs *OsFs) GetMimeType(name string) (string, error) {
	f, err := os.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var buf [512]byte
	n, err := io.ReadFull(f, buf[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}
	ctype := http.DetectContentType(buf[:n])
	// Rewind file.
	_, err = f.Seek(0, io.SeekStart)
	return ctype, err
}
