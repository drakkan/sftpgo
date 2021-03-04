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

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
	"github.com/rs/xid"

	"github.com/spf13/afero"
)

func init() {
	// show that we got memfs support
	version.AddFeature("+memfs")

	// initialize the default memory filesystem backend so
	// that it survives user disconnects. Resets on server
	// restart.
	defaultMemFsBackend = afero.NewMemMapFs()
}

var (
	defaultMemFsBackend afero.Fs
)

const (
	// memFsName is the name for the memory filesystem
	memFsName = "memfs"
)

// MemFs is a filesystem using memory
// The backed is provied by spf13/afero
type MemFs struct {
	name           string
	connectionID   string
	rootDir        string
	virtualFolders []VirtualFolder
	backend        afero.Fs
}

// NewMemFs creates a new
func NewMemFs(connectionID string, rootDir string, virtualFolders []VirtualFolder) (Fs, error) {

	fmt.Println("CREATING MEMFS")

	// TODO: additional config?

	var err error
	fs := &MemFs{
		name:           memFsName,
		connectionID:   connectionID,
		rootDir:        rootDir,
		virtualFolders: virtualFolders,
		backend:        defaultMemFsBackend, // TODO: make it possible to configure user session storages? afero.NewBasePathFs()?
	}

	// TODO: add some method for persistence, even though it's memory only? I.e. feeding it back to disk

	return fs, err
}

// Name returns the name for the Fs implementation
func (fs *MemFs) Name() string {
	return fs.name
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *MemFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *MemFs) Stat(name string) (os.FileInfo, error) {
	fmt.Println("MEM STAT")
	return fs.backend.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs *MemFs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
	//return nil, ErrVfsUnsupported // TODO: symlinking
}

// Open opens the named file for reading
func (fs *MemFs) Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error) {
	fmt.Println("MEM OPEN")
	file, err := fs.backend.Open(name)
	return file, nil, nil, err
}

// Create creates or opens the named file for writing
func (fs *MemFs) Create(name string, flag int) (File, *PipeWriter, func(), error) {

	fmt.Println("MEM CREATE")

	var err error
	var file File

	if flag == 0 {
		file, err = fs.backend.Create(name)
	} else {
		file, err = fs.backend.OpenFile(name, flag, os.ModePerm)
	}

	return file, nil, nil, err
}

// Rename renames (moves) source to target.
func (fs *MemFs) Rename(source, target string) error {
	return fs.backend.Rename(source, target)
}

// Remove removes the named file or (empty) directory.
func (fs *MemFs) Remove(name string, isDir bool) error {
	return fs.backend.Remove(name)
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *MemFs) Mkdir(name string) error {
	return fs.backend.Mkdir(name, os.ModePerm)
}

// Symlink creates source as a symbolic link to target.
func (*MemFs) Symlink(source, target string) error {
	// TODO: seems it can be done with Afero
	return ErrVfsUnsupported
}

// Readlink returns the destination of the named symbolic link
func (*MemFs) Readlink(name string) (string, error) {
	return "", ErrVfsUnsupported
}

// Chown changes the numeric uid and gid of the named file.
func (fs *MemFs) Chown(name string, uid int, gid int) error {
	return fs.backend.Chown(name, uid, gid)
}

// Chmod changes the mode of the named file to mode.
func (fs *MemFs) Chmod(name string, mode os.FileMode) error {
	return fs.backend.Chmod(name, mode)
}

// Chtimes changes the access and modification times of the named file.
func (fs *MemFs) Chtimes(name string, atime, mtime time.Time) error {
	return fs.backend.Chtimes(name, atime, mtime)
}

// Truncate changes the size of the named file.
func (fs *MemFs) Truncate(name string, size int64) error {

	file, err := fs.backend.Open(name)
	if err != nil {
		return err
	}

	return file.Truncate(size)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *MemFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	fmt.Println("MEM READDIR")
	return afero.ReadDir(fs.backend, dirname)
}

// IsUploadResumeSupported returns true if upload resume is supported.
func (*MemFs) IsUploadResumeSupported() bool {
	return true
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
func (*MemFs) IsAtomicUploadSupported() bool {
	return true
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*MemFs) IsNotExist(err error) bool {
	if err == nil {
		return false
	}

	fmt.Println(err)
	fmt.Println(fmt.Sprintf("%#+v", err))
	fmt.Println(fmt.Sprintf("%T", err))

	// TODO: do actual type check for the error? i.e. fs.PathError
	if strings.Contains(err.Error(), "file does not exist") {
		return true
	}

	if strings.Contains(err.Error(), "no such file or directory") {
		return true
	}

	return false
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*MemFs) IsPermission(err error) bool {
	if err == nil {
		return false
	}
	// TODO: do actual type check? i.e. fs.ErrPermissions
	if strings.Contains(err.Error(), "permission denied") {
		return true
	}
	return false
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*MemFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *MemFs) CheckRootPath(username string, uid int, gid int) bool {
	var err error
	if _, err = fs.Stat(fs.rootDir); fs.IsNotExist(err) {
		err = fs.backend.MkdirAll(fs.rootDir, os.ModePerm)
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

func (fs *MemFs) createMissingDirs(filePath string, uid, gid int) error {
	dirsToCreate, err := fs.findNonexistentDirs(filePath, fs.rootDir)
	if err != nil {
		return err
	}
	last := len(dirsToCreate) - 1
	for i := range dirsToCreate {
		d := dirsToCreate[last-i]
		if err := fs.backend.Mkdir(d, os.ModePerm); err != nil {
			fsLog(fs, logger.LevelError, "error creating missing dir: %#v", d)
			return err
		}
		SetPathPermissions(fs, d, uid, gid)
	}
	return nil
}

func (fs *MemFs) findNonexistentDirs(path, rootPath string) ([]string, error) {
	results := []string{}
	cleanPath := filepath.Clean(path)
	parent := filepath.Dir(cleanPath)

	_, err := fs.Stat(parent)
	for os.IsNotExist(err) {
		results = append(results, parent)
		parent = filepath.Dir(parent)
		_, err = fs.Stat(parent)
	}
	if err != nil {
		return results, err
	}
	//p, err := filepath.EvalSymlinks(parent) // TODO: fix symlinks?
	p, err := fs.evalSymlinks(parent)
	if err != nil {
		return results, err
	}
	err = fs.isSubDir(p, rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "error finding non existing dir: %v", err)
	}
	return results, err
}

func (fs *MemFs) isSubDir(sub, rootPath string) error {
	// rootPath must exist and it is already a validated absolute path
	//parent, err := filepath.EvalSymlinks(rootPath) // TODO: fix symlinks?
	parent, err := fs.evalSymlinks(rootPath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "invalid root path %#v: %v", rootPath, err)
		return err
	}
	if parent == sub {
		return nil
	}
	if len(sub) < len(parent) {
		fmt.Println("lensublenparent")
		err = fmt.Errorf("path %#v is not inside %#v", sub, parent)
		return err
	}
	if !strings.HasPrefix(sub, parent+string(afero.FilePathSeparator)) {
		if !(parent == afero.FilePathSeparator) {
			fmt.Println(sub, parent+string(afero.FilePathSeparator))
			fmt.Println("hasprefix")
			err = fmt.Errorf("path %#v is not inside %#v", sub, parent)
			return err
		}
	}
	return nil
}

// ScanRootDirContents returns the number of files contained in the bucket,
// and their size
func (fs *MemFs) ScanRootDirContents() (int, int64, error) {
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

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *MemFs) GetDirSize(dirname string) (int, int64, error) {

	numFiles := 0
	size := int64(0)
	isDir, err := IsDirectory(fs, dirname)
	if err == nil && isDir {
		err = filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info != nil && info.Mode().IsRegular() {
				numFiles++
				size += info.Size()
			}
			return err
		})
	}

	return numFiles, size, err
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
func (*MemFs) GetAtomicUploadPath(name string) string {
	dir := filepath.Dir(name)
	guid := xid.New().String()
	return filepath.Join(dir, ".sftpgo-upload."+guid+"."+filepath.Base(name))
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs *MemFs) GetRelativePath(name string) string {
	basePath := fs.rootDir
	virtualPath := "/"
	for _, v := range fs.virtualFolders {
		if strings.HasPrefix(name, v.MappedPath+string(afero.FilePathSeparator)) ||
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
func (fs *MemFs) Walk(root string, walkFn filepath.WalkFunc) error {
	fmt.Println("MEM WALK")
	return afero.Walk(fs.backend, root, walkFn)
}

// Join joins any number of path elements into a single path
func (*MemFs) Join(elem ...string) string {
	return strings.TrimPrefix(path.Join(elem...), "/")
}

// HasVirtualFolders returns true if folders are emulated
func (MemFs) HasVirtualFolders() bool {
	return false
}

// ResolvePath returns the matching filesystem path for the specified virtual path
func (fs *MemFs) ResolvePath(sftpPath string) (string, error) {

	fmt.Println("MEM RESOLVEPATH")

	if !filepath.IsAbs(fs.rootDir) {
		return "", fmt.Errorf("Invalid root path: %v", fs.rootDir)
	}

	basePath, r := fs.GetFsPaths(sftpPath)
	//p, err := filepath.EvalSymlinks(r) // TODO: fix symlinks?
	p, err := fs.evalSymlinks(r)
	if err != nil && !fs.IsNotExist(err) {
		return "", err
	} else if fs.IsNotExist(err) {
		// The requested path doesn't exist, so at this point we need to iterate up the
		// path chain until we hit a directory that _does_ exist and can be validated.
		_, err = fs.findFirstExistingDir(r, basePath)
		if err != nil {
			fsLog(fs, logger.LevelWarn, "error resolving non-existent path %#v", err)
		}
		return r, err
	}

	err = fs.isSubDir(p, basePath)
	if err != nil {
		fsLog(fs, logger.LevelWarn, "Invalid path resolution, dir %#v original path %#v resolved %#v err: %v",
			p, sftpPath, r, err)
	}
	return r, err

}

func (fs *MemFs) evalSymlinks(path string) (string, error) {
	// TODO: using filepath.EvalSymlinks doesn't work correctly
	// return filepath.EvalSymlinks(path)
	return path, nil
}

// GetFsPaths returns the base path and filesystem path for the given sftpPath.
// base path is the root dir or matching the virtual folder dir for the sftpPath.
// file path is the filesystem path matching the sftpPath
func (fs *MemFs) GetFsPaths(sftpPath string) (string, string) {
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
func (fs *MemFs) getMappedFolderForPath(p string) (virtualPath, mappedPath string) {
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

func (fs *MemFs) findFirstExistingDir(path, rootPath string) (string, error) {
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
	//p, err := filepath.EvalSymlinks(parent) // TODO: fix symlinks?
	p, err := fs.evalSymlinks(parent)
	if err != nil {
		return "", err
	}
	fileInfo, err := fs.Stat(p)
	if err != nil {
		return "", err
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("resolved path is not a dir: %#v", p)
	}
	err = fs.isSubDir(p, rootPath)
	return p, err
}

func (fs *MemFs) resolve(name string, prefix string) (string, bool) {
	result := strings.TrimPrefix(name, prefix)
	isDir := strings.HasSuffix(result, "/")
	if isDir {
		result = strings.TrimSuffix(result, "/")
	}
	return result, isDir
}

func (fs *MemFs) getPrefix(name string) string {
	prefix := ""
	if name != "" && name != "." && name != "/" {
		prefix = strings.TrimPrefix(name, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	return prefix
}

// GetMimeType returns the content type
func (fs *MemFs) GetMimeType(name string) (string, error) {

	file, err := fs.backend.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var buf [512]byte
	n, err := io.ReadFull(file, buf[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}
	ctype := http.DetectContentType(buf[:n])

	// Rewind file.
	_, err = file.Seek(0, io.SeekStart)
	return ctype, err
}

// Close closes the fs
func (fs *MemFs) Close() error {
	return nil
}

// GetAvailableDiskSize return the available size for the specified path
func (*MemFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	// TODO: some maximum amount of memory?
	return nil, ErrStorageSizeUnavailable
}
