// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package vfs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/eikenb/pipeat"
	fscopy "github.com/otiai10/copy"
	"github.com/pkg/sftp"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	// osFsName is the name for the local Fs implementation
	osFsName = "osfs"
)

type pathResolutionError struct {
	err string
}

func (e *pathResolutionError) Error() string {
	return fmt.Sprintf("Path resolution error: %s", e.err)
}

// OsFs is a Fs implementation that uses functions provided by the os package.
type OsFs struct {
	name         string
	connectionID string
	rootDir      string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath       string
	localTempDir    string
	readBufferSize  int
	writeBufferSize int
}

// NewOsFs returns an OsFs object that allows to interact with local Os filesystem
func NewOsFs(connectionID, rootDir, mountPath string, config *sdk.OSFsConfig) Fs {
	var readBufferSize, writeBufferSize int
	if config != nil {
		readBufferSize = config.ReadBufferSize * 1024 * 1024
		writeBufferSize = config.WriteBufferSize * 1024 * 1024
	}
	return &OsFs{
		name:            osFsName,
		connectionID:    connectionID,
		rootDir:         rootDir,
		mountPath:       getMountPath(mountPath),
		localTempDir:    getLocalTempDir(),
		readBufferSize:  readBufferSize,
		writeBufferSize: writeBufferSize,
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
	return os.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs *OsFs) Lstat(name string) (os.FileInfo, error) {
	return os.Lstat(name)
}

// Open opens the named file for reading
func (fs *OsFs) Open(name string, offset int64) (File, PipeReader, func(), error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, nil, err
	}
	if offset > 0 {
		_, err = f.Seek(offset, io.SeekStart)
		if err != nil {
			f.Close()
			return nil, nil, nil, err
		}
	}
	if fs.readBufferSize <= 0 {
		return f, nil, nil, err
	}
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	p := NewPipeReader(r)
	go func() {
		br := bufio.NewReaderSize(f, fs.readBufferSize)
		n, err := doCopy(w, br, nil)
		w.CloseWithError(err) //nolint:errcheck
		f.Close()
		fsLog(fs, logger.LevelDebug, "download completed, path: %q size: %v, err: %v", name, n, err)
	}()

	return nil, p, nil, nil
}

// Create creates or opens the named file for writing
func (fs *OsFs) Create(name string, flag, _ int) (File, PipeWriter, func(), error) {
	if !fs.useWriteBuffering(flag) {
		var err error
		var f *os.File
		if flag == 0 {
			f, err = os.Create(name)
		} else {
			f, err = os.OpenFile(name, flag, 0666)
		}
		return f, nil, nil, err
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, nil, nil, err
	}
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	p := NewPipeWriter(w)

	go func() {
		bw := bufio.NewWriterSize(f, fs.writeBufferSize)
		n, err := doCopy(bw, r, nil)
		errFlush := bw.Flush()
		if err == nil && errFlush != nil {
			err = errFlush
		}
		errClose := f.Close()
		if err == nil && errClose != nil {
			err = errClose
		}
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %q, readed bytes: %v, err: %v", name, n, err)
	}()

	return nil, p, nil, nil
}

// Rename renames (moves) source to target
func (fs *OsFs) Rename(source, target string) (int, int64, error) {
	if source == target {
		return -1, -1, nil
	}
	err := os.Rename(source, target)
	if err != nil && isCrossDeviceError(err) {
		fsLog(fs, logger.LevelError, "cross device error detected while renaming %q -> %q. Trying a copy and remove, this could take a long time",
			source, target)
		var readBufferSize uint
		if fs.readBufferSize > 0 {
			readBufferSize = uint(fs.readBufferSize)
		}

		err = fscopy.Copy(source, target, fscopy.Options{
			OnSymlink: func(_ string) fscopy.SymlinkAction {
				return fscopy.Skip
			},
			CopyBufferSize: readBufferSize,
		})
		if err != nil {
			fsLog(fs, logger.LevelError, "cross device copy error: %v", err)
			return -1, -1, err
		}
		err = os.RemoveAll(source)
		return -1, -1, err
	}
	return -1, -1, err
}

// Remove removes the named file or (empty) directory.
func (*OsFs) Remove(name string, _ bool) error {
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
	// we don't have to follow multiple links:
	// https://github.com/openssh/openssh-portable/blob/7bf2eb958fbb551e7d61e75c176bb3200383285d/sftp-server.c#L1329
	resolved, err := os.Readlink(name)
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(name), resolved)
	}
	return fs.GetRelativePath(resolved), nil
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
func (*OsFs) Chtimes(name string, atime, mtime time.Time, _ bool) error {
	return os.Chtimes(name, atime, mtime)
}

// Truncate changes the size of the named file
func (*OsFs) Truncate(name string, size int64) error {
	return os.Truncate(name, size)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (*OsFs) ReadDir(dirname string) (DirLister, error) {
	f, err := os.Open(dirname)
	if err != nil {
		if isInvalidNameError(err) {
			err = os.ErrNotExist
		}
		return nil, err
	}
	return &osFsDirLister{f}, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported
func (*OsFs) IsUploadResumeSupported() bool {
	return true
}

// IsConditionalUploadResumeSupported returns if resuming uploads is supported
// for the specified size
func (*OsFs) IsConditionalUploadResumeSupported(_ int64) bool {
	return true
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (*OsFs) IsAtomicUploadSupported() bool {
	return true
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*OsFs) IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*OsFs) IsPermission(err error) bool {
	if _, ok := err.(*pathResolutionError); ok {
		return true
	}
	return errors.Is(err, fs.ErrPermission)
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
		if err == nil {
			SetPathPermissions(fs, fs.rootDir, uid, gid)
		} else {
			fsLog(fs, logger.LevelError, "error creating root directory %q for user %q: %v", fs.rootDir, username, err)
		}
	}
	return err == nil
}

// ScanRootDirContents returns the number of files contained in the root
// directory and their size
func (fs *OsFs) ScanRootDirContents() (int, int64, error) {
	return fs.GetDirSize(fs.rootDir)
}

// CheckMetadata checks the metadata consistency
func (*OsFs) CheckMetadata() error {
	return nil
}

// GetAtomicUploadPath returns the path to use for an atomic upload
func (*OsFs) GetAtomicUploadPath(name string) string {
	dir := filepath.Dir(name)
	if tempPath != "" {
		dir = tempPath
	}
	guid := xid.New().String()
	return filepath.Join(dir, ".sftpgo-upload."+guid+"."+filepath.Base(name))
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs *OsFs) GetRelativePath(name string) string {
	virtualPath := "/"
	if fs.mountPath != "" {
		virtualPath = fs.mountPath
	}
	rel, err := filepath.Rel(fs.rootDir, filepath.Clean(name))
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
func (fs *OsFs) ResolvePath(virtualPath string) (string, error) {
	if !filepath.IsAbs(fs.rootDir) {
		return "", fmt.Errorf("invalid root path %q", fs.rootDir)
	}
	if fs.mountPath != "" {
		virtualPath = strings.TrimPrefix(virtualPath, fs.mountPath)
	}
	r := filepath.Clean(filepath.Join(fs.rootDir, virtualPath))
	p, err := filepath.EvalSymlinks(r)
	if isInvalidNameError(err) {
		err = os.ErrNotExist
	}
	isNotExist := fs.IsNotExist(err)
	if err != nil && !isNotExist {
		return "", err
	} else if isNotExist {
		// The requested path doesn't exist, so at this point we need to iterate up the
		// path chain until we hit a directory that _does_ exist and can be validated.
		_, err = fs.findFirstExistingDir(r)
		if err != nil {
			fsLog(fs, logger.LevelError, "error resolving non-existent path %q", err)
		}
		return r, err
	}

	err = fs.isSubDir(p)
	if err != nil {
		fsLog(fs, logger.LevelError, "Invalid path resolution, path %q original path %q resolved %q err: %v",
			p, virtualPath, r, err)
	}
	return r, err
}

// RealPath implements the FsRealPather interface
func (fs *OsFs) RealPath(p string) (string, error) {
	linksWalked := 0
	for {
		info, err := os.Lstat(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fs.GetRelativePath(p), nil
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return fs.GetRelativePath(p), nil
		}
		resolvedLink, err := os.Readlink(p)
		if err != nil {
			return "", err
		}
		resolvedLink = filepath.Clean(resolvedLink)
		if filepath.IsAbs(resolvedLink) {
			p = resolvedLink
		} else {
			p = filepath.Join(filepath.Dir(p), resolvedLink)
		}
		linksWalked++
		if linksWalked > 10 {
			fsLog(fs, logger.LevelError, "unable to get real path, too many links: %d", linksWalked)
			return "", &pathResolutionError{err: "too many links"}
		}
	}
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *OsFs) GetDirSize(dirname string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	isDir, err := isDirectory(fs, dirname)
	if err == nil && isDir {
		err = filepath.Walk(dirname, func(_ string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info != nil && info.Mode().IsRegular() {
				size += info.Size()
				numFiles++
				if numFiles%1000 == 0 {
					fsLog(fs, logger.LevelDebug, "dirname %q scan in progress, files: %d, size: %d", dirname, numFiles, size)
				}
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

func (fs *OsFs) findNonexistentDirs(filePath string) ([]string, error) {
	results := []string{}
	cleanPath := filepath.Clean(filePath)
	parent := filepath.Dir(cleanPath)
	_, err := os.Stat(parent)

	for fs.IsNotExist(err) {
		results = append(results, parent)
		parent = filepath.Dir(parent)
		if util.Contains(results, parent) {
			break
		}
		_, err = os.Stat(parent)
	}
	if err != nil {
		return results, err
	}
	p, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return results, err
	}
	err = fs.isSubDir(p)
	if err != nil {
		fsLog(fs, logger.LevelError, "error finding non existing dir: %v", err)
	}
	return results, err
}

func (fs *OsFs) findFirstExistingDir(path string) (string, error) {
	results, err := fs.findNonexistentDirs(path)
	if err != nil {
		fsLog(fs, logger.LevelError, "unable to find non existent dirs: %v", err)
		return "", err
	}
	var parent string
	if len(results) > 0 {
		lastMissingDir := results[len(results)-1]
		parent = filepath.Dir(lastMissingDir)
	} else {
		parent = fs.rootDir
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
		return "", fmt.Errorf("resolved path is not a dir: %q", p)
	}
	err = fs.isSubDir(p)
	return p, err
}

func (fs *OsFs) isSubDir(sub string) error {
	// fs.rootDir must exist and it is already a validated absolute path
	parent, err := filepath.EvalSymlinks(fs.rootDir)
	if err != nil {
		fsLog(fs, logger.LevelError, "invalid root path %q: %v", fs.rootDir, err)
		return err
	}
	if parent == sub {
		return nil
	}
	if len(sub) < len(parent) {
		err = fmt.Errorf("path %q is not inside %q", sub, parent)
		return &pathResolutionError{err: err.Error()}
	}
	separator := string(os.PathSeparator)
	if parent == filepath.Dir(parent) {
		// parent is the root dir, on Windows we can have C:\, D:\ and so on here
		// so we still need the prefix check
		separator = ""
	}
	if !strings.HasPrefix(sub, parent+separator) {
		err = fmt.Errorf("path %q is not inside %q", sub, parent)
		return &pathResolutionError{err: err.Error()}
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

// Close closes the fs
func (*OsFs) Close() error {
	return nil
}

// GetAvailableDiskSize returns the available size for the specified path
func (*OsFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	return getStatFS(dirName)
}

func (fs *OsFs) useWriteBuffering(flag int) bool {
	if fs.writeBufferSize <= 0 {
		return false
	}
	if flag == 0 {
		return true
	}
	if flag&os.O_TRUNC == 0 {
		fsLog(fs, logger.LevelDebug, "truncate flag missing, buffering write not possible")
		return false
	}
	if flag&os.O_RDWR != 0 {
		fsLog(fs, logger.LevelDebug, "read and write flag found, buffering write not possible")
		return false
	}
	return true
}

type osFsDirLister struct {
	f *os.File
}

func (l *osFsDirLister) Next(limit int) ([]os.FileInfo, error) {
	if limit <= 0 {
		return nil, errInvalidDirListerLimit
	}
	return l.f.Readdir(limit)
}

func (l *osFsDirLister) Close() error {
	return l.f.Close()
}
