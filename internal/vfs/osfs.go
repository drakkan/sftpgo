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
	iofs "io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

const (
	// osFsName is the name for the local Fs implementation
	osFsName = "osfs"
)

// errNoRoot is returned by OsFs methods invoked after Close, or on a filesystem
// whose rootDir is not absolute.
var errNoRoot = errors.New("filesystem is not ready, root directory not initialized")

type pathResolutionError struct {
	err string
}

func (e *pathResolutionError) Error() string {
	return fmt.Sprintf("Path resolution error: %s", e.err)
}

func isPathResolutionError(err error) bool {
	var pErr *pathResolutionError
	return errors.As(err, &pErr)
}

// OsFs is a Fs implementation that uses functions provided by the os package.
type OsFs struct {
	name         string
	connectionID string
	rootDir      string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath       string
	readBufferSize  int
	writeBufferSize int
	root            atomic.Pointer[os.Root]
	rootMu          sync.Mutex
	// closed is read and written only under rootMu
	closed bool
}

// NewOsFs returns an OsFs object that allows to interact with local Os filesystem
func NewOsFs(connectionID, rootDir, mountPath string, config *sdk.OSFsConfig) Fs {
	var readBufferSize, writeBufferSize int
	if config != nil {
		readBufferSize = config.ReadBufferSize * 1024 * 1024
		writeBufferSize = config.WriteBufferSize * 1024 * 1024
	}
	fs := &OsFs{
		name:            osFsName,
		connectionID:    connectionID,
		rootDir:         rootDir,
		mountPath:       getMountPath(mountPath),
		readBufferSize:  readBufferSize,
		writeBufferSize: writeBufferSize,
	}
	fs.openRoot() //nolint:errcheck // best-effort: a missing home is created by CheckRootPath
	return fs
}

// openRoot returns the os.Root confinement, opening it on first use. A failed
// open is retried on the next call and reports the real error (not-exist,
// permission); a closed fs reports errNoRoot instead of reopening.
func (fs *OsFs) openRoot() (*os.Root, error) {
	if root := fs.root.Load(); root != nil {
		return root, nil
	}
	if !filepath.IsAbs(fs.rootDir) {
		return nil, errNoRoot
	}
	fs.rootMu.Lock()
	defer fs.rootMu.Unlock()

	if root := fs.root.Load(); root != nil {
		return root, nil
	}
	if fs.closed {
		return nil, errNoRoot
	}
	root, err := os.OpenRoot(fs.rootDir)
	if err != nil {
		return nil, err
	}
	fs.root.Store(root)
	return root, nil
}

// toRootRelative maps an absolute fsPath to the os.Root and a path relative to
// rootDir, rejecting anything not contained in the root and opening the
// confinement on first use. It returns the loaded *os.Root so callers operate on
// a single, stable handle.
func (fs *OsFs) toRootRelative(name string) (*os.Root, string, error) {
	root, err := fs.openRoot()
	if err != nil {
		return nil, "", err
	}
	cleanName := filepath.Clean(name)
	if strings.TrimRight(cleanName, `\/`) == strings.TrimRight(fs.rootDir, `\/`) {
		return root, ".", nil
	}
	rel, err := filepath.Rel(fs.rootDir, cleanName)
	if err != nil {
		return nil, "", &pathResolutionError{err: fmt.Sprintf("cannot resolve %q inside root %q: %v", name, fs.rootDir, err)}
	}
	if rel == "." {
		return root, ".", nil
	}
	if !filepath.IsLocal(rel) {
		return nil, "", &pathResolutionError{err: fmt.Sprintf("path %q is not inside root %q", name, fs.rootDir)}
	}
	return root, rel, nil
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
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return nil, err
	}
	return root.Stat(rel)
}

// Lstat returns a FileInfo describing the named file
func (fs *OsFs) Lstat(name string) (os.FileInfo, error) {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return nil, err
	}
	return root.Lstat(rel)
}

// Open opens the named file for reading
func (fs *OsFs) Open(name string, offset int64) (File, PipeReader, func(), error) {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return nil, nil, nil, err
	}
	f, err := root.Open(rel)
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
	r, w, err := createPipeFn(fs.rootDir, 0)
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
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return nil, nil, nil, err
	}
	if !fs.useWriteBuffering(flag) {
		var f *os.File
		if flag == 0 {
			f, err = root.Create(rel)
		} else {
			f, err = root.OpenFile(rel, flag, 0666)
		}
		return f, nil, nil, err
	}
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, nil, nil, err
	}
	r, w, err := createPipeFn(fs.rootDir, 0)
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

// Rename renames (moves) source to target. A move that would cross the os.Root
// boundary is reported as ErrCrossRename so the connection layer performs a
// confined copy + delete instead.
func (fs *OsFs) Rename(source, target string, checks int) (int, int64, error) {
	if source == target {
		return -1, -1, nil
	}
	// only a path resolution failure means the move crosses confinement roots
	root, relSource, errSource := fs.toRootRelative(source)
	if errSource != nil && !isPathResolutionError(errSource) {
		return -1, -1, errSource
	}
	_, relTarget, errTarget := fs.toRootRelative(target)
	if errTarget != nil && !isPathResolutionError(errTarget) {
		return -1, -1, errTarget
	}
	if errSource != nil || errTarget != nil {
		return -1, -1, ErrCrossRename
	}
	err := root.Rename(relSource, relTarget)
	if err != nil {
		if isCrossDeviceError(err) {
			return -1, -1, ErrCrossRename
		}
		return -1, -1, err
	}
	if checks&CheckUpdateModTime != 0 {
		fs.Chtimes(target, time.Now(), time.Now(), false) //nolint:errcheck
	}
	return -1, -1, nil
}

// Remove removes the named file or (empty) directory.
func (fs *OsFs) Remove(name string, _ bool) error {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return err
	}
	return root.Remove(rel)
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *OsFs) Mkdir(name string) error {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return err
	}
	return root.Mkdir(rel, os.ModePerm)
}

func (fs *OsFs) Symlink(source, target string) error {
	root, relTarget, err := fs.toRootRelative(target)
	if err != nil {
		return err
	}
	if filepath.IsAbs(source) {
		if rel, err := filepath.Rel(filepath.Dir(target), source); err == nil {
			source = rel
		}
	}
	source = filepath.FromSlash(source)
	return root.Symlink(source, relTarget)
}

func (fs *OsFs) Readlink(name string) (string, error) {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return "", err
	}
	target, err := root.Readlink(rel)
	if err != nil {
		return "", err
	}
	if linkTargetEscapes(target) {
		return "", &pathResolutionError{err: fmt.Sprintf("link target %q escapes from root", target)}
	}
	resolved, err := fs.resolveLinkTarget(root, rel, target)
	if err != nil {
		return "", err
	}
	return fs.GetRelativePath(filepath.Join(fs.rootDir, resolved)), nil
}

func (fs *OsFs) resolveLinkTarget(root *os.Root, linkRel, target string) (string, error) {
	rest := append(splitPathComponents(filepath.Dir(linkRel)), splitPathComponents(target)...)
	resolved := "."
	linksWalked := 0
	for len(rest) > 0 {
		comp := rest[0]
		rest = rest[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if resolved == "." {
				return "", &pathResolutionError{err: fmt.Sprintf("link target %q escapes from root", target)}
			}
			resolved = filepath.Dir(resolved)
			continue
		}
		candidate := filepath.Join(resolved, comp)
		// the final component is reported one level: do not follow it
		if len(rest) == 0 {
			return candidate, nil
		}
		info, err := root.Lstat(candidate)
		if err != nil {
			if isRootEscapeError(err) {
				return "", err
			}
			if fs.IsNotExist(err) {
				// the tail does not exist, so it holds no symlinks
				resolved = candidate
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = candidate
			continue
		}
		linksWalked++
		if linksWalked > maxResolvedSymlinks {
			fsLog(fs, logger.LevelError, "unable to resolve link, too many links: %d", linksWalked)
			return "", &pathResolutionError{err: "too many symbolic links"}
		}
		linkTarget, err := root.Readlink(candidate)
		if err != nil {
			return "", err
		}
		if linkTargetEscapes(linkTarget) {
			return "", &pathResolutionError{err: fmt.Sprintf("link target %q escapes from root", linkTarget)}
		}
		rest = append(splitPathComponents(linkTarget), rest...)
	}
	return resolved, nil
}

func linkTargetEscapes(target string) bool {
	return filepath.IsAbs(target) || filepath.VolumeName(target) != "" ||
		(len(target) > 0 && os.IsPathSeparator(target[0]))
}

func splitPathComponents(p string) []string {
	p = strings.Trim(filepath.ToSlash(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// Chown changes the numeric uid and gid of the named file.
func (fs *OsFs) Chown(name string, uid int, gid int) error {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return err
	}
	return root.Chown(rel, uid, gid)
}

// Chmod changes the mode of the named file to mode
func (fs *OsFs) Chmod(name string, mode os.FileMode) error {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return err
	}
	return root.Chmod(rel, mode)
}

// Chtimes changes the access and modification times of the named file
func (fs *OsFs) Chtimes(name string, atime, mtime time.Time, _ bool) error {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return err
	}
	return root.Chtimes(rel, atime, mtime)
}

// Truncate changes the size of the named file
func (fs *OsFs) Truncate(name string, size int64) error {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(rel, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *OsFs) ReadDir(dirname string) (DirLister, error) {
	root, rel, err := fs.toRootRelative(dirname)
	if err != nil {
		return nil, err
	}
	f, err := root.Open(rel)
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
	return errors.Is(err, iofs.ErrNotExist)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*OsFs) IsPermission(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*pathResolutionError); ok {
		return true
	}
	if isRootEscapeError(err) {
		return true
	}
	return errors.Is(err, iofs.ErrPermission)
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*OsFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the root directory if it does not exist.
func (fs *OsFs) CheckRootPath(username string, uid int, gid int) bool {
	_, err := fs.openRoot()
	if fs.IsNotExist(err) {
		if err := os.MkdirAll(fs.rootDir, os.ModePerm); err != nil {
			fsLog(fs, logger.LevelError, "error creating root directory %q for user %q: %v", fs.rootDir, username, err)
			return false
		}
		if _, err = fs.openRoot(); err == nil {
			SetPathPermissions(fs, fs.rootDir, uid, gid)
		}
	}
	if err != nil {
		fsLog(fs, logger.LevelError, "unable to open root directory %q for user %q: %v", fs.rootDir, username, err)
		return false
	}
	return true
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

// GetAtomicUploadPath returns the path to use for an atomic upload. The temp file
// is always created in the same directory as the target so the atomic rename
// stays on the same filesystem and the file remains reachable through the VFS.
func (*OsFs) GetAtomicUploadPath(name string) string {
	dir := filepath.Dir(name)
	guid := xid.New().String()
	return filepath.Join(dir, ".sftpgo-upload."+guid+"."+filepath.Base(name))
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs *OsFs) GetRelativePath(name string) string {
	return fs.relativeToRoot(fs.rootDir, name)
}

func (fs *OsFs) relativeToRoot(root, name string) string {
	virtualPath := "/"
	if fs.mountPath != "" {
		virtualPath = fs.mountPath
	}
	cleanName := filepath.Clean(name)
	if strings.TrimRight(cleanName, `\/`) == strings.TrimRight(root, `\/`) {
		return virtualPath
	}
	rel, err := filepath.Rel(root, cleanName)
	if err != nil {
		return virtualPath
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return virtualPath
	}
	if rel == "." {
		rel = ""
	}
	return path.Join(virtualPath, rel)
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root. The traversal is confined by the os.Root
// and the walked path passed to walkFn is rebuilt as an absolute fsPath so callers
// keep seeing the same path format as a plain filepath.Walk.
func (fs *OsFs) Walk(root string, walkFn filepath.WalkFunc) error {
	osRoot, rel, err := fs.toRootRelative(root)
	if err != nil {
		return err
	}
	return iofs.WalkDir(osRoot.FS(), filepath.ToSlash(rel), func(p string, d iofs.DirEntry, err error) error {
		absPath := filepath.Join(fs.rootDir, filepath.FromSlash(p))
		var info os.FileInfo
		if err == nil {
			info, err = d.Info()
		}
		return walkFn(absPath, info, err)
	})
}

// Join joins any number of path elements into a single path
func (*OsFs) Join(elem ...string) string {
	return filepath.Join(elem...)
}

// ResolvePath returns the matching filesystem path for the specified virtual
// path.
func (fs *OsFs) ResolvePath(virtualPath string) (string, error) {
	if !filepath.IsAbs(fs.rootDir) {
		return "", fmt.Errorf("invalid root path %q", fs.rootDir)
	}
	if fs.mountPath != "" {
		if after, found := strings.CutPrefix(virtualPath, fs.mountPath); found {
			virtualPath = after
		}
	}
	virtualPath = path.Clean("/" + virtualPath)
	return filepath.Clean(filepath.Join(fs.rootDir, virtualPath)), nil
}

const maxResolvedSymlinks = 10

// RealPath implements the FsRealPather interface. SSH_FXP_REALPATH does not
// mandate link resolution, and avoiding it keeps the result well-defined for
// not-yet-existing paths.
func (fs *OsFs) RealPath(p string) (string, error) {
	return fs.GetRelativePath(p), nil
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *OsFs) GetDirSize(dirname string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	isDir, err := isDirectory(fs, dirname)
	if err == nil && isDir {
		err = fs.Walk(dirname, func(_ string, info os.FileInfo, err error) error {
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

// GetMimeType returns the content type
func (fs *OsFs) GetMimeType(name string) (string, error) {
	root, rel, err := fs.toRootRelative(name)
	if err != nil {
		return "", err
	}
	f, err := root.OpenFile(rel, os.O_RDONLY, 0)
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

func (fs *OsFs) Close() error {
	fs.rootMu.Lock()
	defer fs.rootMu.Unlock()

	fs.closed = true
	if root := fs.root.Swap(nil); root != nil {
		return root.Close()
	}
	return nil
}

// GetAvailableDiskSize returns the available size for the specified path
func (fs *OsFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	root, rel, err := fs.toRootRelative(dirName)
	if err != nil {
		return nil, err
	}

	if _, err := root.Lstat(rel); err != nil {
		return nil, err
	}
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return getStatFS(f, fs.rootDir)
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
