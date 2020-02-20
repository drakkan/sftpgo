package vfs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/tools/godoc/vfs"
	"golang.org/x/tools/godoc/vfs/mapfs"
)

// DynFs is a Fs implementation that fetches a mapping from a remote URL and maps virtual dirs to real dirs
type DynFs struct {
	connectionID string
	configURL    DynFsConfigURL
	rootDir      string
	VirtualFS    vfs.NameSpace
}

type DynFsConfigURL string

func parseDynConfig(configURL DynFsConfigURL) (vfs.NameSpace, error) {
	rawResponse := []byte{}
	virtfs := vfs.NameSpace{}
	var err error

	if configURL == "" {
		return virtfs, nil
	}

	resp, err := retryablehttp.Get(string(configURL))
	if err != nil {
		return virtfs, err
	}
	defer resp.Body.Close()

	rawResponse, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return virtfs, err
	}

	var response []string

	err = json.Unmarshal(rawResponse, &response)
	if err != nil {
		return virtfs, err
	}

	mapResponseToVFS(response, &virtfs)

	return virtfs, nil
}

func mapResponseToVFS(response []string, virtfs *vfs.NameSpace) {
	for _, l := range response {
		splitLine := strings.SplitN(l, ":", 3)
		if len(splitLine) < 2 {
			continue
		}
		virtLoc := splitLine[0]
		realLoc := splitLine[1]

		virtfs.Bind("/", mapfs.New(map[string]string{filepath.Join(virtLoc, ".hidden"): ""}), "/", vfs.BindAfter)
		virtfs.Bind(filepath.Join("/", virtLoc), vfs.OS(realLoc), "/", vfs.BindAfter)
	}
}

// NewDynFs returns an DynFs object that allows to interact with Dynamic filesystem
func NewDynFs(connectionID, rootDir string, configURL DynFsConfigURL) (Fs, error) {
	virtFS, err := parseDynConfig(configURL)
	if err != nil {
		return &DynFs{}, err
	}

	return &DynFs{
		connectionID: connectionID,
		rootDir:      rootDir,
		configURL:    configURL,
		VirtualFS:    virtFS,
	}, nil
}

// Name returns the name for the Fs implementation
func (fs DynFs) Name() string {
	return fmt.Sprintf("DynFs from: %s", fs.configURL)
}

// ConnectionID returns the SSH connection ID associated to this Fs implementation
func (fs DynFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs DynFs) Stat(name string) (os.FileInfo, error) {
	return fs.VirtualFS.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs DynFs) Lstat(name string) (os.FileInfo, error) {
	return fs.VirtualFS.Lstat(name)
}

// Open opens the named file for reading
func (fs DynFs) Open(name string) (*os.File, *pipeat.PipeReaderAt, func(), error) {
	f, err := fs.VirtualFS.Open(name)

	return f.(*os.File), nil, nil, err
}

// Create creates or opens the named file for writing
func (fs DynFs) Create(name string, flag int) (*os.File, *pipeat.PipeWriterAt, func(), error) {
	return nil, nil, nil, errors.New("operation not supported in virtual filesystem")
}

// Rename renames (moves) source to target
func (fs DynFs) Rename(source, target string) error {
	return errors.New("operation not supported in virtual filesystem")
}

// Remove removes the named file or (empty) directory.
func (fs DynFs) Remove(name string, isDir bool) error {
	return errors.New("operation not supported in virtual filesystem")
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs DynFs) Mkdir(name string) error {
	return errors.New("operation not supported in virtual filesystem")
}

// Symlink creates source as a symbolic link to target.
func (fs DynFs) Symlink(source, target string) error {
	return errors.New("operation not supported in virtual filesystem")
}

// Chown changes the numeric uid and gid of the named file.
func (fs DynFs) Chown(name string, uid int, gid int) error {
	return errors.New("operation not supported in virtual filesystem")
}

// Chmod changes the mode of the named file to mode
func (fs DynFs) Chmod(name string, mode os.FileMode) error {
	return errors.New("operation not supported in virtual filesystem")
}

// Chtimes changes the access and modification times of the named file
func (fs DynFs) Chtimes(name string, atime, mtime time.Time) error {
	return errors.New("operation not supported in virtual filesystem")
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs DynFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	return fs.VirtualFS.ReadDir(dirname)
}

// IsUploadResumeSupported returns true if upload resume is supported
func (fs DynFs) IsUploadResumeSupported() bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (fs DynFs) IsAtomicUploadSupported() bool {
	return false
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (fs DynFs) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (fs DynFs) IsPermission(err error) bool {
	return os.IsPermission(err)
}

// CheckRootPath creates the root directory if it does not exists
func (fs DynFs) CheckRootPath(username string, uid int, gid int) bool {
	return true
}

// ScanRootDirContents returns the number of files contained in a directory and
// their size
func (fs DynFs) ScanRootDirContents() (int, int64, error) {
	return 0, 0, nil
}

// GetAtomicUploadPath returns the path to use for an atomic upload
func (fs DynFs) GetAtomicUploadPath(name string) string {
	return ""
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTP users
func (fs DynFs) GetRelativePath(name string) string {
	return name
}

// Join joins any number of path elements into a single path
func (fs DynFs) Join(elem ...string) string {
	return filepath.Join(elem...)
}

// ResolvePath returns the matching filesystem path for the specified sftp path
func (fs DynFs) ResolvePath(sftpPath string) (string, error) {
	return sftpPath, nil
}
