package vfs

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
)

const (
	// osFsName is the name for the local Fs implementation
	sftpFsName = "sftpfs"
)

// SFTPFsConfig defines the configuration for SFTP based filesystem
type SFTPFsConfig struct {
	Endpoint     string      `json:"endpoint,omitempty"`
	Username     string      `json:"username,omitempty"`
	Password     *kms.Secret `json:"password,omitempty"`
	PrivateKey   *kms.Secret `json:"private_key,omitempty"`
	Fingerprints []string    `json:"fingerprints,omitempty"`
	// Prefix is the path prefix to strip from SFTP resource paths.
	Prefix string `json:"prefix,omitempty"`
	// Concurrent reads are safe to use and disabling them will degrade performance.
	// Some servers automatically delete files once they are downloaded.
	// Using concurrent reads is problematic with such servers.
	DisableCouncurrentReads bool `json:"disable_concurrent_reads,omitempty"`
}

func (c *SFTPFsConfig) setEmptyCredentialsIfNil() {
	if c.Password == nil {
		c.Password = kms.NewEmptySecret()
	}
	if c.PrivateKey == nil {
		c.PrivateKey = kms.NewEmptySecret()
	}
}

// Validate returns an error if the configuration is not valid
func (c *SFTPFsConfig) Validate() error {
	c.setEmptyCredentialsIfNil()
	if c.Endpoint == "" {
		return errors.New("endpoint cannot be empty")
	}
	_, _, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %v", err)
	}
	if c.Username == "" {
		return errors.New("username cannot be empty")
	}
	if c.Password.IsEmpty() && c.PrivateKey.IsEmpty() {
		return errors.New("credentials cannot be empty")
	}
	if c.Password.IsEncrypted() && !c.Password.IsValid() {
		return errors.New("invalid encrypted password")
	}
	if !c.Password.IsEmpty() && !c.Password.IsValidInput() {
		return errors.New("invalid password")
	}
	if c.PrivateKey.IsEncrypted() && !c.PrivateKey.IsValid() {
		return errors.New("invalid encrypted private key")
	}
	if !c.PrivateKey.IsEmpty() && !c.PrivateKey.IsValidInput() {
		return errors.New("invalid private key")
	}
	if c.Prefix != "" {
		c.Prefix = utils.CleanPath(c.Prefix)
	} else {
		c.Prefix = "/"
	}
	return nil
}

// EncryptCredentials encrypts password and/or private key if they are in plain text
func (c *SFTPFsConfig) EncryptCredentials(additionalData string) error {
	if c.Password.IsPlain() {
		c.Password.SetAdditionalData(additionalData)
		if err := c.Password.Encrypt(); err != nil {
			return err
		}
	}
	if c.PrivateKey.IsPlain() {
		c.PrivateKey.SetAdditionalData(additionalData)
		if err := c.PrivateKey.Encrypt(); err != nil {
			return err
		}
	}
	return nil
}

// SFTPFs is a Fs implementation for SFTP backends
type SFTPFs struct {
	sync.Mutex
	connectionID string
	config       *SFTPFsConfig
	sshClient    *ssh.Client
	sftpClient   *sftp.Client
	err          chan error
}

// NewSFTPFs returns an SFTPFa object that allows to interact with an SFTP server
func NewSFTPFs(connectionID string, config SFTPFsConfig) (Fs, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !config.Password.IsEmpty() && config.Password.IsEncrypted() {
		if err := config.Password.Decrypt(); err != nil {
			return nil, err
		}
	}
	if !config.PrivateKey.IsEmpty() && config.PrivateKey.IsEncrypted() {
		if err := config.PrivateKey.Decrypt(); err != nil {
			return nil, err
		}
	}
	sftpFs := &SFTPFs{
		connectionID: connectionID,
		config:       &config,
		err:          make(chan error, 1),
	}
	err := sftpFs.createConnection()
	return sftpFs, err
}

// Name returns the name for the Fs implementation
func (fs *SFTPFs) Name() string {
	return fmt.Sprintf("%v %#v", sftpFsName, fs.config.Endpoint)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *SFTPFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *SFTPFs) Stat(name string) (os.FileInfo, error) {
	if err := fs.checkConnection(); err != nil {
		return nil, err
	}
	info, err := fs.sftpClient.Stat(name)
	if err != nil {
		return nil, err
	}
	fi := NewFileInfo(info.Name(), info.IsDir(), info.Size(), info.ModTime(), false)
	fi.SetMode(info.Mode())
	return fi, nil
}

// Lstat returns a FileInfo describing the named file
func (fs *SFTPFs) Lstat(name string) (os.FileInfo, error) {
	if err := fs.checkConnection(); err != nil {
		return nil, err
	}
	info, err := fs.sftpClient.Lstat(name)
	if err != nil {
		return nil, err
	}
	fi := NewFileInfo(info.Name(), info.IsDir(), info.Size(), info.ModTime(), false)
	fi.SetMode(info.Mode())
	return fi, nil
}

// Open opens the named file for reading
func (fs *SFTPFs) Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error) {
	if err := fs.checkConnection(); err != nil {
		return nil, nil, nil, err
	}
	f, err := fs.sftpClient.Open(name)
	return f, nil, nil, err
}

// Create creates or opens the named file for writing
func (fs *SFTPFs) Create(name string, flag int) (File, *PipeWriter, func(), error) {
	err := fs.checkConnection()
	if err != nil {
		return nil, nil, nil, err
	}
	var f File
	if flag == 0 {
		f, err = fs.sftpClient.Create(name)
	} else {
		f, err = fs.sftpClient.OpenFile(name, flag)
	}
	return f, nil, nil, err
}

// Rename renames (moves) source to target.
func (fs *SFTPFs) Rename(source, target string) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	return fs.sftpClient.Rename(source, target)
}

// Remove removes the named file or (empty) directory.
func (fs *SFTPFs) Remove(name string, isDir bool) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	return fs.sftpClient.Remove(name)
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *SFTPFs) Mkdir(name string) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	return fs.sftpClient.Mkdir(name)
}

// Symlink creates source as a symbolic link to target.
func (fs *SFTPFs) Symlink(source, target string) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	return fs.sftpClient.Symlink(source, target)
}

// Readlink returns the destination of the named symbolic link
func (fs *SFTPFs) Readlink(name string) (string, error) {
	if err := fs.checkConnection(); err != nil {
		return "", err
	}
	return fs.sftpClient.ReadLink(name)
}

// Chown changes the numeric uid and gid of the named file.
func (fs *SFTPFs) Chown(name string, uid int, gid int) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	return fs.sftpClient.Chown(name, uid, gid)
}

// Chmod changes the mode of the named file to mode.
func (fs *SFTPFs) Chmod(name string, mode os.FileMode) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	return fs.sftpClient.Chmod(name, mode)
}

// Chtimes changes the access and modification times of the named file.
func (fs *SFTPFs) Chtimes(name string, atime, mtime time.Time) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	return fs.sftpClient.Chtimes(name, atime, mtime)
}

// Truncate changes the size of the named file.
func (fs *SFTPFs) Truncate(name string, size int64) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	return fs.sftpClient.Truncate(name, size)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *SFTPFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	if err := fs.checkConnection(); err != nil {
		return nil, err
	}
	entries, err := fs.sftpClient.ReadDir(dirname)
	if err != nil {
		return nil, err
	}
	result := make([]os.FileInfo, 0, len(entries))

	for _, entry := range entries {
		info := NewFileInfo(entry.Name(), entry.IsDir(), entry.Size(), entry.ModTime(), false)
		info.SetMode(entry.Mode())
		result = append(result, info)
	}
	return result, nil
}

// IsUploadResumeSupported returns true if upload resume is supported.
func (*SFTPFs) IsUploadResumeSupported() bool {
	return true
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
func (*SFTPFs) IsAtomicUploadSupported() bool {
	return true
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*SFTPFs) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*SFTPFs) IsPermission(err error) bool {
	return os.IsPermission(err)
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*SFTPFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *SFTPFs) CheckRootPath(username string, uid int, gid int) bool {
	return true
}

// ScanRootDirContents returns the number of files contained in a directory and
// their size
func (fs *SFTPFs) ScanRootDirContents() (int, int64, error) {
	return fs.GetDirSize(fs.config.Prefix)
}

// GetAtomicUploadPath returns the path to use for an atomic upload
func (*SFTPFs) GetAtomicUploadPath(name string) string {
	dir := path.Dir(name)
	guid := xid.New().String()
	return path.Join(dir, ".sftpgo-upload."+guid+"."+path.Base(name))
}

// GetRelativePath returns the path for a file relative to the sftp prefix if any.
// This is the path as seen by SFTPGo users
func (fs *SFTPFs) GetRelativePath(name string) string {
	rel := path.Clean(name)
	if rel == "." {
		rel = ""
	}
	if !path.IsAbs(rel) {
		return "/" + rel
	}
	if fs.config.Prefix != "/" {
		if !strings.HasPrefix(rel, fs.config.Prefix) {
			rel = "/"
		}
		rel = path.Clean("/" + strings.TrimPrefix(rel, fs.config.Prefix))
	}
	return rel
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root
func (fs *SFTPFs) Walk(root string, walkFn filepath.WalkFunc) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	walker := fs.sftpClient.Walk(root)
	for walker.Step() {
		err := walker.Err()
		if err != nil {
			return err
		}
		err = walkFn(walker.Path(), walker.Stat(), err)
		if err != nil {
			return err
		}
	}
	return nil
}

// Join joins any number of path elements into a single path
func (*SFTPFs) Join(elem ...string) string {
	return path.Join(elem...)
}

// HasVirtualFolders returns true if folders are emulated
func (*SFTPFs) HasVirtualFolders() bool {
	return false
}

// ResolvePath returns the matching filesystem path for the specified virtual path
func (fs *SFTPFs) ResolvePath(virtualPath string) (string, error) {
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean("/" + virtualPath)
	}
	fsPath := fs.Join(fs.config.Prefix, virtualPath)
	if fs.config.Prefix != "/" && fsPath != "/" {
		// we need to check if this path is a symlink outside the given prefix
		// or a file/dir inside a dir symlinked outside the prefix
		if err := fs.checkConnection(); err != nil {
			return "", err
		}
		var validatedPath string
		var err error
		validatedPath, err = fs.getRealPath(fsPath)
		if err != nil && !os.IsNotExist(err) {
			fsLog(fs, logger.LevelWarn, "Invalid path resolution, original path %v resolved %#v err: %v",
				virtualPath, fsPath, err)
			return "", err
		} else if os.IsNotExist(err) {
			for os.IsNotExist(err) {
				validatedPath = path.Dir(validatedPath)
				if validatedPath == "/" {
					err = nil
					break
				}
				validatedPath, err = fs.getRealPath(validatedPath)
			}
			if err != nil {
				fsLog(fs, logger.LevelWarn, "Invalid path resolution, dir %#v original path %#v resolved %#v err: %v",
					validatedPath, virtualPath, fsPath, err)
				return "", err
			}
		}
		if err := fs.isSubDir(validatedPath); err != nil {
			fsLog(fs, logger.LevelWarn, "Invalid path resolution, dir %#v original path %#v resolved %#v err: %v",
				validatedPath, virtualPath, fsPath, err)
			return "", err
		}
	}
	return fsPath, nil
}

// getRealPath returns the real remote path trying to resolve symbolic links if any
func (fs *SFTPFs) getRealPath(name string) (string, error) {
	info, err := fs.sftpClient.Lstat(name)
	if err != nil {
		return name, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fs.sftpClient.ReadLink(name)
	}
	return name, err
}

func (fs *SFTPFs) isSubDir(name string) error {
	if name == fs.config.Prefix {
		return nil
	}
	if len(name) < len(fs.config.Prefix) {
		err := fmt.Errorf("path %#v is not inside: %#v", name, fs.config.Prefix)
		return err
	}
	if !strings.HasPrefix(name, fs.config.Prefix+"/") {
		err := fmt.Errorf("path %#v is not inside: %#v", name, fs.config.Prefix)
		return err
	}
	return nil
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *SFTPFs) GetDirSize(dirname string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	if err := fs.checkConnection(); err != nil {
		return numFiles, size, err
	}
	isDir, err := IsDirectory(fs, dirname)
	if err == nil && isDir {
		walker := fs.sftpClient.Walk(dirname)
		for walker.Step() {
			err := walker.Err()
			if err != nil {
				return numFiles, size, err
			}
			if walker.Stat().Mode().IsRegular() {
				size += walker.Stat().Size()
				numFiles++
			}
		}
	}
	return numFiles, size, err
}

// GetMimeType returns the content type
func (fs *SFTPFs) GetMimeType(name string) (string, error) {
	if err := fs.checkConnection(); err != nil {
		return "", err
	}
	f, err := fs.sftpClient.OpenFile(name, os.O_RDONLY)
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

// GetAvailableDiskSize return the available size for the specified path
func (fs *SFTPFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	if err := fs.checkConnection(); err != nil {
		return nil, err
	}
	if _, ok := fs.sftpClient.HasExtension("statvfs@openssh.com"); !ok {
		return nil, ErrStorageSizeUnavailable
	}
	return fs.sftpClient.StatVFS(dirName)
}

// Close the connection
func (fs *SFTPFs) Close() error {
	fs.Lock()
	defer fs.Unlock()

	var sftpErr, sshErr error
	if fs.sftpClient != nil {
		sftpErr = fs.sftpClient.Close()
	}
	if fs.sshClient != nil {
		sshErr = fs.sshClient.Close()
	}
	if sftpErr != nil {
		return sftpErr
	}
	return sshErr
}

func (fs *SFTPFs) checkConnection() error {
	err := fs.closed()
	if err == nil {
		return nil
	}
	return fs.createConnection()
}

func (fs *SFTPFs) createConnection() error {
	fs.Lock()
	defer fs.Unlock()

	var err error
	clientConfig := &ssh.ClientConfig{
		User: fs.config.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(fs.config.Fingerprints) > 0 {
				fp := ssh.FingerprintSHA256(key)
				for _, provided := range fs.config.Fingerprints {
					if provided == fp {
						return nil
					}
				}
				return fmt.Errorf("Invalid fingerprint %#v", fp)
			}
			fsLog(fs, logger.LevelWarn, "login without host key validation, please provide at least a fingerprint!")
			return nil
		},
		ClientVersion: fmt.Sprintf("SSH-2.0-SFTPGo_%v", version.Get().Version),
	}
	if fs.config.PrivateKey.GetPayload() != "" {
		signer, err := ssh.ParsePrivateKey([]byte(fs.config.PrivateKey.GetPayload()))
		if err != nil {
			fs.err <- err
			return err
		}
		clientConfig.Auth = append(clientConfig.Auth, ssh.PublicKeys(signer))
	}
	if fs.config.Password.GetPayload() != "" {
		clientConfig.Auth = append(clientConfig.Auth, ssh.Password(fs.config.Password.GetPayload()))
	}
	fs.sshClient, err = ssh.Dial("tcp", fs.config.Endpoint, clientConfig)
	if err != nil {
		fs.err <- err
		return err
	}
	fs.sftpClient, err = sftp.NewClient(fs.sshClient)
	if err != nil {
		fs.sshClient.Close()
		fs.err <- err
		return err
	}
	if fs.config.DisableCouncurrentReads {
		fsLog(fs, logger.LevelDebug, "disabling concurrent reads")
		opt := sftp.UseConcurrentReads(false)
		opt(fs.sftpClient) //nolint:errcheck
	}
	go fs.wait()
	return nil
}

func (fs *SFTPFs) wait() {
	// we wait on the sftp client otherwise if the channel is closed but not the connection
	// we don't detect the event.
	fs.err <- fs.sftpClient.Wait()
	fsLog(fs, logger.LevelDebug, "sftp channel closed")

	fs.Lock()
	defer fs.Unlock()

	if fs.sshClient != nil {
		fs.sshClient.Close()
	}
}

func (fs *SFTPFs) closed() error {
	select {
	case err := <-fs.err:
		return err
	default:
		return nil
	}
}
