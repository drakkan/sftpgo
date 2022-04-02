package vfs

import (
	"bufio"
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
	"github.com/sftpgo/sdk"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
)

const (
	// sftpFsName is the name for the SFTP Fs implementation
	sftpFsName = "sftpfs"
)

// ErrSFTPLoop defines the error to return if an SFTP loop is detected
var ErrSFTPLoop = errors.New("SFTP loop or nested local SFTP folders detected")

// SFTPFsConfig defines the configuration for SFTP based filesystem
type SFTPFsConfig struct {
	sdk.BaseSFTPFsConfig
	Password               *kms.Secret `json:"password,omitempty"`
	PrivateKey             *kms.Secret `json:"private_key,omitempty"`
	forbiddenSelfUsernames []string    `json:"-"`
}

// HideConfidentialData hides confidential data
func (c *SFTPFsConfig) HideConfidentialData() {
	if c.Password != nil {
		c.Password.Hide()
	}
	if c.PrivateKey != nil {
		c.PrivateKey.Hide()
	}
}

func (c *SFTPFsConfig) isEqual(other *SFTPFsConfig) bool {
	if c.Endpoint != other.Endpoint {
		return false
	}
	if c.Username != other.Username {
		return false
	}
	if c.Prefix != other.Prefix {
		return false
	}
	if c.DisableCouncurrentReads != other.DisableCouncurrentReads {
		return false
	}
	if c.BufferSize != other.BufferSize {
		return false
	}
	if len(c.Fingerprints) != len(other.Fingerprints) {
		return false
	}
	for _, fp := range c.Fingerprints {
		if !util.IsStringInSlice(fp, other.Fingerprints) {
			return false
		}
	}
	c.setEmptyCredentialsIfNil()
	other.setEmptyCredentialsIfNil()
	if !c.Password.IsEqual(other.Password) {
		return false
	}
	return c.PrivateKey.IsEqual(other.PrivateKey)
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
	if c.BufferSize < 0 || c.BufferSize > 16 {
		return errors.New("invalid buffer_size, valid range is 0-16")
	}
	if err := c.validateCredentials(); err != nil {
		return err
	}
	if c.Prefix != "" {
		c.Prefix = util.CleanPath(c.Prefix)
	} else {
		c.Prefix = "/"
	}
	return nil
}

func (c *SFTPFsConfig) validateCredentials() error {
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
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath    string
	localTempDir string
	config       *SFTPFsConfig
	sshClient    *ssh.Client
	sftpClient   *sftp.Client
	err          chan error
}

// NewSFTPFs returns an SFTPFs object that allows to interact with an SFTP server
func NewSFTPFs(connectionID, mountPath, localTempDir string, forbiddenSelfUsernames []string, config SFTPFsConfig) (Fs, error) {
	if localTempDir == "" {
		if tempPath != "" {
			localTempDir = tempPath
		} else {
			localTempDir = filepath.Clean(os.TempDir())
		}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !config.Password.IsEmpty() {
		if err := config.Password.TryDecrypt(); err != nil {
			return nil, err
		}
	}
	if !config.PrivateKey.IsEmpty() {
		if err := config.PrivateKey.TryDecrypt(); err != nil {
			return nil, err
		}
	}
	config.forbiddenSelfUsernames = forbiddenSelfUsernames
	sftpFs := &SFTPFs{
		connectionID: connectionID,
		mountPath:    getMountPath(mountPath),
		localTempDir: localTempDir,
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
	return fs.sftpClient.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs *SFTPFs) Lstat(name string) (os.FileInfo, error) {
	if err := fs.checkConnection(); err != nil {
		return nil, err
	}
	return fs.sftpClient.Lstat(name)
}

// Open opens the named file for reading
func (fs *SFTPFs) Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error) {
	if err := fs.checkConnection(); err != nil {
		return nil, nil, nil, err
	}
	f, err := fs.sftpClient.Open(name)
	if err != nil {
		return nil, nil, nil, err
	}
	if fs.config.BufferSize == 0 {
		return f, nil, nil, err
	}
	if offset > 0 {
		_, err = f.Seek(offset, io.SeekStart)
		if err != nil {
			f.Close()
			return nil, nil, nil, err
		}
	}
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	go func() {
		// if we enable buffering the client stalls
		//br := bufio.NewReaderSize(f, int(fs.config.BufferSize)*1024*1024)
		//n, err := fs.copy(w, br)
		n, err := io.Copy(w, f)
		w.CloseWithError(err) //nolint:errcheck
		f.Close()
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %v", name, n, err)
	}()

	return nil, r, nil, nil
}

// Create creates or opens the named file for writing
func (fs *SFTPFs) Create(name string, flag int) (File, *PipeWriter, func(), error) {
	err := fs.checkConnection()
	if err != nil {
		return nil, nil, nil, err
	}
	if fs.config.BufferSize == 0 {
		var f File
		if flag == 0 {
			f, err = fs.sftpClient.Create(name)
		} else {
			f, err = fs.sftpClient.OpenFile(name, flag)
		}
		return f, nil, nil, err
	}
	// buffering is enabled
	f, err := fs.sftpClient.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
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
		bw := bufio.NewWriterSize(f, int(fs.config.BufferSize)*1024*1024)
		// we don't use io.Copy since bufio.Writer implements io.WriterTo and
		// so it calls the sftp.File WriteTo method without buffering
		n, err := fs.copy(bw, r)
		errFlush := bw.Flush()
		if err == nil && errFlush != nil {
			err = errFlush
		}
		var errTruncate error
		if err != nil {
			errTruncate = f.Truncate(n)
		}
		errClose := f.Close()
		if err == nil && errClose != nil {
			err = errClose
		}
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, readed bytes: %v, err: %v err truncate: %v",
			name, n, err, errTruncate)
	}()

	return nil, p, nil, nil
}

// Rename renames (moves) source to target.
func (fs *SFTPFs) Rename(source, target string) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	if _, ok := fs.sftpClient.HasExtension("posix-rename@openssh.com"); ok {
		return fs.sftpClient.PosixRename(source, target)
	}
	return fs.sftpClient.Rename(source, target)
}

// Remove removes the named file or (empty) directory.
func (fs *SFTPFs) Remove(name string, isDir bool) error {
	if err := fs.checkConnection(); err != nil {
		return err
	}
	if isDir {
		return fs.sftpClient.RemoveDirectory(name)
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
func (fs *SFTPFs) Chtimes(name string, atime, mtime time.Time, isUploading bool) error {
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
	return fs.sftpClient.ReadDir(dirname)
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
func (fs *SFTPFs) IsUploadResumeSupported() bool {
	return fs.config.BufferSize == 0
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
func (fs *SFTPFs) IsAtomicUploadSupported() bool {
	return fs.config.BufferSize == 0
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*SFTPFs) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*SFTPFs) IsPermission(err error) bool {
	if _, ok := err.(*pathResolutionError); ok {
		return true
	}
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
	if fs.config.BufferSize > 0 {
		// we need a local directory for temporary files
		osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "")
		osFs.CheckRootPath(username, uid, gid)
	}
	if fs.config.Prefix == "/" {
		return true
	}
	if err := fs.checkConnection(); err != nil {
		return false
	}
	if err := fs.sftpClient.MkdirAll(fs.config.Prefix); err != nil {
		fsLog(fs, logger.LevelDebug, "error creating root directory %#v for user %#v: %v", fs.config.Prefix, username, err)
		return false
	}
	return true
}

// ScanRootDirContents returns the number of files contained in a directory and
// their size
func (fs *SFTPFs) ScanRootDirContents() (int, int64, error) {
	return fs.GetDirSize(fs.config.Prefix)
}

// CheckMetadata checks the metadata consistency
func (*SFTPFs) CheckMetadata() error {
	return nil
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
	if fs.mountPath != "" {
		rel = path.Join(fs.mountPath, rel)
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
	if fs.mountPath != "" {
		virtualPath = strings.TrimPrefix(virtualPath, fs.mountPath)
	}
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
			fsLog(fs, logger.LevelError, "Invalid path resolution, original path %v resolved %#v err: %v",
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
				fsLog(fs, logger.LevelError, "Invalid path resolution, dir %#v original path %#v resolved %#v err: %v",
					validatedPath, virtualPath, fsPath, err)
				return "", err
			}
		}
		if err := fs.isSubDir(validatedPath); err != nil {
			fsLog(fs, logger.LevelError, "Invalid path resolution, dir %#v original path %#v resolved %#v err: %v",
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
		return &pathResolutionError{err: err.Error()}
	}
	if !strings.HasPrefix(name, fs.config.Prefix+"/") {
		err := fmt.Errorf("path %#v is not inside: %#v", name, fs.config.Prefix)
		return &pathResolutionError{err: err.Error()}
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

func (fs *SFTPFs) copy(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := make([]byte, 32768)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
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
			fp := ssh.FingerprintSHA256(key)
			if util.IsStringInSlice(fp, sftpFingerprints) {
				if util.IsStringInSlice(fs.config.Username, fs.config.forbiddenSelfUsernames) {
					fsLog(fs, logger.LevelError, "SFTP loop or nested local SFTP folders detected, mount path %#v, username %#v, forbidden usernames: %+v",
						fs.mountPath, fs.config.Username, fs.config.forbiddenSelfUsernames)
					return ErrSFTPLoop
				}
			}
			if len(fs.config.Fingerprints) > 0 {
				for _, provided := range fs.config.Fingerprints {
					if provided == fp {
						return nil
					}
				}
				return fmt.Errorf("invalid fingerprint %#v", fp)
			}
			fsLog(fs, logger.LevelWarn, "login without host key validation, please provide at least a fingerprint!")
			return nil
		},
		Timeout:       10 * time.Second,
		ClientVersion: fmt.Sprintf("SSH-2.0-SFTPGo_%v", version.Get().Version),
	}
	if fs.config.PrivateKey.GetPayload() != "" {
		signer, err := ssh.ParsePrivateKey([]byte(fs.config.PrivateKey.GetPayload()))
		if err != nil {
			fsLog(fs, logger.LevelError, "unable to parse the provided private key: %v", err)
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
		fsLog(fs, logger.LevelError, "unable to connect: %v", err)
		fs.err <- err
		return err
	}
	fs.sftpClient, err = sftp.NewClient(fs.sshClient)
	if err != nil {
		fsLog(fs, logger.LevelError, "unable to create SFTP client: %v", err)
		fs.sshClient.Close()
		fs.err <- err
		return err
	}
	if fs.config.DisableCouncurrentReads {
		fsLog(fs, logger.LevelDebug, "disabling concurrent reads")
		opt := sftp.UseConcurrentReads(false)
		opt(fs.sftpClient) //nolint:errcheck
	}
	if fs.config.BufferSize > 0 {
		fsLog(fs, logger.LevelDebug, "enabling concurrent writes")
		opt := sftp.UseConcurrentWrites(true)
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
