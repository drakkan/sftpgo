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
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
	"github.com/robfig/cron/v3"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	// sftpFsName is the name for the SFTP Fs implementation
	sftpFsName               = "sftpfs"
	logSenderSFTPCache       = "sftpCache"
	maxSessionsPerConnection = 5
)

var (
	// ErrSFTPLoop defines the error to return if an SFTP loop is detected
	ErrSFTPLoop    = errors.New("SFTP loop or nested local SFTP folders detected")
	sftpConnsCache = newSFTPConnectionCache()
)

// SFTPFsConfig defines the configuration for SFTP based filesystem
type SFTPFsConfig struct {
	sdk.BaseSFTPFsConfig
	Password               *kms.Secret `json:"password,omitempty"`
	PrivateKey             *kms.Secret `json:"private_key,omitempty"`
	KeyPassphrase          *kms.Secret `json:"key_passphrase,omitempty"`
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
	if c.KeyPassphrase != nil {
		c.KeyPassphrase.Hide()
	}
}

func (c *SFTPFsConfig) setNilSecretsIfEmpty() {
	if c.Password != nil && c.Password.IsEmpty() {
		c.Password = nil
	}
	if c.PrivateKey != nil && c.PrivateKey.IsEmpty() {
		c.PrivateKey = nil
	}
	if c.KeyPassphrase != nil && c.KeyPassphrase.IsEmpty() {
		c.KeyPassphrase = nil
	}
}

func (c *SFTPFsConfig) isEqual(other SFTPFsConfig) bool {
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
		if !util.Contains(other.Fingerprints, fp) {
			return false
		}
	}
	c.setEmptyCredentialsIfNil()
	other.setEmptyCredentialsIfNil()
	if !c.Password.IsEqual(other.Password) {
		return false
	}
	if !c.KeyPassphrase.IsEqual(other.KeyPassphrase) {
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
	if c.KeyPassphrase == nil {
		c.KeyPassphrase = kms.NewEmptySecret()
	}
}

func (c *SFTPFsConfig) isSameResource(other SFTPFsConfig) bool {
	if c.EqualityCheckMode > 0 || other.EqualityCheckMode > 0 {
		if c.Username != other.Username {
			return false
		}
	}
	return c.Endpoint == other.Endpoint
}

// validate returns an error if the configuration is not valid
func (c *SFTPFsConfig) validate() error {
	c.setEmptyCredentialsIfNil()
	if c.Endpoint == "" {
		return util.NewI18nError(errors.New("endpoint cannot be empty"), util.I18nErrorEndpointRequired)
	}
	if !strings.Contains(c.Endpoint, ":") {
		c.Endpoint += ":22"
	}
	_, _, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		return util.NewI18nError(fmt.Errorf("invalid endpoint: %v", err), util.I18nErrorEndpointInvalid)
	}
	if c.Username == "" {
		return util.NewI18nError(errors.New("username cannot be empty"), util.I18nErrorFsUsernameRequired)
	}
	if c.BufferSize < 0 || c.BufferSize > 16 {
		return errors.New("invalid buffer_size, valid range is 0-16")
	}
	if !isEqualityCheckModeValid(c.EqualityCheckMode) {
		return errors.New("invalid equality_check_mode")
	}
	if err := c.validateCredentials(); err != nil {
		return err
	}
	if c.Prefix != "" {
		c.Prefix = util.CleanPath(c.Prefix)
	} else {
		c.Prefix = "/"
	}
	return c.validatePrivateKey()
}

func (c *SFTPFsConfig) validatePrivateKey() error {
	if c.PrivateKey.IsPlain() {
		var signer ssh.Signer
		var err error
		if c.KeyPassphrase.IsPlain() {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(c.PrivateKey.GetPayload()),
				[]byte(c.KeyPassphrase.GetPayload()))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(c.PrivateKey.GetPayload()))
		}
		if err != nil {
			return util.NewI18nError(fmt.Errorf("invalid private key: %w", err), util.I18nErrorPrivKeyInvalid)
		}
		if key, ok := signer.PublicKey().(ssh.CryptoPublicKey); ok {
			cryptoKey := key.CryptoPublicKey()
			if rsaKey, ok := cryptoKey.(*rsa.PublicKey); ok {
				if size := rsaKey.N.BitLen(); size < 2048 {
					return util.NewI18nError(
						fmt.Errorf("rsa key with size %d not accepted, minimum 2048", size),
						util.I18nErrorKeySizeInvalid,
					)
				}
			}
		}
	}
	return nil
}

func (c *SFTPFsConfig) validateCredentials() error {
	if c.Password.IsEmpty() && c.PrivateKey.IsEmpty() {
		return util.NewI18nError(errors.New("credentials cannot be empty"), util.I18nErrorFsCredentialsRequired)
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
	if c.KeyPassphrase.IsEncrypted() && !c.KeyPassphrase.IsValid() {
		return errors.New("invalid encrypted private key passphrase")
	}
	if !c.KeyPassphrase.IsEmpty() && !c.KeyPassphrase.IsValidInput() {
		return errors.New("invalid private key passphrase")
	}
	return nil
}

// ValidateAndEncryptCredentials validates the config and encrypts credentials if they are in plain text
func (c *SFTPFsConfig) ValidateAndEncryptCredentials(additionalData string) error {
	if err := c.validate(); err != nil {
		var errI18n *util.I18nError
		errValidation := util.NewValidationError(fmt.Sprintf("could not validate SFTP fs config: %v", err))
		if errors.As(err, &errI18n) {
			return util.NewI18nError(errValidation, errI18n.Message)
		}
		return util.NewI18nError(errValidation, util.I18nErrorFsValidation)
	}
	if c.Password.IsPlain() {
		c.Password.SetAdditionalData(additionalData)
		if err := c.Password.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt SFTP fs password: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	if c.PrivateKey.IsPlain() {
		c.PrivateKey.SetAdditionalData(additionalData)
		if err := c.PrivateKey.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt SFTP fs private key: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	if c.KeyPassphrase.IsPlain() {
		c.KeyPassphrase.SetAdditionalData(additionalData)
		if err := c.KeyPassphrase.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt SFTP fs private key passphrase: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	return nil
}

// getUniqueID returns an hash of the settings used to connect to the SFTP server
func (c *SFTPFsConfig) getUniqueID(partition int) uint64 {
	h := fnv.New64a()
	var b bytes.Buffer

	b.WriteString(c.Endpoint)
	b.WriteString(c.Username)
	b.WriteString(strings.Join(c.Fingerprints, ""))
	b.WriteString(strconv.FormatBool(c.DisableCouncurrentReads))
	b.WriteString(strconv.FormatInt(c.BufferSize, 10))
	b.WriteString(c.Password.GetPayload())
	b.WriteString(c.PrivateKey.GetPayload())
	b.WriteString(c.KeyPassphrase.GetPayload())
	if allowSelfConnections != 0 {
		b.WriteString(strings.Join(c.forbiddenSelfUsernames, ""))
	}
	b.WriteString(strconv.Itoa(partition))

	h.Write(b.Bytes())
	return h.Sum64()
}

// SFTPFs is a Fs implementation for SFTP backends
type SFTPFs struct {
	connectionID string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath    string
	localTempDir string
	config       *SFTPFsConfig
	conn         *sftpConnection
}

// NewSFTPFs returns an SFTPFs object that allows to interact with an SFTP server
func NewSFTPFs(connectionID, mountPath, localTempDir string, forbiddenSelfUsernames []string, config SFTPFsConfig) (Fs, error) {
	if localTempDir == "" {
		localTempDir = getLocalTempDir()
	}
	if err := config.validate(); err != nil {
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
	if !config.KeyPassphrase.IsEmpty() {
		if err := config.KeyPassphrase.TryDecrypt(); err != nil {
			return nil, err
		}
	}
	config.forbiddenSelfUsernames = forbiddenSelfUsernames
	sftpFs := &SFTPFs{
		connectionID: connectionID,
		mountPath:    getMountPath(mountPath),
		localTempDir: localTempDir,
		config:       &config,
		conn:         sftpConnsCache.Get(&config, connectionID),
	}
	err := sftpFs.createConnection()
	if err != nil {
		sftpFs.Close() //nolint:errcheck
	}
	return sftpFs, err
}

// Name returns the name for the Fs implementation
func (fs *SFTPFs) Name() string {
	return fmt.Sprintf(`%s %q@%q`, sftpFsName, fs.config.Username, fs.config.Endpoint)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *SFTPFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *SFTPFs) Stat(name string) (os.FileInfo, error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return nil, err
	}
	return client.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs *SFTPFs) Lstat(name string) (os.FileInfo, error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return nil, err
	}
	return client.Lstat(name)
}

// Open opens the named file for reading
func (fs *SFTPFs) Open(name string, offset int64) (File, PipeReader, func(), error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return nil, nil, nil, err
	}
	f, err := client.Open(name)
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
	if fs.config.BufferSize == 0 {
		return f, nil, nil, nil
	}
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	p := NewPipeReader(r)

	go func() {
		// if we enable buffering the client stalls
		//br := bufio.NewReaderSize(f, int(fs.config.BufferSize)*1024*1024)
		//n, err := fs.copy(w, br)
		n, err := io.Copy(w, f)
		w.CloseWithError(err) //nolint:errcheck
		f.Close()
		fsLog(fs, logger.LevelDebug, "download completed, path: %q size: %v, err: %v", name, n, err)
	}()

	return nil, p, nil, nil
}

// Create creates or opens the named file for writing
func (fs *SFTPFs) Create(name string, flag, _ int) (File, PipeWriter, func(), error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return nil, nil, nil, err
	}
	if fs.config.BufferSize == 0 {
		var f File
		if flag == 0 {
			f, err = client.Create(name)
		} else {
			f, err = client.OpenFile(name, flag)
		}
		return f, nil, nil, err
	}
	// buffering is enabled
	f, err := client.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
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
		n, err := doCopy(bw, r, nil)
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
		fsLog(fs, logger.LevelDebug, "upload completed, path: %q, readed bytes: %v, err: %v err truncate: %v",
			name, n, err, errTruncate)
	}()

	return nil, p, nil, nil
}

// Rename renames (moves) source to target.
func (fs *SFTPFs) Rename(source, target string) (int, int64, error) {
	if source == target {
		return -1, -1, nil
	}
	client, err := fs.conn.getClient()
	if err != nil {
		return -1, -1, err
	}
	if _, ok := client.HasExtension("posix-rename@openssh.com"); ok {
		err := client.PosixRename(source, target)
		return -1, -1, err
	}
	err = client.Rename(source, target)
	return -1, -1, err
}

// Remove removes the named file or (empty) directory.
func (fs *SFTPFs) Remove(name string, isDir bool) error {
	client, err := fs.conn.getClient()
	if err != nil {
		return err
	}
	if isDir {
		return client.RemoveDirectory(name)
	}
	return client.Remove(name)
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *SFTPFs) Mkdir(name string) error {
	client, err := fs.conn.getClient()
	if err != nil {
		return err
	}
	return client.Mkdir(name)
}

// Symlink creates source as a symbolic link to target.
func (fs *SFTPFs) Symlink(source, target string) error {
	client, err := fs.conn.getClient()
	if err != nil {
		return err
	}
	return client.Symlink(source, target)
}

// Readlink returns the destination of the named symbolic link
func (fs *SFTPFs) Readlink(name string) (string, error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return "", err
	}
	resolved, err := client.ReadLink(name)
	if err != nil {
		return resolved, err
	}
	resolved = path.Clean(resolved)
	if !path.IsAbs(resolved) {
		// we assume that multiple links are not followed
		resolved = path.Join(path.Dir(name), resolved)
	}
	return fs.GetRelativePath(resolved), nil
}

// Chown changes the numeric uid and gid of the named file.
func (fs *SFTPFs) Chown(name string, uid int, gid int) error {
	client, err := fs.conn.getClient()
	if err != nil {
		return err
	}
	return client.Chown(name, uid, gid)
}

// Chmod changes the mode of the named file to mode.
func (fs *SFTPFs) Chmod(name string, mode os.FileMode) error {
	client, err := fs.conn.getClient()
	if err != nil {
		return err
	}
	return client.Chmod(name, mode)
}

// Chtimes changes the access and modification times of the named file.
func (fs *SFTPFs) Chtimes(name string, atime, mtime time.Time, _ bool) error {
	client, err := fs.conn.getClient()
	if err != nil {
		return err
	}
	return client.Chtimes(name, atime, mtime)
}

// Truncate changes the size of the named file.
func (fs *SFTPFs) Truncate(name string, size int64) error {
	client, err := fs.conn.getClient()
	if err != nil {
		return err
	}
	return client.Truncate(name, size)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *SFTPFs) ReadDir(dirname string) (DirLister, error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return nil, err
	}
	files, err := client.ReadDir(dirname)
	if err != nil {
		return nil, err
	}
	return &baseDirLister{files}, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
func (fs *SFTPFs) IsUploadResumeSupported() bool {
	return fs.config.BufferSize == 0
}

// IsConditionalUploadResumeSupported returns if resuming uploads is supported
// for the specified size
func (fs *SFTPFs) IsConditionalUploadResumeSupported(_ int64) bool {
	return fs.IsUploadResumeSupported()
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
func (fs *SFTPFs) IsAtomicUploadSupported() bool {
	return fs.config.BufferSize == 0
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*SFTPFs) IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*SFTPFs) IsPermission(err error) bool {
	if _, ok := err.(*pathResolutionError); ok {
		return true
	}
	return errors.Is(err, fs.ErrPermission)
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
	// local directory for temporary files in buffer mode
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "", nil)
	osFs.CheckRootPath(username, uid, gid)
	if fs.config.Prefix == "/" {
		return true
	}
	client, err := fs.conn.getClient()
	if err != nil {
		return false
	}
	if err := client.MkdirAll(fs.config.Prefix); err != nil {
		fsLog(fs, logger.LevelDebug, "error creating root directory %q for user %q: %v", fs.config.Prefix, username, err)
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
	client, err := fs.conn.getClient()
	if err != nil {
		return err
	}
	walker := client.Walk(root)
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
		var validatedPath string
		var err error
		validatedPath, err = fs.getRealPath(fsPath)
		isNotExist := fs.IsNotExist(err)
		if err != nil && !isNotExist {
			fsLog(fs, logger.LevelError, "Invalid path resolution, original path %v resolved %q err: %v",
				virtualPath, fsPath, err)
			return "", err
		} else if isNotExist {
			for fs.IsNotExist(err) {
				validatedPath = path.Dir(validatedPath)
				if validatedPath == "/" {
					err = nil
					break
				}
				validatedPath, err = fs.getRealPath(validatedPath)
			}
			if err != nil {
				fsLog(fs, logger.LevelError, "Invalid path resolution, dir %q original path %q resolved %q err: %v",
					validatedPath, virtualPath, fsPath, err)
				return "", err
			}
		}
		if err := fs.isSubDir(validatedPath); err != nil {
			fsLog(fs, logger.LevelError, "Invalid path resolution, dir %q original path %q resolved %q err: %v",
				validatedPath, virtualPath, fsPath, err)
			return "", err
		}
	}
	return fsPath, nil
}

// RealPath implements the FsRealPather interface
func (fs *SFTPFs) RealPath(p string) (string, error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return "", err
	}
	resolved, err := client.RealPath(p)
	if err != nil {
		return "", err
	}
	if fs.config.Prefix != "/" {
		if err := fs.isSubDir(resolved); err != nil {
			fsLog(fs, logger.LevelError, "Invalid real path resolution, original path %q resolved %q err: %v",
				p, resolved, err)
			return "", err
		}
	}
	return fs.GetRelativePath(resolved), nil
}

// getRealPath returns the real remote path trying to resolve symbolic links if any
func (fs *SFTPFs) getRealPath(name string) (string, error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return "", err
	}
	linksWalked := 0
	for {
		info, err := client.Lstat(name)
		if err != nil {
			return name, err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return name, nil
		}
		resolvedLink, err := client.ReadLink(name)
		if err != nil {
			return name, fmt.Errorf("unable to resolve link to %q: %w", name, err)
		}
		resolvedLink = path.Clean(resolvedLink)
		if path.IsAbs(resolvedLink) {
			name = resolvedLink
		} else {
			name = path.Join(path.Dir(name), resolvedLink)
		}
		linksWalked++
		if linksWalked > 10 {
			fsLog(fs, logger.LevelError, "unable to get real path, too many links: %d", linksWalked)
			return "", &pathResolutionError{err: "too many links"}
		}
	}
}

func (fs *SFTPFs) isSubDir(name string) error {
	if name == fs.config.Prefix {
		return nil
	}
	if len(name) < len(fs.config.Prefix) {
		err := fmt.Errorf("path %q is not inside: %q", name, fs.config.Prefix)
		return &pathResolutionError{err: err.Error()}
	}
	if !strings.HasPrefix(name, fs.config.Prefix+"/") {
		err := fmt.Errorf("path %q is not inside: %q", name, fs.config.Prefix)
		return &pathResolutionError{err: err.Error()}
	}
	return nil
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *SFTPFs) GetDirSize(dirname string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	client, err := fs.conn.getClient()
	if err != nil {
		return numFiles, size, err
	}
	isDir, err := isDirectory(fs, dirname)
	if err == nil && isDir {
		walker := client.Walk(dirname)
		for walker.Step() {
			err := walker.Err()
			if err != nil {
				return numFiles, size, err
			}
			if walker.Stat().Mode().IsRegular() {
				size += walker.Stat().Size()
				numFiles++
				if numFiles%1000 == 0 {
					fsLog(fs, logger.LevelDebug, "dirname %q scan in progress, files: %d, size: %d", dirname, numFiles, size)
				}
			}
		}
	}
	return numFiles, size, err
}

// GetMimeType returns the content type
func (fs *SFTPFs) GetMimeType(name string) (string, error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return "", err
	}
	f, err := client.OpenFile(name, os.O_RDONLY)
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

// GetAvailableDiskSize returns the available size for the specified path
func (fs *SFTPFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	client, err := fs.conn.getClient()
	if err != nil {
		return nil, err
	}
	if _, ok := client.HasExtension("statvfs@openssh.com"); !ok {
		return nil, ErrStorageSizeUnavailable
	}
	return client.StatVFS(dirName)
}

// Close the connection
func (fs *SFTPFs) Close() error {
	fs.conn.RemoveSession(fs.connectionID)
	return nil
}

func (fs *SFTPFs) createConnection() error {
	err := fs.conn.OpenConnection()
	if err != nil {
		fsLog(fs, logger.LevelError, "error opening connection: %v", err)
		return err
	}
	return nil
}

type sftpConnection struct {
	config       *SFTPFsConfig
	logSender    string
	sshClient    *ssh.Client
	sftpClient   *sftp.Client
	mu           sync.RWMutex
	isConnected  bool
	sessions     map[string]bool
	lastActivity time.Time
}

func newSFTPConnection(config *SFTPFsConfig, sessionID string) *sftpConnection {
	c := &sftpConnection{
		config:       config,
		logSender:    fmt.Sprintf(`%s "%s@%s"`, sftpFsName, config.Username, config.Endpoint),
		isConnected:  false,
		sessions:     map[string]bool{},
		lastActivity: time.Now().UTC(),
	}
	c.sessions[sessionID] = true
	return c
}

func (c *sftpConnection) OpenConnection() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.openConnNoLock()
}

func (c *sftpConnection) getSigner() (ssh.Signer, error) {
	if c.config.KeyPassphrase.GetPayload() != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(c.config.PrivateKey.GetPayload()),
			[]byte(c.config.KeyPassphrase.GetPayload()))
	}
	return ssh.ParsePrivateKey([]byte(c.config.PrivateKey.GetPayload()))
}

func (c *sftpConnection) openConnNoLock() error {
	if c.isConnected {
		logger.Debug(c.logSender, "", "reusing connection")
		return nil
	}

	logger.Debug(c.logSender, "", "try to open a new connection")
	clientConfig := &ssh.ClientConfig{
		User: c.config.Username,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			if util.Contains(sftpFingerprints, fp) {
				if allowSelfConnections == 0 {
					logger.Log(logger.LevelError, c.logSender, "", "SFTP self connections not allowed")
					return ErrSFTPLoop
				}
				if util.Contains(c.config.forbiddenSelfUsernames, c.config.Username) {
					logger.Log(logger.LevelError, c.logSender, "",
						"SFTP loop or nested local SFTP folders detected, username %q, forbidden usernames: %+v",
						c.config.Username, c.config.forbiddenSelfUsernames)
					return ErrSFTPLoop
				}
			}
			if len(c.config.Fingerprints) > 0 {
				for _, provided := range c.config.Fingerprints {
					if provided == fp {
						return nil
					}
				}
				return fmt.Errorf("invalid fingerprint %q", fp)
			}
			logger.Log(logger.LevelWarn, c.logSender, "", "login without host key validation, please provide at least a fingerprint!")
			return nil
		},
		Timeout:       10 * time.Second,
		ClientVersion: fmt.Sprintf("SSH-2.0-SFTPGo_%v", version.Get().Version),
	}
	if c.config.PrivateKey.GetPayload() != "" {
		signer, err := c.getSigner()
		if err != nil {
			return fmt.Errorf("sftpfs: unable to parse the private key: %w", err)
		}
		clientConfig.Auth = append(clientConfig.Auth, ssh.PublicKeys(signer))
	}
	if c.config.Password.GetPayload() != "" {
		clientConfig.Auth = append(clientConfig.Auth, ssh.Password(c.config.Password.GetPayload()))
	}
	supportedAlgos := ssh.SupportedAlgorithms()
	insecureAlgos := ssh.InsecureAlgorithms()
	// add all available ciphers, KEXs and MACs, they are negotiated according to the order
	clientConfig.Ciphers = append(supportedAlgos.Ciphers, ssh.InsecureCipherAES128CBC,
		ssh.InsecureCipherAES192CBC, ssh.InsecureCipherAES256CBC)
	clientConfig.KeyExchanges = append(supportedAlgos.KeyExchanges, insecureAlgos.KeyExchanges...)
	clientConfig.MACs = append(supportedAlgos.MACs, insecureAlgos.MACs...)
	sshClient, err := ssh.Dial("tcp", c.config.Endpoint, clientConfig)
	if err != nil {
		return fmt.Errorf("sftpfs: unable to connect: %w", err)
	}
	sftpClient, err := sftp.NewClient(sshClient, c.getClientOptions()...)
	if err != nil {
		sshClient.Close()
		return fmt.Errorf("sftpfs: unable to create SFTP client: %w", err)
	}
	c.sshClient = sshClient
	c.sftpClient = sftpClient
	c.isConnected = true
	go c.Wait()
	return nil
}

func (c *sftpConnection) getClientOptions() []sftp.ClientOption {
	var options []sftp.ClientOption
	if c.config.DisableCouncurrentReads {
		options = append(options, sftp.UseConcurrentReads(false))
		logger.Debug(c.logSender, "", "disabling concurrent reads")
	}
	if c.config.BufferSize > 0 {
		options = append(options, sftp.UseConcurrentWrites(true))
		logger.Debug(c.logSender, "", "enabling concurrent writes")
	}
	return options
}

func (c *sftpConnection) getClient() (*sftp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isConnected {
		return c.sftpClient, nil
	}
	err := c.openConnNoLock()
	return c.sftpClient, err
}

func (c *sftpConnection) Wait() {
	done := make(chan struct{})

	go func() {
		var watchdogInProgress atomic.Bool
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if watchdogInProgress.Load() {
					logger.Error(c.logSender, "", "watchdog still in progress, closing hanging connection")
					c.sshClient.Close()
					return
				}
				go func() {
					watchdogInProgress.Store(true)
					defer watchdogInProgress.Store(false)

					_, err := c.sftpClient.Getwd()
					if err != nil {
						logger.Error(c.logSender, "", "watchdog error: %v", err)
					}
				}()
			case <-done:
				logger.Debug(c.logSender, "", "quitting watchdog")
				return
			}
		}
	}()

	// we wait on the sftp client otherwise if the channel is closed but not the connection
	// we don't detect the event.
	err := c.sftpClient.Wait()
	logger.Log(logger.LevelDebug, c.logSender, "", "sftp channel closed: %v", err)
	close(done)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.isConnected = false
	if c.sshClient != nil {
		c.sshClient.Close()
	}
}

func (c *sftpConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	logger.Debug(c.logSender, "", "closing connection")
	var sftpErr, sshErr error
	if c.sftpClient != nil {
		sftpErr = c.sftpClient.Close()
	}
	if c.sshClient != nil {
		sshErr = c.sshClient.Close()
	}
	if sftpErr != nil {
		return sftpErr
	}
	c.isConnected = false
	return sshErr
}

func (c *sftpConnection) AddSession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessions[sessionID] = true
	logger.Debug(c.logSender, "", "added session %s, active sessions: %d", sessionID, len(c.sessions))
}

func (c *sftpConnection) RemoveSession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.sessions, sessionID)
	logger.Debug(c.logSender, "", "removed session %s, active sessions: %d", sessionID, len(c.sessions))
	if len(c.sessions) == 0 {
		c.lastActivity = time.Now().UTC()
	}
}

func (c *sftpConnection) ActiveSessions() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.sessions)
}

func (c *sftpConnection) GetLastActivity() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.sessions) > 0 {
		return time.Now().UTC()
	}
	logger.Debug(c.logSender, "", "last activity %s", c.lastActivity)
	return c.lastActivity
}

type sftpConnectionsCache struct {
	scheduler *cron.Cron
	sync.RWMutex
	items map[uint64]*sftpConnection
}

func newSFTPConnectionCache() *sftpConnectionsCache {
	c := &sftpConnectionsCache{
		scheduler: cron.New(cron.WithLocation(time.UTC), cron.WithLogger(cron.DiscardLogger)),
		items:     make(map[uint64]*sftpConnection),
	}
	_, err := c.scheduler.AddFunc("@every 1m", c.Cleanup)
	util.PanicOnError(err)
	c.scheduler.Start()
	return c
}

func (c *sftpConnectionsCache) Get(config *SFTPFsConfig, sessionID string) *sftpConnection {
	partition := 0
	key := config.getUniqueID(partition)

	c.Lock()
	defer c.Unlock()

	var oldKey uint64
	for {
		if val, ok := c.items[key]; ok {
			activeSessions := val.ActiveSessions()
			if activeSessions < maxSessionsPerConnection || key == oldKey {
				logger.Debug(logSenderSFTPCache, "",
					"reusing connection for session ID %q, key: %d, active sessions %d, active connections: %d",
					sessionID, key, activeSessions+1, len(c.items))
				val.AddSession(sessionID)
				return val
			}
			partition++
			oldKey = key
			key = config.getUniqueID(partition)
			logger.Debug(logSenderSFTPCache, "",
				"connection full, generated new key for partition: %d, active sessions: %d, key: %d, old key: %d",
				partition, activeSessions, oldKey, key)
		} else {
			conn := newSFTPConnection(config, sessionID)
			c.items[key] = conn
			logger.Debug(logSenderSFTPCache, "",
				"adding new connection for session ID %q, partition: %d, key: %d, active connections: %d",
				sessionID, partition, key, len(c.items))
			return conn
		}
	}
}

func (c *sftpConnectionsCache) Remove(key uint64) {
	c.Lock()
	defer c.Unlock()

	if conn, ok := c.items[key]; ok {
		delete(c.items, key)
		logger.Debug(logSenderSFTPCache, "", "removed connection with key %d, active connections: %d", key, len(c.items))

		defer conn.Close()
	}
}

func (c *sftpConnectionsCache) Cleanup() {
	c.RLock()

	for k, conn := range c.items {
		if val := conn.GetLastActivity(); val.Before(time.Now().Add(-30 * time.Second)) {
			logger.Debug(conn.logSender, "", "removing inactive connection, last activity %s", val)

			defer func(key uint64) {
				c.Remove(key)
			}(k)
		}
	}

	c.RUnlock()
}
