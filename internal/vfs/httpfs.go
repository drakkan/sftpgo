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
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	// httpFsName is the name for the HTTP Fs implementation
	httpFsName            = "httpfs"
	maxHTTPFsResponseSize = 1048576
)

var (
	supportedEndpointSchema = []string{"http://", "https://"}
)

// HTTPFsConfig defines the configuration for HTTP based filesystem
type HTTPFsConfig struct {
	sdk.BaseHTTPFsConfig
	Password *kms.Secret `json:"password,omitempty"`
	APIKey   *kms.Secret `json:"api_key,omitempty"`
}

func (c *HTTPFsConfig) isUnixDomainSocket() bool {
	return strings.HasPrefix(c.Endpoint, "http://unix") || strings.HasPrefix(c.Endpoint, "https://unix")
}

// HideConfidentialData hides confidential data
func (c *HTTPFsConfig) HideConfidentialData() {
	if c.Password != nil {
		c.Password.Hide()
	}
	if c.APIKey != nil {
		c.APIKey.Hide()
	}
}

func (c *HTTPFsConfig) setNilSecretsIfEmpty() {
	if c.Password != nil && c.Password.IsEmpty() {
		c.Password = nil
	}
	if c.APIKey != nil && c.APIKey.IsEmpty() {
		c.APIKey = nil
	}
}

func (c *HTTPFsConfig) setEmptyCredentialsIfNil() {
	if c.Password == nil {
		c.Password = kms.NewEmptySecret()
	}
	if c.APIKey == nil {
		c.APIKey = kms.NewEmptySecret()
	}
}

func (c *HTTPFsConfig) isEqual(other HTTPFsConfig) bool {
	if c.Endpoint != other.Endpoint {
		return false
	}
	if c.Username != other.Username {
		return false
	}
	if c.SkipTLSVerify != other.SkipTLSVerify {
		return false
	}
	c.setEmptyCredentialsIfNil()
	other.setEmptyCredentialsIfNil()
	if !c.Password.IsEqual(other.Password) {
		return false
	}
	return c.APIKey.IsEqual(other.APIKey)
}

func (c *HTTPFsConfig) isSameResource(other HTTPFsConfig) bool {
	if c.EqualityCheckMode > 0 || other.EqualityCheckMode > 0 {
		if c.Username != other.Username {
			return false
		}
	}
	return c.Endpoint == other.Endpoint
}

// validate returns an error if the configuration is not valid
func (c *HTTPFsConfig) validate() error {
	c.setEmptyCredentialsIfNil()
	if c.Endpoint == "" {
		return util.NewI18nError(errors.New("httpfs: endpoint cannot be empty"), util.I18nErrorEndpointRequired)
	}
	c.Endpoint = strings.TrimRight(c.Endpoint, "/")
	endpointURL, err := url.Parse(c.Endpoint)
	if err != nil {
		return util.NewI18nError(fmt.Errorf("httpfs: invalid endpoint: %w", err), util.I18nErrorEndpointInvalid)
	}
	if !util.IsStringPrefixInSlice(c.Endpoint, supportedEndpointSchema) {
		return util.NewI18nError(
			errors.New("httpfs: invalid endpoint schema: http and https are supported"),
			util.I18nErrorEndpointInvalid,
		)
	}
	if endpointURL.Host == "unix" {
		socketPath := endpointURL.Query().Get("socket_path")
		if !filepath.IsAbs(socketPath) {
			return util.NewI18nError(
				fmt.Errorf("httpfs: invalid unix domain socket path: %q", socketPath),
				util.I18nErrorEndpointInvalid,
			)
		}
	}
	if !isEqualityCheckModeValid(c.EqualityCheckMode) {
		return errors.New("invalid equality_check_mode")
	}
	if c.Password.IsEncrypted() && !c.Password.IsValid() {
		return errors.New("httpfs: invalid encrypted password")
	}
	if !c.Password.IsEmpty() && !c.Password.IsValidInput() {
		return errors.New("httpfs: invalid password")
	}
	if c.APIKey.IsEncrypted() && !c.APIKey.IsValid() {
		return errors.New("httpfs: invalid encrypted API key")
	}
	if !c.APIKey.IsEmpty() && !c.APIKey.IsValidInput() {
		return errors.New("httpfs: invalid API key")
	}
	return nil
}

// ValidateAndEncryptCredentials validates the config and encrypts credentials if they are in plain text
func (c *HTTPFsConfig) ValidateAndEncryptCredentials(additionalData string) error {
	err := c.validate()
	if err != nil {
		var errI18n *util.I18nError
		errValidation := util.NewValidationError(fmt.Sprintf("could not validate HTTP fs config: %v", err))
		if errors.As(err, &errI18n) {
			return util.NewI18nError(errValidation, errI18n.Message)
		}
		return util.NewI18nError(errValidation, util.I18nErrorFsValidation)
	}
	if c.Password.IsPlain() {
		c.Password.SetAdditionalData(additionalData)
		if err := c.Password.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt HTTP fs password: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	if c.APIKey.IsPlain() {
		c.APIKey.SetAdditionalData(additionalData)
		if err := c.APIKey.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt HTTP fs API key: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	return nil
}

// HTTPFs is a Fs implementation for the SFTPGo HTTP filesystem backend
type HTTPFs struct {
	connectionID string
	localTempDir string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath  string
	config     *HTTPFsConfig
	client     *http.Client
	ctxTimeout time.Duration
}

// NewHTTPFs returns an HTTPFs object that allows to interact with SFTPGo HTTP filesystem backends
func NewHTTPFs(connectionID, localTempDir, mountPath string, config HTTPFsConfig) (Fs, error) {
	if localTempDir == "" {
		localTempDir = getLocalTempDir()
	}
	config.setEmptyCredentialsIfNil()
	if !config.Password.IsEmpty() {
		if err := config.Password.TryDecrypt(); err != nil {
			return nil, err
		}
	}
	if !config.APIKey.IsEmpty() {
		if err := config.APIKey.TryDecrypt(); err != nil {
			return nil, err
		}
	}
	fs := &HTTPFs{
		connectionID: connectionID,
		localTempDir: localTempDir,
		mountPath:    mountPath,
		config:       &config,
		ctxTimeout:   30 * time.Second,
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 1 << 16
	transport.WriteBufferSize = 1 << 16
	transport.ReadBufferSize = 1 << 16
	if fs.config.isUnixDomainSocket() {
		endpointURL, err := url.Parse(fs.config.Endpoint)
		if err != nil {
			return nil, err
		}
		if endpointURL.Host == "unix" {
			socketPath := endpointURL.Query().Get("socket_path")
			if !filepath.IsAbs(socketPath) {
				return nil, fmt.Errorf("httpfs: invalid unix domain socket path: %q", socketPath)
			}
			if endpointURL.Scheme == "https" {
				transport.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
					var tlsConfig *tls.Config
					var d tls.Dialer
					if config.SkipTLSVerify {
						tlsConfig = getInsecureTLSConfig()
					}
					d.Config = tlsConfig
					return d.DialContext(ctx, "unix", socketPath)
				}
			} else {
				transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				}
			}
			endpointURL.Path = path.Join(endpointURL.Path, endpointURL.Query().Get("api_prefix"))
			endpointURL.RawQuery = ""
			endpointURL.RawFragment = ""
			fs.config.Endpoint = endpointURL.String()
		}
	}
	if config.SkipTLSVerify {
		if transport.TLSClientConfig != nil {
			transport.TLSClientConfig.InsecureSkipVerify = true
		} else {
			transport.TLSClientConfig = getInsecureTLSConfig()
		}
	}
	fs.client = &http.Client{
		Transport: transport,
	}
	return fs, nil
}

// Name returns the name for the Fs implementation
func (fs *HTTPFs) Name() string {
	return fmt.Sprintf("%v %q", httpFsName, fs.config.Endpoint)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *HTTPFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *HTTPFs) Stat(name string) (os.FileInfo, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := fs.sendHTTPRequest(ctx, http.MethodGet, "stat", name, "", "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPFsResponseSize))
	if err != nil {
		return nil, err
	}
	var response statResponse
	err = json.Unmarshal(respBody, &response)
	if err != nil {
		return nil, err
	}
	return response.getFileInfo(), nil
}

// Lstat returns a FileInfo describing the named file
func (fs *HTTPFs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs *HTTPFs) Open(name string, offset int64) (File, PipeReader, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	p := NewPipeReader(r)
	ctx, cancelFn := context.WithCancel(context.Background())

	var queryString string
	if offset > 0 {
		queryString = fmt.Sprintf("?offset=%d", offset)
	}

	go func() {
		defer cancelFn()

		resp, err := fs.sendHTTPRequest(ctx, http.MethodGet, "open", name, queryString, "", nil)
		if err != nil {
			fsLog(fs, logger.LevelError, "download error, path %q, err: %v", name, err)
			w.CloseWithError(err) //nolint:errcheck
			metric.HTTPFsTransferCompleted(0, 1, err)
			return
		}
		defer resp.Body.Close()
		n, err := io.Copy(w, resp.Body)
		w.CloseWithError(err) //nolint:errcheck
		fsLog(fs, logger.LevelDebug, "download completed, path %q size: %v, err: %+v", name, n, err)
		metric.HTTPFsTransferCompleted(n, 1, err)
	}()

	return nil, p, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs *HTTPFs) Create(name string, flag, checks int) (File, PipeWriter, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	p := NewPipeWriter(w)
	ctx, cancelFn := context.WithCancel(context.Background())

	go func() {
		defer cancelFn()

		contentType := mime.TypeByExtension(path.Ext(name))
		queryString := fmt.Sprintf("?flags=%d&checks=%d", flag, checks)
		resp, err := fs.sendHTTPRequest(ctx, http.MethodPost, "create", name, queryString, contentType,
			&wrapReader{reader: r})
		if err != nil {
			fsLog(fs, logger.LevelError, "upload error, path %q, err: %v", name, err)
			r.CloseWithError(err) //nolint:errcheck
			p.Done(err)
			metric.HTTPFsTransferCompleted(0, 0, err)
			return
		}
		defer resp.Body.Close()

		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %q, readed bytes: %d", name, r.GetReadedBytes())
		metric.HTTPFsTransferCompleted(r.GetReadedBytes(), 0, err)
	}()

	return nil, p, cancelFn, nil
}

// Rename renames (moves) source to target.
func (fs *HTTPFs) Rename(source, target string) (int, int64, error) {
	if source == target {
		return -1, -1, nil
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	queryString := fmt.Sprintf("?target=%s", url.QueryEscape(target))
	resp, err := fs.sendHTTPRequest(ctx, http.MethodPatch, "rename", source, queryString, "", nil)
	if err != nil {
		return -1, -1, err
	}
	defer resp.Body.Close()
	return -1, -1, nil
}

// Remove removes the named file or (empty) directory.
func (fs *HTTPFs) Remove(name string, _ bool) error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := fs.sendHTTPRequest(ctx, http.MethodDelete, "remove", name, "", "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *HTTPFs) Mkdir(name string) error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := fs.sendHTTPRequest(ctx, http.MethodPost, "mkdir", name, "", "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Symlink creates source as a symbolic link to target.
func (*HTTPFs) Symlink(_, _ string) error {
	return ErrVfsUnsupported
}

// Readlink returns the destination of the named symbolic link
func (*HTTPFs) Readlink(_ string) (string, error) {
	return "", ErrVfsUnsupported
}

// Chown changes the numeric uid and gid of the named file.
func (fs *HTTPFs) Chown(_ string, _ int, _ int) error {
	return ErrVfsUnsupported
}

// Chmod changes the mode of the named file to mode.
func (fs *HTTPFs) Chmod(name string, mode os.FileMode) error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	queryString := fmt.Sprintf("?mode=%d", mode)
	resp, err := fs.sendHTTPRequest(ctx, http.MethodPatch, "chmod", name, queryString, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Chtimes changes the access and modification times of the named file.
func (fs *HTTPFs) Chtimes(name string, atime, mtime time.Time, _ bool) error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	queryString := fmt.Sprintf("?access_time=%s&modification_time=%s", atime.UTC().Format(time.RFC3339),
		mtime.UTC().Format(time.RFC3339))
	resp, err := fs.sendHTTPRequest(ctx, http.MethodPatch, "chtimes", name, queryString, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Truncate changes the size of the named file.
// Truncate by path is not supported, while truncating an opened
// file is handled inside base transfer
func (fs *HTTPFs) Truncate(name string, size int64) error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	queryString := fmt.Sprintf("?size=%d", size)
	resp, err := fs.sendHTTPRequest(ctx, http.MethodPatch, "truncate", name, queryString, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *HTTPFs) ReadDir(dirname string) (DirLister, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := fs.sendHTTPRequest(ctx, http.MethodGet, "readdir", dirname, "", "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPFsResponseSize*10))
	if err != nil {
		return nil, err
	}
	var response []statResponse
	err = json.Unmarshal(respBody, &response)
	if err != nil {
		return nil, err
	}
	result := make([]os.FileInfo, 0, len(response))
	for _, stat := range response {
		result = append(result, stat.getFileInfo())
	}
	return &baseDirLister{result}, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
func (*HTTPFs) IsUploadResumeSupported() bool {
	return false
}

// IsConditionalUploadResumeSupported returns if resuming uploads is supported
// for the specified size
func (*HTTPFs) IsConditionalUploadResumeSupported(_ int64) bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
func (*HTTPFs) IsAtomicUploadSupported() bool {
	return false
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*HTTPFs) IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*HTTPFs) IsPermission(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*HTTPFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *HTTPFs) CheckRootPath(username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "", nil)
	return osFs.CheckRootPath(username, uid, gid)
}

// ScanRootDirContents returns the number of files and their size
func (fs *HTTPFs) ScanRootDirContents() (int, int64, error) {
	return fs.GetDirSize("/")
}

// CheckMetadata checks the metadata consistency
func (*HTTPFs) CheckMetadata() error {
	return nil
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *HTTPFs) GetDirSize(dirname string) (int, int64, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := fs.sendHTTPRequest(ctx, http.MethodGet, "dirsize", dirname, "", "", nil)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPFsResponseSize))
	if err != nil {
		return 0, 0, err
	}

	var response dirSizeResponse
	err = json.Unmarshal(respBody, &response)
	if err != nil {
		return 0, 0, err
	}
	return response.Files, response.Size, nil
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
func (*HTTPFs) GetAtomicUploadPath(_ string) string {
	return ""
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs *HTTPFs) GetRelativePath(name string) string {
	rel := path.Clean(name)
	if rel == "." {
		rel = ""
	}
	if !path.IsAbs(rel) {
		rel = "/" + rel
	}
	if fs.mountPath != "" {
		rel = path.Join(fs.mountPath, rel)
	}
	return rel
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root. The result are unordered
func (fs *HTTPFs) Walk(root string, walkFn filepath.WalkFunc) error {
	info, err := fs.Lstat(root)
	if err != nil {
		return walkFn(root, nil, err)
	}
	return fs.walk(root, info, walkFn)
}

// Join joins any number of path elements into a single path
func (*HTTPFs) Join(elem ...string) string {
	return strings.TrimPrefix(path.Join(elem...), "/")
}

// HasVirtualFolders returns true if folders are emulated
func (*HTTPFs) HasVirtualFolders() bool {
	return false
}

// ResolvePath returns the matching filesystem path for the specified virtual path
func (fs *HTTPFs) ResolvePath(virtualPath string) (string, error) {
	if fs.mountPath != "" {
		virtualPath = strings.TrimPrefix(virtualPath, fs.mountPath)
	}
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean("/" + virtualPath)
	}
	return virtualPath, nil
}

// GetMimeType returns the content type
func (fs *HTTPFs) GetMimeType(name string) (string, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := fs.sendHTTPRequest(ctx, http.MethodGet, "stat", name, "", "", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPFsResponseSize))
	if err != nil {
		return "", err
	}

	var response mimeTypeResponse
	err = json.Unmarshal(respBody, &response)
	if err != nil {
		return "", err
	}
	return response.Mime, nil
}

// Close closes the fs
func (fs *HTTPFs) Close() error {
	fs.client.CloseIdleConnections()
	return nil
}

// GetAvailableDiskSize returns the available size for the specified path
func (fs *HTTPFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := fs.sendHTTPRequest(ctx, http.MethodGet, "statvfs", dirName, "", "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPFsResponseSize))
	if err != nil {
		return nil, err
	}

	var response statVFSResponse
	err = json.Unmarshal(respBody, &response)
	if err != nil {
		return nil, err
	}
	return response.toSFTPStatVFS(), nil
}

func (fs *HTTPFs) sendHTTPRequest(ctx context.Context, method, base, name, queryString, contentType string,
	body io.Reader,
) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s/%s%s", fs.config.Endpoint, base, url.PathEscape(name), queryString)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if fs.config.APIKey.GetPayload() != "" {
		req.Header.Set("X-API-KEY", fs.config.APIKey.GetPayload())
	}
	if fs.config.Username != "" || fs.config.Password.GetPayload() != "" {
		req.SetBasicAuth(fs.config.Username, fs.config.Password.GetPayload())
	}
	resp, err := fs.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("unable to send HTTP request to URL %v: %w", url, err)
	}
	if err = getErrorFromResponseCode(resp.StatusCode); err != nil {
		resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

// walk recursively descends path, calling walkFn.
func (fs *HTTPFs) walk(filePath string, info fs.FileInfo, walkFn filepath.WalkFunc) error {
	if !info.IsDir() {
		return walkFn(filePath, info, nil)
	}
	lister, err := fs.ReadDir(filePath)
	err1 := walkFn(filePath, info, err)
	if err != nil || err1 != nil {
		if err == nil {
			lister.Close()
		}
		return err1
	}
	defer lister.Close()

	for {
		files, err := lister.Next(ListerBatchSize)
		finished := errors.Is(err, io.EOF)
		if err != nil && !finished {
			return err
		}
		for _, fi := range files {
			objName := path.Join(filePath, fi.Name())
			err = fs.walk(objName, fi, walkFn)
			if err != nil {
				return err
			}
		}
		if finished {
			return nil
		}
	}
}

func getErrorFromResponseCode(code int) error {
	switch code {
	case 401, 403:
		return os.ErrPermission
	case 404:
		return os.ErrNotExist
	case 501:
		return ErrVfsUnsupported
	case 200, 201:
		return nil
	default:
		return fmt.Errorf("unexpected response code: %v", code)
	}
}

func getInsecureTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

type wrapReader struct {
	reader io.Reader
}

func (r *wrapReader) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

type statResponse struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	Mode         uint32    `json:"mode"`
	LastModified time.Time `json:"last_modified"`
}

func (s *statResponse) getFileInfo() os.FileInfo {
	info := NewFileInfo(s.Name, false, s.Size, s.LastModified, false)
	info.SetMode(fs.FileMode(s.Mode))
	return info
}

type dirSizeResponse struct {
	Files int   `json:"files"`
	Size  int64 `json:"size"`
}

type mimeTypeResponse struct {
	Mime string `json:"mime"`
}

type statVFSResponse struct {
	ID      uint32 `json:"-"`
	Bsize   uint64 `json:"bsize"`
	Frsize  uint64 `json:"frsize"`
	Blocks  uint64 `json:"blocks"`
	Bfree   uint64 `json:"bfree"`
	Bavail  uint64 `json:"bavail"`
	Files   uint64 `json:"files"`
	Ffree   uint64 `json:"ffree"`
	Favail  uint64 `json:"favail"`
	Fsid    uint64 `json:"fsid"`
	Flag    uint64 `json:"flag"`
	Namemax uint64 `json:"namemax"`
}

func (s *statVFSResponse) toSFTPStatVFS() *sftp.StatVFS {
	return &sftp.StatVFS{
		Bsize:   s.Bsize,
		Frsize:  s.Frsize,
		Blocks:  s.Blocks,
		Bfree:   s.Bfree,
		Bavail:  s.Bavail,
		Files:   s.Files,
		Ffree:   s.Ffree,
		Favail:  s.Ffree,
		Flag:    s.Flag,
		Namemax: s.Namemax,
	}
}
