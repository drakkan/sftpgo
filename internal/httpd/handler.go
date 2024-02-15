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

package httpd

import (
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

// Connection details for a HTTP connection used to inteact with an SFTPGo filesystem
type Connection struct {
	*common.BaseConnection
	request *http.Request
}

// GetClientVersion returns the connected client's version.
func (c *Connection) GetClientVersion() string {
	if c.request != nil {
		return c.request.UserAgent()
	}
	return ""
}

// GetLocalAddress returns local connection address
func (c *Connection) GetLocalAddress() string {
	return util.GetHTTPLocalAddress(c.request)
}

// GetRemoteAddress returns the connected client's address
func (c *Connection) GetRemoteAddress() string {
	if c.request != nil {
		return c.request.RemoteAddr
	}
	return ""
}

// Disconnect closes the active transfer
func (c *Connection) Disconnect() (err error) {
	return c.SignalTransfersAbort()
}

// GetCommand returns the request method
func (c *Connection) GetCommand() string {
	if c.request != nil {
		return strings.ToUpper(c.request.Method)
	}
	return ""
}

// Stat returns a FileInfo describing the named file/directory, or an error,
// if any happens
func (c *Connection) Stat(name string, mode int) (os.FileInfo, error) {
	c.UpdateLastActivity()

	if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	fi, err := c.DoStat(name, mode, true)
	if err != nil {
		return nil, err
	}
	return fi, err
}

// ReadDir returns a list of directory entries
func (c *Connection) ReadDir(name string) (vfs.DirLister, error) {
	c.UpdateLastActivity()

	return c.ListDir(name)
}

func (c *Connection) getFileReader(name string, offset int64, method string) (io.ReadCloser, error) {
	c.UpdateLastActivity()

	transferQuota := c.GetTransferQuota()
	if !transferQuota.HasDownloadSpace() {
		c.Log(logger.LevelInfo, "denying file read due to quota limits")
		return nil, util.NewI18nError(c.GetReadQuotaExceededError(), util.I18nErrorQuotaRead)
	}

	if !c.User.HasPerm(dataprovider.PermDownload, path.Dir(name)) {
		return nil, util.NewI18nError(c.GetPermissionDeniedError(), util.I18nError403Message)
	}

	if ok, policy := c.User.IsFileAllowed(name); !ok {
		c.Log(logger.LevelWarn, "reading file %q is not allowed", name)
		return nil, util.NewI18nError(c.GetErrorForDeniedFile(policy), util.I18nError403Message)
	}

	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return nil, err
	}

	if method != http.MethodHead {
		if _, err := common.ExecutePreAction(c.BaseConnection, common.OperationPreDownload, p, name, 0, 0); err != nil {
			c.Log(logger.LevelDebug, "download for file %q denied by pre action: %v", name, err)
			return nil, util.NewI18nError(c.GetPermissionDeniedError(), util.I18nError403Message)
		}
	}

	file, r, cancelFn, err := fs.Open(p, offset)
	if err != nil {
		c.Log(logger.LevelError, "could not open file %q for reading: %+v", p, err)
		return nil, c.GetFsError(fs, err)
	}

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, p, p, name, common.TransferDownload,
		0, 0, 0, 0, false, fs, transferQuota)
	return newHTTPDFile(baseTransfer, nil, r), nil
}

func (c *Connection) getFileWriter(name string) (io.WriteCloser, error) {
	c.UpdateLastActivity()

	if ok, _ := c.User.IsFileAllowed(name); !ok {
		c.Log(logger.LevelWarn, "writing file %q is not allowed", name)
		return nil, c.GetPermissionDeniedError()
	}

	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return nil, err
	}
	filePath := p
	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		filePath = fs.GetAtomicUploadPath(p)
	}

	stat, statErr := fs.Lstat(p)
	if (statErr == nil && stat.Mode()&os.ModeSymlink != 0) || fs.IsNotExist(statErr) {
		if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(name)) {
			return nil, c.GetPermissionDeniedError()
		}
		return c.handleUploadFile(fs, p, filePath, name, true, 0)
	}

	if statErr != nil {
		c.Log(logger.LevelError, "error performing file stat %q: %+v", p, statErr)
		return nil, c.GetFsError(fs, statErr)
	}

	// This happen if we upload a file that has the same name of an existing directory
	if stat.IsDir() {
		c.Log(logger.LevelError, "attempted to open a directory for writing to: %q", p)
		return nil, c.GetOpUnsupportedError()
	}

	if !c.User.HasPerm(dataprovider.PermOverwrite, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		_, _, err = fs.Rename(p, filePath)
		if err != nil {
			c.Log(logger.LevelError, "error renaming existing file for atomic upload, source: %q, dest: %q, err: %+v",
				p, filePath, err)
			return nil, c.GetFsError(fs, err)
		}
	}

	return c.handleUploadFile(fs, p, filePath, name, false, stat.Size())
}

func (c *Connection) handleUploadFile(fs vfs.Fs, resolvedPath, filePath, requestPath string, isNewFile bool, fileSize int64) (io.WriteCloser, error) {
	diskQuota, transferQuota := c.HasSpace(isNewFile, false, requestPath)
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() {
		c.Log(logger.LevelInfo, "denying file write due to quota limits")
		return nil, common.ErrQuotaExceeded
	}
	_, err := common.ExecutePreAction(c.BaseConnection, common.OperationPreUpload, resolvedPath, requestPath, fileSize, os.O_TRUNC)
	if err != nil {
		c.Log(logger.LevelDebug, "upload for file %q denied by pre action: %v", requestPath, err)
		return nil, c.GetPermissionDeniedError()
	}

	maxWriteSize, _ := c.GetMaxWriteSize(diskQuota, false, fileSize, fs.IsUploadResumeSupported())

	file, w, cancelFn, err := fs.Create(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, c.GetCreateChecks(requestPath, isNewFile, false))
	if err != nil {
		c.Log(logger.LevelError, "error opening existing file, source: %q, err: %+v", filePath, err)
		return nil, c.GetFsError(fs, err)
	}

	initialSize := int64(0)
	truncatedSize := int64(0) // bytes truncated and not included in quota
	if !isNewFile {
		if vfs.HasTruncateSupport(fs) {
			vfolder, err := c.User.GetVirtualFolderForPath(path.Dir(requestPath))
			if err == nil {
				dataprovider.UpdateVirtualFolderQuota(&vfolder.BaseVirtualFolder, 0, -fileSize, false) //nolint:errcheck
				if vfolder.IsIncludedInUserQuota() {
					dataprovider.UpdateUserQuota(&c.User, 0, -fileSize, false) //nolint:errcheck
				}
			} else {
				dataprovider.UpdateUserQuota(&c.User, 0, -fileSize, false) //nolint:errcheck
			}
		} else {
			initialSize = fileSize
			truncatedSize = fileSize
		}
		if maxWriteSize > 0 {
			maxWriteSize += fileSize
		}
	}

	vfs.SetPathPermissions(fs, filePath, c.User.GetUID(), c.User.GetGID())

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, 0, initialSize, maxWriteSize, truncatedSize, isNewFile, fs, transferQuota)
	return newHTTPDFile(baseTransfer, w, nil), nil
}

func newThrottledReader(r io.ReadCloser, limit int64, conn *Connection) *throttledReader {
	t := &throttledReader{
		id:    conn.GetTransferID(),
		limit: limit,
		r:     r,
		start: time.Now(),
		conn:  conn,
	}
	t.bytesRead.Store(0)
	t.abortTransfer.Store(false)
	conn.AddTransfer(t)
	return t
}

type throttledReader struct {
	bytesRead     atomic.Int64
	id            int64
	limit         int64
	r             io.ReadCloser
	abortTransfer atomic.Bool
	start         time.Time
	conn          *Connection
	mu            sync.Mutex
	errAbort      error
}

func (t *throttledReader) GetID() int64 {
	return t.id
}

func (t *throttledReader) GetType() int {
	return common.TransferUpload
}

func (t *throttledReader) GetSize() int64 {
	return t.bytesRead.Load()
}

func (t *throttledReader) GetDownloadedSize() int64 {
	return 0
}

func (t *throttledReader) GetUploadedSize() int64 {
	return t.bytesRead.Load()
}

func (t *throttledReader) GetVirtualPath() string {
	return "**reading request body**"
}

func (t *throttledReader) GetStartTime() time.Time {
	return t.start
}

func (t *throttledReader) GetAbortError() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.errAbort != nil {
		return t.errAbort
	}
	return common.ErrTransferAborted
}

func (t *throttledReader) SignalClose(err error) {
	t.mu.Lock()
	t.errAbort = err
	t.mu.Unlock()
	t.abortTransfer.Store(true)
}

func (t *throttledReader) GetTruncatedSize() int64 {
	return 0
}

func (t *throttledReader) HasSizeLimit() bool {
	return false
}

func (t *throttledReader) Truncate(_ string, _ int64) (int64, error) {
	return 0, vfs.ErrVfsUnsupported
}

func (t *throttledReader) GetRealFsPath(_ string) string {
	return ""
}

func (t *throttledReader) SetTimes(_ string, _ time.Time, _ time.Time) bool {
	return false
}

func (t *throttledReader) Read(p []byte) (n int, err error) {
	if t.abortTransfer.Load() {
		return 0, t.GetAbortError()
	}

	t.conn.UpdateLastActivity()
	n, err = t.r.Read(p)
	if t.limit > 0 {
		t.bytesRead.Add(int64(n))
		trasferredBytes := t.bytesRead.Load()
		elapsed := time.Since(t.start).Nanoseconds() / 1000000
		wantedElapsed := 1000 * (trasferredBytes / 1024) / t.limit
		if wantedElapsed > elapsed {
			toSleep := time.Duration(wantedElapsed - elapsed)
			time.Sleep(toSleep * time.Millisecond)
		}
	}
	return
}

func (t *throttledReader) Close() error {
	return t.r.Close()
}
