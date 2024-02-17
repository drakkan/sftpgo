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

package common

import (
	"errors"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

var (
	// ErrTransferClosed defines the error returned for a closed transfer
	ErrTransferClosed = errors.New("transfer already closed")
)

// BaseTransfer contains protocols common transfer details for an upload or a download.
type BaseTransfer struct { //nolint:maligned
	ID              int64
	BytesSent       atomic.Int64
	BytesReceived   atomic.Int64
	Fs              vfs.Fs
	File            vfs.File
	Connection      *BaseConnection
	cancelFn        func()
	fsPath          string
	effectiveFsPath string
	requestPath     string
	ftpMode         string
	start           time.Time
	MaxWriteSize    int64
	MinWriteOffset  int64
	InitialSize     int64
	truncatedSize   int64
	isNewFile       bool
	transferType    int
	AbortTransfer   atomic.Bool
	aTime           time.Time
	mTime           time.Time
	transferQuota   dataprovider.TransferQuota
	metadata        map[string]string
	sync.Mutex
	errAbort    error
	ErrTransfer error
}

// NewBaseTransfer returns a new BaseTransfer and adds it to the given connection
func NewBaseTransfer(file vfs.File, conn *BaseConnection, cancelFn func(), fsPath, effectiveFsPath, requestPath string,
	transferType int, minWriteOffset, initialSize, maxWriteSize, truncatedSize int64, isNewFile bool, fs vfs.Fs,
	transferQuota dataprovider.TransferQuota,
) *BaseTransfer {
	t := &BaseTransfer{
		ID:              conn.GetTransferID(),
		File:            file,
		Connection:      conn,
		cancelFn:        cancelFn,
		fsPath:          fsPath,
		effectiveFsPath: effectiveFsPath,
		start:           time.Now(),
		transferType:    transferType,
		MinWriteOffset:  minWriteOffset,
		InitialSize:     initialSize,
		isNewFile:       isNewFile,
		requestPath:     requestPath,
		MaxWriteSize:    maxWriteSize,
		truncatedSize:   truncatedSize,
		transferQuota:   transferQuota,
		Fs:              fs,
	}
	t.AbortTransfer.Store(false)
	t.BytesSent.Store(0)
	t.BytesReceived.Store(0)

	conn.AddTransfer(t)
	return t
}

// GetTransferQuota returns data transfer quota limits
func (t *BaseTransfer) GetTransferQuota() dataprovider.TransferQuota {
	return t.transferQuota
}

// SetFtpMode sets the FTP mode for the current transfer
func (t *BaseTransfer) SetFtpMode(mode string) {
	t.ftpMode = mode
}

// GetID returns the transfer ID
func (t *BaseTransfer) GetID() int64 {
	return t.ID
}

// GetType returns the transfer type
func (t *BaseTransfer) GetType() int {
	return t.transferType
}

// GetSize returns the transferred size
func (t *BaseTransfer) GetSize() int64 {
	if t.transferType == TransferDownload {
		return t.BytesSent.Load()
	}
	return t.BytesReceived.Load()
}

// GetDownloadedSize returns the transferred size
func (t *BaseTransfer) GetDownloadedSize() int64 {
	return t.BytesSent.Load()
}

// GetUploadedSize returns the transferred size
func (t *BaseTransfer) GetUploadedSize() int64 {
	return t.BytesReceived.Load()
}

// GetStartTime returns the start time
func (t *BaseTransfer) GetStartTime() time.Time {
	return t.start
}

// GetAbortError returns the error to send to the client if the transfer was aborted
func (t *BaseTransfer) GetAbortError() error {
	t.Lock()
	defer t.Unlock()

	if t.errAbort != nil {
		return t.errAbort
	}
	return getQuotaExceededError(t.Connection.protocol)
}

// SignalClose signals that the transfer should be closed after the next read/write.
// The optional error argument allow to send a specific error, otherwise a generic
// transfer aborted error is sent
func (t *BaseTransfer) SignalClose(err error) {
	t.Lock()
	t.errAbort = err
	t.Unlock()
	t.AbortTransfer.Store(true)
}

// GetTruncatedSize returns the truncated sized if this is an upload overwriting
// an existing file
func (t *BaseTransfer) GetTruncatedSize() int64 {
	return t.truncatedSize
}

// HasSizeLimit returns true if there is an upload or download size limit
func (t *BaseTransfer) HasSizeLimit() bool {
	if t.MaxWriteSize > 0 {
		return true
	}
	if t.transferQuota.HasSizeLimits() {
		return true
	}

	return false
}

// GetVirtualPath returns the transfer virtual path
func (t *BaseTransfer) GetVirtualPath() string {
	return t.requestPath
}

// GetFsPath returns the transfer filesystem path
func (t *BaseTransfer) GetFsPath() string {
	return t.fsPath
}

// SetTimes stores access and modification times if fsPath matches the current file
func (t *BaseTransfer) SetTimes(fsPath string, atime time.Time, mtime time.Time) bool {
	if fsPath == t.GetFsPath() {
		t.aTime = atime
		t.mTime = mtime
		return true
	}
	return false
}

// GetRealFsPath returns the real transfer filesystem path.
// If atomic uploads are enabled this differ from fsPath
func (t *BaseTransfer) GetRealFsPath(fsPath string) string {
	if fsPath == t.GetFsPath() {
		if t.File != nil || vfs.IsLocalOsFs(t.Fs) {
			return t.effectiveFsPath
		}
		return t.fsPath
	}
	return ""
}

// SetMetadata sets the metadata for the file
func (t *BaseTransfer) SetMetadata(val map[string]string) {
	t.metadata = val
}

// SetCancelFn sets the cancel function for the transfer
func (t *BaseTransfer) SetCancelFn(cancelFn func()) {
	t.cancelFn = cancelFn
}

// ConvertError accepts an error that occurs during a read or write and
// converts it into a more understandable form for the client if it is a
// well-known type of error
func (t *BaseTransfer) ConvertError(err error) error {
	if t.Fs.IsNotExist(err) {
		return t.Connection.GetNotExistError()
	} else if t.Fs.IsPermission(err) {
		return t.Connection.GetPermissionDeniedError()
	}
	return err
}

// CheckRead returns an error if read if not allowed
func (t *BaseTransfer) CheckRead() error {
	if t.transferQuota.AllowedDLSize == 0 && t.transferQuota.AllowedTotalSize == 0 {
		return nil
	}
	if t.transferQuota.AllowedTotalSize > 0 {
		if t.BytesSent.Load()+t.BytesReceived.Load() > t.transferQuota.AllowedTotalSize {
			return t.Connection.GetReadQuotaExceededError()
		}
	} else if t.transferQuota.AllowedDLSize > 0 {
		if t.BytesSent.Load() > t.transferQuota.AllowedDLSize {
			return t.Connection.GetReadQuotaExceededError()
		}
	}
	return nil
}

// CheckWrite returns an error if write if not allowed
func (t *BaseTransfer) CheckWrite() error {
	if t.MaxWriteSize > 0 && t.BytesReceived.Load() > t.MaxWriteSize {
		return t.Connection.GetQuotaExceededError()
	}
	if t.transferQuota.AllowedULSize == 0 && t.transferQuota.AllowedTotalSize == 0 {
		return nil
	}
	if t.transferQuota.AllowedTotalSize > 0 {
		if t.BytesSent.Load()+t.BytesReceived.Load() > t.transferQuota.AllowedTotalSize {
			return t.Connection.GetQuotaExceededError()
		}
	} else if t.transferQuota.AllowedULSize > 0 {
		if t.BytesReceived.Load() > t.transferQuota.AllowedULSize {
			return t.Connection.GetQuotaExceededError()
		}
	}
	return nil
}

// Truncate changes the size of the opened file.
// Supported for local fs only
func (t *BaseTransfer) Truncate(fsPath string, size int64) (int64, error) {
	if fsPath == t.GetFsPath() {
		if t.File != nil {
			initialSize := t.InitialSize
			err := t.File.Truncate(size)
			if err == nil {
				t.Lock()
				t.InitialSize = size
				if t.MaxWriteSize > 0 {
					sizeDiff := initialSize - size
					t.MaxWriteSize += sizeDiff
					metric.TransferCompleted(t.BytesSent.Load(), t.BytesReceived.Load(),
						t.transferType, t.ErrTransfer, vfs.IsSFTPFs(t.Fs))
					if t.transferQuota.HasSizeLimits() {
						go func(ulSize, dlSize int64, user dataprovider.User) {
							dataprovider.UpdateUserTransferQuota(&user, ulSize, dlSize, false) //nolint:errcheck
						}(t.BytesReceived.Load(), t.BytesSent.Load(), t.Connection.User)
					}
					t.BytesReceived.Store(0)
				}
				t.Unlock()
			}
			t.Connection.Log(logger.LevelDebug, "file %q truncated to size %v max write size %v new initial size %v err: %v",
				fsPath, size, t.MaxWriteSize, t.InitialSize, err)
			return initialSize, err
		}
		if size == 0 && t.BytesSent.Load() == 0 {
			// for cloud providers the file is always truncated to zero, we don't support append/resume for uploads.
			// For buffered SFTP and local fs we can have buffered bytes so we returns an error
			if !vfs.IsBufferedLocalOrSFTPFs(t.Fs) {
				return 0, nil
			}
		}
		return 0, vfs.ErrVfsUnsupported
	}
	return 0, errTransferMismatch
}

// TransferError is called if there is an unexpected error.
// For example network or client issues
func (t *BaseTransfer) TransferError(err error) {
	t.Lock()
	defer t.Unlock()
	if t.ErrTransfer != nil {
		return
	}
	t.ErrTransfer = err
	if t.cancelFn != nil {
		t.cancelFn()
	}
	elapsed := time.Since(t.start).Nanoseconds() / 1000000
	t.Connection.Log(logger.LevelError, "Unexpected error for transfer, path: %q, error: \"%v\" bytes sent: %v, "+
		"bytes received: %v transfer running since %v ms", t.fsPath, t.ErrTransfer, t.BytesSent.Load(),
		t.BytesReceived.Load(), elapsed)
}

func (t *BaseTransfer) getUploadFileSize() (int64, int, error) {
	var fileSize int64
	var deletedFiles int

	info, err := t.Fs.Stat(t.fsPath)
	if err == nil {
		fileSize = info.Size()
	}
	if t.ErrTransfer != nil && vfs.IsCryptOsFs(t.Fs) {
		errDelete := t.Fs.Remove(t.fsPath, false)
		if errDelete != nil {
			t.Connection.Log(logger.LevelWarn, "error removing partial crypto file %q: %v", t.fsPath, errDelete)
		} else {
			fileSize = 0
			deletedFiles = 1
			t.BytesReceived.Store(0)
			t.MinWriteOffset = 0
		}
	}
	return fileSize, deletedFiles, err
}

// return 1 if the file is outside the user home dir
func (t *BaseTransfer) checkUploadOutsideHomeDir(err error) int {
	if err == nil {
		return 0
	}
	if Config.TempPath == "" {
		return 0
	}
	err = t.Fs.Remove(t.effectiveFsPath, false)
	t.Connection.Log(logger.LevelWarn, "upload in temp path cannot be renamed, delete temporary file: %q, deletion error: %v",
		t.effectiveFsPath, err)
	// the file is outside the home dir so don't update the quota
	t.BytesReceived.Store(0)
	t.MinWriteOffset = 0
	return 1
}

// Close it is called when the transfer is completed.
// It logs the transfer info, updates the user quota (for uploads)
// and executes any defined action.
// If there is an error no action will be executed and, in atomic mode,
// we try to delete the temporary file
func (t *BaseTransfer) Close() error {
	defer t.Connection.RemoveTransfer(t)

	var err error
	numFiles := t.getUploadedFiles()
	metric.TransferCompleted(t.BytesSent.Load(), t.BytesReceived.Load(),
		t.transferType, t.ErrTransfer, vfs.IsSFTPFs(t.Fs))
	if t.transferQuota.HasSizeLimits() {
		dataprovider.UpdateUserTransferQuota(&t.Connection.User, t.BytesReceived.Load(), //nolint:errcheck
			t.BytesSent.Load(), false)
	}
	if (t.File != nil || vfs.IsLocalOsFs(t.Fs)) && t.Connection.IsQuotaExceededError(t.ErrTransfer) {
		// if quota is exceeded we try to remove the partial file for uploads to local filesystem
		err = t.Fs.Remove(t.effectiveFsPath, false)
		if err == nil {
			t.BytesReceived.Store(0)
			t.MinWriteOffset = 0
		}
		t.Connection.Log(logger.LevelWarn, "upload denied due to space limit, delete temporary file: %q, deletion error: %v",
			t.effectiveFsPath, err)
	} else if t.isAtomicUpload() {
		if t.ErrTransfer == nil || Config.UploadMode&UploadModeAtomicWithResume != 0 {
			_, _, err = t.Fs.Rename(t.effectiveFsPath, t.fsPath)
			t.Connection.Log(logger.LevelDebug, "atomic upload completed, rename: %q -> %q, error: %v",
				t.effectiveFsPath, t.fsPath, err)
			// the file must be removed if it is uploaded to a path outside the home dir and cannot be renamed
			t.checkUploadOutsideHomeDir(err)
		} else {
			err = t.Fs.Remove(t.effectiveFsPath, false)
			t.Connection.Log(logger.LevelWarn, "atomic upload completed with error: \"%v\", delete temporary file: %q, deletion error: %v",
				t.ErrTransfer, t.effectiveFsPath, err)
			if err == nil {
				t.BytesReceived.Store(0)
				t.MinWriteOffset = 0
			}
		}
	}
	elapsed := time.Since(t.start).Nanoseconds() / 1000000
	var uploadFileSize int64
	if t.transferType == TransferDownload {
		logger.TransferLog(downloadLogSender, t.fsPath, elapsed, t.BytesSent.Load(), t.Connection.User.Username,
			t.Connection.ID, t.Connection.protocol, t.Connection.localAddr, t.Connection.remoteAddr, t.ftpMode)
		ExecuteActionNotification(t.Connection, operationDownload, t.fsPath, t.requestPath, "", "", "", //nolint:errcheck
			t.BytesSent.Load(), t.ErrTransfer, elapsed, t.metadata)
	} else {
		statSize, deletedFiles, errStat := t.getUploadFileSize()
		if errStat == nil {
			uploadFileSize = statSize
		} else {
			uploadFileSize = t.BytesReceived.Load() + t.MinWriteOffset
			if t.Fs.IsNotExist(errStat) {
				uploadFileSize = 0
				numFiles--
			}
		}
		numFiles -= deletedFiles
		t.Connection.Log(logger.LevelDebug, "upload file size %d, num files %d, deleted files %d, fs path %q",
			uploadFileSize, numFiles, deletedFiles, t.fsPath)
		numFiles, uploadFileSize = t.executeUploadHook(numFiles, uploadFileSize, elapsed)
		t.updateQuota(numFiles, uploadFileSize)
		t.updateTimes()
		logger.TransferLog(uploadLogSender, t.fsPath, elapsed, t.BytesReceived.Load(), t.Connection.User.Username,
			t.Connection.ID, t.Connection.protocol, t.Connection.localAddr, t.Connection.remoteAddr, t.ftpMode)
	}
	if t.ErrTransfer != nil {
		t.Connection.Log(logger.LevelError, "transfer error: %v, path: %q", t.ErrTransfer, t.fsPath)
		if err == nil {
			err = t.ErrTransfer
		}
	}
	t.updateTransferTimestamps(uploadFileSize, elapsed)
	return err
}

func (t *BaseTransfer) isAtomicUpload() bool {
	return t.transferType == TransferUpload && t.effectiveFsPath != t.fsPath
}

func (t *BaseTransfer) updateTransferTimestamps(uploadFileSize, elapsed int64) {
	if t.ErrTransfer != nil {
		return
	}
	if t.transferType == TransferUpload {
		if t.Connection.User.FirstUpload == 0 && !t.Connection.uploadDone.Load() {
			if err := dataprovider.UpdateUserTransferTimestamps(t.Connection.User.Username, true); err == nil {
				t.Connection.uploadDone.Store(true)
				ExecuteActionNotification(t.Connection, operationFirstUpload, t.fsPath, t.requestPath, "", //nolint:errcheck
					"", "", uploadFileSize, t.ErrTransfer, elapsed, t.metadata)
			}
		}
		return
	}
	if t.Connection.User.FirstDownload == 0 && !t.Connection.downloadDone.Load() && t.BytesSent.Load() > 0 {
		if err := dataprovider.UpdateUserTransferTimestamps(t.Connection.User.Username, false); err == nil {
			t.Connection.downloadDone.Store(true)
			ExecuteActionNotification(t.Connection, operationFirstDownload, t.fsPath, t.requestPath, "", //nolint:errcheck
				"", "", t.BytesSent.Load(), t.ErrTransfer, elapsed, t.metadata)
		}
	}
}

func (t *BaseTransfer) executeUploadHook(numFiles int, fileSize, elapsed int64) (int, int64) {
	err := ExecuteActionNotification(t.Connection, operationUpload, t.fsPath, t.requestPath, "", "", "",
		fileSize, t.ErrTransfer, elapsed, t.metadata)
	if err != nil {
		if t.ErrTransfer == nil {
			t.ErrTransfer = err
		}
		// try to remove the uploaded file
		err = t.Fs.Remove(t.fsPath, false)
		if err == nil {
			numFiles--
			fileSize = 0
			t.BytesReceived.Store(0)
			t.MinWriteOffset = 0
		} else {
			t.Connection.Log(logger.LevelWarn, "unable to remove path %q after upload hook failure: %v", t.fsPath, err)
		}
	}
	return numFiles, fileSize
}

func (t *BaseTransfer) getUploadedFiles() int {
	numFiles := 0
	if t.isNewFile {
		numFiles = 1
	}
	return numFiles
}

func (t *BaseTransfer) updateTimes() {
	if !t.aTime.IsZero() && !t.mTime.IsZero() {
		err := t.Fs.Chtimes(t.fsPath, t.aTime, t.mTime, false)
		t.Connection.Log(logger.LevelDebug, "set times for file %q, atime: %v, mtime: %v, err: %v",
			t.fsPath, t.aTime, t.mTime, err)
	}
}

func (t *BaseTransfer) updateQuota(numFiles int, fileSize int64) bool {
	// Uploads on some filesystem (S3 and similar) are atomic, if there is an error nothing is uploaded
	if t.File == nil && t.ErrTransfer != nil && vfs.HasImplicitAtomicUploads(t.Fs) {
		return false
	}
	sizeDiff := fileSize - t.InitialSize
	if t.transferType == TransferUpload && (numFiles != 0 || sizeDiff != 0) {
		vfolder, err := t.Connection.User.GetVirtualFolderForPath(path.Dir(t.requestPath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(&vfolder.BaseVirtualFolder, numFiles, //nolint:errcheck
				sizeDiff, false)
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(&t.Connection.User, numFiles, sizeDiff, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(&t.Connection.User, numFiles, sizeDiff, false) //nolint:errcheck
		}
		return true
	}
	return false
}

// HandleThrottle manage bandwidth throttling
func (t *BaseTransfer) HandleThrottle() {
	var wantedBandwidth int64
	var trasferredBytes int64
	if t.transferType == TransferDownload {
		wantedBandwidth = t.Connection.User.DownloadBandwidth
		trasferredBytes = t.BytesSent.Load()
	} else {
		wantedBandwidth = t.Connection.User.UploadBandwidth
		trasferredBytes = t.BytesReceived.Load()
	}
	if wantedBandwidth > 0 {
		// real and wanted elapsed as milliseconds, bytes as kilobytes
		realElapsed := time.Since(t.start).Nanoseconds() / 1000000
		// trasferredBytes / 1024 = KB/s, we multiply for 1000 to get milliseconds
		wantedElapsed := 1000 * (trasferredBytes / 1024) / wantedBandwidth
		if wantedElapsed > realElapsed {
			toSleep := time.Duration(wantedElapsed - realElapsed)
			time.Sleep(toSleep * time.Millisecond)
		}
	}
}
