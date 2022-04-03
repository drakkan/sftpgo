package common

import (
	"errors"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/vfs"
)

var (
	// ErrTransferClosed defines the error returned for a closed transfer
	ErrTransferClosed = errors.New("transfer already closed")
)

// BaseTransfer contains protocols common transfer details for an upload or a download.
type BaseTransfer struct { //nolint:maligned
	ID              int64
	BytesSent       int64
	BytesReceived   int64
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
	AbortTransfer   int32
	aTime           time.Time
	mTime           time.Time
	transferQuota   dataprovider.TransferQuota
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
		BytesSent:       0,
		BytesReceived:   0,
		MaxWriteSize:    maxWriteSize,
		AbortTransfer:   0,
		truncatedSize:   truncatedSize,
		transferQuota:   transferQuota,
		Fs:              fs,
	}

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
		return atomic.LoadInt64(&t.BytesSent)
	}
	return atomic.LoadInt64(&t.BytesReceived)
}

// GetDownloadedSize returns the transferred size
func (t *BaseTransfer) GetDownloadedSize() int64 {
	return atomic.LoadInt64(&t.BytesSent)
}

// GetUploadedSize returns the transferred size
func (t *BaseTransfer) GetUploadedSize() int64 {
	return atomic.LoadInt64(&t.BytesReceived)
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
	atomic.StoreInt32(&(t.AbortTransfer), 1)
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
		if t.File != nil {
			return t.File.Name()
		}
		return t.fsPath
	}
	return ""
}

// SetCancelFn sets the cancel function for the transfer
func (t *BaseTransfer) SetCancelFn(cancelFn func()) {
	t.cancelFn = cancelFn
}

// CheckRead returns an error if read if not allowed
func (t *BaseTransfer) CheckRead() error {
	if t.transferQuota.AllowedDLSize == 0 && t.transferQuota.AllowedTotalSize == 0 {
		return nil
	}
	if t.transferQuota.AllowedTotalSize > 0 {
		if atomic.LoadInt64(&t.BytesSent)+atomic.LoadInt64(&t.BytesReceived) > t.transferQuota.AllowedTotalSize {
			return t.Connection.GetReadQuotaExceededError()
		}
	} else if t.transferQuota.AllowedDLSize > 0 {
		if atomic.LoadInt64(&t.BytesSent) > t.transferQuota.AllowedDLSize {
			return t.Connection.GetReadQuotaExceededError()
		}
	}
	return nil
}

// CheckWrite returns an error if write if not allowed
func (t *BaseTransfer) CheckWrite() error {
	if t.MaxWriteSize > 0 && atomic.LoadInt64(&t.BytesReceived) > t.MaxWriteSize {
		return t.Connection.GetQuotaExceededError()
	}
	if t.transferQuota.AllowedULSize == 0 && t.transferQuota.AllowedTotalSize == 0 {
		return nil
	}
	if t.transferQuota.AllowedTotalSize > 0 {
		if atomic.LoadInt64(&t.BytesSent)+atomic.LoadInt64(&t.BytesReceived) > t.transferQuota.AllowedTotalSize {
			return t.Connection.GetQuotaExceededError()
		}
	} else if t.transferQuota.AllowedULSize > 0 {
		if atomic.LoadInt64(&t.BytesReceived) > t.transferQuota.AllowedULSize {
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
					metric.TransferCompleted(atomic.LoadInt64(&t.BytesSent), atomic.LoadInt64(&t.BytesReceived), t.transferType, t.ErrTransfer)
					if t.transferQuota.HasSizeLimits() {
						go func(ulSize, dlSize int64, user dataprovider.User) {
							dataprovider.UpdateUserTransferQuota(&user, ulSize, dlSize, false) //nolint:errcheck
						}(atomic.LoadInt64(&t.BytesReceived), atomic.LoadInt64(&t.BytesSent), t.Connection.User)
					}
					atomic.StoreInt64(&t.BytesReceived, 0)
				}
				t.Unlock()
			}
			t.Connection.Log(logger.LevelDebug, "file %#v truncated to size %v max write size %v new initial size %v err: %v",
				fsPath, size, t.MaxWriteSize, t.InitialSize, err)
			return initialSize, err
		}
		if size == 0 && atomic.LoadInt64(&t.BytesSent) == 0 {
			// for cloud providers the file is always truncated to zero, we don't support append/resume for uploads
			// for buffered SFTP we can have buffered bytes so we returns an error
			if !vfs.IsBufferedSFTPFs(t.Fs) {
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
	t.Connection.Log(logger.LevelError, "Unexpected error for transfer, path: %#v, error: \"%v\" bytes sent: %v, "+
		"bytes received: %v transfer running since %v ms", t.fsPath, t.ErrTransfer, atomic.LoadInt64(&t.BytesSent),
		atomic.LoadInt64(&t.BytesReceived), elapsed)
}

func (t *BaseTransfer) getUploadFileSize() (int64, error) {
	var fileSize int64
	info, err := t.Fs.Stat(t.fsPath)
	if err == nil {
		fileSize = info.Size()
	}
	if vfs.IsCryptOsFs(t.Fs) && t.ErrTransfer != nil {
		errDelete := t.Fs.Remove(t.fsPath, false)
		if errDelete != nil {
			t.Connection.Log(logger.LevelWarn, "error removing partial crypto file %#v: %v", t.fsPath, errDelete)
		}
	}
	return fileSize, err
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
	t.Connection.Log(logger.LevelWarn, "upload in temp path cannot be renamed, delete temporary file: %#v, deletion error: %v",
		t.effectiveFsPath, err)
	// the file is outside the home dir so don't update the quota
	atomic.StoreInt64(&t.BytesReceived, 0)
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
	numFiles := 0
	if t.isNewFile {
		numFiles = 1
	}
	metric.TransferCompleted(atomic.LoadInt64(&t.BytesSent), atomic.LoadInt64(&t.BytesReceived),
		t.transferType, t.ErrTransfer)
	if t.transferQuota.HasSizeLimits() {
		dataprovider.UpdateUserTransferQuota(&t.Connection.User, atomic.LoadInt64(&t.BytesReceived), //nolint:errcheck
			atomic.LoadInt64(&t.BytesSent), false)
	}
	if t.File != nil && t.Connection.IsQuotaExceededError(t.ErrTransfer) {
		// if quota is exceeded we try to remove the partial file for uploads to local filesystem
		err = t.Fs.Remove(t.File.Name(), false)
		if err == nil {
			numFiles--
			atomic.StoreInt64(&t.BytesReceived, 0)
			t.MinWriteOffset = 0
		}
		t.Connection.Log(logger.LevelWarn, "upload denied due to space limit, delete temporary file: %#v, deletion error: %v",
			t.File.Name(), err)
	} else if t.transferType == TransferUpload && t.effectiveFsPath != t.fsPath {
		if t.ErrTransfer == nil || Config.UploadMode == UploadModeAtomicWithResume {
			err = t.Fs.Rename(t.effectiveFsPath, t.fsPath)
			t.Connection.Log(logger.LevelDebug, "atomic upload completed, rename: %#v -> %#v, error: %v",
				t.effectiveFsPath, t.fsPath, err)
			// the file must be removed if it is uploaded to a path outside the home dir and cannot be renamed
			numFiles -= t.checkUploadOutsideHomeDir(err)
		} else {
			err = t.Fs.Remove(t.effectiveFsPath, false)
			t.Connection.Log(logger.LevelWarn, "atomic upload completed with error: \"%v\", delete temporary file: %#v, deletion error: %v",
				t.ErrTransfer, t.effectiveFsPath, err)
			if err == nil {
				numFiles--
				atomic.StoreInt64(&t.BytesReceived, 0)
				t.MinWriteOffset = 0
			}
		}
	}
	elapsed := time.Since(t.start).Nanoseconds() / 1000000
	if t.transferType == TransferDownload {
		logger.TransferLog(downloadLogSender, t.fsPath, elapsed, atomic.LoadInt64(&t.BytesSent), t.Connection.User.Username,
			t.Connection.ID, t.Connection.protocol, t.Connection.localAddr, t.Connection.remoteAddr, t.ftpMode)
		ExecuteActionNotification(t.Connection, operationDownload, t.fsPath, t.requestPath, "", "", "",
			atomic.LoadInt64(&t.BytesSent), t.ErrTransfer)
	} else {
		fileSize := atomic.LoadInt64(&t.BytesReceived) + t.MinWriteOffset
		if statSize, errStat := t.getUploadFileSize(); errStat == nil {
			fileSize = statSize
		}
		t.Connection.Log(logger.LevelDebug, "uploaded file size %v", fileSize)
		t.updateQuota(numFiles, fileSize)
		t.updateTimes()
		logger.TransferLog(uploadLogSender, t.fsPath, elapsed, atomic.LoadInt64(&t.BytesReceived), t.Connection.User.Username,
			t.Connection.ID, t.Connection.protocol, t.Connection.localAddr, t.Connection.remoteAddr, t.ftpMode)
		ExecuteActionNotification(t.Connection, operationUpload, t.fsPath, t.requestPath, "", "", "", fileSize, t.ErrTransfer)
	}
	if t.ErrTransfer != nil {
		t.Connection.Log(logger.LevelError, "transfer error: %v, path: %#v", t.ErrTransfer, t.fsPath)
		if err == nil {
			err = t.ErrTransfer
		}
	}
	return err
}

func (t *BaseTransfer) updateTimes() {
	if !t.aTime.IsZero() && !t.mTime.IsZero() {
		err := t.Fs.Chtimes(t.fsPath, t.aTime, t.mTime, true)
		t.Connection.Log(logger.LevelDebug, "set times for file %#v, atime: %v, mtime: %v, err: %v",
			t.fsPath, t.aTime, t.mTime, err)
	}
}

func (t *BaseTransfer) updateQuota(numFiles int, fileSize int64) bool {
	// S3 uploads are atomic, if there is an error nothing is uploaded
	if t.File == nil && t.ErrTransfer != nil && !t.Connection.User.HasBufferedSFTP(t.GetVirtualPath()) {
		return false
	}
	sizeDiff := fileSize - t.InitialSize
	if t.transferType == TransferUpload && (numFiles != 0 || sizeDiff > 0) {
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
		trasferredBytes = atomic.LoadInt64(&t.BytesSent)
	} else {
		wantedBandwidth = t.Connection.User.UploadBandwidth
		trasferredBytes = atomic.LoadInt64(&t.BytesReceived)
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
