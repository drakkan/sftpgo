package common

import (
	"errors"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/vfs"
)

var (
	// ErrTransferClosed defines the error returned for a closed transfer
	ErrTransferClosed = errors.New("transfer already closed")
)

// BaseTransfer contains protocols common transfer details for an upload or a download.
type BaseTransfer struct { //nolint:maligned
	ID             uint64
	Fs             vfs.Fs
	File           vfs.File
	Connection     *BaseConnection
	cancelFn       func()
	fsPath         string
	start          time.Time
	transferType   int
	MinWriteOffset int64
	InitialSize    int64
	isNewFile      bool
	requestPath    string
	BytesSent      int64
	BytesReceived  int64
	MaxWriteSize   int64
	AbortTransfer  int32
	sync.Mutex
	ErrTransfer error
}

// NewBaseTransfer returns a new BaseTransfer and adds it to the given connection
func NewBaseTransfer(file vfs.File, conn *BaseConnection, cancelFn func(), fsPath, requestPath string, transferType int,
	minWriteOffset, initialSize, maxWriteSize int64, isNewFile bool, fs vfs.Fs) *BaseTransfer {
	t := &BaseTransfer{
		ID:             conn.GetTransferID(),
		File:           file,
		Connection:     conn,
		cancelFn:       cancelFn,
		fsPath:         fsPath,
		start:          time.Now(),
		transferType:   transferType,
		MinWriteOffset: minWriteOffset,
		InitialSize:    initialSize,
		isNewFile:      isNewFile,
		requestPath:    requestPath,
		BytesSent:      0,
		BytesReceived:  0,
		MaxWriteSize:   maxWriteSize,
		AbortTransfer:  0,
		Fs:             fs,
	}

	conn.AddTransfer(t)
	return t
}

// GetID returns the transfer ID
func (t *BaseTransfer) GetID() uint64 {
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

// GetStartTime returns the start time
func (t *BaseTransfer) GetStartTime() time.Time {
	return t.start
}

// SignalClose signals that the transfer should be closed.
// For same protocols, for example WebDAV, we have no
// access to the network connection, so we use this method
// to make the next read or write to fail
func (t *BaseTransfer) SignalClose() {
	atomic.StoreInt32(&(t.AbortTransfer), 1)
}

// GetVirtualPath returns the transfer virtual path
func (t *BaseTransfer) GetVirtualPath() string {
	return t.requestPath
}

// GetFsPath returns the transfer filesystem path
func (t *BaseTransfer) GetFsPath() string {
	return t.fsPath
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
					metrics.TransferCompleted(atomic.LoadInt64(&t.BytesSent), atomic.LoadInt64(&t.BytesReceived), t.transferType, t.ErrTransfer)
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
			return 0, nil
		}
		return 0, ErrOpUnsupported
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
	t.Connection.Log(logger.LevelWarn, "Unexpected error for transfer, path: %#v, error: \"%v\" bytes sent: %v, "+
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
		errDelete := os.Remove(t.fsPath)
		if errDelete != nil {
			t.Connection.Log(logger.LevelWarn, "error removing partial crypto file %#v: %v", t.fsPath, errDelete)
		}
	}
	return fileSize, err
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
	metrics.TransferCompleted(atomic.LoadInt64(&t.BytesSent), atomic.LoadInt64(&t.BytesReceived), t.transferType, t.ErrTransfer)
	if t.ErrTransfer == ErrQuotaExceeded && t.File != nil {
		// if quota is exceeded we try to remove the partial file for uploads to local filesystem
		err = os.Remove(t.File.Name())
		if err == nil {
			numFiles--
			atomic.StoreInt64(&t.BytesReceived, 0)
			t.MinWriteOffset = 0
		}
		t.Connection.Log(logger.LevelWarn, "upload denied due to space limit, delete temporary file: %#v, deletion error: %v",
			t.File.Name(), err)
	} else if t.transferType == TransferUpload && t.File != nil && t.File.Name() != t.fsPath {
		if t.ErrTransfer == nil || Config.UploadMode == UploadModeAtomicWithResume {
			err = os.Rename(t.File.Name(), t.fsPath)
			t.Connection.Log(logger.LevelDebug, "atomic upload completed, rename: %#v -> %#v, error: %v",
				t.File.Name(), t.fsPath, err)
		} else {
			err = os.Remove(t.File.Name())
			t.Connection.Log(logger.LevelWarn, "atomic upload completed with error: \"%v\", delete temporary file: %#v, "+
				"deletion error: %v", t.ErrTransfer, t.File.Name(), err)
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
			t.Connection.ID, t.Connection.protocol)
		action := newActionNotification(&t.Connection.User, operationDownload, t.fsPath, "", "", t.Connection.protocol,
			atomic.LoadInt64(&t.BytesSent), t.ErrTransfer)
		go actionHandler.Handle(action) //nolint:errcheck
	} else {
		fileSize := atomic.LoadInt64(&t.BytesReceived) + t.MinWriteOffset
		if statSize, err := t.getUploadFileSize(); err == nil {
			fileSize = statSize
		}
		t.Connection.Log(logger.LevelDebug, "uploaded file size %v", fileSize)
		t.updateQuota(numFiles, fileSize)
		logger.TransferLog(uploadLogSender, t.fsPath, elapsed, atomic.LoadInt64(&t.BytesReceived), t.Connection.User.Username,
			t.Connection.ID, t.Connection.protocol)
		action := newActionNotification(&t.Connection.User, operationUpload, t.fsPath, "", "", t.Connection.protocol,
			fileSize, t.ErrTransfer)
		go actionHandler.Handle(action) //nolint:errcheck
	}
	if t.ErrTransfer != nil {
		t.Connection.Log(logger.LevelWarn, "transfer error: %v, path: %#v", t.ErrTransfer, t.fsPath)
		if err == nil {
			err = t.ErrTransfer
		}
	}
	return err
}

func (t *BaseTransfer) updateQuota(numFiles int, fileSize int64) bool {
	// S3 uploads are atomic, if there is an error nothing is uploaded
	if t.File == nil && t.ErrTransfer != nil {
		return false
	}
	sizeDiff := fileSize - t.InitialSize
	if t.transferType == TransferUpload && (numFiles != 0 || sizeDiff > 0) {
		vfolder, err := t.Connection.User.GetVirtualFolderForPath(path.Dir(t.requestPath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(vfolder.BaseVirtualFolder, numFiles, //nolint:errcheck
				sizeDiff, false)
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(t.Connection.User, numFiles, sizeDiff, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(t.Connection.User, numFiles, sizeDiff, false) //nolint:errcheck
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
		// trasferredBytes / 1000 = KB/s, we multiply for 1000 to get milliseconds
		wantedElapsed := 1000 * (trasferredBytes / 1000) / wantedBandwidth
		if wantedElapsed > realElapsed {
			toSleep := time.Duration(wantedElapsed - realElapsed)
			time.Sleep(toSleep * time.Millisecond)
		}
	}
}
