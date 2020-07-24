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
)

var (
	// ErrTransferClosed defines the error returned for a closed transfer
	ErrTransferClosed = errors.New("transfer already closed")
)

// BaseTransfer contains protocols common transfer details for an upload or a download.
type BaseTransfer struct {
	ID             uint64
	File           *os.File
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
	sync.Mutex
	ErrTransfer error
}

// NewBaseTransfer returns a new BaseTransfer and adds it to the given connection
func NewBaseTransfer(file *os.File, conn *BaseConnection, cancelFn func(), fsPath, requestPath string, transferType int,
	minWriteOffset, initialSize int64, isNewFile bool) *BaseTransfer {
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

// GetVirtualPath returns the transfer virtual path
func (t *BaseTransfer) GetVirtualPath() string {
	return t.requestPath
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

// Close it is called when the transfer is completed.
// It closes the underlying file, logs the transfer info, updates the
// user quota (for uploads) and executes any defined action.
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
		go action.execute() //nolint:errcheck
	} else {
		logger.TransferLog(uploadLogSender, t.fsPath, elapsed, atomic.LoadInt64(&t.BytesReceived), t.Connection.User.Username,
			t.Connection.ID, t.Connection.protocol)
		action := newActionNotification(&t.Connection.User, operationUpload, t.fsPath, "", "", t.Connection.protocol,
			atomic.LoadInt64(&t.BytesReceived)+t.MinWriteOffset, t.ErrTransfer)
		go action.execute() //nolint:errcheck
	}
	if t.ErrTransfer != nil {
		t.Connection.Log(logger.LevelWarn, "transfer error: %v, path: %#v", t.ErrTransfer, t.fsPath)
		if err == nil {
			err = t.ErrTransfer
		}
	}
	t.updateQuota(numFiles)
	return err
}

func (t *BaseTransfer) updateQuota(numFiles int) bool {
	// S3 uploads are atomic, if there is an error nothing is uploaded
	if t.File == nil && t.ErrTransfer != nil {
		return false
	}
	bytesReceived := atomic.LoadInt64(&t.BytesReceived)
	if t.transferType == TransferUpload && (numFiles != 0 || bytesReceived > 0) {
		vfolder, err := t.Connection.User.GetVirtualFolderForPath(path.Dir(t.requestPath))
		if err == nil {
			dataprovider.UpdateVirtualFolderQuota(vfolder.BaseVirtualFolder, numFiles, //nolint:errcheck
				bytesReceived-t.InitialSize, false)
			if vfolder.IsIncludedInUserQuota() {
				dataprovider.UpdateUserQuota(t.Connection.User, numFiles, bytesReceived-t.InitialSize, false) //nolint:errcheck
			}
		} else {
			dataprovider.UpdateUserQuota(t.Connection.User, numFiles, bytesReceived-t.InitialSize, false) //nolint:errcheck
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
