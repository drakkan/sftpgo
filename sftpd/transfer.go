package sftpd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/eikenb/pipeat"
)

const (
	transferUpload = iota
	transferDownload
)

var (
	errTransferClosed = errors.New("transfer already closed")
)

// Transfer contains the transfer details for an upload or a download.
// It implements the io Reader and Writer interface to handle files downloads and uploads
type Transfer struct {
	file           *os.File
	writerAt       *pipeat.PipeWriterAt
	readerAt       *pipeat.PipeReaderAt
	cancelFn       func()
	path           string
	start          time.Time
	bytesSent      int64
	bytesReceived  int64
	user           dataprovider.User
	connectionID   string
	transferType   int
	lastActivity   time.Time
	isNewFile      bool
	protocol       string
	transferError  error
	isFinished     bool
	minWriteOffset int64
	expectedSize   int64
	lock           *sync.Mutex
}

// TransferError is called if there is an unexpected error.
// For example network or client issues
func (t *Transfer) TransferError(err error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.transferError != nil {
		return
	}
	t.transferError = err
	if t.cancelFn != nil {
		t.cancelFn()
	}
	elapsed := time.Since(t.start).Nanoseconds() / 1000000
	logger.Warn(logSender, t.connectionID, "Unexpected error for transfer, path: %#v, error: \"%v\" bytes sent: %v, "+
		"bytes received: %v transfer running since %v ms", t.path, t.transferError, t.bytesSent, t.bytesReceived, elapsed)
}

// ReadAt reads len(p) bytes from the File to download starting at byte offset off and updates the bytes sent.
// It handles download bandwidth throttling too
func (t *Transfer) ReadAt(p []byte, off int64) (n int, err error) {
	t.lastActivity = time.Now()
	var readed int
	var e error
	if t.readerAt != nil {
		readed, e = t.readerAt.ReadAt(p, off)
	} else {
		readed, e = t.file.ReadAt(p, off)
	}
	t.lock.Lock()
	t.bytesSent += int64(readed)
	t.lock.Unlock()
	if e != nil && e != io.EOF {
		t.TransferError(e)
		return readed, e
	}
	t.handleThrottle()
	return readed, e
}

// WriteAt writes len(p) bytes to the uploaded file starting at byte offset off and updates the bytes received.
// It handles upload bandwidth throttling too
func (t *Transfer) WriteAt(p []byte, off int64) (n int, err error) {
	t.lastActivity = time.Now()
	if off < t.minWriteOffset {
		err := fmt.Errorf("Invalid write offset: %v minimum valid value: %v", off, t.minWriteOffset)
		t.TransferError(err)
		return 0, err
	}
	var written int
	var e error
	if t.writerAt != nil {
		written, e = t.writerAt.WriteAt(p, off)
	} else {
		written, e = t.file.WriteAt(p, off)
	}
	t.lock.Lock()
	t.bytesReceived += int64(written)
	t.lock.Unlock()
	if e != nil {
		t.TransferError(e)
		return written, e
	}
	t.handleThrottle()
	return written, e
}

// Close it is called when the transfer is completed.
// It closes the underlying file, logs the transfer info, updates the user quota (for uploads)
// and executes any defined action.
// If there is an error no action will be executed and, in atomic mode, we try to delete
// the temporary file
func (t *Transfer) Close() error {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.isFinished {
		return errTransferClosed
	}
	err := t.closeIO()
	t.isFinished = true
	numFiles := 0
	if t.isNewFile {
		numFiles = 1
	}
	t.checkDownloadSize()
	if t.transferType == transferUpload && t.file != nil && t.file.Name() != t.path {
		if t.transferError == nil || uploadMode == uploadModeAtomicWithResume {
			err = os.Rename(t.file.Name(), t.path)
			logger.Debug(logSender, t.connectionID, "atomic upload completed, rename: %#v -> %#v, error: %v",
				t.file.Name(), t.path, err)
		} else {
			err = os.Remove(t.file.Name())
			logger.Warn(logSender, t.connectionID, "atomic upload completed with error: \"%v\", delete temporary file: %#v, "+
				"deletion error: %v", t.transferError, t.file.Name(), err)
			if err == nil {
				numFiles--
				t.bytesReceived = 0
			}
		}
	}
	if t.transferError == nil {
		elapsed := time.Since(t.start).Nanoseconds() / 1000000
		if t.transferType == transferDownload {
			logger.TransferLog(downloadLogSender, t.path, elapsed, t.bytesSent, t.user.Username, t.connectionID, t.protocol)
			go executeAction(operationDownload, t.user.Username, t.path, "", "", t.bytesSent)
		} else {
			logger.TransferLog(uploadLogSender, t.path, elapsed, t.bytesReceived, t.user.Username, t.connectionID, t.protocol)
			go executeAction(operationUpload, t.user.Username, t.path, "", "", t.bytesReceived+t.minWriteOffset)
		}
	} else {
		logger.Warn(logSender, t.connectionID, "transfer error: %v, path: %#v", t.transferError, t.path)
		if err == nil {
			err = t.transferError
		}
	}
	metrics.TransferCompleted(t.bytesSent, t.bytesReceived, t.transferType, t.transferError)
	removeTransfer(t)
	if t.transferType == transferUpload && (numFiles != 0 || t.bytesReceived > 0) {
		dataprovider.UpdateUserQuota(dataProvider, t.user, numFiles, t.bytesReceived, false)
	}
	return err
}

func (t *Transfer) closeIO() error {
	var err error
	if t.writerAt != nil {
		err = t.writerAt.Close()
	} else if t.readerAt != nil {
		err = t.readerAt.Close()
	} else {
		err = t.file.Close()
	}
	return err
}

func (t *Transfer) checkDownloadSize() {
	if t.transferType == transferDownload && t.transferError == nil && t.bytesSent < t.expectedSize {
		t.transferError = fmt.Errorf("incomplete download: %v/%v bytes transferred", t.bytesSent, t.expectedSize)
	}
}

func (t *Transfer) handleThrottle() {
	var wantedBandwidth int64
	var trasferredBytes int64
	if t.transferType == transferDownload {
		wantedBandwidth = t.user.DownloadBandwidth
		trasferredBytes = t.bytesSent
	} else {
		wantedBandwidth = t.user.UploadBandwidth
		trasferredBytes = t.bytesReceived
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

// used for ssh commands.
// It reads from src until EOF so it does not treat an EOF from Read as an error to be reported.
// EOF from Write is reported as error
func (t *Transfer) copyFromReaderToWriter(dst io.Writer, src io.Reader, maxWriteSize int64) (int64, error) {
	var written int64
	var err error
	if maxWriteSize < 0 {
		return 0, errQuotaExceeded
	}
	buf := make([]byte, 32768)
	for {
		t.lastActivity = time.Now()
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
				if t.transferType == transferDownload {
					t.bytesSent = written
				} else {
					t.bytesReceived = written
				}
				if maxWriteSize > 0 && written > maxWriteSize {
					err = errQuotaExceeded
					break
				}
			}
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
		t.handleThrottle()
	}
	t.transferError = err
	if t.bytesSent > 0 || t.bytesReceived > 0 || err != nil {
		metrics.TransferCompleted(t.bytesSent, t.bytesReceived, t.transferType, t.transferError)
	}
	return written, err
}
