package sftpd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
)

const (
	transferUpload = iota
	transferDownload
)

// Transfer contains the transfer details for an upload or a download.
// It implements the io Reader and Writer interface to handle files downloads and uploads
type Transfer struct {
	file           *os.File
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
}

// TransferError is called if there is an unexpected error.
// For example network or client issues
func (t *Transfer) TransferError(err error) {
	t.transferError = err
	elapsed := time.Since(t.start).Nanoseconds() / 1000000
	logger.Warn(logSender, t.connectionID, "Unexpected error for transfer, path: %#v, error: \"%v\" bytes sent: %v, "+
		"bytes received: %v transfer running since %v ms", t.path, t.transferError, t.bytesSent, t.bytesReceived, elapsed)
}

// ReadAt reads len(p) bytes from the File to download starting at byte offset off and updates the bytes sent.
// It handles download bandwidth throttling too
func (t *Transfer) ReadAt(p []byte, off int64) (n int, err error) {
	t.lastActivity = time.Now()
	readed, e := t.file.ReadAt(p, off)
	t.bytesSent += int64(readed)
	t.handleThrottle()
	return readed, e
}

// WriteAt writes len(p) bytes to the uploaded file starting at byte offset off and updates the bytes received.
// It handles upload bandwidth throttling too
func (t *Transfer) WriteAt(p []byte, off int64) (n int, err error) {
	t.lastActivity = time.Now()
	if off < t.minWriteOffset {
		logger.Warn(logSender, t.connectionID, "Invalid write offset %v minimum valid value %v", off, t.minWriteOffset)
		return 0, fmt.Errorf("invalid write offset %v", off)
	}
	written, e := t.file.WriteAt(p, off)
	t.bytesReceived += int64(written)
	t.handleThrottle()
	return written, e
}

// Close it is called when the transfer is completed.
// It closes the underlying file, log the transfer info, update the user quota (for uploads)
// and execute any defined actions.
// If there is an error no action will be executed and, in atomic mode, we try to delete
// the temporary file
func (t *Transfer) Close() error {
	err := t.file.Close()
	if t.isFinished {
		return err
	}
	t.isFinished = true
	numFiles := 0
	if t.isNewFile {
		numFiles = 1
	}
	if t.transferType == transferUpload && t.file.Name() != t.path {
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
			go executeAction(operationDownload, t.user.Username, t.path, "", "")
		} else {
			logger.TransferLog(uploadLogSender, t.path, elapsed, t.bytesReceived, t.user.Username, t.connectionID, t.protocol)
			go executeAction(operationUpload, t.user.Username, t.path, "", "")
		}
	}
	metrics.TransferCompleted(t.bytesSent, t.bytesReceived, t.transferType, t.transferError)
	removeTransfer(t)
	if t.transferType == transferUpload && (numFiles != 0 || t.bytesReceived > 0) {
		dataprovider.UpdateUserQuota(dataProvider, t.user, numFiles, t.bytesReceived, false)
	}
	return err
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
