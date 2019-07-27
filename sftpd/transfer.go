package sftpd

import (
	"os"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
)

const (
	transferUpload = iota
	transferDownload
)

// Transfer struct, it contains the transfer details for an upload or a download
type Transfer struct {
	file          *os.File
	path          string
	start         time.Time
	bytesSent     int64
	bytesReceived int64
	user          dataprovider.User
	connectionID  string
	transferType  int
	lastActivity  time.Time
	isNewFile     bool
}

// ReadAt update sent bytes
func (t *Transfer) ReadAt(p []byte, off int64) (n int, err error) {
	t.lastActivity = time.Now()
	readed, e := t.file.ReadAt(p, off)
	t.bytesSent += int64(readed)
	t.handleThrottle()
	return readed, e
}

// WriteAt update received bytes
func (t *Transfer) WriteAt(p []byte, off int64) (n int, err error) {
	t.lastActivity = time.Now()
	written, e := t.file.WriteAt(p, off)
	t.bytesReceived += int64(written)
	t.handleThrottle()
	return written, e
}

// Close method called when the transfer is completed, we log the transfer info
func (t *Transfer) Close() error {
	err := t.file.Close()
	elapsed := time.Since(t.start).Nanoseconds() / 1000000
	if t.transferType == transferDownload {
		logger.TransferLog(sftpdDownloadLogSender, t.path, elapsed, t.bytesSent, t.user.Username, t.connectionID)
		executeAction(operationDownload, t.user.Username, t.path, "")
	} else {
		logger.TransferLog(sftpUploadLogSender, t.path, elapsed, t.bytesReceived, t.user.Username, t.connectionID)
		executeAction(operationUpload, t.user.Username, t.path, "")
	}
	removeTransfer(t)
	if t.transferType == transferUpload && t.bytesReceived > 0 && t.isNewFile {
		numFiles := 0
		numFiles++
		dataprovider.UpdateUserQuota(dataProvider, t.user.Username, numFiles, t.bytesReceived, false)
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
