package ftpd

import (
	"errors"
	"io"
	"sync/atomic"

	"github.com/eikenb/pipeat"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/vfs"
)

// transfer contains the transfer details for an upload or a download.
// It implements the ftpserver.FileTransfer interface to handle files downloads and uploads
type transfer struct {
	*common.BaseTransfer
	writer         io.WriteCloser
	reader         io.ReadCloser
	isFinished     bool
	maxWriteSize   int64
	expectedOffset int64
}

func newTransfer(baseTransfer *common.BaseTransfer, pipeWriter *vfs.PipeWriter, pipeReader *pipeat.PipeReaderAt,
	maxWriteSize, expectedOffset int64) *transfer {
	var writer io.WriteCloser
	var reader io.ReadCloser
	if baseTransfer.File != nil {
		writer = baseTransfer.File
		reader = baseTransfer.File
	} else if pipeWriter != nil {
		writer = pipeWriter
	} else if pipeReader != nil {
		reader = pipeReader
	}
	return &transfer{
		BaseTransfer:   baseTransfer,
		writer:         writer,
		reader:         reader,
		isFinished:     false,
		maxWriteSize:   maxWriteSize,
		expectedOffset: expectedOffset,
	}
}

// Read reads the contents to downloads.
func (t *transfer) Read(p []byte) (n int, err error) {
	t.Connection.UpdateLastActivity()
	var readed int
	var e error

	readed, e = t.reader.Read(p)
	atomic.AddInt64(&t.BytesSent, int64(readed))

	if e != nil && e != io.EOF {
		t.TransferError(e)
		return readed, e
	}
	t.HandleThrottle()
	return readed, e
}

// Write writes the uploaded contents.
func (t *transfer) Write(p []byte) (n int, err error) {
	t.Connection.UpdateLastActivity()
	var written int
	var e error

	written, e = t.writer.Write(p)
	atomic.AddInt64(&t.BytesReceived, int64(written))

	if t.maxWriteSize > 0 && e == nil && atomic.LoadInt64(&t.BytesReceived) > t.maxWriteSize {
		e = common.ErrQuotaExceeded
	}
	if e != nil {
		t.TransferError(e)
		return written, e
	}
	t.HandleThrottle()
	return written, e
}

// Seek sets the offset to resume an upload or a download
func (t *transfer) Seek(offset int64, whence int) (int64, error) {
	t.Connection.UpdateLastActivity()
	if t.File != nil {
		ret, err := t.File.Seek(offset, whence)
		if err != nil {
			t.TransferError(err)
		}
		return ret, err
	}
	if t.reader != nil && t.expectedOffset == offset && whence == io.SeekStart {
		return offset, nil
	}
	t.TransferError(errors.New("seek is unsupported for this transfer"))
	return 0, common.ErrOpUnsupported
}

// Close it is called when the transfer is completed.
func (t *transfer) Close() error {
	if err := t.setFinished(); err != nil {
		return err
	}
	err := t.closeIO()
	errBaseClose := t.BaseTransfer.Close()
	if errBaseClose != nil {
		err = errBaseClose
	}
	return t.Connection.GetFsError(err)
}

func (t *transfer) closeIO() error {
	var err error
	if t.File != nil {
		err = t.File.Close()
	} else if t.writer != nil {
		err = t.writer.Close()
		t.Lock()
		// we set ErrTransfer here so quota is not updated, in this case the uploads are atomic
		if err != nil && t.ErrTransfer == nil {
			t.ErrTransfer = err
		}
		t.Unlock()
	} else if t.reader != nil {
		err = t.reader.Close()
	}
	return err
}

func (t *transfer) setFinished() error {
	t.Lock()
	defer t.Unlock()
	if t.isFinished {
		return common.ErrTransferClosed
	}
	t.isFinished = true
	return nil
}
