package sftpd

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/eikenb/pipeat"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/vfs"
)

type writerAtCloser interface {
	io.WriterAt
	io.Closer
}

type readerAtCloser interface {
	io.ReaderAt
	io.Closer
}

type failingReader struct {
	innerReader readerAtCloser
	errRead     error
}

func (r *failingReader) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, r.errRead
}

func (r *failingReader) Close() error {
	if r.innerReader == nil {
		return nil
	}
	return r.innerReader.Close()
}

// transfer defines the transfer details.
// It implements the io.ReaderAt and io.WriterAt interfaces to handle SFTP downloads and uploads
type transfer struct {
	*common.BaseTransfer
	writerAt   writerAtCloser
	readerAt   readerAtCloser
	isFinished bool
}

func newTransfer(baseTransfer *common.BaseTransfer, pipeWriter *vfs.PipeWriter, pipeReader *pipeat.PipeReaderAt,
	errForRead error) *transfer {
	var writer writerAtCloser
	var reader readerAtCloser
	if baseTransfer.File != nil {
		writer = baseTransfer.File
		if errForRead == nil {
			reader = baseTransfer.File
		} else {
			reader = &failingReader{
				innerReader: baseTransfer.File,
				errRead:     errForRead,
			}
		}
	} else if pipeWriter != nil {
		writer = pipeWriter
	} else if pipeReader != nil {
		if errForRead == nil {
			reader = pipeReader
		} else {
			reader = &failingReader{
				innerReader: pipeReader,
				errRead:     errForRead,
			}
		}
	}
	if baseTransfer.File == nil && errForRead != nil && pipeReader == nil {
		reader = &failingReader{
			innerReader: nil,
			errRead:     errForRead,
		}
	}
	return &transfer{
		BaseTransfer: baseTransfer,
		writerAt:     writer,
		readerAt:     reader,
		isFinished:   false,
	}
}

// ReadAt reads len(p) bytes from the File to download starting at byte offset off and updates the bytes sent.
// It handles download bandwidth throttling too
func (t *transfer) ReadAt(p []byte, off int64) (n int, err error) {
	t.Connection.UpdateLastActivity()

	n, err = t.readerAt.ReadAt(p, off)
	atomic.AddInt64(&t.BytesSent, int64(n))

	if err == nil {
		err = t.CheckRead()
	}
	if err != nil && err != io.EOF {
		if t.GetType() == common.TransferDownload {
			t.TransferError(err)
		}
		return
	}
	t.HandleThrottle()
	return
}

// WriteAt writes len(p) bytes to the uploaded file starting at byte offset off and updates the bytes received.
// It handles upload bandwidth throttling too
func (t *transfer) WriteAt(p []byte, off int64) (n int, err error) {
	t.Connection.UpdateLastActivity()
	if off < t.MinWriteOffset {
		err := fmt.Errorf("invalid write offset: %v minimum valid value: %v", off, t.MinWriteOffset)
		t.TransferError(err)
		return 0, err
	}

	n, err = t.writerAt.WriteAt(p, off)
	atomic.AddInt64(&t.BytesReceived, int64(n))

	if err == nil {
		err = t.CheckWrite()
	}
	if err != nil {
		t.TransferError(err)
		return
	}
	t.HandleThrottle()
	return
}

// Close it is called when the transfer is completed.
// It closes the underlying file, logs the transfer info, updates the user quota (for uploads)
// and executes any defined action.
// If there is an error no action will be executed and, in atomic mode, we try to delete
// the temporary file
func (t *transfer) Close() error {
	if err := t.setFinished(); err != nil {
		return err
	}
	err := t.closeIO()
	errBaseClose := t.BaseTransfer.Close()
	if errBaseClose != nil {
		err = errBaseClose
	}
	return t.Connection.GetFsError(t.Fs, err)
}

func (t *transfer) closeIO() error {
	var err error
	if t.File != nil {
		err = t.File.Close()
	} else if t.writerAt != nil {
		err = t.writerAt.Close()
		t.Lock()
		// we set ErrTransfer here so quota is not updated, in this case the uploads are atomic
		if err != nil && t.ErrTransfer == nil {
			t.ErrTransfer = err
		}
		t.Unlock()
	} else if t.readerAt != nil {
		err = t.readerAt.Close()
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

// used for ssh commands.
// It reads from src until EOF so it does not treat an EOF from Read as an error to be reported.
// EOF from Write is reported as error
func (t *transfer) copyFromReaderToWriter(dst io.Writer, src io.Reader) (int64, error) {
	defer t.Connection.RemoveTransfer(t)

	var written int64
	var err error

	if t.MaxWriteSize < 0 {
		return 0, common.ErrQuotaExceeded
	}
	isDownload := t.GetType() == common.TransferDownload
	buf := make([]byte, 32768)
	for {
		t.Connection.UpdateLastActivity()
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
				if isDownload {
					atomic.StoreInt64(&t.BytesSent, written)
					if errCheck := t.CheckRead(); errCheck != nil {
						err = errCheck
						break
					}
				} else {
					atomic.StoreInt64(&t.BytesReceived, written)
					if errCheck := t.CheckWrite(); errCheck != nil {
						err = errCheck
						break
					}
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
		t.HandleThrottle()
	}
	t.ErrTransfer = err
	if written > 0 || err != nil {
		metric.TransferCompleted(atomic.LoadInt64(&t.BytesSent), atomic.LoadInt64(&t.BytesReceived), t.GetType(), t.ErrTransfer)
	}
	return written, err
}
