package httpd

import (
	"errors"
	"io"
	"sync/atomic"

	"github.com/eikenb/pipeat"

	"github.com/drakkan/sftpgo/common"
)

var errTransferAborted = errors.New("transfer aborted")

type httpdFile struct {
	*common.BaseTransfer
	reader     io.ReadCloser
	isFinished bool
}

func newHTTPDFile(baseTransfer *common.BaseTransfer, pipeReader *pipeat.PipeReaderAt) *httpdFile {
	var reader io.ReadCloser
	if baseTransfer.File != nil {
		reader = baseTransfer.File
	} else if pipeReader != nil {
		reader = pipeReader
	}
	return &httpdFile{
		BaseTransfer: baseTransfer,
		reader:       reader,
		isFinished:   false,
	}
}

// Read reads the contents to downloads.
func (f *httpdFile) Read(p []byte) (n int, err error) {
	if atomic.LoadInt32(&f.AbortTransfer) == 1 {
		return 0, errTransferAborted
	}

	f.Connection.UpdateLastActivity()

	n, err = f.reader.Read(p)
	atomic.AddInt64(&f.BytesSent, int64(n))

	if err != nil && err != io.EOF {
		f.TransferError(err)
		return
	}
	f.HandleThrottle()
	return
}

// Close closes the current transfer
func (f *httpdFile) Close() error {
	if err := f.setFinished(); err != nil {
		return err
	}
	err := f.closeIO()
	errBaseClose := f.BaseTransfer.Close()
	if errBaseClose != nil {
		err = errBaseClose
	}

	return f.Connection.GetFsError(f.Fs, err)
}

func (f *httpdFile) closeIO() error {
	var err error
	if f.File != nil {
		err = f.File.Close()
	} else if f.reader != nil {
		err = f.reader.Close()
	}
	return err
}

func (f *httpdFile) setFinished() error {
	f.Lock()
	defer f.Unlock()

	if f.isFinished {
		return common.ErrTransferClosed
	}
	f.isFinished = true
	return nil
}
