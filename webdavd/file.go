package webdavd

import (
	"context"
	"errors"
	"io"
	"mime"
	"os"
	"path"
	"sync/atomic"
	"time"

	"github.com/eikenb/pipeat"
	"golang.org/x/net/webdav"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/vfs"
)

var errTransferAborted = errors.New("transfer aborted")

type webDavFile struct {
	*common.BaseTransfer
	writer      io.WriteCloser
	reader      io.ReadCloser
	isFinished  bool
	startOffset int64
	info        os.FileInfo
}

func newWebDavFile(baseTransfer *common.BaseTransfer, pipeWriter *vfs.PipeWriter, pipeReader *pipeat.PipeReaderAt,
	info os.FileInfo) *webDavFile {
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
	return &webDavFile{
		BaseTransfer: baseTransfer,
		writer:       writer,
		reader:       reader,
		isFinished:   false,
		startOffset:  0,
		info:         info,
	}
}

type webDavFileInfo struct {
	os.FileInfo
	file *webDavFile
}

// ContentType implements webdav.ContentTyper interface
func (fi webDavFileInfo) ContentType(ctx context.Context) (string, error) {
	var contentType string
	if c, ok := fi.FileInfo.(vfs.FileContentTyper); ok {
		contentType = c.GetContentType()
	}
	if len(contentType) > 0 {
		return contentType, nil
	}
	contentType = mime.TypeByExtension(path.Ext(fi.file.GetVirtualPath()))
	if len(contentType) > 0 {
		return contentType, nil
	}
	if c, ok := fi.file.Fs.(vfs.MimeTyper); ok {
		contentType, err := c.GetMimeType(fi.file.GetFsPath())
		return contentType, err
	}
	return contentType, webdav.ErrNotImplemented
}

// Readdir reads directory entries from the handle
func (f *webDavFile) Readdir(count int) ([]os.FileInfo, error) {
	if f.isDir() {
		return f.Connection.ListDir(f.GetFsPath(), f.GetVirtualPath())
	}
	return nil, errors.New("we can only list directories contents, this is not a directory")
}

// Stat the handle
func (f *webDavFile) Stat() (os.FileInfo, error) {
	if f.info != nil {
		fi := webDavFileInfo{
			FileInfo: f.info,
			file:     f,
		}
		return fi, nil
	}
	f.Lock()
	closed := f.isFinished
	errUpload := f.ErrTransfer
	f.Unlock()
	if f.GetType() == common.TransferUpload && closed && errUpload == nil {
		info := webDavFileInfo{
			FileInfo: vfs.NewFileInfo(f.GetFsPath(), false, atomic.LoadInt64(&f.BytesReceived), time.Now()),
			file:     f,
		}
		return info, nil
	}
	info, err := f.Fs.Stat(f.GetFsPath())
	if err != nil {
		return info, err
	}
	fi := webDavFileInfo{
		FileInfo: info,
		file:     f,
	}
	return fi, err
}

// Read reads the contents to downloads.
func (f *webDavFile) Read(p []byte) (n int, err error) {
	if atomic.LoadInt32(&f.AbortTransfer) == 1 {
		return 0, errTransferAborted
	}

	f.Connection.UpdateLastActivity()

	// the file is read sequentially we don't need to check for concurrent reads and so
	// lock the transfer while opening the remote file
	if f.reader == nil {
		if f.GetType() != common.TransferDownload {
			f.TransferError(common.ErrOpUnsupported)
			return 0, common.ErrOpUnsupported
		}
		_, r, cancelFn, err := f.Fs.Open(f.GetFsPath(), 0)
		f.Lock()
		f.reader = r
		f.ErrTransfer = err
		f.BaseTransfer.SetCancelFn(cancelFn)
		f.startOffset = 0
		f.Unlock()
		if err != nil {
			return 0, err
		}
	}
	var readed int
	var e error

	readed, e = f.reader.Read(p)
	atomic.AddInt64(&f.BytesSent, int64(readed))

	if e != nil && e != io.EOF {
		f.TransferError(e)
		return readed, e
	}
	f.HandleThrottle()
	return readed, e
}

// Write writes the uploaded contents.
func (f *webDavFile) Write(p []byte) (n int, err error) {
	if atomic.LoadInt32(&f.AbortTransfer) == 1 {
		return 0, errTransferAborted
	}

	f.Connection.UpdateLastActivity()
	var written int
	var e error

	written, e = f.writer.Write(p)
	atomic.AddInt64(&f.BytesReceived, int64(written))

	if f.MaxWriteSize > 0 && e == nil && atomic.LoadInt64(&f.BytesReceived) > f.MaxWriteSize {
		e = common.ErrQuotaExceeded
	}
	if e != nil {
		f.TransferError(e)
		return written, e
	}
	f.HandleThrottle()
	return written, e
}

// Seek sets the offset for the next Read or Write on the writer to offset,
// interpreted according to whence: 0 means relative to the origin of the file,
// 1 means relative to the current offset, and 2 means relative to the end.
// It returns the new offset and an error, if any.
func (f *webDavFile) Seek(offset int64, whence int) (int64, error) {
	f.Connection.UpdateLastActivity()
	if f.File != nil {
		ret, err := f.File.Seek(offset, whence)
		if err != nil {
			f.TransferError(err)
		}
		return ret, err
	}
	if f.GetType() == common.TransferDownload {
		readOffset := f.startOffset + atomic.LoadInt64(&f.BytesSent)
		if offset == 0 && readOffset == 0 {
			if whence == io.SeekStart {
				return 0, nil
			} else if whence == io.SeekEnd && f.info != nil {
				return f.info.Size(), nil
			}
		}

		// close the reader and create a new one at startByte
		if f.reader != nil {
			f.reader.Close() //nolint:errcheck
		}
		startByte := int64(0)
		atomic.StoreInt64(&f.BytesReceived, 0)
		atomic.StoreInt64(&f.BytesSent, 0)

		switch whence {
		case io.SeekStart:
			startByte = offset
		case io.SeekCurrent:
			startByte = readOffset + offset
		case io.SeekEnd:
			if f.info != nil {
				startByte = f.info.Size() - offset
			} else {
				err := errors.New("unable to get file size, seek from end not possible")
				f.TransferError(err)
				return 0, err
			}
		}

		_, r, cancelFn, err := f.Fs.Open(f.GetFsPath(), startByte)

		f.Lock()
		if err == nil {
			f.startOffset = startByte
			f.reader = r
		}
		f.ErrTransfer = err
		f.BaseTransfer.SetCancelFn(cancelFn)
		f.Unlock()

		return startByte, err
	}
	return 0, common.ErrOpUnsupported
}

// Close closes the open directory or the current transfer
func (f *webDavFile) Close() error {
	if err := f.setFinished(); err != nil {
		return err
	}
	err := f.closeIO()
	if f.isTransfer() {
		errBaseClose := f.BaseTransfer.Close()
		if errBaseClose != nil {
			err = errBaseClose
		}
	} else {
		f.Connection.RemoveTransfer(f.BaseTransfer)
	}
	return f.Connection.GetFsError(err)
}

func (f *webDavFile) closeIO() error {
	var err error
	if f.File != nil {
		err = f.File.Close()
	} else if f.writer != nil {
		err = f.writer.Close()
		f.Lock()
		// we set ErrTransfer here so quota is not updated, in this case the uploads are atomic
		if err != nil && f.ErrTransfer == nil {
			f.ErrTransfer = err
		}
		f.Unlock()
	} else if f.reader != nil {
		err = f.reader.Close()
	}
	return err
}

func (f *webDavFile) setFinished() error {
	f.Lock()
	defer f.Unlock()
	if f.isFinished {
		return common.ErrTransferClosed
	}
	f.isFinished = true
	return nil
}

func (f *webDavFile) isDir() bool {
	if f.info == nil {
		return false
	}
	return f.info.IsDir()
}

func (f *webDavFile) isTransfer() bool {
	if f.GetType() == common.TransferDownload {
		return (f.reader != nil)
	}
	return true
}
