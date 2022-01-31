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

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/vfs"
)

var errTransferAborted = errors.New("transfer aborted")

type webDavFile struct {
	*common.BaseTransfer
	writer      io.WriteCloser
	reader      io.ReadCloser
	info        os.FileInfo
	startOffset int64
	isFinished  bool
	readTryed   int32
}

func newWebDavFile(baseTransfer *common.BaseTransfer, pipeWriter *vfs.PipeWriter, pipeReader *pipeat.PipeReaderAt) *webDavFile {
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
		info:         nil,
		readTryed:    0,
	}
}

type webDavFileInfo struct {
	os.FileInfo
	Fs          vfs.Fs
	virtualPath string
	fsPath      string
}

// ContentType implements webdav.ContentTyper interface
func (fi *webDavFileInfo) ContentType(ctx context.Context) (string, error) {
	extension := path.Ext(fi.virtualPath)
	contentType := mime.TypeByExtension(extension)
	if contentType != "" {
		return contentType, nil
	}
	contentType = mimeTypeCache.getMimeFromCache(extension)
	if contentType != "" {
		return contentType, nil
	}
	contentType, err := fi.Fs.GetMimeType(fi.fsPath)
	if contentType != "" {
		mimeTypeCache.addMimeToCache(extension, contentType)
		return contentType, err
	}
	return "", webdav.ErrNotImplemented
}

// Readdir reads directory entries from the handle
func (f *webDavFile) Readdir(count int) ([]os.FileInfo, error) {
	if !f.Connection.User.HasPerm(dataprovider.PermListItems, f.GetVirtualPath()) {
		return nil, f.Connection.GetPermissionDeniedError()
	}
	fileInfos, err := f.Connection.ListDir(f.GetVirtualPath())
	if err != nil {
		return nil, err
	}
	result := make([]os.FileInfo, 0, len(fileInfos))
	for _, fileInfo := range fileInfos {
		result = append(result, &webDavFileInfo{
			FileInfo:    fileInfo,
			Fs:          f.Fs,
			virtualPath: path.Join(f.GetVirtualPath(), fileInfo.Name()),
			fsPath:      f.Fs.Join(f.GetFsPath(), fileInfo.Name()),
		})
	}
	return result, nil
}

// Stat the handle
func (f *webDavFile) Stat() (os.FileInfo, error) {
	if f.GetType() == common.TransferDownload && !f.Connection.User.HasPerm(dataprovider.PermListItems, path.Dir(f.GetVirtualPath())) {
		return nil, f.Connection.GetPermissionDeniedError()
	}
	f.Lock()
	errUpload := f.ErrTransfer
	f.Unlock()
	if f.GetType() == common.TransferUpload && errUpload == nil {
		info := &webDavFileInfo{
			FileInfo:    vfs.NewFileInfo(f.GetFsPath(), false, atomic.LoadInt64(&f.BytesReceived), time.Now(), false),
			Fs:          f.Fs,
			virtualPath: f.GetVirtualPath(),
			fsPath:      f.GetFsPath(),
		}
		return info, nil
	}
	info, err := f.Fs.Stat(f.GetFsPath())
	if err != nil {
		return nil, err
	}
	if vfs.IsCryptOsFs(f.Fs) {
		info = f.Fs.(*vfs.CryptFs).ConvertFileInfo(info)
	}
	fi := &webDavFileInfo{
		FileInfo:    info,
		Fs:          f.Fs,
		virtualPath: f.GetVirtualPath(),
		fsPath:      f.GetFsPath(),
	}
	return fi, nil
}

// Read reads the contents to downloads.
func (f *webDavFile) Read(p []byte) (n int, err error) {
	if atomic.LoadInt32(&f.AbortTransfer) == 1 {
		return 0, errTransferAborted
	}
	if atomic.LoadInt32(&f.readTryed) == 0 {
		if !f.Connection.User.HasPerm(dataprovider.PermDownload, path.Dir(f.GetVirtualPath())) {
			return 0, f.Connection.GetPermissionDeniedError()
		}
		transferQuota := f.BaseTransfer.GetTransferQuota()
		if !transferQuota.HasDownloadSpace() {
			f.Connection.Log(logger.LevelInfo, "denying file read due to quota limits")
			return 0, f.Connection.GetReadQuotaExceededError()
		}

		if ok, policy := f.Connection.User.IsFileAllowed(f.GetVirtualPath()); !ok {
			f.Connection.Log(logger.LevelWarn, "reading file %#v is not allowed", f.GetVirtualPath())
			return 0, f.Connection.GetErrorForDeniedFile(policy)
		}
		err := common.ExecutePreAction(f.Connection, common.OperationPreDownload, f.GetFsPath(), f.GetVirtualPath(), 0, 0)
		if err != nil {
			f.Connection.Log(logger.LevelDebug, "download for file %#v denied by pre action: %v", f.GetVirtualPath(), err)
			return 0, f.Connection.GetPermissionDeniedError()
		}
		atomic.StoreInt32(&f.readTryed, 1)
	}

	f.Connection.UpdateLastActivity()

	// the file is read sequentially we don't need to check for concurrent reads and so
	// lock the transfer while opening the remote file
	if f.reader == nil {
		if f.GetType() != common.TransferDownload {
			f.TransferError(common.ErrOpUnsupported)
			return 0, common.ErrOpUnsupported
		}
		_, r, cancelFn, e := f.Fs.Open(f.GetFsPath(), 0)
		f.Lock()
		if e == nil {
			f.reader = r
			f.BaseTransfer.SetCancelFn(cancelFn)
		}
		f.ErrTransfer = e
		f.startOffset = 0
		f.Unlock()
		if e != nil {
			return 0, e
		}
	}

	n, err = f.reader.Read(p)
	atomic.AddInt64(&f.BytesSent, int64(n))
	if err == nil {
		err = f.CheckRead()
	}
	if err != nil && err != io.EOF {
		f.TransferError(err)
		return
	}
	f.HandleThrottle()
	return
}

// Write writes the uploaded contents.
func (f *webDavFile) Write(p []byte) (n int, err error) {
	if atomic.LoadInt32(&f.AbortTransfer) == 1 {
		return 0, errTransferAborted
	}

	f.Connection.UpdateLastActivity()

	n, err = f.writer.Write(p)
	atomic.AddInt64(&f.BytesReceived, int64(n))

	if err == nil {
		err = f.CheckWrite()
	}
	if err != nil {
		f.TransferError(err)
		return
	}
	f.HandleThrottle()
	return
}

func (f *webDavFile) updateStatInfo() error {
	if f.info != nil {
		return nil
	}
	info, err := f.Fs.Stat(f.GetFsPath())
	if err != nil {
		return err
	}
	if vfs.IsCryptOsFs(f.Fs) {
		info = f.Fs.(*vfs.CryptFs).ConvertFileInfo(info)
	}
	f.info = info
	return nil
}

func (f *webDavFile) updateTransferQuotaOnSeek() {
	transferQuota := f.GetTransferQuota()
	if transferQuota.HasSizeLimits() {
		go func(ulSize, dlSize int64, user dataprovider.User) {
			dataprovider.UpdateUserTransferQuota(&user, ulSize, dlSize, false) //nolint:errcheck
		}(atomic.LoadInt64(&f.BytesReceived), atomic.LoadInt64(&f.BytesSent), f.Connection.User)
	}
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
			} else if whence == io.SeekEnd {
				if err := f.updateStatInfo(); err != nil {
					return 0, err
				}
				return f.info.Size(), nil
			}
		}

		// close the reader and create a new one at startByte
		if f.reader != nil {
			f.reader.Close() //nolint:errcheck
			f.reader = nil
		}
		startByte := int64(0)
		atomic.StoreInt64(&f.BytesReceived, 0)
		atomic.StoreInt64(&f.BytesSent, 0)
		f.updateTransferQuotaOnSeek()

		switch whence {
		case io.SeekStart:
			startByte = offset
		case io.SeekCurrent:
			startByte = readOffset + offset
		case io.SeekEnd:
			if err := f.updateStatInfo(); err != nil {
				f.TransferError(err)
				return 0, err
			}
			startByte = f.info.Size() - offset
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
	return f.Connection.GetFsError(f.Fs, err)
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

func (f *webDavFile) isTransfer() bool {
	if f.GetType() == common.TransferDownload {
		return atomic.LoadInt32(&f.readTryed) > 0
	}
	return true
}
