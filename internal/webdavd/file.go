// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package webdavd

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"sync/atomic"
	"time"

	"github.com/drakkan/webdav"
	"github.com/eikenb/pipeat"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

var (
	errTransferAborted = errors.New("transfer aborted")
	lastModifiedProps  = []string{"Win32LastModifiedTime", "getlastmodified"}
)

type webDavFile struct {
	*common.BaseTransfer
	writer      io.WriteCloser
	reader      io.ReadCloser
	info        os.FileInfo
	startOffset int64
	isFinished  bool
	readTried   atomic.Bool
}

func newWebDavFile(baseTransfer *common.BaseTransfer, pipeWriter vfs.PipeWriter, pipeReader *pipeat.PipeReaderAt) *webDavFile {
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
	f := &webDavFile{
		BaseTransfer: baseTransfer,
		writer:       writer,
		reader:       reader,
		isFinished:   false,
		startOffset:  0,
		info:         nil,
	}
	f.readTried.Store(false)
	return f
}

type webDavFileInfo struct {
	os.FileInfo
	Fs          vfs.Fs
	virtualPath string
	fsPath      string
}

// ContentType implements webdav.ContentTyper interface
func (fi *webDavFileInfo) ContentType(_ context.Context) (string, error) {
	extension := path.Ext(fi.virtualPath)
	if ctype, ok := customMimeTypeMapping[extension]; ok {
		return ctype, nil
	}
	if extension == "" || extension == ".dat" {
		return "application/octet-stream", nil
	}
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
func (f *webDavFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, webdav.ErrNotImplemented
}

// ReadDir implements the FileDirLister interface
func (f *webDavFile) ReadDir() (webdav.DirLister, error) {
	if !f.Connection.User.HasPerm(dataprovider.PermListItems, f.GetVirtualPath()) {
		return nil, f.Connection.GetPermissionDeniedError()
	}
	lister, err := f.Connection.ListDir(f.GetVirtualPath())
	if err != nil {
		return nil, err
	}
	return &webDavDirLister{
		DirLister:      lister,
		fs:             f.Fs,
		virtualDirPath: f.GetVirtualPath(),
		fsDirPath:      f.GetFsPath(),
	}, nil
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
			FileInfo:    vfs.NewFileInfo(f.GetFsPath(), false, f.BytesReceived.Load(), time.Now(), false),
			Fs:          f.Fs,
			virtualPath: f.GetVirtualPath(),
			fsPath:      f.GetFsPath(),
		}
		return info, nil
	}
	info, err := f.Fs.Stat(f.GetFsPath())
	if err != nil {
		return nil, f.Connection.GetFsError(f.Fs, err)
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

func (f *webDavFile) checkFirstRead() error {
	if !f.Connection.User.HasPerm(dataprovider.PermDownload, path.Dir(f.GetVirtualPath())) {
		return f.Connection.GetPermissionDeniedError()
	}
	transferQuota := f.BaseTransfer.GetTransferQuota()
	if !transferQuota.HasDownloadSpace() {
		f.Connection.Log(logger.LevelInfo, "denying file read due to quota limits")
		return f.Connection.GetReadQuotaExceededError()
	}
	if ok, policy := f.Connection.User.IsFileAllowed(f.GetVirtualPath()); !ok {
		f.Connection.Log(logger.LevelWarn, "reading file %q is not allowed", f.GetVirtualPath())
		return f.Connection.GetErrorForDeniedFile(policy)
	}
	_, err := common.ExecutePreAction(f.Connection, common.OperationPreDownload, f.GetFsPath(), f.GetVirtualPath(), 0, 0)
	if err != nil {
		f.Connection.Log(logger.LevelDebug, "download for file %q denied by pre action: %v", f.GetVirtualPath(), err)
		return f.Connection.GetPermissionDeniedError()
	}
	f.readTried.Store(true)
	return nil
}

// Read reads the contents to downloads.
func (f *webDavFile) Read(p []byte) (n int, err error) {
	if f.AbortTransfer.Load() {
		return 0, errTransferAborted
	}
	if !f.readTried.Load() {
		if err := f.checkFirstRead(); err != nil {
			return 0, err
		}
	}
	f.Connection.UpdateLastActivity()

	// the file is read sequentially we don't need to check for concurrent reads and so
	// lock the transfer while opening the remote file
	if f.reader == nil {
		if f.GetType() != common.TransferDownload {
			f.TransferError(common.ErrOpUnsupported)
			return 0, common.ErrOpUnsupported
		}
		file, r, cancelFn, e := f.Fs.Open(f.GetFsPath(), 0)
		f.Lock()
		if e == nil {
			if file != nil {
				f.File = file
				f.writer = f.File
				f.reader = f.File
			} else if r != nil {
				f.reader = r
			}
			f.BaseTransfer.SetCancelFn(cancelFn)
		}
		f.ErrTransfer = e
		f.startOffset = 0
		f.Unlock()
		if e != nil {
			return 0, f.Connection.GetFsError(f.Fs, e)
		}
	}

	n, err = f.reader.Read(p)
	f.BytesSent.Add(int64(n))
	if err == nil {
		err = f.CheckRead()
	}
	if err != nil && err != io.EOF {
		f.TransferError(err)
		err = f.ConvertError(err)
		return
	}
	f.HandleThrottle()
	return
}

// Write writes the uploaded contents.
func (f *webDavFile) Write(p []byte) (n int, err error) {
	if f.AbortTransfer.Load() {
		return 0, errTransferAborted
	}

	f.Connection.UpdateLastActivity()

	n, err = f.writer.Write(p)
	f.BytesReceived.Add(int64(n))

	if err == nil {
		err = f.CheckWrite()
	}
	if err != nil {
		f.TransferError(err)
		err = f.ConvertError(err)
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
		}(f.BytesReceived.Load(), f.BytesSent.Load(), f.Connection.User)
	}
}

func (f *webDavFile) checkFile() error {
	if f.File == nil && vfs.FsOpenReturnsFile(f.Fs) {
		file, _, _, err := f.Fs.Open(f.GetFsPath(), 0)
		if err != nil {
			f.Connection.Log(logger.LevelWarn, "could not open file %q for seeking: %v",
				f.GetFsPath(), err)
			f.TransferError(err)
			return err
		}
		f.File = file
		f.reader = file
		f.writer = file
	}
	return nil
}

func (f *webDavFile) seekFile(offset int64, whence int) (int64, error) {
	ret, err := f.File.Seek(offset, whence)
	if err != nil {
		f.TransferError(err)
	}
	return ret, err
}

// Seek sets the offset for the next Read or Write on the writer to offset,
// interpreted according to whence: 0 means relative to the origin of the file,
// 1 means relative to the current offset, and 2 means relative to the end.
// It returns the new offset and an error, if any.
func (f *webDavFile) Seek(offset int64, whence int) (int64, error) {
	f.Connection.UpdateLastActivity()
	if err := f.checkFile(); err != nil {
		return 0, err
	}
	if f.File != nil {
		return f.seekFile(offset, whence)
	}
	if f.GetType() == common.TransferDownload {
		readOffset := f.startOffset + f.BytesSent.Load()
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
		f.BytesReceived.Store(0)
		f.BytesSent.Store(0)
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
		if metadater, ok := f.reader.(vfs.Metadater); ok {
			f.BaseTransfer.SetMetadata(metadater.Metadata())
		}
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
		return f.readTried.Load()
	}
	return true
}

// DeadProps returns a copy of the dead properties held.
// We always return nil for now, we only support the last modification time
// and it is already included in "live" properties
func (f *webDavFile) DeadProps() (map[xml.Name]webdav.Property, error) {
	return nil, nil
}

// Patch patches the dead properties held.
// In our minimal implementation we just support Win32LastModifiedTime and
// getlastmodified to set the the modification time.
// We ignore any other property and just return an OK response if the patch sets
// the modification time, otherwise a Forbidden response
func (f *webDavFile) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	resp := make([]webdav.Propstat, 0, len(patches))
	hasError := false
	for _, patch := range patches {
		status := http.StatusForbidden
		pstat := webdav.Propstat{}
		for _, p := range patch.Props {
			if status == http.StatusForbidden && !hasError {
				if !patch.Remove && util.Contains(lastModifiedProps, p.XMLName.Local) {
					parsed, err := parseTime(string(p.InnerXML))
					if err != nil {
						f.Connection.Log(logger.LevelWarn, "unsupported last modification time: %q, err: %v",
							string(p.InnerXML), err)
						hasError = true
						continue
					}
					attrs := &common.StatAttributes{
						Flags: common.StatAttrTimes,
						Atime: parsed,
						Mtime: parsed,
					}
					if err := f.Connection.SetStat(f.GetVirtualPath(), attrs); err != nil {
						f.Connection.Log(logger.LevelWarn, "unable to set modification time for %q, err :%v",
							f.GetVirtualPath(), err)
						hasError = true
						continue
					}
					status = http.StatusOK
				}
			}
			pstat.Props = append(pstat.Props, webdav.Property{XMLName: p.XMLName})
		}
		pstat.Status = status
		resp = append(resp, pstat)
	}
	return resp, nil
}

type webDavDirLister struct {
	vfs.DirLister
	fs             vfs.Fs
	virtualDirPath string
	fsDirPath      string
}

func (l *webDavDirLister) Next(limit int) ([]os.FileInfo, error) {
	files, err := l.DirLister.Next(limit)
	for idx := range files {
		info := files[idx]
		files[idx] = &webDavFileInfo{
			FileInfo:    info,
			Fs:          l.fs,
			virtualPath: path.Join(l.virtualDirPath, info.Name()),
			fsPath:      l.fs.Join(l.fsDirPath, info.Name()),
		}
	}
	return files, err
}
