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

package httpd

import (
	"io"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

type httpdFile struct {
	*common.BaseTransfer
	writer     io.WriteCloser
	reader     io.ReadCloser
	isFinished bool
}

func newHTTPDFile(baseTransfer *common.BaseTransfer, pipeWriter vfs.PipeWriter, pipeReader vfs.PipeReader) *httpdFile {
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
	return &httpdFile{
		BaseTransfer: baseTransfer,
		writer:       writer,
		reader:       reader,
		isFinished:   false,
	}
}

// Read reads the contents to downloads.
func (f *httpdFile) Read(p []byte) (n int, err error) {
	if f.AbortTransfer.Load() {
		err := f.GetAbortError()
		f.TransferError(err)
		return 0, err
	}

	f.Connection.UpdateLastActivity()

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

// Write writes the contents to upload
func (f *httpdFile) Write(p []byte) (n int, err error) {
	if f.AbortTransfer.Load() {
		err := f.GetAbortError()
		f.TransferError(err)
		return 0, err
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
			f.SetMetadata(metadater.Metadata())
		}
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
