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

package ftpd

import (
	"errors"
	"io"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

// transfer contains the transfer details for an upload or a download.
// It implements the ftpserver.FileTransfer interface to handle files downloads and uploads
type transfer struct {
	*common.BaseTransfer
	writer         io.WriteCloser
	reader         io.ReadCloser
	isFinished     bool
	expectedOffset int64
}

func newTransfer(baseTransfer *common.BaseTransfer, pipeWriter vfs.PipeWriter, pipeReader vfs.PipeReader,
	expectedOffset int64) *transfer {
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
		expectedOffset: expectedOffset,
	}
}

// Read reads the contents to downloads.
func (t *transfer) Read(p []byte) (n int, err error) {
	t.Connection.UpdateLastActivity()

	n, err = t.reader.Read(p)
	t.BytesSent.Add(int64(n))

	if err == nil {
		err = t.CheckRead()
	}
	if err != nil && err != io.EOF {
		t.TransferError(err)
		err = t.ConvertError(err)
		return
	}
	t.HandleThrottle()
	return
}

// Write writes the uploaded contents.
func (t *transfer) Write(p []byte) (n int, err error) {
	t.Connection.UpdateLastActivity()

	n, err = t.writer.Write(p)
	t.BytesReceived.Add(int64(n))

	if err == nil {
		err = t.CheckWrite()
	}
	if err != nil {
		t.TransferError(err)
		err = t.ConvertError(err)
		return
	}
	t.HandleThrottle()
	return
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
	if (t.reader != nil || t.writer != nil) && t.expectedOffset == offset && whence == io.SeekStart {
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
	return t.Connection.GetFsError(t.Fs, err)
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
		if metadater, ok := t.reader.(vfs.Metadater); ok {
			t.BaseTransfer.SetMetadata(metadater.Metadata())
		}
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
