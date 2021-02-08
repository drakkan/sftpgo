package sftpd

import (
	"io"
	"os"
	"time"

	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/vfs"
)

type cdirMiddleware struct {
	next Middleware
}

var _ Middleware = &cdirMiddleware{}

func NewHandlersFromMiddleware(h Middleware) sftp.Handlers {
	return sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

func NewCurrentDirMiddleware(next Middleware) Middleware {
	return &cdirMiddleware{next: next}
}

func (c *cdirMiddleware) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	return c.next.Filewrite(request)
}

func (c *cdirMiddleware) OpenFile(request *sftp.Request) (sftp.WriterAtReaderAt, error) {
	return c.next.OpenFile(request)
}

func (c *cdirMiddleware) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	list, err := c.next.Filelist(request)
	if err == nil && request.Method == methodList {
		if rawListerAt, ok := list.(listerAt); ok {
			found := false
			latest := time.Time{}
			for _, at := range rawListerAt {
				if at.Name() == `.` {
					found = true
				}
				if at.ModTime().After(latest) {
					latest = at.ModTime()
				}
			}
			if !latest.IsZero() && !found {
				rawListerAt = append([]os.FileInfo{vfs.NewFileInfo(`.`, true, 0, latest, false)}, rawListerAt...)
			}
			return rawListerAt, nil
		}
	}
	return list, err
}

func (c *cdirMiddleware) Lstat(request *sftp.Request) (sftp.ListerAt, error) {
	return c.next.Lstat(request)
}

func (c *cdirMiddleware) Filecmd(request *sftp.Request) error {
	return c.next.Filecmd(request)
}

func (c *cdirMiddleware) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	return c.next.Fileread(request)
}
