package httpd

import (
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

// Connection details for a HTTP connection used to inteact with an SFTPGo filesystem
type Connection struct {
	*common.BaseConnection
	request *http.Request
}

// GetClientVersion returns the connected client's version.
func (c *Connection) GetClientVersion() string {
	if c.request != nil {
		return c.request.UserAgent()
	}
	return ""
}

// GetRemoteAddress return the connected client's address
func (c *Connection) GetRemoteAddress() string {
	if c.request != nil {
		return c.request.RemoteAddr
	}
	return ""
}

// Disconnect closes the active transfer
func (c *Connection) Disconnect() (err error) {
	return c.SignalTransfersAbort()
}

// GetCommand returns the request method
func (c *Connection) GetCommand() string {
	if c.request != nil {
		return strings.ToUpper(c.request.Method)
	}
	return ""
}

// Stat returns a FileInfo describing the named file/directory, or an error,
// if any happens
func (c *Connection) Stat(name string, mode int) (os.FileInfo, error) {
	c.UpdateLastActivity()

	name = utils.CleanPath(name)
	if !c.User.HasPerm(dataprovider.PermListItems, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	fi, err := c.DoStat(name, mode)
	if err != nil {
		c.Log(logger.LevelDebug, "error running stat on path %#v: %+v", name, err)
		return nil, err
	}
	return fi, err
}

// ReadDir returns a list of directory entries
func (c *Connection) ReadDir(name string) ([]os.FileInfo, error) {
	c.UpdateLastActivity()

	name = utils.CleanPath(name)
	return c.ListDir(name)
}

func (c *Connection) getFileReader(name string, offset int64, method string) (io.ReadCloser, error) {
	c.UpdateLastActivity()

	name = utils.CleanPath(name)
	if !c.User.HasPerm(dataprovider.PermDownload, path.Dir(name)) {
		return nil, c.GetPermissionDeniedError()
	}

	if !c.User.IsFileAllowed(name) {
		c.Log(logger.LevelWarn, "reading file %#v is not allowed", name)
		return nil, c.GetPermissionDeniedError()
	}

	fs, p, err := c.GetFsAndResolvedPath(name)
	if err != nil {
		return nil, err
	}

	if method != http.MethodHead {
		if err := common.ExecutePreAction(&c.User, common.OperationPreDownload, p, name, c.GetProtocol(), 0, 0); err != nil {
			c.Log(logger.LevelDebug, "download for file %#v denied by pre action: %v", name, err)
			return nil, c.GetPermissionDeniedError()
		}
	}

	file, r, cancelFn, err := fs.Open(p, offset)
	if err != nil {
		c.Log(logger.LevelWarn, "could not open file %#v for reading: %+v", p, err)
		return nil, c.GetFsError(fs, err)
	}

	baseTransfer := common.NewBaseTransfer(file, c.BaseConnection, cancelFn, p, p, name, common.TransferDownload,
		0, 0, 0, false, fs)
	return newHTTPDFile(baseTransfer, r), nil
}
