package webdavd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	configDir = ".."
	testFile  = "test_dav_file"
)

var (
	errWalkDir  = errors.New("err walk dir")
	errWalkFile = errors.New("err walk file")
)

// MockOsFs mockable OsFs
type MockOsFs struct {
	vfs.Fs
	err                     error
	isAtomicUploadSupported bool
}

// Name returns the name for the Fs implementation
func (fs MockOsFs) Name() string {
	return "mockOsFs"
}

// Open returns nil
func (MockOsFs) Open(name string, offset int64) (*os.File, *pipeat.PipeReaderAt, func(), error) {
	return nil, nil, nil, nil
}

// IsUploadResumeSupported returns true if upload resume is supported
func (MockOsFs) IsUploadResumeSupported() bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (fs MockOsFs) IsAtomicUploadSupported() bool {
	return fs.isAtomicUploadSupported
}

// Remove removes the named file or (empty) directory.
func (fs MockOsFs) Remove(name string, isDir bool) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Remove(name)
}

// Rename renames (moves) source to target
func (fs MockOsFs) Rename(source, target string) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Rename(source, target)
}

// Walk returns a duplicate path for testing
func (fs MockOsFs) Walk(root string, walkFn filepath.WalkFunc) error {
	if fs.err == errWalkDir {
		walkFn("fsdpath", vfs.NewFileInfo("dpath", true, 0, time.Now()), nil) //nolint:errcheck
		walkFn("fsdpath", vfs.NewFileInfo("dpath", true, 0, time.Now()), nil) //nolint:errcheck
		return nil
	}
	walkFn("fsfpath", vfs.NewFileInfo("fpath", false, 0, time.Now()), nil) //nolint:errcheck
	return fs.err
}

// GetMimeType implements vfs.MimeTyper
func (fs MockOsFs) GetMimeType(name string) (string, error) {
	return "application/octet-stream", nil
}

func newMockOsFs(err error, atomicUpload bool, connectionID, rootDir string) vfs.Fs {
	return &MockOsFs{
		Fs:                      vfs.NewOsFs(connectionID, rootDir, nil),
		err:                     err,
		isAtomicUploadSupported: atomicUpload,
	}
}

func TestOrderDirsToRemove(t *testing.T) {
	user := dataprovider.User{}
	fs := vfs.NewOsFs("id", os.TempDir(), nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, user, fs),
		request:        nil,
	}
	dirsToRemove := []objectMapping{}

	orderedDirs := connection.orderDirsToRemove(dirsToRemove)
	assert.Equal(t, len(dirsToRemove), len(orderedDirs))

	dirsToRemove = []objectMapping{
		{
			fsPath:      "dir1",
			virtualPath: "",
		},
	}
	orderedDirs = connection.orderDirsToRemove(dirsToRemove)
	assert.Equal(t, len(dirsToRemove), len(orderedDirs))

	dirsToRemove = []objectMapping{
		{
			fsPath:      "dir1",
			virtualPath: "",
		},
		{
			fsPath:      "dir12",
			virtualPath: "",
		},
		{
			fsPath:      filepath.Join("dir1", "a", "b"),
			virtualPath: "",
		},
		{
			fsPath:      filepath.Join("dir1", "a"),
			virtualPath: "",
		},
	}

	orderedDirs = connection.orderDirsToRemove(dirsToRemove)
	if assert.Equal(t, len(dirsToRemove), len(orderedDirs)) {
		assert.Equal(t, "dir12", orderedDirs[0].fsPath)
		assert.Equal(t, filepath.Join("dir1", "a", "b"), orderedDirs[1].fsPath)
		assert.Equal(t, filepath.Join("dir1", "a"), orderedDirs[2].fsPath)
		assert.Equal(t, "dir1", orderedDirs[3].fsPath)
	}
}

func TestUserInvalidParams(t *testing.T) {
	u := dataprovider.User{
		Username: "username",
		HomeDir:  "invalid",
	}
	c := &Configuration{
		BindPort: 9000,
	}
	server, err := newServer(c, configDir)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", u.Username), nil)
	assert.NoError(t, err)

	_, err = server.validateUser(u, req)
	if assert.Error(t, err) {
		assert.EqualError(t, err, fmt.Sprintf("cannot login user with invalid home dir: %#v", u.HomeDir))
	}

	u.HomeDir = filepath.Clean(os.TempDir())
	subDir := "subdir"
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir1", subDir)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
	})

	_, err = server.validateUser(u, req)
	if assert.Error(t, err) {
		assert.EqualError(t, err, "overlapping mapped folders are allowed only with quota tracking disabled")
	}

	req.TLS = &tls.ConnectionState{}
	writeLog(req, nil)
}

func TestRemoteAddress(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/username", nil)
	assert.NoError(t, err)
	assert.Empty(t, req.RemoteAddr)

	remoteAddr1 := "100.100.100.100"
	remoteAddr2 := "172.172.172.172"

	req.Header.Set("X-Forwarded-For", remoteAddr1)
	checkRemoteAddress(req)
	assert.Equal(t, remoteAddr1, req.RemoteAddr)
	req.RemoteAddr = ""

	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%v, %v", remoteAddr2, remoteAddr1))
	checkRemoteAddress(req)
	assert.Equal(t, remoteAddr2, req.RemoteAddr)

	req.Header.Del("X-Forwarded-For")
	req.RemoteAddr = ""
	req.Header.Set("X-Real-IP", remoteAddr1)
	checkRemoteAddress(req)
	assert.Equal(t, remoteAddr1, req.RemoteAddr)
	req.RemoteAddr = ""

	oldValue := common.Config.ProxyProtocol
	common.Config.ProxyProtocol = 1

	checkRemoteAddress(req)
	assert.Empty(t, req.RemoteAddr)

	common.Config.ProxyProtocol = oldValue
}

func TestConnWithNilRequest(t *testing.T) {
	c := &Connection{}
	assert.Empty(t, c.GetClientVersion())
	assert.Empty(t, c.GetCommand())
	assert.Empty(t, c.GetRemoteAddress())
}

func TestResolvePathErrors(t *testing.T) {
	ctx := context.Background()
	user := dataprovider.User{
		HomeDir: "invalid",
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, user, fs),
	}

	err := connection.Mkdir(ctx, "", os.ModePerm)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	err = connection.Rename(ctx, "oldName", "newName")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	_, err = connection.Stat(ctx, "name")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	err = connection.RemoveAll(ctx, "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	_, err = connection.OpenFile(ctx, "", 0, os.ModePerm)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	if runtime.GOOS != "windows" {
		connection.User.HomeDir = filepath.Clean(os.TempDir())
		connection.Fs = vfs.NewOsFs("connID", connection.User.HomeDir, nil)
		subDir := "sub"
		testTxtFile := "file.txt"
		err = os.MkdirAll(filepath.Join(os.TempDir(), subDir, subDir), os.ModePerm)
		assert.NoError(t, err)
		err = ioutil.WriteFile(filepath.Join(os.TempDir(), subDir, subDir, testTxtFile), []byte("content"), os.ModePerm)
		assert.NoError(t, err)
		err = os.Chmod(filepath.Join(os.TempDir(), subDir, subDir), 0001)
		assert.NoError(t, err)
		err = connection.Rename(ctx, testTxtFile, path.Join(subDir, subDir, testTxtFile))
		if assert.Error(t, err) {
			assert.EqualError(t, err, common.ErrPermissionDenied.Error())
		}
		_, err = connection.putFile(filepath.Join(connection.User.HomeDir, subDir, subDir, testTxtFile),
			path.Join(subDir, subDir, testTxtFile))
		if assert.Error(t, err) {
			assert.EqualError(t, err, common.ErrPermissionDenied.Error())
		}
		err = os.Chmod(filepath.Join(os.TempDir(), subDir, subDir), os.ModePerm)
		assert.NoError(t, err)
		err = os.RemoveAll(filepath.Join(os.TempDir(), subDir))
		assert.NoError(t, err)
	}
}

func TestFileAccessErrors(t *testing.T) {
	ctx := context.Background()
	user := dataprovider.User{
		HomeDir: filepath.Clean(os.TempDir()),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, user, fs),
	}
	missingPath := "missing path"
	fsMissingPath := filepath.Join(user.HomeDir, missingPath)
	err := connection.RemoveAll(ctx, missingPath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	info := vfs.NewFileInfo(missingPath, true, 0, time.Now())
	_, err = connection.getFile(fsMissingPath, missingPath, info)
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	info = vfs.NewFileInfo(missingPath, false, 123, time.Now())
	_, err = connection.getFile(fsMissingPath, missingPath, info)
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	p := filepath.Join(user.HomeDir, "adir", missingPath)
	_, err = connection.handleUploadToNewFile(p, p, path.Join("adir", missingPath))
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	_, err = connection.handleUploadToExistingFile(p, p, 0, path.Join("adir", missingPath))
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}

	connection.Fs = newMockOsFs(nil, false, fs.ConnectionID(), user.HomeDir)
	_, err = connection.handleUploadToExistingFile(p, p, 0, path.Join("adir", missingPath))
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}

	f, err := ioutil.TempFile("", "temp")
	assert.NoError(t, err)
	err = f.Close()
	assert.NoError(t, err)
	davFile, err := connection.handleUploadToExistingFile(f.Name(), f.Name(), 123, f.Name())
	if assert.NoError(t, err) {
		transfer := davFile.(*webDavFile)
		transfers := connection.GetTransfers()
		if assert.Equal(t, 1, len(transfers)) {
			assert.Equal(t, transfers[0].ID, transfer.GetID())
			assert.Equal(t, int64(123), transfer.InitialSize)
			err = transfer.Close()
			assert.NoError(t, err)
			assert.Equal(t, 0, len(connection.GetTransfers()))
		}
	}

	err = os.Remove(f.Name())
	assert.NoError(t, err)
}

func TestRemoveDirTree(t *testing.T) {
	user := dataprovider.User{
		HomeDir: filepath.Clean(os.TempDir()),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, user, fs),
	}

	vpath := path.Join("adir", "missing")
	p := filepath.Join(user.HomeDir, "adir", "missing")
	err := connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.True(t, os.IsNotExist(err))
	}

	connection.Fs = newMockOsFs(nil, false, "mockID", user.HomeDir)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.True(t, os.IsNotExist(err))
	}

	errFake := errors.New("fake err")
	connection.Fs = newMockOsFs(errFake, false, "mockID", user.HomeDir)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errFake.Error())
	}

	connection.Fs = newMockOsFs(errWalkDir, true, "mockID", user.HomeDir)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.True(t, os.IsNotExist(err))
	}

	connection.Fs = newMockOsFs(errWalkFile, false, "mockID", user.HomeDir)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errWalkFile.Error())
	}

	connection.User.Permissions["/"] = []string{dataprovider.PermListItems}
	connection.Fs = newMockOsFs(nil, false, "mockID", user.HomeDir)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrPermissionDenied.Error())
	}
}

func TestContentType(t *testing.T) {
	user := dataprovider.User{
		HomeDir: filepath.Clean(os.TempDir()),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, user, fs),
	}
	testFilePath := filepath.Join(user.HomeDir, testFile)
	ctx := context.Background()
	baseTransfer := common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, false)
	info := vfs.NewFileInfo(testFilePath, true, 0, time.Now())
	davFile := newWebDavFile(baseTransfer, nil, nil, 0, info, fs)
	fi, err := davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "inode/directory", ctype)
	}
	err = davFile.Close()
	assert.NoError(t, err)
	fs = newMockOsFs(nil, false, fs.ConnectionID(), user.GetHomeDir())
	err = ioutil.WriteFile(testFilePath, []byte(""), os.ModePerm)
	assert.NoError(t, err)
	fi, err = os.Stat(testFilePath)
	assert.NoError(t, err)
	davFile = newWebDavFile(baseTransfer, nil, nil, 0, fi, fs)
	fi, err = davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "application/octet-stream", ctype)
	}
	_, err = davFile.Readdir(-1)
	assert.Error(t, err)
	err = davFile.Close()
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}

func TestTransferReadWriteErrors(t *testing.T) {
	user := dataprovider.User{
		HomeDir: filepath.Clean(os.TempDir()),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, user, fs),
	}
	testFilePath := filepath.Join(user.HomeDir, testFile)
	baseTransfer := common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferUpload, 0, 0, false)
	davFile := newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	assert.False(t, davFile.isDir())
	p := make([]byte, 1)
	_, err := davFile.Read(p)
	assert.EqualError(t, err, common.ErrOpUnsupported.Error())

	r, w, err := pipeat.Pipe()
	assert.NoError(t, err)
	davFile = newWebDavFile(baseTransfer, nil, r, 0, nil, fs)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)
	davFile = newWebDavFile(baseTransfer, vfs.NewPipeWriter(w), nil, 0, nil, fs)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)
	err = r.Close()
	assert.NoError(t, err)
	err = w.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, false)
	davFile = newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	_, err = davFile.Read(p)
	assert.True(t, os.IsNotExist(err))
	_, err = davFile.Stat()
	assert.True(t, os.IsNotExist(err))

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, false)
	err = ioutil.WriteFile(testFilePath, []byte(""), os.ModePerm)
	assert.NoError(t, err)
	f, err := os.Open(testFilePath)
	if assert.NoError(t, err) {
		err = f.Close()
		assert.NoError(t, err)
	}
	davFile = newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	davFile.reader = f
	err = davFile.Close()
	assert.EqualError(t, err, common.ErrGenericFailure.Error())
	err = davFile.Close()
	assert.EqualError(t, err, common.ErrTransferClosed.Error())
	_, err = davFile.Read(p)
	assert.Error(t, err)
	info, err := davFile.Stat()
	if assert.NoError(t, err) {
		assert.Equal(t, int64(0), info.Size())
	}

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, false)
	davFile = newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	davFile.writer = f
	err = davFile.Close()
	assert.EqualError(t, err, common.ErrGenericFailure.Error())

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}

func TestTransferSeek(t *testing.T) {
	user := dataprovider.User{
		HomeDir: filepath.Clean(os.TempDir()),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, user, fs),
	}
	testFilePath := filepath.Join(user.HomeDir, testFile)
	baseTransfer := common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferUpload, 0, 0, false)
	davFile := newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	_, err := davFile.Seek(0, io.SeekStart)
	assert.EqualError(t, err, common.ErrOpUnsupported.Error())
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, false)
	davFile = newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	_, err = davFile.Seek(0, io.SeekCurrent)
	assert.True(t, os.IsNotExist(err))
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	err = ioutil.WriteFile(testFilePath, []byte("content"), os.ModePerm)
	assert.NoError(t, err)
	f, err := os.Open(testFilePath)
	if assert.NoError(t, err) {
		err = f.Close()
		assert.NoError(t, err)
	}
	baseTransfer = common.NewBaseTransfer(f, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, false)
	davFile = newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	_, err = davFile.Seek(0, io.SeekStart)
	assert.Error(t, err)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, false)
	davFile = newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	davFile.reader = f
	res, err := davFile.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), res)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	info, err := os.Stat(testFilePath)
	assert.NoError(t, err)
	davFile = newWebDavFile(baseTransfer, nil, nil, 0, info, fs)
	davFile.reader = f
	res, err = davFile.Seek(0, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(7), res)

	davFile = newWebDavFile(baseTransfer, nil, nil, 0, info, fs)
	davFile.reader = f
	davFile.fs = newMockOsFs(nil, true, fs.ConnectionID(), user.GetHomeDir())
	res, err = davFile.Seek(2, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), res)

	davFile = newWebDavFile(baseTransfer, nil, nil, 0, info, fs)
	davFile.fs = newMockOsFs(nil, true, fs.ConnectionID(), user.GetHomeDir())
	res, err = davFile.Seek(2, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), res)

	davFile = newWebDavFile(baseTransfer, nil, nil, 0, nil, fs)
	res, err = davFile.Seek(2, io.SeekEnd)
	assert.EqualError(t, err, "unable to get file size, seek from end not possible")
	assert.Equal(t, int64(0), res)

	assert.Len(t, common.Connections.GetStats(), 0)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}
