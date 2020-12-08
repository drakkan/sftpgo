package webdavd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/webdav"

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
	reader                  *pipeat.PipeReaderAt
}

// Name returns the name for the Fs implementation
func (fs *MockOsFs) Name() string {
	return "mockOsFs"
}

// Open returns nil
func (fs *MockOsFs) Open(name string, offset int64) (vfs.File, *pipeat.PipeReaderAt, func(), error) {
	return nil, fs.reader, nil, nil
}

// IsUploadResumeSupported returns true if upload resume is supported
func (*MockOsFs) IsUploadResumeSupported() bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (fs *MockOsFs) IsAtomicUploadSupported() bool {
	return fs.isAtomicUploadSupported
}

// Remove removes the named file or (empty) directory.
func (fs *MockOsFs) Remove(name string, isDir bool) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Remove(name)
}

// Rename renames (moves) source to target
func (fs *MockOsFs) Rename(source, target string) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Rename(source, target)
}

// Walk returns a duplicate path for testing
func (fs *MockOsFs) Walk(root string, walkFn filepath.WalkFunc) error {
	if fs.err == errWalkDir {
		walkFn("fsdpath", vfs.NewFileInfo("dpath", true, 0, time.Now(), false), nil) //nolint:errcheck
		walkFn("fsdpath", vfs.NewFileInfo("dpath", true, 0, time.Now(), false), nil) //nolint:errcheck
		return nil
	}
	walkFn("fsfpath", vfs.NewFileInfo("fpath", false, 0, time.Now(), false), nil) //nolint:errcheck
	return fs.err
}

// GetMimeType returns the content type
func (fs *MockOsFs) GetMimeType(name string) (string, error) {
	return "application/custom-mime", nil
}

func newMockOsFs(err error, atomicUpload bool, connectionID, rootDir string, reader *pipeat.PipeReaderAt) vfs.Fs {
	return &MockOsFs{
		Fs:                      vfs.NewOsFs(connectionID, rootDir, nil),
		err:                     err,
		isAtomicUploadSupported: atomicUpload,
		reader:                  reader,
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
	_, err = connection.getFile(fsMissingPath, missingPath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	_, err = connection.getFile(fsMissingPath, missingPath)
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

	connection.Fs = newMockOsFs(nil, false, fs.ConnectionID(), user.HomeDir, nil)
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

	connection.Fs = newMockOsFs(nil, false, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.True(t, os.IsNotExist(err))
	}

	errFake := errors.New("fake err")
	connection.Fs = newMockOsFs(errFake, false, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errFake.Error())
	}

	connection.Fs = newMockOsFs(errWalkDir, true, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.True(t, os.IsNotExist(err))
	}

	connection.Fs = newMockOsFs(errWalkFile, false, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(p, vpath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errWalkFile.Error())
	}

	connection.User.Permissions["/"] = []string{dataprovider.PermListItems}
	connection.Fs = newMockOsFs(nil, false, "mockID", user.HomeDir, nil)
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
		common.TransferDownload, 0, 0, 0, false, fs)
	fs = newMockOsFs(nil, false, fs.ConnectionID(), user.GetHomeDir(), nil)
	err := ioutil.WriteFile(testFilePath, []byte(""), os.ModePerm)
	assert.NoError(t, err)
	davFile := newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = fs
	fi, err := davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "application/custom-mime", ctype)
	}
	_, err = davFile.Readdir(-1)
	assert.Error(t, err)
	err = davFile.Close()
	assert.NoError(t, err)

	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = vfs.NewOsFs("id", user.HomeDir, nil)
	fi, err = davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/plain; charset=utf-8", ctype)
	}
	err = davFile.Close()
	assert.NoError(t, err)

	fi.(*webDavFileInfo).fsPath = "missing"
	_, err = fi.(*webDavFileInfo).ContentType(ctx)
	assert.EqualError(t, err, webdav.ErrNotImplemented.Error())

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
		common.TransferUpload, 0, 0, 0, false, fs)
	davFile := newWebDavFile(baseTransfer, nil, nil)
	p := make([]byte, 1)
	_, err := davFile.Read(p)
	assert.EqualError(t, err, common.ErrOpUnsupported.Error())

	r, w, err := pipeat.Pipe()
	assert.NoError(t, err)
	davFile = newWebDavFile(baseTransfer, nil, r)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)
	davFile = newWebDavFile(baseTransfer, vfs.NewPipeWriter(w), nil)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)
	err = r.Close()
	assert.NoError(t, err)
	err = w.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, false, fs)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Read(p)
	assert.True(t, os.IsNotExist(err))
	_, err = davFile.Stat()
	assert.True(t, os.IsNotExist(err))

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, false, fs)
	err = ioutil.WriteFile(testFilePath, []byte(""), os.ModePerm)
	assert.NoError(t, err)
	f, err := os.Open(testFilePath)
	if assert.NoError(t, err) {
		err = f.Close()
		assert.NoError(t, err)
	}
	davFile = newWebDavFile(baseTransfer, nil, nil)
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

	r, w, err = pipeat.Pipe()
	assert.NoError(t, err)
	mockFs := newMockOsFs(nil, false, fs.ConnectionID(), user.HomeDir, r)
	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, false, mockFs)
	davFile = newWebDavFile(baseTransfer, nil, nil)

	writeContent := []byte("content\r\n")
	go func() {
		n, err := w.Write(writeContent)
		assert.NoError(t, err)
		assert.Equal(t, len(writeContent), n)
		err = w.Close()
		assert.NoError(t, err)
	}()

	p = make([]byte, 64)
	n, err := davFile.Read(p)
	assert.EqualError(t, err, io.EOF.Error())
	assert.Equal(t, len(writeContent), n)
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, false, fs)
	davFile = newWebDavFile(baseTransfer, nil, nil)
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
	testFileContents := []byte("content")
	baseTransfer := common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferUpload, 0, 0, 0, false, fs)
	davFile := newWebDavFile(baseTransfer, nil, nil)
	_, err := davFile.Seek(0, io.SeekStart)
	assert.EqualError(t, err, common.ErrOpUnsupported.Error())
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, false, fs)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Seek(0, io.SeekCurrent)
	assert.True(t, os.IsNotExist(err))
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	err = ioutil.WriteFile(testFilePath, testFileContents, os.ModePerm)
	assert.NoError(t, err)
	f, err := os.Open(testFilePath)
	if assert.NoError(t, err) {
		err = f.Close()
		assert.NoError(t, err)
	}
	baseTransfer = common.NewBaseTransfer(f, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, false, fs)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Seek(0, io.SeekStart)
	assert.Error(t, err)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, false, fs)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	res, err := davFile.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), res)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	davFile = newWebDavFile(baseTransfer, nil, nil)
	res, err = davFile.Seek(0, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(testFileContents)), res)
	err = davFile.updateStatInfo()
	assert.Nil(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath+"1", testFile,
		common.TransferDownload, 0, 0, 0, false, fs)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Seek(0, io.SeekEnd)
	assert.True(t, os.IsNotExist(err))
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, false, fs)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.reader = f
	davFile.Fs = newMockOsFs(nil, true, fs.ConnectionID(), user.GetHomeDir(), nil)
	res, err = davFile.Seek(2, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), res)

	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = newMockOsFs(nil, true, fs.ConnectionID(), user.GetHomeDir(), nil)
	res, err = davFile.Seek(2, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), res)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath+"1", testFile,
		common.TransferDownload, 0, 0, 0, false, fs)

	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = newMockOsFs(nil, true, fs.ConnectionID(), user.GetHomeDir(), nil)
	res, err = davFile.Seek(2, io.SeekEnd)
	assert.True(t, os.IsNotExist(err))
	assert.Equal(t, int64(0), res)

	assert.Len(t, common.Connections.GetStats(), 0)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}

func TestBasicUsersCache(t *testing.T) {
	username := "webdav_internal_test"
	password := "pwd"
	u := dataprovider.User{
		Username:       username,
		Password:       password,
		HomeDir:        filepath.Join(os.TempDir(), username),
		Status:         1,
		ExpirationDate: 0,
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	err := dataprovider.AddUser(u)
	assert.NoError(t, err)
	user, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)

	c := &Configuration{
		BindPort: 9000,
		Cache: Cache{
			Users: UsersCacheConfig{
				MaxSize:        50,
				ExpirationTime: 1,
			},
		},
	}
	server, err := newServer(c, configDir)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user.Username), nil)
	assert.NoError(t, err)

	_, _, _, err = server.authenticate(req) //nolint:dogsled
	assert.Error(t, err)

	now := time.Now()
	req.SetBasicAuth(username, password)
	_, isCached, _, err := server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)
	// now the user should be cached
	var cachedUser *dataprovider.CachedUser
	result, ok := dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		cachedUser = result.(*dataprovider.CachedUser)
		assert.False(t, cachedUser.IsExpired())
		assert.True(t, cachedUser.Expiration.After(now.Add(time.Duration(c.Cache.Users.ExpirationTime)*time.Minute)))
		// authenticate must return the cached user now
		authUser, isCached, _, err := server.authenticate(req)
		assert.NoError(t, err)
		assert.True(t, isCached)
		assert.Equal(t, cachedUser.User, authUser)
	}
	// a wrong password must fail
	req.SetBasicAuth(username, "wrong")
	_, _, _, err = server.authenticate(req) //nolint:dogsled
	assert.EqualError(t, err, dataprovider.ErrInvalidCredentials.Error())
	req.SetBasicAuth(username, password)

	// force cached user expiration
	cachedUser.Expiration = now
	dataprovider.CacheWebDAVUser(cachedUser, c.Cache.Users.MaxSize)
	result, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		cachedUser = result.(*dataprovider.CachedUser)
		assert.True(t, cachedUser.IsExpired())
	}
	// now authenticate should get the user from the data provider and update the cache
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)
	result, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		cachedUser = result.(*dataprovider.CachedUser)
		assert.False(t, cachedUser.IsExpired())
	}
	// cache is invalidated after a user modification
	err = dataprovider.UpdateUser(user)
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.False(t, ok)

	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.True(t, ok)
	// cache is invalidated after user deletion
	err = dataprovider.DeleteUser(user)
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.False(t, ok)
}

func TestUsersCacheSizeAndExpiration(t *testing.T) {
	username := "webdav_internal_test"
	password := "pwd"
	u := dataprovider.User{
		HomeDir:        filepath.Join(os.TempDir(), username),
		Status:         1,
		ExpirationDate: 0,
	}
	u.Username = username + "1"
	u.Password = password + "1"
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	err := dataprovider.AddUser(u)
	assert.NoError(t, err)
	user1, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	u.Username = username + "2"
	u.Password = password + "2"
	err = dataprovider.AddUser(u)
	assert.NoError(t, err)
	user2, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	u.Username = username + "3"
	u.Password = password + "3"
	err = dataprovider.AddUser(u)
	assert.NoError(t, err)
	user3, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	u.Username = username + "4"
	u.Password = password + "4"
	err = dataprovider.AddUser(u)
	assert.NoError(t, err)
	user4, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)

	c := &Configuration{
		BindPort: 9000,
		Cache: Cache{
			Users: UsersCacheConfig{
				MaxSize:        3,
				ExpirationTime: 1,
			},
		},
	}
	server, err := newServer(c, configDir)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user1.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user1.Username, password+"1")
	_, isCached, _, err := server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user2.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user2.Username, password+"2")
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user3.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user3.Username, password+"3")
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)

	// the first 3 users are now cached
	_, ok := dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user4.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user4.Username, password+"4")
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)
	// user1, the first cached, should be removed now
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.True(t, ok)

	// user1 logins, user2 should be removed
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user1.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user1.Username, password+"1")
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.True(t, ok)

	// user2 logins, user3 should be removed
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user2.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user2.Username, password+"2")
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.True(t, ok)

	// user3 logins, user4 should be removed
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user3.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user3.Username, password+"3")
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)

	// now remove user1 after an update
	err = dataprovider.UpdateUser(user1)
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.False(t, ok)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user4.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user4.Username, password+"4")
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user1.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user1.Username, password+"1")
	_, isCached, _, err = server.authenticate(req)
	assert.NoError(t, err)
	assert.False(t, isCached)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.True(t, ok)

	err = dataprovider.DeleteUser(user1)
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user2)
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user3)
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user4)
	assert.NoError(t, err)
}

func TestRecoverer(t *testing.T) {
	c := &Configuration{
		BindPort: 9000,
	}
	server, err := newServer(c, configDir)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, nil)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestMimeCache(t *testing.T) {
	cache := mimeCache{
		maxSize:   0,
		mimeTypes: make(map[string]string),
	}
	cache.addMimeToCache(".zip", "application/zip")
	mtype := cache.getMimeFromCache(".zip")
	assert.Equal(t, "", mtype)
	cache.maxSize = 1
	cache.addMimeToCache(".zip", "application/zip")
	mtype = cache.getMimeFromCache(".zip")
	assert.Equal(t, "application/zip", mtype)
	cache.addMimeToCache(".jpg", "image/jpeg")
	mtype = cache.getMimeFromCache(".jpg")
	assert.Equal(t, "", mtype)
}
