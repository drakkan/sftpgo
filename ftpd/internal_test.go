package ftpd

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
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
)

type mockFTPClientContext struct {
}

func (cc mockFTPClientContext) Path() string {
	return ""
}

func (cc mockFTPClientContext) SetDebug(debug bool) {}

func (cc mockFTPClientContext) Debug() bool {
	return false
}

func (cc mockFTPClientContext) ID() uint32 {
	return 1
}

func (cc mockFTPClientContext) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: []byte("127.0.0.1")}
}

func (cc mockFTPClientContext) LocalAddr() net.Addr {
	return &net.IPAddr{IP: []byte("127.0.0.1")}
}

func (cc mockFTPClientContext) GetClientVersion() string {
	return "mock version"
}

func (cc mockFTPClientContext) Close(code int, message string) error {
	return nil
}

// MockOsFs mockable OsFs
type MockOsFs struct {
	vfs.Fs
	err                     error
	statErr                 error
	isAtomicUploadSupported bool
}

// Name returns the name for the Fs implementation
func (fs MockOsFs) Name() string {
	return "mockOsFs"
}

// IsUploadResumeSupported returns true if upload resume is supported
func (MockOsFs) IsUploadResumeSupported() bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (fs MockOsFs) IsAtomicUploadSupported() bool {
	return fs.isAtomicUploadSupported
}

// Stat returns a FileInfo describing the named file
func (fs MockOsFs) Stat(name string) (os.FileInfo, error) {
	if fs.statErr != nil {
		return nil, fs.statErr
	}
	return os.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs MockOsFs) Lstat(name string) (os.FileInfo, error) {
	if fs.statErr != nil {
		return nil, fs.statErr
	}
	return os.Lstat(name)
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

func newMockOsFs(err, statErr error, atomicUpload bool, connectionID, rootDir string) vfs.Fs {
	return &MockOsFs{
		Fs:                      vfs.NewOsFs(connectionID, rootDir, nil),
		err:                     err,
		statErr:                 statErr,
		isAtomicUploadSupported: atomicUpload,
	}
}

func TestInitialization(t *testing.T) {
	c := &Configuration{
		BindPort:           2121,
		CertificateFile:    "acert",
		CertificateKeyFile: "akey",
	}
	err := c.Initialize(configDir)
	assert.Error(t, err)
	c.CertificateFile = ""
	c.CertificateKeyFile = ""
	c.BannerFile = "afile"
	server, err := NewServer(c, configDir)
	if assert.NoError(t, err) {
		assert.Equal(t, "", server.initialMsg)
		_, err = server.GetTLSConfig()
		assert.Error(t, err)
	}
	err = ReloadTLSCertificate()
	assert.NoError(t, err)
}

func TestServerGetSettings(t *testing.T) {
	oldConfig := common.Config
	c := &Configuration{
		BindPort: 2121,
		PassivePortRange: PortRange{
			Start: 10000,
			End:   11000,
		},
	}
	server, err := NewServer(c, configDir)
	assert.NoError(t, err)
	settings, err := server.GetSettings()
	assert.NoError(t, err)
	assert.Equal(t, 10000, settings.PassiveTransferPortRange.Start)
	assert.Equal(t, 11000, settings.PassiveTransferPortRange.End)

	common.Config.ProxyProtocol = 1
	common.Config.ProxyAllowed = []string{"invalid"}
	_, err = server.GetSettings()
	assert.Error(t, err)
	server.config.BindPort = 8021
	_, err = server.GetSettings()
	assert.Error(t, err)

	common.Config = oldConfig
}

func TestUserInvalidParams(t *testing.T) {
	u := dataprovider.User{
		HomeDir: "invalid",
	}
	c := &Configuration{
		BindPort: 2121,
		PassivePortRange: PortRange{
			Start: 10000,
			End:   11000,
		},
	}
	server, err := NewServer(c, configDir)
	assert.NoError(t, err)
	_, err = server.validateUser(u, mockFTPClientContext{})
	assert.Error(t, err)

	u.Username = "a"
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
	_, err = server.validateUser(u, mockFTPClientContext{})
	assert.Error(t, err)
	u.VirtualFolders = nil
	_, err = server.validateUser(u, mockFTPClientContext{})
	assert.Error(t, err)
}

func TestClientVersion(t *testing.T) {
	mockCC := mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	user := dataprovider.User{}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, user, nil),
		clientContext:  mockCC,
	}
	common.Connections.Add(connection)
	stats := common.Connections.GetStats()
	if assert.Len(t, stats, 1) {
		assert.Equal(t, "mock version", stats[0].ClientVersion)
		common.Connections.Remove(connection.GetID())
	}
	assert.Len(t, common.Connections.GetStats(), 0)
}

func TestDriverMethodsNotImplemented(t *testing.T) {
	mockCC := mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	user := dataprovider.User{}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, user, nil),
		clientContext:  mockCC,
	}
	_, err := connection.Create("")
	assert.EqualError(t, err, errNotImplemented.Error())
	err = connection.MkdirAll("", os.ModePerm)
	assert.EqualError(t, err, errNotImplemented.Error())
	_, err = connection.Open("")
	assert.EqualError(t, err, errNotImplemented.Error())
	_, err = connection.OpenFile("", 0, os.ModePerm)
	assert.EqualError(t, err, errNotImplemented.Error())
	err = connection.RemoveAll("")
	assert.EqualError(t, err, errNotImplemented.Error())
	assert.Equal(t, connection.GetID(), connection.Name())
}

func TestResolvePathErrors(t *testing.T) {
	user := dataprovider.User{
		HomeDir: "invalid",
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	fs := vfs.NewOsFs(connID, user.HomeDir, nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, user, fs),
		clientContext:  mockCC,
	}
	err := connection.Mkdir("", os.ModePerm)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Remove("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.RemoveDir("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Rename("", "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Symlink("", "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	_, err = connection.Stat("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Chmod("", os.ModePerm)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Chtimes("", time.Now(), time.Now())
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	_, err = connection.ReadDir("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	_, err = connection.GetHandle("", 0, 0)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
}

func TestUploadFileStatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test is not available on Windows")
	}
	user := dataprovider.User{
		Username: "user",
		HomeDir:  filepath.Clean(os.TempDir()),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	fs := vfs.NewOsFs(connID, user.HomeDir, nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, user, fs),
		clientContext:  mockCC,
	}
	testFile := filepath.Join(user.HomeDir, "test", "testfile")
	err := os.MkdirAll(filepath.Dir(testFile), os.ModePerm)
	assert.NoError(t, err)
	err = ioutil.WriteFile(testFile, []byte("data"), os.ModePerm)
	assert.NoError(t, err)
	err = os.Chmod(filepath.Dir(testFile), 0001)
	assert.NoError(t, err)
	_, err = connection.uploadFile(testFile, "test", 0)
	assert.Error(t, err)
	err = os.Chmod(filepath.Dir(testFile), os.ModePerm)
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Dir(testFile))
	assert.NoError(t, err)
}

func TestUploadOverwriteErrors(t *testing.T) {
	user := dataprovider.User{
		Username: "user",
		HomeDir:  filepath.Clean(os.TempDir()),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	fs := newMockOsFs(nil, nil, false, connID, user.GetHomeDir())
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, user, fs),
		clientContext:  mockCC,
	}
	flags := 0
	flags |= os.O_APPEND
	_, err := connection.handleFTPUploadToExistingFile(flags, "", "", 0, "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrOpUnsupported.Error())
	}

	f, err := ioutil.TempFile("", "temp")
	assert.NoError(t, err)
	err = f.Close()
	assert.NoError(t, err)
	flags = 0
	flags |= os.O_CREATE
	flags |= os.O_TRUNC
	tr, err := connection.handleFTPUploadToExistingFile(flags, f.Name(), f.Name(), 123, f.Name())
	if assert.NoError(t, err) {
		transfer := tr.(*transfer)
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

	_, err = connection.handleFTPUploadToExistingFile(os.O_TRUNC, filepath.Join(os.TempDir(), "sub", "file"),
		filepath.Join(os.TempDir(), "sub", "file1"), 0, "/sub/file1")
	assert.Error(t, err)
	connection.Fs = vfs.NewOsFs(connID, user.GetHomeDir(), nil)
	_, err = connection.handleFTPUploadToExistingFile(0, "missing1", "missing2", 0, "missing")
	assert.Error(t, err)
}

func TestTransferErrors(t *testing.T) {
	testfile := "testfile"
	file, err := os.Create(testfile)
	assert.NoError(t, err)
	user := dataprovider.User{
		Username: "user",
		HomeDir:  filepath.Clean(os.TempDir()),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	fs := newMockOsFs(nil, nil, false, connID, user.GetHomeDir())
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, user, fs),
		clientContext:  mockCC,
	}
	baseTransfer := common.NewBaseTransfer(file, connection.BaseConnection, nil, file.Name(), testfile, common.TransferDownload,
		0, 0, 0, false, fs)
	tr := newTransfer(baseTransfer, nil, nil, 0)
	err = tr.Close()
	assert.NoError(t, err)
	_, err = tr.Seek(10, 0)
	assert.Error(t, err)
	buf := make([]byte, 64)
	_, err = tr.Read(buf)
	assert.Error(t, err)
	err = tr.Close()
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrTransferClosed.Error())
	}
	assert.Len(t, connection.GetTransfers(), 0)

	r, _, err := pipeat.Pipe()
	assert.NoError(t, err)
	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testfile, testfile,
		common.TransferUpload, 0, 0, 0, false, fs)
	tr = newTransfer(baseTransfer, nil, r, 10)
	pos, err := tr.Seek(10, 0)
	assert.NoError(t, err)
	assert.Equal(t, pos, tr.expectedOffset)
	err = tr.closeIO()
	assert.NoError(t, err)

	r, w, err := pipeat.Pipe()
	assert.NoError(t, err)
	pipeWriter := vfs.NewPipeWriter(w)
	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testfile, testfile,
		common.TransferUpload, 0, 0, 0, false, fs)
	tr = newTransfer(baseTransfer, pipeWriter, nil, 0)

	err = r.Close()
	assert.NoError(t, err)
	errFake := fmt.Errorf("fake upload error")
	go func() {
		time.Sleep(100 * time.Millisecond)
		pipeWriter.Done(errFake)
	}()
	err = tr.closeIO()
	assert.EqualError(t, err, errFake.Error())
	_, err = tr.Seek(1, 0)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrOpUnsupported.Error())
	}
	err = os.Remove(testfile)
	assert.NoError(t, err)
}
