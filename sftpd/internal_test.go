package sftpd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const osWindows = "windows"

type MockChannel struct {
	Buffer        *bytes.Buffer
	StdErrBuffer  *bytes.Buffer
	ReadError     error
	WriteError    error
	ShortWriteErr bool
}

func (c *MockChannel) Read(data []byte) (int, error) {
	if c.ReadError != nil {
		return 0, c.ReadError
	}
	return c.Buffer.Read(data)
}

func (c *MockChannel) Write(data []byte) (int, error) {
	if c.WriteError != nil {
		return 0, c.WriteError
	}
	if c.ShortWriteErr {
		return 0, nil
	}
	return c.Buffer.Write(data)
}

func (c *MockChannel) Close() error {
	return nil
}

func (c *MockChannel) CloseWrite() error {
	return nil
}

func (c *MockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

func (c *MockChannel) Stderr() io.ReadWriter {
	return c.StdErrBuffer
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

func TestNewActionNotification(t *testing.T) {
	user := dataprovider.User{
		Username: "username",
	}
	user.FsConfig.Provider = 0
	user.FsConfig.S3Config = vfs.S3FsConfig{
		Bucket:   "s3bucket",
		Endpoint: "endpoint",
	}
	user.FsConfig.GCSConfig = vfs.GCSFsConfig{
		Bucket: "gcsbucket",
	}
	a := newActionNotification(user, operationDownload, "path", "target", "", 123, nil)
	assert.Equal(t, user.Username, a.Username)
	assert.Equal(t, 0, len(a.Bucket))
	assert.Equal(t, 0, len(a.Endpoint))

	user.FsConfig.Provider = 1
	a = newActionNotification(user, operationDownload, "path", "target", "", 123, nil)
	assert.Equal(t, "s3bucket", a.Bucket)
	assert.Equal(t, "endpoint", a.Endpoint)

	user.FsConfig.Provider = 2
	a = newActionNotification(user, operationDownload, "path", "target", "", 123, nil)
	assert.Equal(t, "gcsbucket", a.Bucket)
	assert.Equal(t, 0, len(a.Endpoint))
}

func TestWrongActions(t *testing.T) {
	actionsCopy := actions

	badCommand := "/bad/command"
	if runtime.GOOS == osWindows {
		badCommand = "C:\\bad\\command"
	}
	actions = Actions{
		ExecuteOn:           []string{operationDownload},
		Command:             badCommand,
		HTTPNotificationURL: "",
	}
	user := dataprovider.User{
		Username: "username",
	}
	err := executeAction(newActionNotification(user, operationDownload, "path", "", "", 0, nil))
	assert.Error(t, err, "action with bad command must fail")

	err = executeAction(newActionNotification(user, operationDelete, "path", "", "", 0, nil))
	assert.NoError(t, err)
	actions.Command = ""
	actions.HTTPNotificationURL = "http://foo\x7f.com/"
	err = executeAction(newActionNotification(user, operationDownload, "path", "", "", 0, nil))
	assert.Error(t, err, "action with bad url must fail")

	actions = actionsCopy
}

func TestActionHTTP(t *testing.T) {
	actionsCopy := actions
	actions = Actions{
		ExecuteOn:           []string{operationDownload},
		Command:             "",
		HTTPNotificationURL: "http://127.0.0.1:8080/",
	}
	user := dataprovider.User{
		Username: "username",
	}
	err := executeAction(newActionNotification(user, operationDownload, "path", "", "", 0, nil))
	assert.NoError(t, err)

	actions = actionsCopy
}

func TestRemoveNonexistentTransfer(t *testing.T) {
	transfer := Transfer{}
	err := removeTransfer(&transfer)
	assert.Error(t, err, "remove nonexistent transfer must fail")
}

func TestRemoveNonexistentQuotaScan(t *testing.T) {
	err := RemoveQuotaScan("username")
	assert.Error(t, err, "remove nonexistent quota scan must fail")
}

func TestGetOSOpenFlags(t *testing.T) {
	var flags sftp.FileOpenFlags
	flags.Write = true
	flags.Excl = true
	osFlags := getOSOpenFlags(flags)
	assert.NotEqual(t, 0, osFlags&os.O_WRONLY)
	assert.NotEqual(t, 0, osFlags&os.O_EXCL)

	flags.Append = true
	// append flag should be ignored to allow resume
	assert.NotEqual(t, 0, osFlags&os.O_WRONLY)
	assert.NotEqual(t, 0, osFlags&os.O_EXCL)
}

func TestUploadResumeInvalidOffset(t *testing.T) {
	testfile := "testfile" //nolint:goconst
	file, err := os.Create(testfile)
	assert.NoError(t, err)
	transfer := Transfer{
		file:          file,
		path:          file.Name(),
		start:         time.Now(),
		bytesSent:     0,
		bytesReceived: 0,
		user: dataprovider.User{
			Username: "testuser",
		},
		connectionID:   "",
		transferType:   transferUpload,
		lastActivity:   time.Now(),
		isNewFile:      false,
		protocol:       protocolSFTP,
		transferError:  nil,
		isFinished:     false,
		minWriteOffset: 10,
		lock:           new(sync.Mutex),
	}
	_, err = transfer.WriteAt([]byte("test"), 0)
	assert.Error(t, err, "upload with invalid offset must fail")
	err = transfer.Close()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "Invalid write offset")
	}
	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestReadWriteErrors(t *testing.T) {
	testfile := "testfile"
	file, err := os.Create(testfile)
	assert.NoError(t, err)
	transfer := Transfer{
		file:          file,
		path:          file.Name(),
		start:         time.Now(),
		bytesSent:     0,
		bytesReceived: 0,
		user: dataprovider.User{
			Username: "testuser",
		},
		connectionID:   "",
		transferType:   transferDownload,
		lastActivity:   time.Now(),
		isNewFile:      false,
		protocol:       protocolSFTP,
		transferError:  nil,
		isFinished:     false,
		minWriteOffset: 0,
		lock:           new(sync.Mutex),
	}
	err = file.Close()
	assert.NoError(t, err)
	_, err = transfer.WriteAt([]byte("test"), 0)
	assert.Error(t, err, "writing to closed file must fail")
	buf := make([]byte, 32768)
	_, err = transfer.ReadAt(buf, 0)
	assert.Error(t, err, "reading from a closed file must fail")
	err = transfer.Close()
	assert.Error(t, err)

	r, _, err := pipeat.Pipe()
	assert.NoError(t, err)
	transfer = Transfer{
		readerAt:      r,
		writerAt:      nil,
		start:         time.Now(),
		bytesSent:     0,
		bytesReceived: 0,
		user: dataprovider.User{
			Username: "testuser",
		},
		connectionID:  "",
		transferType:  transferDownload,
		lastActivity:  time.Now(),
		isNewFile:     false,
		protocol:      protocolSFTP,
		transferError: nil,
		isFinished:    false,
		lock:          new(sync.Mutex),
	}
	err = transfer.closeIO()
	assert.NoError(t, err)
	_, err = transfer.ReadAt(buf, 0)
	assert.Error(t, err, "reading from a closed pipe must fail")

	r, w, err := pipeat.Pipe()
	assert.NoError(t, err)
	transfer = Transfer{
		readerAt:      nil,
		writerAt:      vfs.NewPipeWriter(w),
		start:         time.Now(),
		bytesSent:     0,
		bytesReceived: 0,
		user: dataprovider.User{
			Username: "testuser",
		},
		connectionID:  "",
		transferType:  transferDownload,
		lastActivity:  time.Now(),
		isNewFile:     false,
		protocol:      protocolSFTP,
		transferError: nil,
		isFinished:    false,
		lock:          new(sync.Mutex),
	}
	err = r.Close()
	assert.NoError(t, err)
	errFake := fmt.Errorf("fake upload error")
	go func() {
		time.Sleep(100 * time.Millisecond)
		transfer.writerAt.Done(errFake)
	}()
	err = transfer.closeIO()
	assert.EqualError(t, err, errFake.Error())
	_, err = transfer.WriteAt([]byte("test"), 0)
	assert.Error(t, err, "writing to closed pipe must fail")

	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestTransferCancelFn(t *testing.T) {
	testfile := "testfile"
	file, err := os.Create(testfile)
	assert.NoError(t, err)
	isCancelled := false
	cancelFn := func() {
		isCancelled = true
	}
	transfer := Transfer{
		file:          file,
		cancelFn:      cancelFn,
		path:          file.Name(),
		start:         time.Now(),
		bytesSent:     0,
		bytesReceived: 0,
		user: dataprovider.User{
			Username: "testuser",
		},
		connectionID:   "",
		transferType:   transferDownload,
		lastActivity:   time.Now(),
		isNewFile:      false,
		protocol:       protocolSFTP,
		transferError:  nil,
		isFinished:     false,
		minWriteOffset: 0,
		lock:           new(sync.Mutex),
	}
	errFake := errors.New("fake error, this will trigger cancelFn")
	transfer.TransferError(errFake)
	err = transfer.Close()
	assert.EqualError(t, err, errFake.Error())
	assert.True(t, isCancelled, "cancelFn not called!")

	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestMockFsErrors(t *testing.T) {
	errFake := errors.New("fake error")
	fs := newMockOsFs(errFake, errFake, false, "123", os.TempDir())
	u := dataprovider.User{}
	u.Username = "test_username"
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.HomeDir = os.TempDir()
	c := Connection{
		fs:   fs,
		User: u,
	}
	testfile := filepath.Join(u.HomeDir, "testfile")
	request := sftp.NewRequest("Remove", testfile)
	err := ioutil.WriteFile(testfile, []byte("test"), 0666)
	assert.NoError(t, err)
	err = c.handleSFTPRemove(testfile, request)
	assert.EqualError(t, err, sftp.ErrSSHFxFailure.Error())
	_, err = c.Filewrite(request)
	assert.EqualError(t, err, sftp.ErrSSHFxFailure.Error())

	var flags sftp.FileOpenFlags
	flags.Write = true
	flags.Trunc = false
	flags.Append = true
	_, err = c.handleSFTPUploadToExistingFile(flags, testfile, testfile, 0, false)
	assert.EqualError(t, err, sftp.ErrSSHFxOpUnsupported.Error())

	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestUploadFiles(t *testing.T) {
	oldUploadMode := uploadMode
	uploadMode = uploadModeAtomic
	c := Connection{
		fs: vfs.NewOsFs("123", os.TempDir(), nil),
	}
	var flags sftp.FileOpenFlags
	flags.Write = true
	flags.Trunc = true
	_, err := c.handleSFTPUploadToExistingFile(flags, "missing_path", "other_missing_path", 0, false)
	assert.Error(t, err, "upload to existing file must fail if one or both paths are invalid")

	uploadMode = uploadModeStandard
	_, err = c.handleSFTPUploadToExistingFile(flags, "missing_path", "other_missing_path", 0, false)
	assert.Error(t, err, "upload to existing file must fail if one or both paths are invalid")

	missingFile := "missing/relative/file.txt"
	if runtime.GOOS == osWindows {
		missingFile = "missing\\relative\\file.txt"
	}
	_, err = c.handleSFTPUploadToNewFile(".", missingFile, false)
	assert.Error(t, err, "upload new file in missing path must fail")

	c.fs = newMockOsFs(nil, nil, false, "123", os.TempDir())
	f, err := ioutil.TempFile("", "temp")
	assert.NoError(t, err)
	err = f.Close()
	assert.NoError(t, err)

	_, err = c.handleSFTPUploadToExistingFile(flags, f.Name(), f.Name(), 123, false)
	assert.NoError(t, err)
	if assert.Equal(t, 1, len(activeTransfers)) {
		transfer := activeTransfers[0]
		assert.Equal(t, int64(123), transfer.initialSize)
		err = transfer.Close()
		assert.NoError(t, err)
		assert.Equal(t, 0, len(activeTransfers))
	}
	err = os.Remove(f.Name())
	assert.NoError(t, err)
	uploadMode = oldUploadMode
}

func TestWithInvalidHome(t *testing.T) {
	u := dataprovider.User{}
	u.HomeDir = "home_rel_path" //nolint:goconst
	_, err := loginUser(u, dataprovider.SSHLoginMethodPassword, "", nil)
	assert.Error(t, err, "login a user with an invalid home_dir must fail")

	u.HomeDir = os.TempDir()
	fs, err := u.GetFilesystem("123")
	assert.NoError(t, err)
	c := Connection{
		User: u,
		fs:   fs,
	}
	_, err = c.fs.ResolvePath("../upper_path")
	assert.Error(t, err, "tested path is not a home subdir")
}

func TestSFTPCmdTargetPath(t *testing.T) {
	u := dataprovider.User{}
	if runtime.GOOS == osWindows {
		u.HomeDir = "C:\\invalid_home"
	} else {
		u.HomeDir = "/invalid_home"
	}
	u.Username = "testuser"
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	fs, err := u.GetFilesystem("123")
	assert.NoError(t, err)
	connection := Connection{
		User: u,
		fs:   fs,
	}
	_, err = connection.getSFTPCmdTargetPath("invalid_path")
	assert.EqualError(t, err, sftp.ErrSSHFxNoSuchFile.Error())
}

func TestGetSFTPErrorFromOSError(t *testing.T) {
	err := os.ErrNotExist
	fs := vfs.NewOsFs("", os.TempDir(), nil)
	err = vfs.GetSFTPError(fs, err)
	assert.EqualError(t, err, sftp.ErrSSHFxNoSuchFile.Error())

	err = os.ErrPermission
	err = vfs.GetSFTPError(fs, err)
	assert.EqualError(t, err, sftp.ErrSSHFxPermissionDenied.Error())
	err = vfs.GetSFTPError(fs, nil)
	assert.NoError(t, err)
}

func TestSetstatModeIgnore(t *testing.T) {
	originalMode := setstatMode
	setstatMode = 1
	connection := Connection{}
	err := connection.handleSFTPSetstat("invalid", nil)
	assert.NoError(t, err)
	setstatMode = originalMode
}

func TestSFTPGetUsedQuota(t *testing.T) {
	u := dataprovider.User{}
	u.HomeDir = "home_rel_path"
	u.Username = "test_invalid_user"
	u.QuotaSize = 4096
	u.QuotaFiles = 1
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	connection := Connection{
		User: u,
	}
	assert.False(t, connection.hasSpace(false))
}

func TestSupportedSSHCommands(t *testing.T) {
	cmds := GetSupportedSSHCommands()
	assert.Equal(t, len(supportedSSHCommands), len(cmds))

	for _, c := range cmds {
		assert.True(t, utils.IsStringInSlice(c, supportedSSHCommands))
	}
}

func TestSSHCommandPath(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
	}
	connection := Connection{
		channel: &mockSSHChannel,
	}
	sshCommand := sshCommand{
		command:    "test",
		connection: connection,
		args:       []string{},
	}
	assert.Equal(t, "", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", "/tmp/../path"}
	assert.Equal(t, "/path", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", "/tmp/"}
	assert.Equal(t, "/tmp/", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", "tmp/"}
	assert.Equal(t, "/tmp/", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", "/tmp/../../../path"}
	assert.Equal(t, "/path", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", ".."}
	assert.Equal(t, "/", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", "."}
	assert.Equal(t, "/", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", "//"}
	assert.Equal(t, "/", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", "../.."}
	assert.Equal(t, "/", sshCommand.getDestPath())

	sshCommand.args = []string{"-t", "/.."}
	assert.Equal(t, "/", sshCommand.getDestPath())

	sshCommand.args = []string{"-f", "/a space.txt"}
	assert.Equal(t, "/a space.txt", sshCommand.getDestPath())
}

func TestSSHParseCommandPayload(t *testing.T) {
	cmd := "command -a  -f  /ab\\ à/some\\ spaces\\ \\ \\(\\).txt"
	name, args, _ := parseCommandPayload(cmd)
	assert.Equal(t, "command", name)
	assert.Equal(t, 3, len(args))
	assert.Equal(t, "/ab à/some spaces  ().txt", args[2])

	_, _, err := parseCommandPayload("")
	assert.Error(t, err, "parsing invalid command must fail")
}

func TestSSHCommandErrors(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
	}
	server, client := net.Pipe()
	defer func() {
		err := server.Close()
		assert.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()
	user := dataprovider.User{}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		User:    user,
		fs:      fs,
	}
	cmd := sshCommand{
		command:    "md5sum",
		connection: connection,
		args:       []string{},
	}
	err = cmd.handle()
	assert.Error(t, err, "ssh command must fail, we are sending a fake error")

	cmd = sshCommand{
		command:    "md5sum",
		connection: connection,
		args:       []string{"/../../test_file.dat"},
	}
	err = cmd.handle()
	assert.Error(t, err, "ssh command must fail, we are requesting an invalid path")

	cmd = sshCommand{
		command:    "git-receive-pack",
		connection: connection,
		args:       []string{"/../../testrepo"},
	}
	err = cmd.handle()
	assert.Error(t, err, "ssh command must fail, we are requesting an invalid path")

	cmd.connection.User.HomeDir = os.TempDir()
	cmd.connection.User.QuotaFiles = 1
	cmd.connection.User.UsedQuotaFiles = 2
	fs, err = cmd.connection.User.GetFilesystem("123")
	assert.NoError(t, err)
	cmd.connection.fs = fs
	err = cmd.handle()
	assert.EqualError(t, err, errQuotaExceeded.Error())

	cmd.connection.User.QuotaFiles = 0
	cmd.connection.User.UsedQuotaFiles = 0
	cmd.connection.User.Permissions = make(map[string][]string)
	cmd.connection.User.Permissions["/"] = []string{dataprovider.PermListItems}
	err = cmd.handle()
	assert.EqualError(t, err, errPermissionDenied.Error())

	cmd.connection.User.Permissions["/"] = []string{dataprovider.PermAny}
	cmd.command = "invalid_command"
	command, err := cmd.getSystemCommand()
	assert.NoError(t, err)

	err = cmd.executeSystemCommand(command)
	assert.Error(t, err, "invalid command must fail")

	command, err = cmd.getSystemCommand()
	assert.NoError(t, err)

	_, err = command.cmd.StderrPipe()
	assert.NoError(t, err)

	err = cmd.executeSystemCommand(command)
	assert.Error(t, err, "command must fail, pipe was already assigned")

	err = cmd.executeSystemCommand(command)
	assert.Error(t, err, "command must fail, pipe was already assigned")

	command, err = cmd.getSystemCommand()
	assert.NoError(t, err)

	_, err = command.cmd.StdoutPipe()
	assert.NoError(t, err)
	err = cmd.executeSystemCommand(command)
	assert.Error(t, err, "command must fail, pipe was already assigned")
}

func TestCommandsWithExtensionsFilter(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	user := dataprovider.User{
		Username: "test",
		HomeDir:  os.TempDir(),
		Status:   1,
	}
	user.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/subdir",
			AllowedExtensions: []string{".jpg"},
			DeniedExtensions:  []string{},
		},
	}

	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		User:    user,
		fs:      fs,
	}
	cmd := sshCommand{
		command:    "md5sum",
		connection: connection,
		args:       []string{"subdir/test.png"},
	}
	err = cmd.handleHashCommands()
	assert.EqualError(t, err, errPermissionDenied.Error())

	cmd = sshCommand{
		command:    "rsync",
		connection: connection,
		args:       []string{"--server", "-vlogDtprze.iLsfxC", ".", "/"},
	}
	_, err = cmd.getSystemCommand()
	assert.EqualError(t, err, errUnsupportedConfig.Error())

	cmd = sshCommand{
		command:    "git-receive-pack",
		connection: connection,
		args:       []string{"/subdir"},
	}
	_, err = cmd.getSystemCommand()
	assert.EqualError(t, err, errUnsupportedConfig.Error())

	cmd = sshCommand{
		command:    "git-receive-pack",
		connection: connection,
		args:       []string{"/subdir/dir"},
	}
	_, err = cmd.getSystemCommand()
	assert.EqualError(t, err, errUnsupportedConfig.Error())

	cmd = sshCommand{
		command:    "git-receive-pack",
		connection: connection,
		args:       []string{"/adir/subdir"},
	}
	_, err = cmd.getSystemCommand()
	assert.NoError(t, err)
}

func TestSSHCommandsRemoteFs(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
	}
	server, client := net.Pipe()
	defer func() {
		err := server.Close()
		assert.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()
	user := dataprovider.User{}
	user.FsConfig = dataprovider.Filesystem{
		Provider: 1,
		S3Config: vfs.S3FsConfig{
			Bucket:   "s3bucket",
			Endpoint: "endpoint",
			Region:   "eu-west-1",
		},
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		User:    user,
		fs:      fs,
	}
	cmd := sshCommand{
		command:    "md5sum",
		connection: connection,
		args:       []string{},
	}
	err = cmd.handleHashCommands()
	assert.Error(t, err, "command must fail for a non local filesystem")

	command, err := cmd.getSystemCommand()
	assert.NoError(t, err)

	err = cmd.executeSystemCommand(command)
	assert.Error(t, err, "command must fail for a non local filesystem")
}

func TestSSHCommandQuotaScan(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
	}
	server, client := net.Pipe()
	defer func() {
		err := server.Close()
		assert.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	user := dataprovider.User{
		Permissions: permissions,
		QuotaFiles:  1,
		HomeDir:     "invalid_path",
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		User:    user,
		fs:      fs,
	}
	cmd := sshCommand{
		command:    "git-receive-pack",
		connection: connection,
		args:       []string{"/testrepo"},
	}
	err = cmd.rescanHomeDir()
	assert.Error(t, err, "scanning an invalid home dir must fail")
}

func TestGitVirtualFolders(t *testing.T) {
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	user := dataprovider.User{
		Permissions: permissions,
		HomeDir:     os.TempDir(),
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	conn := Connection{
		User: user,
		fs:   fs,
	}
	cmd := sshCommand{
		command:    "git-receive-pack",
		connection: conn,
		args:       []string{"/vdir"},
	}
	cmd.connection.User.VirtualFolders = append(cmd.connection.User.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  os.TempDir(),
	})
	_, err = cmd.getSystemCommand()
	assert.EqualError(t, err, errUnsupportedConfig.Error())

	cmd.connection.User.VirtualFolders = nil
	cmd.connection.User.VirtualFolders = append(cmd.connection.User.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  os.TempDir(),
	})
	cmd.args = []string{"/vdir/subdir"}
	_, err = cmd.getSystemCommand()
	assert.EqualError(t, err, errUnsupportedConfig.Error())

	cmd.args = []string{"/adir/subdir"}
	_, err = cmd.getSystemCommand()
	assert.NoError(t, err)
}

func TestRsyncOptions(t *testing.T) {
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	user := dataprovider.User{
		Permissions: permissions,
		HomeDir:     os.TempDir(),
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	conn := Connection{
		User: user,
		fs:   fs,
	}
	sshCmd := sshCommand{
		command:    "rsync",
		connection: conn,
		args:       []string{"--server", "-vlogDtprze.iLsfxC", ".", "/"},
	}
	cmd, err := sshCmd.getSystemCommand()
	assert.NoError(t, err)
	assert.True(t, utils.IsStringInSlice("--safe-links", cmd.cmd.Args),
		"--safe-links must be added if the user has the create symlinks permission")

	permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermCreateDirs,
		dataprovider.PermListItems, dataprovider.PermOverwrite, dataprovider.PermDelete, dataprovider.PermRename}
	user.Permissions = permissions
	fs, err = user.GetFilesystem("123")
	assert.NoError(t, err)

	conn = Connection{
		User: user,
		fs:   fs,
	}
	sshCmd = sshCommand{
		command:    "rsync",
		connection: conn,
		args:       []string{"--server", "-vlogDtprze.iLsfxC", ".", "/"},
	}
	cmd, err = sshCmd.getSystemCommand()
	assert.NoError(t, err)
	assert.True(t, utils.IsStringInSlice("--munge-links", cmd.cmd.Args),
		"--munge-links must be added if the user has the create symlinks permission")

	sshCmd.connection.User.VirtualFolders = append(sshCmd.connection.User.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  os.TempDir(),
	})
	_, err = sshCmd.getSystemCommand()
	assert.EqualError(t, err, errUnsupportedConfig.Error())
}

func TestSystemCommandErrors(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	writeErr := fmt.Errorf("test write error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   writeErr,
	}
	server, client := net.Pipe()
	defer func() {
		err := server.Close()
		assert.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	user := dataprovider.User{
		Permissions: permissions,
		HomeDir:     os.TempDir(),
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		User:    user,
		fs:      fs,
	}
	sshCmd := sshCommand{
		command:    "ls",
		connection: connection,
		args:       []string{"/"},
	}
	systemCmd, err := sshCmd.getSystemCommand()
	assert.NoError(t, err)

	systemCmd.cmd.Dir = os.TempDir()
	// FIXME: the command completes but the fake client was unable to read the response
	// no error is reported in this case. We can see that the expected code is executed
	// reading the test coverage
	sshCmd.executeSystemCommand(systemCmd) //nolint:errcheck

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	sshCmd.connection.channel = &mockSSHChannel
	transfer := Transfer{
		transferType: transferDownload,
		lock:         new(sync.Mutex)}
	destBuff := make([]byte, 65535)
	dst := bytes.NewBuffer(destBuff)
	_, err = transfer.copyFromReaderToWriter(dst, sshCmd.connection.channel, 0)
	assert.EqualError(t, err, readErr.Error())

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	sshCmd.connection.channel = &mockSSHChannel
	_, err = transfer.copyFromReaderToWriter(dst, sshCmd.connection.channel, 1)
	assert.EqualError(t, err, errQuotaExceeded.Error())

	mockSSHChannel = MockChannel{
		Buffer:        bytes.NewBuffer(buf),
		StdErrBuffer:  bytes.NewBuffer(stdErrBuf),
		ReadError:     nil,
		WriteError:    nil,
		ShortWriteErr: true,
	}
	sshCmd.connection.channel = &mockSSHChannel
	_, err = transfer.copyFromReaderToWriter(sshCmd.connection.channel, dst, 0)
	assert.EqualError(t, err, io.ErrShortWrite.Error())
}

func TestTransferUpdateQuota(t *testing.T) {
	transfer := Transfer{
		transferType:  transferUpload,
		bytesReceived: 123,
		lock:          new(sync.Mutex)}
	transfer.TransferError(errors.New("fake error"))
	assert.False(t, transfer.updateQuota(1))
}

func TestGetConnectionInfo(t *testing.T) {
	c := ConnectionStatus{
		Username:      "test_user",
		ConnectionID:  "123",
		ClientVersion: "client",
		RemoteAddress: "127.0.0.1:1234",
		Protocol:      protocolSSH,
		SSHCommand:    "sha1sum /test_file.dat",
	}
	info := c.GetConnectionInfo()
	assert.Contains(t, info, "sha1sum /test_file.dat")
}

func TestSCPFileMode(t *testing.T) {
	mode := getFileModeAsString(0, true)
	assert.Equal(t, "0755", mode)

	mode = getFileModeAsString(0700, true)
	assert.Equal(t, "0700", mode)

	mode = getFileModeAsString(0750, true)
	assert.Equal(t, "0750", mode)

	mode = getFileModeAsString(0777, true)
	assert.Equal(t, "0777", mode)

	mode = getFileModeAsString(0640, false)
	assert.Equal(t, "0640", mode)

	mode = getFileModeAsString(0600, false)
	assert.Equal(t, "0600", mode)

	mode = getFileModeAsString(0, false)
	assert.Equal(t, "0644", mode)

	fileMode := uint32(0777)
	fileMode = fileMode | uint32(os.ModeSetgid)
	fileMode = fileMode | uint32(os.ModeSetuid)
	fileMode = fileMode | uint32(os.ModeSticky)
	mode = getFileModeAsString(os.FileMode(fileMode), false)
	assert.Equal(t, "7777", mode)

	fileMode = uint32(0644)
	fileMode = fileMode | uint32(os.ModeSetgid)
	mode = getFileModeAsString(os.FileMode(fileMode), false)
	assert.Equal(t, "4644", mode)

	fileMode = uint32(0600)
	fileMode = fileMode | uint32(os.ModeSetuid)
	mode = getFileModeAsString(os.FileMode(fileMode), false)
	assert.Equal(t, "2600", mode)

	fileMode = uint32(0044)
	fileMode = fileMode | uint32(os.ModeSticky)
	mode = getFileModeAsString(os.FileMode(fileMode), false)
	assert.Equal(t, "1044", mode)
}

func TestSCPParseUploadMessage(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
	}
	connection := Connection{
		channel: &mockSSHChannel,
		fs:      vfs.NewOsFs("", os.TempDir(), nil),
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-t", "/tmp"},
		},
	}
	_, _, err := scpCommand.parseUploadMessage("invalid")
	assert.Error(t, err, "parsing invalid upload message must fail")

	_, _, err = scpCommand.parseUploadMessage("D0755 0")
	assert.Error(t, err, "parsing incomplete upload message must fail")

	_, _, err = scpCommand.parseUploadMessage("D0755 invalidsize testdir")
	assert.Error(t, err, "parsing upload message with invalid size must fail")

	_, _, err = scpCommand.parseUploadMessage("D0755 0 ")
	assert.Error(t, err, "parsing upload message with invalid name must fail")
}

func TestSCPProtocolMessages(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	writeErr := fmt.Errorf("test write error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   writeErr,
	}
	connection := Connection{
		channel: &mockSSHChannel,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-t", "/tmp"},
		},
	}
	_, err := scpCommand.readProtocolMessage()
	assert.EqualError(t, err, readErr.Error())

	err = scpCommand.sendConfirmationMessage()
	assert.EqualError(t, err, writeErr.Error())

	err = scpCommand.sendProtocolMessage("E\n")
	assert.EqualError(t, err, writeErr.Error())

	_, err = scpCommand.getNextUploadProtocolMessage()
	assert.EqualError(t, err, readErr.Error())

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer([]byte("T1183832947 0 1183833773 0\n")),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   writeErr,
	}
	scpCommand.connection.channel = &mockSSHChannel
	_, err = scpCommand.getNextUploadProtocolMessage()
	assert.EqualError(t, err, writeErr.Error())

	respBuffer := []byte{0x02}
	protocolErrorMsg := "protocol error msg"
	respBuffer = append(respBuffer, protocolErrorMsg...)
	respBuffer = append(respBuffer, 0x0A)
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(respBuffer),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.readConfirmationMessage()
	if assert.Error(t, err) {
		assert.Equal(t, protocolErrorMsg, err.Error())
	}
}

func TestSCPTestDownloadProtocolMessages(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	writeErr := fmt.Errorf("test write error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   writeErr,
	}
	connection := Connection{
		channel: &mockSSHChannel,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-f", "-p", "/tmp"},
		},
	}
	path := "testDir"
	err := os.Mkdir(path, 0777)
	assert.NoError(t, err)
	stat, err := os.Stat(path)
	assert.NoError(t, err)
	err = scpCommand.sendDownloadProtocolMessages(path, stat)
	assert.EqualError(t, err, writeErr.Error())

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}

	err = scpCommand.sendDownloadProtocolMessages(path, stat)
	assert.EqualError(t, err, readErr.Error())

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   writeErr,
	}
	scpCommand.args = []string{"-f", "/tmp"}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.sendDownloadProtocolMessages(path, stat)
	assert.EqualError(t, err, writeErr.Error())

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.sendDownloadProtocolMessages(path, stat)
	assert.EqualError(t, err, readErr.Error())

	err = os.Remove(path)
	assert.NoError(t, err)
}

func TestSCPCommandHandleErrors(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	writeErr := fmt.Errorf("test write error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   writeErr,
	}
	server, client := net.Pipe()
	defer func() {
		err := server.Close()
		assert.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-f", "/tmp"},
		},
	}
	err := scpCommand.handle()
	assert.EqualError(t, err, readErr.Error())
	scpCommand.args = []string{"-i", "/tmp"}
	err = scpCommand.handle()
	assert.Error(t, err, "invalid scp command must fail")
}

func TestSCPErrorsMockFs(t *testing.T) {
	errFake := errors.New("fake error")
	fs := newMockOsFs(errFake, errFake, false, "1234", os.TempDir())
	u := dataprovider.User{}
	u.Username = "test"
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.HomeDir = os.TempDir()
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
	}
	server, client := net.Pipe()
	defer func() {
		err := server.Close()
		assert.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		fs:      fs,
		User:    u,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-t", "/tmp"},
		},
	}
	err := scpCommand.handleUpload("test", 0)
	assert.EqualError(t, err, errFake.Error())

	testfile := filepath.Join(u.HomeDir, "testfile")
	err = ioutil.WriteFile(testfile, []byte("test"), 0666)
	assert.NoError(t, err)
	stat, err := os.Stat(u.HomeDir)
	assert.NoError(t, err)
	err = scpCommand.handleRecursiveDownload(u.HomeDir, stat)
	assert.EqualError(t, err, errFake.Error())

	scpCommand.sshCommand.connection.fs = newMockOsFs(errFake, nil, true, "123", os.TempDir())
	err = scpCommand.handleUpload(filepath.Base(testfile), 0)
	assert.EqualError(t, err, errFake.Error())

	err = scpCommand.handleUploadFile(testfile, testfile, 0, false, 4, false)
	assert.NoError(t, err)
	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestSCPRecursiveDownloadErrors(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	writeErr := fmt.Errorf("test write error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   writeErr,
	}
	server, client := net.Pipe()
	defer func() {
		err := server.Close()
		assert.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		fs:      vfs.NewOsFs("123", os.TempDir(), nil),
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-f", "/tmp"},
		},
	}
	path := "testDir"
	err := os.Mkdir(path, 0777)
	assert.NoError(t, err)
	stat, err := os.Stat(path)
	assert.NoError(t, err)
	err = scpCommand.handleRecursiveDownload("invalid_dir", stat)
	assert.EqualError(t, err, writeErr.Error())

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.handleRecursiveDownload("invalid_dir", stat)
	assert.Error(t, err, "recursive upload download must fail for a non existing dir")

	err = os.Remove(path)
	assert.NoError(t, err)
}

func TestSCPRecursiveUploadErrors(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	writeErr := fmt.Errorf("test write error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   writeErr,
	}
	connection := Connection{
		channel: &mockSSHChannel,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-t", "/tmp"},
		},
	}
	err := scpCommand.handleRecursiveUpload()
	assert.Error(t, err, "recursive upload must fail, we send a fake error message")

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.handleRecursiveUpload()
	assert.Error(t, err, "recursive upload must fail, we send a fake error message")
}

func TestSCPCreateDirs(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	u := dataprovider.User{}
	u.HomeDir = "home_rel_path"
	u.Username = "test"
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	fs, err := u.GetFilesystem("123")
	assert.NoError(t, err)
	connection := Connection{
		User:    u,
		channel: &mockSSHChannel,
		fs:      fs,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-t", "/tmp"},
		},
	}
	err = scpCommand.handleCreateDir("invalid_dir")
	assert.Error(t, err, "create invalid dir must fail")
}

func TestSCPDownloadFileData(t *testing.T) {
	testfile := "testfile"
	buf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	writeErr := fmt.Errorf("test write error")
	stdErrBuf := make([]byte, 65535)
	mockSSHChannelReadErr := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	mockSSHChannelWriteErr := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   writeErr,
	}
	connection := Connection{
		channel: &mockSSHChannelReadErr,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-f", "/tmp"},
		},
	}
	err := ioutil.WriteFile(testfile, []byte("test"), 0666)
	assert.NoError(t, err)
	stat, err := os.Stat(testfile)
	assert.NoError(t, err)
	err = scpCommand.sendDownloadFileData(testfile, stat, nil)
	assert.EqualError(t, err, readErr.Error())

	scpCommand.connection.channel = &mockSSHChannelWriteErr
	err = scpCommand.sendDownloadFileData(testfile, stat, nil)
	assert.EqualError(t, err, writeErr.Error())

	scpCommand.args = []string{"-r", "-p", "-f", "/tmp"}
	err = scpCommand.sendDownloadFileData(testfile, stat, nil)
	assert.EqualError(t, err, writeErr.Error())

	scpCommand.connection.channel = &mockSSHChannelReadErr
	err = scpCommand.sendDownloadFileData(testfile, stat, nil)
	assert.EqualError(t, err, readErr.Error())

	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestSCPUploadFiledata(t *testing.T) {
	testfile := "testfile"
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	readErr := fmt.Errorf("test read error")
	writeErr := fmt.Errorf("test write error")
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   writeErr,
	}
	connection := Connection{
		User: dataprovider.User{
			Username: "testuser",
		},
		protocol: protocolSCP,
		channel:  &mockSSHChannel,
		fs:       vfs.NewOsFs("", os.TempDir(), nil),
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-t", "/tmp"},
		},
	}
	file, err := os.Create(testfile)
	assert.NoError(t, err)

	transfer := Transfer{
		file:           file,
		path:           file.Name(),
		start:          time.Now(),
		bytesSent:      0,
		bytesReceived:  0,
		user:           scpCommand.connection.User,
		connectionID:   "",
		transferType:   transferDownload,
		lastActivity:   time.Now(),
		isNewFile:      true,
		protocol:       connection.protocol,
		transferError:  nil,
		isFinished:     false,
		minWriteOffset: 0,
		lock:           new(sync.Mutex),
	}
	addTransfer(&transfer)
	err = scpCommand.getUploadFileData(2, &transfer)
	assert.Error(t, err, "upload must fail, we send a fake write error message")

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	file, err = os.Create(testfile)
	assert.NoError(t, err)
	transfer.file = file
	transfer.isFinished = false
	addTransfer(&transfer)
	err = scpCommand.getUploadFileData(2, &transfer)
	assert.Error(t, err, "upload must fail, we send a fake read error message")

	respBuffer := []byte("12")
	respBuffer = append(respBuffer, 0x02)
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(respBuffer),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	file, err = os.Create(testfile)
	assert.NoError(t, err)
	transfer.file = file
	transfer.isFinished = false
	addTransfer(&transfer)
	err = scpCommand.getUploadFileData(2, &transfer)
	assert.Error(t, err, "upload must fail, we have not enough data to read")

	// the file is already closed so we have an error on trasfer closing
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	addTransfer(&transfer)
	err = scpCommand.getUploadFileData(0, &transfer)
	assert.EqualError(t, err, errTransferClosed.Error())

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	addTransfer(&transfer)
	err = scpCommand.getUploadFileData(2, &transfer)
	assert.True(t, errors.Is(err, os.ErrClosed))

	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestUploadError(t *testing.T) {
	oldUploadMode := uploadMode
	uploadMode = uploadModeAtomic
	connection := Connection{
		User: dataprovider.User{
			Username: "testuser",
		},
		protocol: protocolSCP,
	}
	testfile := "testfile"
	fileTempName := "temptestfile"
	file, err := os.Create(fileTempName)
	assert.NoError(t, err)
	transfer := Transfer{
		file:           file,
		path:           testfile,
		start:          time.Now(),
		bytesSent:      0,
		bytesReceived:  100,
		user:           connection.User,
		connectionID:   "",
		transferType:   transferUpload,
		lastActivity:   time.Now(),
		isNewFile:      true,
		protocol:       connection.protocol,
		transferError:  nil,
		isFinished:     false,
		minWriteOffset: 0,
		lock:           new(sync.Mutex),
	}
	addTransfer(&transfer)
	errFake := errors.New("fake error")
	transfer.TransferError(errFake)
	err = transfer.Close()
	assert.EqualError(t, err, errFake.Error())
	assert.Equal(t, int64(0), transfer.bytesReceived)

	assert.NoFileExists(t, testfile)
	assert.NoFileExists(t, fileTempName)

	uploadMode = oldUploadMode
}

func TestConnectionStatusStruct(t *testing.T) {
	var transfers []connectionTransfer
	transferUL := connectionTransfer{
		OperationType: operationUpload,
		StartTime:     utils.GetTimeAsMsSinceEpoch(time.Now()),
		Size:          123,
		LastActivity:  utils.GetTimeAsMsSinceEpoch(time.Now()),
		Path:          "/test.upload",
	}
	transferDL := connectionTransfer{
		OperationType: operationDownload,
		StartTime:     utils.GetTimeAsMsSinceEpoch(time.Now()),
		Size:          123,
		LastActivity:  utils.GetTimeAsMsSinceEpoch(time.Now()),
		Path:          "/test.download",
	}
	transfers = append(transfers, transferUL)
	transfers = append(transfers, transferDL)
	c := ConnectionStatus{
		Username:       "test",
		ConnectionID:   "123",
		ClientVersion:  "fakeClient-1.0.0",
		RemoteAddress:  "127.0.0.1:1234",
		ConnectionTime: utils.GetTimeAsMsSinceEpoch(time.Now()),
		LastActivity:   utils.GetTimeAsMsSinceEpoch(time.Now()),
		Protocol:       "SFTP",
		Transfers:      transfers,
	}
	durationString := c.GetConnectionDuration()
	assert.NotEqual(t, 0, len(durationString))

	transfersString := c.GetTransfersAsString()
	assert.NotEqual(t, 0, len(transfersString))

	connInfo := c.GetConnectionInfo()
	assert.NotEqual(t, 0, len(connInfo))
}

func TestProxyProtocolVersion(t *testing.T) {
	c := Configuration{
		ProxyProtocol: 1,
	}
	proxyListener, err := c.getProxyListener(nil)
	assert.NoError(t, err)
	assert.Nil(t, proxyListener.Policy)

	c.ProxyProtocol = 2
	proxyListener, _ = c.getProxyListener(nil)
	assert.NoError(t, err)
	assert.NotNil(t, proxyListener.Policy)

	c.ProxyProtocol = 1
	c.ProxyAllowed = []string{"invalid"}
	_, err = c.getProxyListener(nil)
	assert.Error(t, err)

	c.ProxyProtocol = 2
	_, err = c.getProxyListener(nil)
	assert.Error(t, err)
}

func TestLoadHostKeys(t *testing.T) {
	c := Configuration{}
	c.HostKeys = []string{".", "missing file"}
	err := c.checkAndLoadHostKeys("..", &ssh.ServerConfig{})
	assert.Error(t, err)
	testfile := filepath.Join(os.TempDir(), "invalidkey")
	err = ioutil.WriteFile(testfile, []byte("some bytes"), 0666)
	assert.NoError(t, err)
	c.HostKeys = []string{testfile}
	err = c.checkAndLoadHostKeys("..", &ssh.ServerConfig{})
	assert.Error(t, err)
	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestCertCheckerInitErrors(t *testing.T) {
	c := Configuration{}
	c.TrustedUserCAKeys = []string{".", "missing file"}
	err := c.initializeCertChecker("")
	assert.Error(t, err)
	testfile := filepath.Join(os.TempDir(), "invalidkey")
	err = ioutil.WriteFile(testfile, []byte("some bytes"), 0666)
	assert.NoError(t, err)
	c.TrustedUserCAKeys = []string{testfile}
	err = c.initializeCertChecker("")
	assert.Error(t, err)
	err = os.Remove(testfile)
	assert.NoError(t, err)
}
