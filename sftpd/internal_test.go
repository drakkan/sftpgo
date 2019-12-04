package sftpd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/utils"
	"github.com/pkg/sftp"
)

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

func TestWrongActions(t *testing.T) {
	actionsCopy := actions
	badCommand := "/bad/command"
	if runtime.GOOS == "windows" {
		badCommand = "C:\\bad\\command"
	}
	actions = Actions{
		ExecuteOn:           []string{operationDownload},
		Command:             badCommand,
		HTTPNotificationURL: "",
	}
	err := executeAction(operationDownload, "username", "path", "", "")
	if err == nil {
		t.Errorf("action with bad command must fail")
	}
	err = executeAction(operationDelete, "username", "path", "", "")
	if err != nil {
		t.Errorf("action not configured must silently fail")
	}
	actions.Command = ""
	actions.HTTPNotificationURL = "http://foo\x7f.com/"
	err = executeAction(operationDownload, "username", "path", "", "")
	if err == nil {
		t.Errorf("action with bad url must fail")
	}
	actions = actionsCopy
}

func TestRemoveNonexistentTransfer(t *testing.T) {
	transfer := Transfer{}
	err := removeTransfer(&transfer)
	if err == nil {
		t.Errorf("remove nonexistent transfer must fail")
	}
}

func TestRemoveNonexistentQuotaScan(t *testing.T) {
	err := RemoveQuotaScan("username")
	if err == nil {
		t.Errorf("remove nonexistent transfer must fail")
	}
}

func TestGetOSOpenFlags(t *testing.T) {
	var flags sftp.FileOpenFlags
	flags.Write = true
	flags.Excl = true
	osFlags := getOSOpenFlags(flags)
	if osFlags&os.O_WRONLY == 0 || osFlags&os.O_EXCL == 0 {
		t.Errorf("error getting os flags from sftp file open flags")
	}
	flags.Append = true
	// append flag should be ignored to allow resume
	if osFlags&os.O_WRONLY == 0 || osFlags&os.O_EXCL == 0 {
		t.Errorf("error getting os flags from sftp file open flags")
	}
}

func TestUploadResumeInvalidOffset(t *testing.T) {
	testfile := "testfile"
	file, _ := os.Create(testfile)
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
	}
	_, err := transfer.WriteAt([]byte("test"), 0)
	if err == nil {
		t.Errorf("upload with invalid offset must fail")
	}
	os.Remove(testfile)
}

func TestUploadFiles(t *testing.T) {
	oldUploadMode := uploadMode
	uploadMode = uploadModeAtomic
	c := Connection{}
	var flags sftp.FileOpenFlags
	flags.Write = true
	flags.Trunc = true
	_, err := c.handleSFTPUploadToExistingFile(flags, "missing_path", "other_missing_path", 0)
	if err == nil {
		t.Errorf("upload to existing file must fail if one or both paths are invalid")
	}
	uploadMode = uploadModeStandard
	_, err = c.handleSFTPUploadToExistingFile(flags, "missing_path", "other_missing_path", 0)
	if err == nil {
		t.Errorf("upload to existing file must fail if one or both paths are invalid")
	}
	missingFile := "missing/relative/file.txt"
	if runtime.GOOS == "windows" {
		missingFile = "missing\\relative\\file.txt"
	}
	_, err = c.handleSFTPUploadToNewFile(".", missingFile)
	if err == nil {
		t.Errorf("upload new file in missing path must fail")
	}
	uploadMode = oldUploadMode
}

func TestWithInvalidHome(t *testing.T) {
	u := dataprovider.User{}
	u.HomeDir = "home_rel_path"
	_, err := loginUser(u, "password")
	if err == nil {
		t.Errorf("login a user with an invalid home_dir must fail")
	}
	c := Connection{
		User: u,
	}
	err = c.isSubDir("dir_rel_path")
	if err == nil {
		t.Errorf("tested path is not a home subdir")
	}
}

func TestSFTPCmdTargetPath(t *testing.T) {
	u := dataprovider.User{}
	u.HomeDir = "home_rel_path"
	u.Username = "test"
	u.Permissions = []string{"*"}
	connection := Connection{
		User: u,
	}
	_, err := connection.getSFTPCmdTargetPath("invalid_path")
	if err != sftp.ErrSSHFxNoSuchFile {
		t.Errorf("getSFTPCmdTargetPath must fal with the expected error: %v", err)
	}
}

func TestGetSFTPErrorFromOSError(t *testing.T) {
	err := os.ErrNotExist
	err = getSFTPErrorFromOSError(err)
	if err != sftp.ErrSSHFxNoSuchFile {
		t.Errorf("unexpected error: %v", err)
	}
	err = os.ErrPermission
	err = getSFTPErrorFromOSError(err)
	if err != sftp.ErrSSHFxPermissionDenied {
		t.Errorf("unexpected error: %v", err)
	}
	err = getSFTPErrorFromOSError(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSetstatModeIgnore(t *testing.T) {
	originalMode := setstatMode
	setstatMode = 1
	connection := Connection{}
	err := connection.handleSFTPSetstat("invalid", nil)
	if err != nil {
		t.Errorf("unexpected error: %v setstat should be silently ignore in mode 1", err)
	}
	setstatMode = 0
	req := sftp.NewRequest("Setstat", "invalid")
	err = connection.handleSFTPSetstat("invalid", req)
	if err != sftp.ErrSSHFxBadMessage {
		t.Errorf("unexpected error: %v", err)
	}
	setstatMode = originalMode
}

func TestSFTPGetUsedQuota(t *testing.T) {
	u := dataprovider.User{}
	u.HomeDir = "home_rel_path"
	u.Username = "test_invalid_user"
	u.QuotaSize = 4096
	u.QuotaFiles = 1
	u.Permissions = []string{"*"}
	connection := Connection{
		User: u,
	}
	res := connection.hasSpace(false)
	if res != false {
		t.Errorf("has space must return false if the user is invalid")
	}
}

func TestSupportedSSHCommands(t *testing.T) {
	cmds := GetSupportedSSHCommands()
	if len(cmds) != len(supportedSSHCommands) {
		t.Errorf("supported ssh commands does not match")
	}
	for _, c := range cmds {
		if !utils.IsStringInSlice(c, supportedSSHCommands) {
			t.Errorf("invalid ssh command: %v", c)
		}
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
	path := sshCommand.getDestPath()
	if path != "" {
		t.Errorf("path must be empty")
	}
	sshCommand.args = []string{"-t", "/tmp/../path"}
	path = sshCommand.getDestPath()
	if path != "/path" {
		t.Errorf("unexpected path: %v", path)
	}
	sshCommand.args = []string{"-t", "/tmp/"}
	path = sshCommand.getDestPath()
	if path != "/tmp/" {
		t.Errorf("unexpected path: %v", path)
	}
	sshCommand.args = []string{"-t", "tmp/"}
	path = sshCommand.getDestPath()
	if path != "/tmp/" {
		t.Errorf("unexpected path: %v", path)
	}
	sshCommand.args = []string{"-t", "/tmp/../../../path"}
	path = sshCommand.getDestPath()
	if path != "/path" {
		t.Errorf("unexpected path: %v", path)
	}
	sshCommand.args = []string{"-t", ".."}
	path = sshCommand.getDestPath()
	if path != "/" {
		t.Errorf("unexpected path: %v", path)
	}
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
	defer server.Close()
	defer client.Close()
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		User: dataprovider.User{
			Permissions: []string{dataprovider.PermAny},
		},
	}
	cmd := sshCommand{
		command:    "md5sum",
		connection: connection,
		args:       []string{},
	}
	err := cmd.handle()
	if err == nil {
		t.Errorf("ssh command must fail, we are sending a fake error")
	}
	cmd = sshCommand{
		command:    "md5sum",
		connection: connection,
		args:       []string{"/../../test_file.dat"},
	}
	err = cmd.handle()
	if err == nil {
		t.Errorf("ssh command must fail, we are requesting an invalid path")
	}
	cmd = sshCommand{
		command:    "git-receive-pack",
		connection: connection,
		args:       []string{"/../../testrepo"},
	}
	err = cmd.handle()
	if err == nil {
		t.Errorf("ssh command must fail, we are requesting an invalid path")
	}
	cmd.connection.User.HomeDir = os.TempDir()
	cmd.connection.User.QuotaFiles = 1
	cmd.connection.User.UsedQuotaFiles = 2
	err = cmd.handle()
	if err != errQuotaExceeded {
		t.Errorf("unexpected error: %v", err)
	}
	cmd.connection.User.QuotaFiles = 0
	cmd.connection.User.UsedQuotaFiles = 0
	cmd.connection.User.Permissions = []string{dataprovider.PermListItems}
	err = cmd.handle()
	if err != errPermissionDenied {
		t.Errorf("unexpected error: %v", err)
	}
	cmd.connection.User.Permissions = []string{dataprovider.PermAny}
	cmd.command = "invalid_command"
	command, err := cmd.getSystemCommand()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	err = cmd.executeSystemCommand(command)
	if err == nil {
		t.Errorf("invalid command must fail")
	}
	command, err = cmd.getSystemCommand()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	command.cmd.StderrPipe()
	err = cmd.executeSystemCommand(command)
	if err == nil {
		t.Errorf("command must fail, pipe was already assigned")
	}
	err = cmd.executeSystemCommand(command)
	if err == nil {
		t.Errorf("command must fail, pipe was already assigned")
	}
	command, err = cmd.getSystemCommand()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	command.cmd.StdoutPipe()
	err = cmd.executeSystemCommand(command)
	if err == nil {
		t.Errorf("command must fail, pipe was already assigned")
	}
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
	defer server.Close()
	defer client.Close()
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		User: dataprovider.User{
			Permissions: []string{dataprovider.PermAny},
			QuotaFiles:  1,
			HomeDir:     "invalid_path",
		},
	}
	cmd := sshCommand{
		command:    "git-receive-pack",
		connection: connection,
		args:       []string{"/testrepo"},
	}
	err := cmd.rescanHomeDir()
	if err == nil {
		t.Errorf("scanning an invalid home dir must fail")
	}
}

func TestRsyncOptions(t *testing.T) {
	conn := Connection{
		User: dataprovider.User{
			Permissions: []string{dataprovider.PermAny},
			HomeDir:     os.TempDir(),
		},
	}
	sshCmd := sshCommand{
		command:    "rsync",
		connection: conn,
		args:       []string{"--server", "-vlogDtprze.iLsfxC", ".", "/"},
	}
	cmd, err := sshCmd.getSystemCommand()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !utils.IsStringInSlice("--safe-links", cmd.cmd.Args) {
		t.Errorf("--safe-links must be added if the user has the create symlinks permission")
	}
	conn = Connection{
		User: dataprovider.User{
			Permissions: []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermCreateDirs,
				dataprovider.PermListItems, dataprovider.PermOverwrite, dataprovider.PermDelete, dataprovider.PermRename},
			HomeDir: os.TempDir(),
		},
	}
	sshCmd = sshCommand{
		command:    "rsync",
		connection: conn,
		args:       []string{"--server", "-vlogDtprze.iLsfxC", ".", "/"},
	}
	cmd, err = sshCmd.getSystemCommand()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !utils.IsStringInSlice("--munge-links", cmd.cmd.Args) {
		t.Errorf("--munge-links must be added if the user has the create symlinks permission")
	}
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
	defer server.Close()
	defer client.Close()
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
		User: dataprovider.User{
			Permissions: []string{dataprovider.PermAny},
			HomeDir:     os.TempDir(),
		},
	}
	sshCmd := sshCommand{
		command:    "ls",
		connection: connection,
		args:       []string{},
	}
	systemCmd, err := sshCmd.getSystemCommand()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	systemCmd.cmd.Dir = os.TempDir()
	// FIXME: the command completes but the fake client was unable to read the response
	// no error is reported in this case
	sshCmd.executeSystemCommand(systemCmd)

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	sshCmd.connection.channel = &mockSSHChannel
	transfer := Transfer{transferType: transferDownload}
	destBuff := make([]byte, 65535)
	dst := bytes.NewBuffer(destBuff)
	_, err = transfer.copyFromReaderToWriter(dst, sshCmd.connection.channel, 0)
	if err != readErr {
		t.Errorf("unexpected error: %v", err)
	}

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	sshCmd.connection.channel = &mockSSHChannel
	_, err = transfer.copyFromReaderToWriter(dst, sshCmd.connection.channel, 1)
	if err != errQuotaExceeded {
		t.Errorf("unexpected error: %v", err)
	}

	mockSSHChannel = MockChannel{
		Buffer:        bytes.NewBuffer(buf),
		StdErrBuffer:  bytes.NewBuffer(stdErrBuf),
		ReadError:     nil,
		WriteError:    nil,
		ShortWriteErr: true,
	}
	sshCmd.connection.channel = &mockSSHChannel
	_, err = transfer.copyFromReaderToWriter(sshCmd.connection.channel, dst, 0)
	if err != io.ErrShortWrite {
		t.Errorf("unexpected error: %v", err)
	}
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
	if !strings.Contains(info, "sha1sum /test_file.dat") {
		t.Errorf("ssh command not found in connection info")
	}
}

func TestSCPFileMode(t *testing.T) {
	mode := getFileModeAsString(0, true)
	if mode != "0755" {
		t.Errorf("invalid file mode: %v expected: 0755", mode)
	}
	mode = getFileModeAsString(0700, true)
	if mode != "0700" {
		t.Errorf("invalid file mode: %v expected: 0700", mode)
	}
	mode = getFileModeAsString(0750, true)
	if mode != "0750" {
		t.Errorf("invalid file mode: %v expected: 0750", mode)
	}
	mode = getFileModeAsString(0777, true)
	if mode != "0777" {
		t.Errorf("invalid file mode: %v expected: 0777", mode)
	}
	mode = getFileModeAsString(0640, false)
	if mode != "0640" {
		t.Errorf("invalid file mode: %v expected: 0640", mode)
	}
	mode = getFileModeAsString(0600, false)
	if mode != "0600" {
		t.Errorf("invalid file mode: %v expected: 0600", mode)
	}
	mode = getFileModeAsString(0, false)
	if mode != "0644" {
		t.Errorf("invalid file mode: %v expected: 0644", mode)
	}
	fileMode := uint32(0777)
	fileMode = fileMode | uint32(os.ModeSetgid)
	fileMode = fileMode | uint32(os.ModeSetuid)
	fileMode = fileMode | uint32(os.ModeSticky)
	mode = getFileModeAsString(os.FileMode(fileMode), false)
	if mode != "7777" {
		t.Errorf("invalid file mode: %v expected: 7777", mode)
	}
	fileMode = uint32(0644)
	fileMode = fileMode | uint32(os.ModeSetgid)
	mode = getFileModeAsString(os.FileMode(fileMode), false)
	if mode != "4644" {
		t.Errorf("invalid file mode: %v expected: 4644", mode)
	}
	fileMode = uint32(0600)
	fileMode = fileMode | uint32(os.ModeSetuid)
	mode = getFileModeAsString(os.FileMode(fileMode), false)
	if mode != "2600" {
		t.Errorf("invalid file mode: %v expected: 2600", mode)
	}
	fileMode = uint32(0044)
	fileMode = fileMode | uint32(os.ModeSticky)
	mode = getFileModeAsString(os.FileMode(fileMode), false)
	if mode != "1044" {
		t.Errorf("invalid file mode: %v expected: 1044", mode)
	}
}

func TestSCPGetNonExistingDirContent(t *testing.T) {
	_, err := getDirContents("non_existing")
	if err == nil {
		t.Errorf("get non existing dir contents must fail")
	}
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
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-t", "/tmp"},
		},
	}
	_, _, err := scpCommand.parseUploadMessage("invalid")
	if err == nil {
		t.Errorf("parsing invalid upload message must fail")
	}
	_, _, err = scpCommand.parseUploadMessage("D0755 0")
	if err == nil {
		t.Errorf("parsing incomplete upload message must fail")
	}
	_, _, err = scpCommand.parseUploadMessage("D0755 invalidsize testdir")
	if err == nil {
		t.Errorf("parsing upload message with invalid size must fail")
	}
	_, _, err = scpCommand.parseUploadMessage("D0755 0 ")
	if err == nil {
		t.Errorf("parsing upload message with invalid name must fail")
	}
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
	if err == nil || err != readErr {
		t.Errorf("read protocol message must fail, we are sending a fake error")
	}
	err = scpCommand.sendConfirmationMessage()
	if err != writeErr {
		t.Errorf("write confirmation message must fail, we are sending a fake error")
	}
	err = scpCommand.sendProtocolMessage("E\n")
	if err != writeErr {
		t.Errorf("write confirmation message must fail, we are sending a fake error")
	}
	_, err = scpCommand.getNextUploadProtocolMessage()
	if err == nil || err != readErr {
		t.Errorf("read next upload protocol message must fail, we are sending a fake read error")
	}
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer([]byte("T1183832947 0 1183833773 0\n")),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   writeErr,
	}
	scpCommand.connection.channel = &mockSSHChannel
	_, err = scpCommand.getNextUploadProtocolMessage()
	if err == nil || err != writeErr {
		t.Errorf("read next upload protocol message must fail, we are sending a fake write error")
	}
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
	if err == nil || err.Error() != protocolErrorMsg {
		t.Errorf("read confirmation message must return the expected protocol error, actual err: %v", err)
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
	os.Mkdir(path, 0777)
	stat, _ := os.Stat(path)
	err := scpCommand.sendDownloadProtocolMessages(path, stat)
	if err != writeErr {
		t.Errorf("sendDownloadProtocolMessages must return the expected error: %v", err)
	}

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}

	err = scpCommand.sendDownloadProtocolMessages(path, stat)
	if err != readErr {
		t.Errorf("sendDownloadProtocolMessages must return the expected error: %v", err)
	}

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   writeErr,
	}
	scpCommand.args = []string{"-f", "/tmp"}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.sendDownloadProtocolMessages(path, stat)
	if err != writeErr {
		t.Errorf("sendDownloadProtocolMessages must return the expected error: %v", err)
	}

	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.sendDownloadProtocolMessages(path, stat)
	if err != readErr {
		t.Errorf("sendDownloadProtocolMessages must return the expected error: %v", err)
	}
	os.Remove(path)
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
	defer server.Close()
	defer client.Close()
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
	if err == nil || err != readErr {
		t.Errorf("scp download must fail, we are sending a fake error")
	}
	scpCommand.args = []string{"-i", "/tmp"}
	err = scpCommand.handle()
	if err == nil {
		t.Errorf("invalid scp command must fail")
	}
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
	defer server.Close()
	defer client.Close()
	connection := Connection{
		channel: &mockSSHChannel,
		netConn: client,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-f", "/tmp"},
		},
	}
	path := "testDir"
	os.Mkdir(path, 0777)
	stat, _ := os.Stat(path)
	err := scpCommand.handleRecursiveDownload("invalid_dir", stat)
	if err != writeErr {
		t.Errorf("recursive upload download must fail with the expected error: %v", err)
	}
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.handleRecursiveDownload("invalid_dir", stat)
	if err == nil {
		t.Errorf("recursive upload download must fail for a non existing dir")
	}

	os.Remove(path)
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
	if err == nil {
		t.Errorf("recursive upload must fail, we send a fake error message")
	}
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	err = scpCommand.handleRecursiveUpload()
	if err == nil {
		t.Errorf("recursive upload must fail, we send a fake error message")
	}
}

func TestSCPCreateDirs(t *testing.T) {
	buf := make([]byte, 65535)
	stdErrBuf := make([]byte, 65535)
	u := dataprovider.User{}
	u.HomeDir = "home_rel_path"
	u.Username = "test"
	u.Permissions = []string{"*"}
	mockSSHChannel := MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	connection := Connection{
		User:    u,
		channel: &mockSSHChannel,
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-t", "/tmp"},
		},
	}
	err := scpCommand.handleCreateDir("invalid_dir")
	if err == nil {
		t.Errorf("create invalid dir must fail")
	}
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
	ioutil.WriteFile(testfile, []byte("test"), 0666)
	stat, _ := os.Stat(testfile)
	err := scpCommand.sendDownloadFileData(testfile, stat, nil)
	if err != readErr {
		t.Errorf("send download file data must fail with the expected error: %v", err)
	}
	scpCommand.connection.channel = &mockSSHChannelWriteErr
	err = scpCommand.sendDownloadFileData(testfile, stat, nil)
	if err != writeErr {
		t.Errorf("send download file data must fail with the expected error: %v", err)
	}
	scpCommand.args = []string{"-r", "-p", "-f", "/tmp"}
	err = scpCommand.sendDownloadFileData(testfile, stat, nil)
	if err != writeErr {
		t.Errorf("send download file data must fail with the expected error: %v", err)
	}
	scpCommand.connection.channel = &mockSSHChannelReadErr
	err = scpCommand.sendDownloadFileData(testfile, stat, nil)
	if err != readErr {
		t.Errorf("send download file data must fail with the expected error: %v", err)
	}
	os.Remove(testfile)
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
	}
	scpCommand := scpCommand{
		sshCommand: sshCommand{
			command:    "scp",
			connection: connection,
			args:       []string{"-r", "-t", "/tmp"},
		},
	}
	file, _ := os.Create(testfile)
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
	}
	addTransfer(&transfer)
	err := scpCommand.getUploadFileData(2, &transfer)
	if err == nil {
		t.Errorf("upload must fail, we send a fake write error message")
	}
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    readErr,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	file, _ = os.Create(testfile)
	transfer.file = file
	addTransfer(&transfer)
	err = scpCommand.getUploadFileData(2, &transfer)
	if err == nil {
		t.Errorf("upload must fail, we send a fake read error message")
	}

	respBuffer := []byte("12")
	respBuffer = append(respBuffer, 0x02)
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(respBuffer),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	scpCommand.connection.channel = &mockSSHChannel
	file, _ = os.Create(testfile)
	transfer.file = file
	addTransfer(&transfer)
	err = scpCommand.getUploadFileData(2, &transfer)
	if err == nil {
		t.Errorf("upload must fail, we have not enough data to read")
	}

	// the file is already closed so we have an error on trasfer closing
	mockSSHChannel = MockChannel{
		Buffer:       bytes.NewBuffer(buf),
		StdErrBuffer: bytes.NewBuffer(stdErrBuf),
		ReadError:    nil,
		WriteError:   nil,
	}
	addTransfer(&transfer)
	err = scpCommand.getUploadFileData(0, &transfer)
	if err == nil {
		t.Errorf("upload must fail, the file is closed")
	}
	os.Remove(testfile)
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
	file, _ := os.Create(fileTempName)
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
	}
	addTransfer(&transfer)
	transfer.TransferError(fmt.Errorf("fake error"))
	transfer.Close()
	if transfer.bytesReceived > 0 {
		t.Errorf("byte sent should be 0 for a failed transfer: %v", transfer.bytesSent)
	}
	_, err := os.Stat(testfile)
	if !os.IsNotExist(err) {
		t.Errorf("file uploaded must be deleted after an error: %v", err)
	}
	_, err = os.Stat(fileTempName)
	if !os.IsNotExist(err) {
		t.Errorf("file uploaded must be deleted after an error: %v", err)
	}
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
	if len(durationString) == 0 {
		t.Errorf("error getting connection duration")
	}
	transfersString := c.GetTransfersAsString()
	if len(transfersString) == 0 {
		t.Errorf("error getting transfers as string")
	}
	connInfo := c.GetConnectionInfo()
	if len(connInfo) == 0 {
		t.Errorf("error getting connection info")
	}
}

func TestSFTPExtensions(t *testing.T) {
	initialSFTPExtensions := sftpExtensions
	c := Configuration{}
	err := c.configureSFTPExtensions()
	if err != nil {
		t.Errorf("error configuring SFTP extensions")
	}
	sftpExtensions = append(sftpExtensions, "invalid@example.com")
	err = c.configureSFTPExtensions()
	if err == nil {
		t.Errorf("configuring invalid SFTP extensions must fail")
	}
	sftpExtensions = initialSFTPExtensions
}

func TestWrapCmd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executing a command as another uid/gid is not supported on Windows")
	}
	cmd := exec.Command("ls")
	cmd = wrapCmd(cmd, 1000, 1001)
	if cmd.SysProcAttr.Credential.Uid != 1000 {
		t.Errorf("unexpected uid")
	}
	if cmd.SysProcAttr.Credential.Gid != 1001 {
		t.Errorf("unexpected gid")
	}
}
