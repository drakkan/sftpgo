package common

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/vfs"
)

func TestNewActionNotification(t *testing.T) {
	user := &dataprovider.User{
		Username: "username",
	}
	user.FsConfig.Provider = dataprovider.LocalFilesystemProvider
	user.FsConfig.S3Config = vfs.S3FsConfig{
		Bucket:   "s3bucket",
		Endpoint: "endpoint",
	}
	user.FsConfig.GCSConfig = vfs.GCSFsConfig{
		Bucket: "gcsbucket",
	}
	user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{
		Container: "azcontainer",
		SASURL:    "azsasurl",
		Endpoint:  "azendpoint",
	}
	a := newActionNotification(user, operationDownload, "path", "target", "", ProtocolSFTP, 123, errors.New("fake error"))
	assert.Equal(t, user.Username, a.Username)
	assert.Equal(t, 0, len(a.Bucket))
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 0, a.Status)

	user.FsConfig.Provider = dataprovider.S3FilesystemProvider
	a = newActionNotification(user, operationDownload, "path", "target", "", ProtocolSSH, 123, nil)
	assert.Equal(t, "s3bucket", a.Bucket)
	assert.Equal(t, "endpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	user.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	a = newActionNotification(user, operationDownload, "path", "target", "", ProtocolSCP, 123, ErrQuotaExceeded)
	assert.Equal(t, "gcsbucket", a.Bucket)
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 2, a.Status)

	user.FsConfig.Provider = dataprovider.AzureBlobFilesystemProvider
	a = newActionNotification(user, operationDownload, "path", "target", "", ProtocolSCP, 123, nil)
	assert.Equal(t, "azcontainer", a.Bucket)
	assert.Equal(t, "azsasurl", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	user.FsConfig.AzBlobConfig.SASURL = ""
	a = newActionNotification(user, operationDownload, "path", "target", "", ProtocolSCP, 123, nil)
	assert.Equal(t, "azcontainer", a.Bucket)
	assert.Equal(t, "azendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)
}

func TestActionHTTP(t *testing.T) {
	actionsCopy := Config.Actions

	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationDownload},
		Hook:      fmt.Sprintf("http://%v", httpAddr),
	}
	user := &dataprovider.User{
		Username: "username",
	}
	a := newActionNotification(user, operationDownload, "path", "target", "", ProtocolSFTP, 123, nil)
	err := actionHandler.Handle(a)
	assert.NoError(t, err)

	Config.Actions.Hook = "http://invalid:1234"
	err = actionHandler.Handle(a)
	assert.Error(t, err)

	Config.Actions.Hook = fmt.Sprintf("http://%v/404", httpAddr)
	err = actionHandler.Handle(a)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errUnexpectedHTTResponse.Error())
	}

	Config.Actions = actionsCopy
}

func TestActionCMD(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	actionsCopy := Config.Actions

	hookCmd, err := exec.LookPath("true")
	assert.NoError(t, err)

	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationDownload},
		Hook:      hookCmd,
	}
	user := &dataprovider.User{
		Username: "username",
	}
	a := newActionNotification(user, operationDownload, "path", "target", "", ProtocolSFTP, 123, nil)
	err = actionHandler.Handle(a)
	assert.NoError(t, err)

	SSHCommandActionNotification(user, "path", "target", "sha1sum", nil)

	Config.Actions = actionsCopy
}

func TestWrongActions(t *testing.T) {
	actionsCopy := Config.Actions

	badCommand := "/bad/command"
	if runtime.GOOS == osWindows {
		badCommand = "C:\\bad\\command"
	}
	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationUpload},
		Hook:      badCommand,
	}
	user := &dataprovider.User{
		Username: "username",
	}

	a := newActionNotification(user, operationUpload, "", "", "", ProtocolSFTP, 123, nil)
	err := actionHandler.Handle(a)
	assert.Error(t, err, "action with bad command must fail")

	a.Action = operationDelete
	err = actionHandler.Handle(a)
	assert.EqualError(t, err, errUnconfiguredAction.Error())

	Config.Actions.Hook = "http://foo\x7f.com/"
	a.Action = operationUpload
	err = actionHandler.Handle(a)
	assert.Error(t, err, "action with bad url must fail")

	Config.Actions.Hook = ""
	err = actionHandler.Handle(a)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errNoHook.Error())
	}

	Config.Actions.Hook = "relative path"
	err = actionHandler.Handle(a)
	if assert.Error(t, err) {
		assert.EqualError(t, err, fmt.Sprintf("invalid notification command %#v", Config.Actions.Hook))
	}

	Config.Actions = actionsCopy
}

func TestPreDeleteAction(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	actionsCopy := Config.Actions

	hookCmd, err := exec.LookPath("true")
	assert.NoError(t, err)
	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationPreDelete},
		Hook:      hookCmd,
	}
	homeDir := filepath.Join(os.TempDir(), "test_user")
	err = os.MkdirAll(homeDir, os.ModePerm)
	assert.NoError(t, err)
	user := dataprovider.User{
		Username: "username",
		HomeDir:  homeDir,
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("id", homeDir, nil)
	c := NewBaseConnection("id", ProtocolSFTP, user, fs)

	testfile := filepath.Join(user.HomeDir, "testfile")
	err = ioutil.WriteFile(testfile, []byte("test"), os.ModePerm)
	assert.NoError(t, err)
	info, err := os.Stat(testfile)
	assert.NoError(t, err)
	err = c.RemoveFile(testfile, "testfile", info)
	assert.NoError(t, err)
	assert.FileExists(t, testfile)

	os.RemoveAll(homeDir)

	Config.Actions = actionsCopy
}

type actionHandlerStub struct {
	called bool
}

func (h *actionHandlerStub) Handle(notification *ActionNotification) error {
	h.called = true

	return nil
}

func TestInitializeActionHandler(t *testing.T) {
	handler := &actionHandlerStub{}

	InitializeActionHandler(handler)
	t.Cleanup(func() {
		InitializeActionHandler(&defaultActionHandler{})
	})

	err := actionHandler.Handle(&ActionNotification{})

	assert.NoError(t, err)
	assert.True(t, handler.called)
}
