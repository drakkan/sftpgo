package common

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/lithammer/shortuuid/v3"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"github.com/sftpgo/sdk/plugin/notifier"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/vfs"
)

func TestNewActionNotification(t *testing.T) {
	user := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "username",
		},
	}
	user.FsConfig.Provider = sdk.LocalFilesystemProvider
	user.FsConfig.S3Config = vfs.S3FsConfig{
		BaseS3FsConfig: sdk.BaseS3FsConfig{
			Bucket:   "s3bucket",
			Endpoint: "endpoint",
		},
	}
	user.FsConfig.GCSConfig = vfs.GCSFsConfig{
		BaseGCSFsConfig: sdk.BaseGCSFsConfig{
			Bucket: "gcsbucket",
		},
	}
	user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{
		BaseAzBlobFsConfig: sdk.BaseAzBlobFsConfig{
			Container: "azcontainer",
			Endpoint:  "azendpoint",
		},
	}
	user.FsConfig.SFTPConfig = vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: "sftpendpoint",
		},
	}
	sessionID := xid.New().String()
	a := newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "", sessionID,
		123, 0, errors.New("fake error"))
	assert.Equal(t, user.Username, a.Username)
	assert.Equal(t, 0, len(a.Bucket))
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 2, a.Status)

	user.FsConfig.Provider = sdk.S3FilesystemProvider
	a = newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSSH, "", sessionID,
		123, 0, nil)
	assert.Equal(t, "s3bucket", a.Bucket)
	assert.Equal(t, "endpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	user.FsConfig.Provider = sdk.GCSFilesystemProvider
	a = newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, 0, ErrQuotaExceeded)
	assert.Equal(t, "gcsbucket", a.Bucket)
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 3, a.Status)

	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	a = newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, 0, nil)
	assert.Equal(t, "azcontainer", a.Bucket)
	assert.Equal(t, "azendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	a = newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, os.O_APPEND, nil)
	assert.Equal(t, "azcontainer", a.Bucket)
	assert.Equal(t, "azendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)
	assert.Equal(t, os.O_APPEND, a.OpenFlags)

	user.FsConfig.Provider = sdk.SFTPFilesystemProvider
	a = newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "", sessionID,
		123, 0, nil)
	assert.Equal(t, "sftpendpoint", a.Endpoint)
}

func TestActionHTTP(t *testing.T) {
	actionsCopy := Config.Actions

	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationDownload},
		Hook:      fmt.Sprintf("http://%v", httpAddr),
	}
	user := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "username",
		},
	}
	a := newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "",
		xid.New().String(), 123, 0, nil)
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
		BaseUser: sdk.BaseUser{
			Username: "username",
		},
	}
	sessionID := shortuuid.New()
	a := newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "", sessionID,
		123, 0, nil)
	err = actionHandler.Handle(a)
	assert.NoError(t, err)

	c := NewBaseConnection("id", ProtocolSFTP, "", "", *user)
	ExecuteActionNotification(c, OperationSSHCmd, "path", "vpath", "target", "vtarget", "sha1sum", 0, nil)

	ExecuteActionNotification(c, operationDownload, "path", "vpath", "", "", "", 0, nil)

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
		BaseUser: sdk.BaseUser{
			Username: "username",
		},
	}

	a := newActionNotification(user, operationUpload, "", "", "", "", "", ProtocolSFTP, "", xid.New().String(),
		123, 0, nil)
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
		BaseUser: sdk.BaseUser{
			Username: "username",
			HomeDir:  homeDir,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("id", homeDir, "")
	c := NewBaseConnection("id", ProtocolSFTP, "", "", user)

	testfile := filepath.Join(user.HomeDir, "testfile")
	err = os.WriteFile(testfile, []byte("test"), os.ModePerm)
	assert.NoError(t, err)
	info, err := os.Stat(testfile)
	assert.NoError(t, err)
	err = c.RemoveFile(fs, testfile, "testfile", info)
	assert.NoError(t, err)
	assert.FileExists(t, testfile)

	os.RemoveAll(homeDir)

	Config.Actions = actionsCopy
}

func TestUnconfiguredHook(t *testing.T) {
	actionsCopy := Config.Actions

	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationDownload},
		Hook:      "",
	}
	pluginsConfig := []plugin.Config{
		{
			Type: "notifier",
		},
	}
	err := plugin.Initialize(pluginsConfig, true)
	assert.Error(t, err)
	assert.True(t, plugin.Handler.HasNotifiers())

	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{})
	err = ExecutePreAction(c, OperationPreDownload, "", "", 0, 0)
	assert.NoError(t, err)
	err = ExecutePreAction(c, operationPreDelete, "", "", 0, 0)
	assert.ErrorIs(t, err, errUnconfiguredAction)

	ExecuteActionNotification(c, operationDownload, "", "", "", "", "", 0, nil)

	err = plugin.Initialize(nil, true)
	assert.NoError(t, err)
	assert.False(t, plugin.Handler.HasNotifiers())

	Config.Actions = actionsCopy
}

type actionHandlerStub struct {
	called bool
}

func (h *actionHandlerStub) Handle(event *notifier.FsEvent) error {
	h.called = true

	return nil
}

func TestInitializeActionHandler(t *testing.T) {
	handler := &actionHandlerStub{}

	InitializeActionHandler(handler)
	t.Cleanup(func() {
		InitializeActionHandler(&defaultActionHandler{})
	})

	err := actionHandler.Handle(&notifier.FsEvent{})

	assert.NoError(t, err)
	assert.True(t, handler.called)
}
