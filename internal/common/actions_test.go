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

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func TestNewActionNotification(t *testing.T) {
	user := dataprovider.User{
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
	user.FsConfig.HTTPConfig = vfs.HTTPFsConfig{
		BaseHTTPFsConfig: sdk.BaseHTTPFsConfig{
			Endpoint: "httpendpoint",
		},
	}
	c := NewBaseConnection("id", ProtocolSSH, "", "", user)
	sessionID := xid.New().String()
	a := newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "", sessionID,
		123, 0, c.getNotificationStatus(errors.New("fake error")), 0, nil)
	assert.Equal(t, user.Username, a.Username)
	assert.Equal(t, 0, len(a.Bucket))
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 2, a.Status)

	user.FsConfig.Provider = sdk.S3FilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSSH, "", sessionID,
		123, 0, c.getNotificationStatus(nil), 0, nil)
	assert.Equal(t, "s3bucket", a.Bucket)
	assert.Equal(t, "endpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	user.FsConfig.Provider = sdk.GCSFilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, 0, c.getNotificationStatus(ErrQuotaExceeded), 0, nil)
	assert.Equal(t, "gcsbucket", a.Bucket)
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 3, a.Status)
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, 0, c.getNotificationStatus(fmt.Errorf("wrapper quota error: %w", ErrQuotaExceeded)), 0, nil)
	assert.Equal(t, "gcsbucket", a.Bucket)
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 3, a.Status)

	user.FsConfig.Provider = sdk.HTTPFilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSSH, "", sessionID,
		123, 0, c.getNotificationStatus(nil), 0, nil)
	assert.Equal(t, "httpendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, 0, c.getNotificationStatus(nil), 0, nil)
	assert.Equal(t, "azcontainer", a.Bucket)
	assert.Equal(t, "azendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, os.O_APPEND, c.getNotificationStatus(nil), 0, nil)
	assert.Equal(t, "azcontainer", a.Bucket)
	assert.Equal(t, "azendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)
	assert.Equal(t, os.O_APPEND, a.OpenFlags)

	user.FsConfig.Provider = sdk.SFTPFilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "", sessionID,
		123, 0, c.getNotificationStatus(nil), 0, nil)
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
		xid.New().String(), 123, 0, 1, 0, nil)
	status, err := actionHandler.Handle(a)
	assert.NoError(t, err)
	assert.Equal(t, 1, status)

	Config.Actions.Hook = "http://invalid:1234"
	status, err = actionHandler.Handle(a)
	assert.Error(t, err)
	assert.Equal(t, 1, status)

	Config.Actions.Hook = fmt.Sprintf("http://%v/404", httpAddr)
	status, err = actionHandler.Handle(a)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errUnexpectedHTTResponse.Error())
	}
	assert.Equal(t, 1, status)

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
		123, 0, 1, 0, map[string]string{"key": "value"})
	status, err := actionHandler.Handle(a)
	assert.NoError(t, err)
	assert.Equal(t, 1, status)

	c := NewBaseConnection("id", ProtocolSFTP, "", "", *user)
	err = ExecuteActionNotification(c, OperationSSHCmd, "path", "vpath", "target", "vtarget", "sha1sum", 0, nil, 0, nil)
	assert.NoError(t, err)

	err = ExecuteActionNotification(c, operationDownload, "path", "vpath", "", "", "", 0, nil, 0, nil)
	assert.NoError(t, err)

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
		123, 0, 1, 0, nil)
	status, err := actionHandler.Handle(a)
	assert.Error(t, err, "action with bad command must fail")
	assert.Equal(t, 1, status)

	a.Action = operationDelete
	status, err = actionHandler.Handle(a)
	assert.NoError(t, err)
	assert.Equal(t, 0, status)

	Config.Actions.Hook = "http://foo\x7f.com/"
	a.Action = operationUpload
	status, err = actionHandler.Handle(a)
	assert.Error(t, err, "action with bad url must fail")
	assert.Equal(t, 1, status)

	Config.Actions.Hook = ""
	status, err = actionHandler.Handle(a)
	assert.NoError(t, err)
	assert.Equal(t, 0, status)

	Config.Actions.Hook = "relative path"
	status, err = actionHandler.Handle(a)
	if assert.Error(t, err) {
		assert.EqualError(t, err, fmt.Sprintf("invalid notification command %q", Config.Actions.Hook))
	}
	assert.Equal(t, 1, status)

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
		Hook:      "missing hook",
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
	fs := vfs.NewOsFs("id", homeDir, "", nil)
	c := NewBaseConnection("id", ProtocolSFTP, "", "", user)

	testfile := filepath.Join(user.HomeDir, "testfile")
	err = os.WriteFile(testfile, []byte("test"), os.ModePerm)
	assert.NoError(t, err)
	info, err := os.Stat(testfile)
	assert.NoError(t, err)
	err = c.RemoveFile(fs, testfile, "testfile", info)
	assert.ErrorIs(t, err, c.GetPermissionDeniedError())
	assert.FileExists(t, testfile)
	Config.Actions.Hook = hookCmd
	err = c.RemoveFile(fs, testfile, "testfile", info)
	assert.NoError(t, err)
	assert.NoFileExists(t, testfile)

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
	err := plugin.Initialize(pluginsConfig, "debug")
	assert.Error(t, err)
	assert.True(t, plugin.Handler.HasNotifiers())

	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{})
	status, err := ExecutePreAction(c, OperationPreDownload, "", "", 0, 0)
	assert.NoError(t, err)
	assert.Equal(t, status, 0)
	status, err = ExecutePreAction(c, operationPreDelete, "", "", 0, 0)
	assert.NoError(t, err)
	assert.Equal(t, status, 0)

	err = ExecuteActionNotification(c, operationDownload, "", "", "", "", "", 0, nil, 0, nil)
	assert.NoError(t, err)

	err = plugin.Initialize(nil, "debug")
	assert.NoError(t, err)
	assert.False(t, plugin.Handler.HasNotifiers())

	Config.Actions = actionsCopy
}

type actionHandlerStub struct {
	called bool
}

func (h *actionHandlerStub) Handle(_ *notifier.FsEvent) (int, error) {
	h.called = true

	return 1, nil
}

func TestInitializeActionHandler(t *testing.T) {
	handler := &actionHandlerStub{}

	InitializeActionHandler(handler)
	t.Cleanup(func() {
		InitializeActionHandler(&defaultActionHandler{})
	})

	status, err := actionHandler.Handle(&notifier.FsEvent{})
	assert.NoError(t, err)
	assert.True(t, handler.called)
	assert.Equal(t, 1, status)
}
