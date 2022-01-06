package common

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/smtp"
)

func TestRetentionValidation(t *testing.T) {
	check := RetentionCheck{}
	check.Folders = append(check.Folders, FolderRetention{
		Path:      "relative",
		Retention: 10,
	})
	err := check.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "please specify an absolute POSIX path")

	check.Folders = []FolderRetention{
		{
			Path:      "/",
			Retention: -1,
		},
	}
	err = check.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid folder retention")

	check.Folders = []FolderRetention{
		{
			Path:      "/ab/..",
			Retention: 0,
		},
	}
	err = check.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nothing to delete")
	assert.Equal(t, "/", check.Folders[0].Path)

	check.Folders = append(check.Folders, FolderRetention{
		Path:      "/../..",
		Retention: 24,
	})
	err = check.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `duplicated folder path "/"`)

	check.Folders = []FolderRetention{
		{
			Path:      "/dir1",
			Retention: 48,
		},
		{
			Path:      "/dir2",
			Retention: 96,
		},
	}
	err = check.Validate()
	assert.NoError(t, err)
	assert.Len(t, check.Notifications, 0)
	assert.Empty(t, check.Email)

	check.Notifications = []RetentionCheckNotification{RetentionCheckNotificationEmail}
	err = check.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "you must configure an SMTP server")

	smtpCfg := smtp.Config{
		Host:          "mail.example.com",
		Port:          25,
		TemplatesPath: "templates",
	}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)

	err = check.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "you must add a valid email address")

	check.Email = "admin@example.com"
	err = check.Validate()
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)

	check.Notifications = []RetentionCheckNotification{RetentionCheckNotificationHook}
	err = check.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data_retention_hook")

	check.Notifications = []string{"not valid"}
	err = check.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid notification")
}

func TestRetentionEmailNotifications(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize("..")
	require.NoError(t, err)

	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user1",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	check := RetentionCheck{
		Notifications: []RetentionCheckNotification{RetentionCheckNotificationEmail},
		Email:         "notification@example.com",
		results: []*folderRetentionCheckResult{
			{
				Path:         "/",
				Retention:    24,
				DeletedFiles: 10,
				DeletedSize:  32657,
				Elapsed:      10 * time.Second,
			},
		},
	}
	conn := NewBaseConnection("", "", "", "", user)
	conn.SetProtocol(ProtocolDataRetention)
	conn.ID = fmt.Sprintf("data_retention_%v", user.Username)
	check.conn = conn
	check.sendNotifications(1*time.Second, nil)
	err = check.sendEmailNotification(1*time.Second, nil)
	assert.NoError(t, err)
	err = check.sendEmailNotification(1*time.Second, errors.New("test error"))
	assert.NoError(t, err)

	smtpCfg.Port = 2626
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)
	err = check.sendEmailNotification(1*time.Second, nil)
	assert.Error(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)
	err = check.sendEmailNotification(1*time.Second, nil)
	assert.Error(t, err)
}

func TestRetentionHookNotifications(t *testing.T) {
	dataRetentionHook := Config.DataRetentionHook

	Config.DataRetentionHook = fmt.Sprintf("http://%v", httpAddr)
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user2",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	check := RetentionCheck{
		Notifications: []RetentionCheckNotification{RetentionCheckNotificationHook},
		results: []*folderRetentionCheckResult{
			{
				Path:         "/",
				Retention:    24,
				DeletedFiles: 10,
				DeletedSize:  32657,
				Elapsed:      10 * time.Second,
			},
		},
	}
	conn := NewBaseConnection("", "", "", "", user)
	conn.SetProtocol(ProtocolDataRetention)
	conn.ID = fmt.Sprintf("data_retention_%v", user.Username)
	check.conn = conn
	check.sendNotifications(1*time.Second, nil)
	err := check.sendHookNotification(1*time.Second, nil)
	assert.NoError(t, err)

	Config.DataRetentionHook = fmt.Sprintf("http://%v/404", httpAddr)
	err = check.sendHookNotification(1*time.Second, nil)
	assert.ErrorIs(t, err, errUnexpectedHTTResponse)

	Config.DataRetentionHook = "http://foo\x7f.com/retention"
	err = check.sendHookNotification(1*time.Second, err)
	assert.Error(t, err)

	Config.DataRetentionHook = "relativepath"
	err = check.sendHookNotification(1*time.Second, err)
	assert.Error(t, err)

	if runtime.GOOS != osWindows {
		hookCmd, err := exec.LookPath("true")
		assert.NoError(t, err)

		Config.DataRetentionHook = hookCmd
		err = check.sendHookNotification(1*time.Second, err)
		assert.NoError(t, err)
	}

	Config.DataRetentionHook = dataRetentionHook
}

func TestRetentionPermissionsAndGetFolder(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user1",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDelete}
	user.Permissions["/dir1"] = []string{dataprovider.PermListItems}
	user.Permissions["/dir2/sub1"] = []string{dataprovider.PermCreateDirs}
	user.Permissions["/dir2/sub2"] = []string{dataprovider.PermDelete}

	check := RetentionCheck{
		Folders: []FolderRetention{
			{
				Path:                  "/dir2",
				Retention:             24 * 7,
				IgnoreUserPermissions: true,
			},
			{
				Path:                  "/dir3",
				Retention:             24 * 7,
				IgnoreUserPermissions: false,
			},
			{
				Path:                  "/dir2/sub1/sub",
				Retention:             24,
				IgnoreUserPermissions: true,
			},
		},
	}

	conn := NewBaseConnection("", "", "", "", user)
	conn.SetProtocol(ProtocolDataRetention)
	conn.ID = fmt.Sprintf("data_retention_%v", user.Username)
	check.conn = conn
	check.updateUserPermissions()
	assert.Equal(t, []string{dataprovider.PermListItems, dataprovider.PermDelete}, conn.User.Permissions["/"])
	assert.Equal(t, []string{dataprovider.PermListItems}, conn.User.Permissions["/dir1"])
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/dir2"])
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/dir2/sub1/sub"])
	assert.Equal(t, []string{dataprovider.PermCreateDirs}, conn.User.Permissions["/dir2/sub1"])
	assert.Equal(t, []string{dataprovider.PermDelete}, conn.User.Permissions["/dir2/sub2"])

	_, err := check.getFolderRetention("/")
	assert.Error(t, err)
	folder, err := check.getFolderRetention("/dir3")
	assert.NoError(t, err)
	assert.Equal(t, "/dir3", folder.Path)
	folder, err = check.getFolderRetention("/dir2/sub3")
	assert.NoError(t, err)
	assert.Equal(t, "/dir2", folder.Path)
	folder, err = check.getFolderRetention("/dir2/sub2")
	assert.NoError(t, err)
	assert.Equal(t, "/dir2", folder.Path)
	folder, err = check.getFolderRetention("/dir2/sub1")
	assert.NoError(t, err)
	assert.Equal(t, "/dir2", folder.Path)
	folder, err = check.getFolderRetention("/dir2/sub1/sub/sub")
	assert.NoError(t, err)
	assert.Equal(t, "/dir2/sub1/sub", folder.Path)
}

func TestRetentionCheckAddRemove(t *testing.T) {
	username := "username"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	check := RetentionCheck{
		Folders: []FolderRetention{
			{
				Path:      "/",
				Retention: 48,
			},
		},
		Notifications: []RetentionCheckNotification{RetentionCheckNotificationHook},
	}
	assert.NotNil(t, RetentionChecks.Add(check, &user))
	checks := RetentionChecks.Get()
	require.Len(t, checks, 1)
	assert.Equal(t, username, checks[0].Username)
	assert.Greater(t, checks[0].StartTime, int64(0))
	require.Len(t, checks[0].Folders, 1)
	assert.Equal(t, check.Folders[0].Path, checks[0].Folders[0].Path)
	assert.Equal(t, check.Folders[0].Retention, checks[0].Folders[0].Retention)
	require.Len(t, checks[0].Notifications, 1)
	assert.Equal(t, RetentionCheckNotificationHook, checks[0].Notifications[0])

	assert.Nil(t, RetentionChecks.Add(check, &user))
	assert.True(t, RetentionChecks.remove(username))
	require.Len(t, RetentionChecks.Get(), 0)
	assert.False(t, RetentionChecks.remove(username))
}

func TestCleanupErrors(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "u",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	check := &RetentionCheck{
		Folders: []FolderRetention{
			{
				Path:      "/path",
				Retention: 48,
			},
		},
	}
	check = RetentionChecks.Add(*check, &user)
	require.NotNil(t, check)

	err := check.removeFile("missing file", nil)
	assert.Error(t, err)

	err = check.cleanupFolder("/")
	assert.Error(t, err)

	assert.True(t, RetentionChecks.remove(user.Username))
}
