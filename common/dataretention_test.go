package common

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/sdk"
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
	assert.Equal(t, RetentionCheckNotificationNone, check.Notification)
	assert.Empty(t, check.Email)

	check.Notification = RetentionCheckNotificationEmail
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
}

func TestEmailNotifications(t *testing.T) {
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
		Notification: RetentionCheckNotificationEmail,
		Email:        "notification@example.com",
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
	conn.ID = fmt.Sprintf("retention_check_%v", user.Username)
	check.conn = conn
	err = check.sendNotification(time.Now(), nil)
	assert.NoError(t, err)
	err = check.sendNotification(time.Now(), errors.New("test error"))
	assert.NoError(t, err)

	smtpCfg.Port = 2626
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)
	err = check.sendNotification(time.Now(), nil)
	assert.Error(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)
	err = check.sendNotification(time.Now(), nil)
	assert.Error(t, err)
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
	conn.ID = fmt.Sprintf("retention_check_%v", user.Username)
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
	}
	assert.NotNil(t, RetentionChecks.Add(check, &user))
	checks := RetentionChecks.Get()
	require.Len(t, checks, 1)
	assert.Equal(t, username, checks[0].Username)
	assert.Greater(t, checks[0].StartTime, int64(0))
	require.Len(t, checks[0].Folders, 1)
	assert.Equal(t, check.Folders[0].Path, checks[0].Folders[0].Path)
	assert.Equal(t, check.Folders[0].Retention, checks[0].Folders[0].Retention)

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
