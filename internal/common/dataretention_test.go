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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xrogers/gonas/v2/internal/dataprovider"
	"github.com/xrogers/gonas/v2/internal/util"
	"github.com/xrogers/gonas/v2/internal/vfs"
)

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
		Folders: []dataprovider.FolderRetention{
			{
				Path:      "/dir2",
				Retention: 24 * 7,
			},
			{
				Path:      "/dir3",
				Retention: 24 * 7,
			},
			{
				Path:      "/dir2/sub1/sub",
				Retention: 24,
			},
		},
	}

	conn := NewBaseConnection("", "", "", "", user)
	conn.SetProtocol(ProtocolDataRetention)
	conn.ID = fmt.Sprintf("data_retention_%v", user.Username)
	check.conn = conn
	check.updateUserPermissions()
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/"])
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/dir1"])
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/dir2/sub1"])
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/dir2/sub2"])

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
		Folders: []dataprovider.FolderRetention{
			{
				Path:      "/",
				Retention: 48,
			},
		},
	}
	assert.NotNil(t, RetentionChecks.Add(check, &user))
	checks := RetentionChecks.Get("")
	require.Len(t, checks, 1)
	assert.Equal(t, username, checks[0].Username)
	assert.Greater(t, checks[0].StartTime, int64(0))
	require.Len(t, checks[0].Folders, 1)
	assert.Equal(t, check.Folders[0].Path, checks[0].Folders[0].Path)
	assert.Equal(t, check.Folders[0].Retention, checks[0].Folders[0].Retention)

	assert.Nil(t, RetentionChecks.Add(check, &user))
	assert.True(t, RetentionChecks.remove(username))
	require.Len(t, RetentionChecks.Get(""), 0)
	assert.False(t, RetentionChecks.remove(username))
}

func TestRetentionCheckRole(t *testing.T) {
	username := "retuser"
	role1 := "retrole1"
	role2 := "retrole2"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Role:     role1,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	check := RetentionCheck{
		Folders: []dataprovider.FolderRetention{
			{
				Path:      "/",
				Retention: 48,
			},
		},
	}
	assert.NotNil(t, RetentionChecks.Add(check, &user))
	checks := RetentionChecks.Get("")
	require.Len(t, checks, 1)
	assert.Empty(t, checks[0].Role)
	checks = RetentionChecks.Get(role1)
	require.Len(t, checks, 1)
	checks = RetentionChecks.Get(role2)
	require.Len(t, checks, 0)
	user.Role = ""
	assert.Nil(t, RetentionChecks.Add(check, &user))
	assert.True(t, RetentionChecks.remove(username))
	require.Len(t, RetentionChecks.Get(""), 0)
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
		Folders: []dataprovider.FolderRetention{
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

	err = check.cleanupFolder("/", 0)
	assert.Error(t, err)

	err = check.cleanupFolder("/", 1000)
	assert.ErrorIs(t, err, util.ErrRecursionTooDeep)

	assert.True(t, RetentionChecks.remove(user.Username))
}

func TestRetentionConfiguredFolderFolded(t *testing.T) {
	homeDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(homeDir, "EMPTY"), os.ModePerm))
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "retention_fold",
			HomeDir:  homeDir,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	check := RetentionCheck{
		Folders: []dataprovider.FolderRetention{
			{Path: "/", Retention: 24},
			{Path: "/keep", Retention: 0},
			{Path: "/keep/sub", Retention: 48},
			{Path: "/d\u00e9", Retention: 0},
			{Path: "/empty", Retention: 0, DeleteEmptyDirs: true},
		},
	}
	check.conn = NewBaseConnection("", ProtocolDataRetention, "", "", user)
	// runs before the removal of homeDir: Windows refuses to remove an open directory
	t.Cleanup(func() {
		assert.NoError(t, check.conn.CloseFS())
	})
	assertFolder := func(walked, expected string) {
		t.Helper()
		folder, err := check.getFolderRetention(walked)
		if assert.NoError(t, err, walked) {
			assert.Equal(t, expected, folder.Path, walked)
		}
	}
	saved := foldsNamesAt
	t.Cleanup(func() {
		foldsNamesAt = saved
	})
	// where the storage keeps letter case apart the stored names are other folders
	foldsNamesAt = func(*dataprovider.User, string) bool {
		return false
	}
	assertFolder("/Keep/x", "/")
	check.checkEmptyDirRemoval("/empty", true)
	assert.DirExists(t, filepath.Join(homeDir, "EMPTY"))
	// where it matches names ignoring case they reach the configured folders
	foldsNamesAt = func(*dataprovider.User, string) bool {
		return true
	}
	assertFolder("/Keep/x", "/keep")
	assertFolder("/KEEP/SUB/x", "/keep/sub")
	assertFolder("/kept/x", "/")
	assertFolder("/d\u00e9/x", "/d\u00e9")
	// letters outside ASCII are compared as written
	assertFolder("/D\u00c9/x", "/")
	// a stored spelling of a configured folder is not removed as an empty directory
	check.checkEmptyDirRemoval("/EMPTY", true)
	assert.DirExists(t, filepath.Join(homeDir, "EMPTY"))
	foldsNamesAt = func(*dataprovider.User, string) bool {
		return false
	}
	check.checkEmptyDirRemoval("/EMPTY", true)
	assert.NoDirExists(t, filepath.Join(homeDir, "EMPTY"))
}

func TestRetentionConfiguredFolderOtherMount(t *testing.T) {
	homeDir := t.TempDir()
	mappedPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(homeDir, "Data"), os.ModePerm))
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "retention_mount",
			HomeDir:  homeDir,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		VirtualFolders: []vfs.VirtualFolder{{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "retention_mount",
				MappedPath: mappedPath,
				FsConfig:   vfs.Filesystem{Provider: sdk.LocalFilesystemProvider},
			},
			VirtualPath: "/data",
		}},
	}
	check := RetentionCheck{
		Folders: []dataprovider.FolderRetention{
			{Path: "/", Retention: 0},
			{Path: "/data", Retention: 1},
		},
	}
	check.conn = NewBaseConnection("", ProtocolDataRetention, "", "", user)
	saved := foldsNamesAt
	t.Cleanup(func() {
		foldsNamesAt = saved
	})
	foldsNamesAt = func(*dataprovider.User, string) bool {
		return true
	}
	// a home directory spelled like a mount point is not the mount: mount points are
	// reached by their exact name only
	folder, err := check.getFolderRetention("/Data/x")
	require.NoError(t, err)
	assert.Equal(t, "/", folder.Path)
	folder, err = check.getFolderRetention("/data/x")
	require.NoError(t, err)
	assert.Equal(t, "/data", folder.Path)
}
