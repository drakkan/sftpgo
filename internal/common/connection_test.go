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
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

var (
	errWalkDir = errors.New("err walk dir")
)

// MockOsFs mockable OsFs
type MockOsFs struct {
	vfs.Fs
	hasVirtualFolders bool
	name              string
	err               error
}

// Name returns the name for the Fs implementation
func (fs *MockOsFs) Name() string {
	if fs.name != "" {
		return fs.name
	}
	return "mockOsFs"
}

// HasVirtualFolders returns true if folders are emulated
func (fs *MockOsFs) HasVirtualFolders() bool {
	return fs.hasVirtualFolders
}

func (fs *MockOsFs) IsUploadResumeSupported() bool {
	return !fs.hasVirtualFolders
}

func (fs *MockOsFs) Chtimes(_ string, _, _ time.Time, _ bool) error {
	return vfs.ErrVfsUnsupported
}

func (fs *MockOsFs) Lstat(name string) (os.FileInfo, error) {
	if fs.err != nil {
		return nil, fs.err
	}
	return fs.Fs.Lstat(name)
}

// Walk returns a duplicate path for testing
func (fs *MockOsFs) Walk(_ string, walkFn filepath.WalkFunc) error {
	if fs.err == errWalkDir {
		walkFn("fsdpath", vfs.NewFileInfo("dpath", true, 0, time.Now(), false), nil)        //nolint:errcheck
		return walkFn("fsdpath", vfs.NewFileInfo("dpath", true, 0, time.Now(), false), nil) //nolint:errcheck
	}
	walkFn("fsfpath", vfs.NewFileInfo("fpath", false, 0, time.Now(), false), nil) //nolint:errcheck
	return fs.err
}

func newMockOsFs(hasVirtualFolders bool, connectionID, rootDir, name string, err error) vfs.Fs {
	return &MockOsFs{
		Fs:                vfs.NewOsFs(connectionID, rootDir, "", nil),
		name:              name,
		hasVirtualFolders: hasVirtualFolders,
		err:               err,
	}
}

func TestRemoveErrors(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "map")
	homePath := filepath.Join(os.TempDir(), "home")

	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "remove_errors_user",
			HomeDir:  homePath,
		},
		VirtualFolders: []vfs.VirtualFolder{
			{
				BaseVirtualFolder: vfs.BaseVirtualFolder{
					Name:       filepath.Base(mappedPath),
					MappedPath: mappedPath,
				},
				VirtualPath: "/virtualpath",
			},
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("", os.TempDir(), "", nil)
	conn := NewBaseConnection("", ProtocolFTP, "", "", user)
	err := conn.IsRemoveDirAllowed(fs, mappedPath, "/virtualpath1")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "permission denied")
	}
	err = conn.RemoveFile(fs, filepath.Join(homePath, "missing_file"), "/missing_file",
		vfs.NewFileInfo("info", false, 100, time.Now(), false))
	assert.Error(t, err)
}

func TestSetStatMode(t *testing.T) {
	oldSetStatMode := Config.SetstatMode
	Config.SetstatMode = 1

	fakePath := "fake path"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: os.TempDir(),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := newMockOsFs(true, "", user.GetHomeDir(), "", nil)
	conn := NewBaseConnection("", ProtocolWebDAV, "", "", user)
	err := conn.handleChmod(fs, fakePath, fakePath, nil)
	assert.NoError(t, err)
	err = conn.handleChown(fs, fakePath, fakePath, nil)
	assert.NoError(t, err)
	err = conn.handleChtimes(fs, fakePath, fakePath, nil)
	assert.NoError(t, err)

	Config.SetstatMode = 2
	err = conn.handleChmod(fs, fakePath, fakePath, nil)
	assert.NoError(t, err)
	err = conn.handleChtimes(fs, fakePath, fakePath, &StatAttributes{
		Atime: time.Now(),
		Mtime: time.Now(),
	})
	assert.NoError(t, err)

	Config.SetstatMode = oldSetStatMode
}

func TestRecursiveRenameWalkError(t *testing.T) {
	fs := vfs.NewOsFs("", filepath.Clean(os.TempDir()), "", nil)
	conn := NewBaseConnection("", ProtocolWebDAV, "", "", dataprovider.User{
		BaseUser: sdk.BaseUser{
			Permissions: map[string][]string{
				"/": {dataprovider.PermListItems, dataprovider.PermUpload,
					dataprovider.PermDownload, dataprovider.PermRenameDirs},
			},
		},
	})
	err := conn.checkRecursiveRenameDirPermissions(fs, fs, filepath.Join(os.TempDir(), "/source"),
		filepath.Join(os.TempDir(), "/target"), "/source", "/target",
		vfs.NewFileInfo("source", true, 0, time.Now(), false))
	assert.ErrorIs(t, err, os.ErrNotExist)

	fs = newMockOsFs(false, "mockID", filepath.Clean(os.TempDir()), "S3Fs", errWalkDir)
	err = conn.checkRecursiveRenameDirPermissions(fs, fs, filepath.Join(os.TempDir(), "/source"),
		filepath.Join(os.TempDir(), "/target"), "/source", "/target",
		vfs.NewFileInfo("source", true, 0, time.Now(), false))
	if assert.Error(t, err) {
		assert.Equal(t, err.Error(), conn.GetOpUnsupportedError().Error())
	}

	conn.User.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermDownload, dataprovider.PermRenameFiles}
	// no dir rename permission, the quick check path returns permission error without walking
	err = conn.checkRecursiveRenameDirPermissions(fs, fs, filepath.Join(os.TempDir(), "/source"),
		filepath.Join(os.TempDir(), "/target"), "/source", "/target",
		vfs.NewFileInfo("source", true, 0, time.Now(), false))
	if assert.Error(t, err) {
		assert.EqualError(t, err, conn.GetPermissionDeniedError().Error())
	}
}

func TestCrossRenameFsErrors(t *testing.T) {
	fs := vfs.NewOsFs("", os.TempDir(), "", nil)
	conn := NewBaseConnection("", ProtocolWebDAV, "", "", dataprovider.User{})
	res := conn.hasSpaceForCrossRename(fs, vfs.QuotaCheckResult{}, 1, "missingsource")
	assert.False(t, res)
	if runtime.GOOS != osWindows {
		dirPath := filepath.Join(os.TempDir(), "d")
		err := os.Mkdir(dirPath, os.ModePerm)
		assert.NoError(t, err)
		err = os.Chmod(dirPath, 0001)
		assert.NoError(t, err)

		res = conn.hasSpaceForCrossRename(fs, vfs.QuotaCheckResult{}, 1, dirPath)
		assert.False(t, res)

		err = os.Chmod(dirPath, os.ModePerm)
		assert.NoError(t, err)
		err = os.Remove(dirPath)
		assert.NoError(t, err)
	}
}

func TestRenameVirtualFolders(t *testing.T) {
	vdir := "/avdir"
	u := dataprovider.User{}
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       "name",
			MappedPath: "mappedPath",
		},
		VirtualPath: vdir,
	})
	fs := vfs.NewOsFs("", os.TempDir(), "", nil)
	conn := NewBaseConnection("", ProtocolFTP, "", "", u)
	res := conn.isRenamePermitted(fs, fs, "source", "target", vdir, "vdirtarget", nil)
	assert.False(t, res)
}

func TestRenamePerms(t *testing.T) {
	src := "source"
	target := "target"
	sub := "/sub"
	subTarget := sub + "/target"
	u := dataprovider.User{}
	u.Permissions = map[string][]string{}
	u.Permissions["/"] = []string{dataprovider.PermCreateDirs, dataprovider.PermUpload, dataprovider.PermCreateSymlinks,
		dataprovider.PermDeleteFiles}
	conn := NewBaseConnection("", ProtocolSFTP, "", "", u)
	assert.False(t, conn.hasRenamePerms(src, target, nil))
	u.Permissions["/"] = []string{dataprovider.PermRename}
	assert.True(t, conn.hasRenamePerms(src, target, nil))
	u.Permissions["/"] = []string{dataprovider.PermCreateDirs, dataprovider.PermUpload, dataprovider.PermDeleteFiles,
		dataprovider.PermDeleteDirs}
	assert.False(t, conn.hasRenamePerms(src, target, nil))

	info := vfs.NewFileInfo(src, true, 0, time.Now(), false)
	u.Permissions["/"] = []string{dataprovider.PermRenameFiles}
	assert.False(t, conn.hasRenamePerms(src, target, info))
	u.Permissions["/"] = []string{dataprovider.PermRenameDirs}
	assert.True(t, conn.hasRenamePerms(src, target, info))
	u.Permissions["/"] = []string{dataprovider.PermRename}
	assert.True(t, conn.hasRenamePerms(src, target, info))
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDeleteDirs}
	assert.False(t, conn.hasRenamePerms(src, target, info))
	// test with different permissions between source and target
	u.Permissions["/"] = []string{dataprovider.PermRename}
	u.Permissions[sub] = []string{dataprovider.PermRenameFiles}
	assert.False(t, conn.hasRenamePerms(src, subTarget, info))
	u.Permissions[sub] = []string{dataprovider.PermRenameDirs}
	assert.True(t, conn.hasRenamePerms(src, subTarget, info))
	// test files
	info = vfs.NewFileInfo(src, false, 0, time.Now(), false)
	u.Permissions["/"] = []string{dataprovider.PermRenameDirs}
	assert.False(t, conn.hasRenamePerms(src, target, info))
	u.Permissions["/"] = []string{dataprovider.PermRenameFiles}
	assert.True(t, conn.hasRenamePerms(src, target, info))
	u.Permissions["/"] = []string{dataprovider.PermRename}
	assert.True(t, conn.hasRenamePerms(src, target, info))
	// test with different permissions between source and target
	u.Permissions["/"] = []string{dataprovider.PermRename}
	u.Permissions[sub] = []string{dataprovider.PermRenameDirs}
	assert.False(t, conn.hasRenamePerms(src, subTarget, info))
	u.Permissions[sub] = []string{dataprovider.PermRenameFiles}
	assert.True(t, conn.hasRenamePerms(src, subTarget, info))
}

func TestRenameNestedFolders(t *testing.T) {
	u := dataprovider.User{}
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       "vfolder",
			MappedPath: filepath.Join(os.TempDir(), "f"),
		},
		VirtualPath: "/vdirs/f",
	})
	conn := NewBaseConnection("", ProtocolSFTP, "", "", u)
	err := conn.checkFolderRename(nil, nil, filepath.Clean(os.TempDir()), filepath.Join(os.TempDir(), "subdir"), "/src", "/dst", nil)
	assert.Error(t, err)
	err = conn.checkFolderRename(nil, nil, filepath.Join(os.TempDir(), "subdir"), filepath.Clean(os.TempDir()), "/src", "/dst", nil)
	assert.Error(t, err)
	err = conn.checkFolderRename(nil, nil, "", "", "/src/sub", "/src", nil)
	assert.Error(t, err)
	err = conn.checkFolderRename(nil, nil, filepath.Join(os.TempDir(), "src"), filepath.Join(os.TempDir(), "vdirs"), "/src", "/vdirs", nil)
	assert.Error(t, err)
}

func TestUpdateQuotaAfterRename(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: userTestUsername,
			HomeDir:  filepath.Join(os.TempDir(), "home"),
		},
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir1",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	err := os.MkdirAll(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("id")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, "", "", user)
	request := sftp.NewRequest("Rename", "/testfile")
	if runtime.GOOS != osWindows {
		request.Filepath = "/dir"
		request.Target = path.Join("/vdir", "dir")
		testDirPath := filepath.Join(mappedPath, "dir")
		err := os.MkdirAll(testDirPath, os.ModePerm)
		assert.NoError(t, err)
		err = os.Chmod(testDirPath, 0001)
		assert.NoError(t, err)
		err = c.updateQuotaAfterRename(fs, request.Filepath, request.Target, testDirPath, 0, -1, -1)
		assert.Error(t, err)
		err = os.Chmod(testDirPath, os.ModePerm)
		assert.NoError(t, err)
	}
	testFile1 := "/testfile1"
	request.Target = testFile1
	request.Filepath = path.Join("/vdir", "file")
	err = c.updateQuotaAfterRename(fs, request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 0, -1, -1)
	assert.Error(t, err)
	err = os.WriteFile(filepath.Join(mappedPath, "file"), []byte("test content"), os.ModePerm)
	assert.NoError(t, err)
	request.Filepath = testFile1
	request.Target = path.Join("/vdir", "file")
	err = c.updateQuotaAfterRename(fs, request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 12, -1, -1)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "testfile1"), []byte("test content"), os.ModePerm)
	assert.NoError(t, err)
	request.Target = testFile1
	request.Filepath = path.Join("/vdir", "file")
	err = c.updateQuotaAfterRename(fs, request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 12, -1, -1)
	assert.NoError(t, err)
	request.Target = path.Join("/vdir1", "file")
	request.Filepath = path.Join("/vdir", "file")
	err = c.updateQuotaAfterRename(fs, request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 12, -1, -1)
	assert.NoError(t, err)
	err = c.updateQuotaAfterRename(fs, request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 12, 1, 100)
	assert.NoError(t, err)

	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestErrorsMapping(t *testing.T) {
	fs := vfs.NewOsFs("", os.TempDir(), "", nil)
	conn := NewBaseConnection("", ProtocolSFTP, "", "", dataprovider.User{BaseUser: sdk.BaseUser{HomeDir: os.TempDir()}})
	osErrorsProtocols := []string{ProtocolWebDAV, ProtocolFTP, ProtocolHTTP, ProtocolHTTPShare,
		ProtocolDataRetention, ProtocolOIDC, protocolEventAction}
	for _, protocol := range supportedProtocols {
		conn.SetProtocol(protocol)
		err := conn.GetFsError(fs, os.ErrNotExist)
		if protocol == ProtocolSFTP {
			assert.ErrorIs(t, err, sftp.ErrSSHFxNoSuchFile)
		} else if util.Contains(osErrorsProtocols, protocol) {
			assert.EqualError(t, err, os.ErrNotExist.Error())
		} else {
			assert.EqualError(t, err, ErrNotExist.Error())
		}
		err = conn.GetFsError(fs, os.ErrPermission)
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxPermissionDenied.Error())
		} else {
			assert.EqualError(t, err, ErrPermissionDenied.Error())
		}
		err = conn.GetFsError(fs, os.ErrClosed)
		if protocol == ProtocolSFTP {
			assert.ErrorIs(t, err, sftp.ErrSSHFxFailure)
		} else {
			assert.EqualError(t, err, ErrGenericFailure.Error())
		}
		err = conn.GetFsError(fs, ErrPermissionDenied)
		if protocol == ProtocolSFTP {
			assert.ErrorIs(t, err, sftp.ErrSSHFxFailure)
		} else {
			assert.EqualError(t, err, ErrPermissionDenied.Error())
		}
		err = conn.GetFsError(fs, vfs.ErrVfsUnsupported)
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxOpUnsupported.Error())
		} else {
			assert.EqualError(t, err, ErrOpUnsupported.Error())
		}
		err = conn.GetFsError(fs, vfs.ErrStorageSizeUnavailable)
		if protocol == ProtocolSFTP {
			assert.ErrorIs(t, err, sftp.ErrSSHFxOpUnsupported)
			assert.Contains(t, err.Error(), vfs.ErrStorageSizeUnavailable.Error())
		} else {
			assert.EqualError(t, err, vfs.ErrStorageSizeUnavailable.Error())
		}
		err = conn.GetQuotaExceededError()
		assert.True(t, conn.IsQuotaExceededError(err))
		err = conn.GetReadQuotaExceededError()
		if protocol == ProtocolSFTP {
			assert.ErrorIs(t, err, sftp.ErrSSHFxFailure)
			assert.Contains(t, err.Error(), ErrReadQuotaExceeded.Error())
		} else {
			assert.ErrorIs(t, err, ErrReadQuotaExceeded)
		}
		err = conn.GetNotExistError()
		assert.True(t, conn.IsNotExistError(err))
		err = conn.GetFsError(fs, nil)
		assert.NoError(t, err)
		err = conn.GetOpUnsupportedError()
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxOpUnsupported.Error())
		} else {
			assert.EqualError(t, err, ErrOpUnsupported.Error())
		}
		err = conn.GetFsError(fs, ErrShuttingDown)
		if protocol == ProtocolSFTP {
			assert.ErrorIs(t, err, sftp.ErrSSHFxFailure)
			assert.Contains(t, err.Error(), ErrShuttingDown.Error())
		} else {
			assert.EqualError(t, err, ErrShuttingDown.Error())
		}
	}
}

func TestMaxWriteSize(t *testing.T) {
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:    userTestUsername,
			Permissions: permissions,
			HomeDir:     filepath.Clean(os.TempDir()),
		},
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	conn := NewBaseConnection("", ProtocolFTP, "", "", user)
	quotaResult := vfs.QuotaCheckResult{
		HasSpace: true,
	}
	size, err := conn.GetMaxWriteSize(quotaResult, false, 0, fs.IsUploadResumeSupported())
	assert.NoError(t, err)
	assert.Equal(t, int64(0), size)

	conn.User.Filters.MaxUploadFileSize = 100
	size, err = conn.GetMaxWriteSize(quotaResult, false, 0, fs.IsUploadResumeSupported())
	assert.NoError(t, err)
	assert.Equal(t, int64(100), size)

	quotaResult.QuotaSize = 1000
	size, err = conn.GetMaxWriteSize(quotaResult, false, 50, fs.IsUploadResumeSupported())
	assert.NoError(t, err)
	assert.Equal(t, int64(100), size)

	quotaResult.QuotaSize = 1000
	quotaResult.UsedSize = 990
	size, err = conn.GetMaxWriteSize(quotaResult, false, 50, fs.IsUploadResumeSupported())
	assert.NoError(t, err)
	assert.Equal(t, int64(60), size)

	quotaResult.QuotaSize = 0
	quotaResult.UsedSize = 0
	size, err = conn.GetMaxWriteSize(quotaResult, true, 100, fs.IsUploadResumeSupported())
	assert.True(t, conn.IsQuotaExceededError(err))
	assert.Equal(t, int64(0), size)

	size, err = conn.GetMaxWriteSize(quotaResult, true, 10, fs.IsUploadResumeSupported())
	assert.NoError(t, err)
	assert.Equal(t, int64(90), size)

	fs = newMockOsFs(true, fs.ConnectionID(), user.GetHomeDir(), "", nil)
	size, err = conn.GetMaxWriteSize(quotaResult, true, 100, fs.IsUploadResumeSupported())
	assert.EqualError(t, err, ErrOpUnsupported.Error())
	assert.Equal(t, int64(0), size)
}

func TestCheckParentDirsErrors(t *testing.T) {
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:    userTestUsername,
			Permissions: permissions,
			HomeDir:     filepath.Clean(os.TempDir()),
		},
		FsConfig: vfs.Filesystem{
			Provider: sdk.CryptedFilesystemProvider,
		},
	}
	c := NewBaseConnection(xid.New().String(), ProtocolSFTP, "", "", user)
	err := c.CheckParentDirs("/a/dir")
	assert.Error(t, err)

	user.FsConfig.Provider = sdk.LocalFilesystemProvider
	user.VirtualFolders = nil
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
			},
		},
		VirtualPath: "/vdir",
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Clean(os.TempDir()),
		},
		VirtualPath: "/vdir/sub",
	})
	c = NewBaseConnection(xid.New().String(), ProtocolSFTP, "", "", user)
	err = c.CheckParentDirs("/vdir/sub/dir")
	assert.Error(t, err)

	user = dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:    userTestUsername,
			Permissions: permissions,
			HomeDir:     filepath.Clean(os.TempDir()),
		},
		FsConfig: vfs.Filesystem{
			Provider: sdk.S3FilesystemProvider,
			S3Config: vfs.S3FsConfig{
				BaseS3FsConfig: sdk.BaseS3FsConfig{
					Bucket:    "buck",
					Region:    "us-east-1",
					AccessKey: "key",
				},
				AccessSecret: kms.NewPlainSecret("s3secret"),
			},
		},
	}
	c = NewBaseConnection(xid.New().String(), ProtocolSFTP, "", "", user)
	err = c.CheckParentDirs("/a/dir")
	assert.NoError(t, err)

	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Clean(os.TempDir()),
		},
		VirtualPath: "/local/dir",
	})

	c = NewBaseConnection(xid.New().String(), ProtocolSFTP, "", "", user)
	err = c.CheckParentDirs("/local/dir/sub-dir")
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Join(os.TempDir(), "sub-dir"))
	assert.NoError(t, err)
}

func TestErrorResolvePath(t *testing.T) {
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Join(os.TempDir(), "u"),
			Status:  1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("invalid JSON for credentials")
	u.VirtualFolders = []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "f",
				MappedPath: filepath.Join(os.TempDir(), "f"),
			},
			VirtualPath: "/f",
		},
	}

	conn := NewBaseConnection("", ProtocolSFTP, "", "", u)
	err := conn.doRecursiveRemoveDirEntry("/vpath", nil, 0)
	assert.Error(t, err)
	err = conn.doRecursiveRemove(nil, "/fspath", "/vpath", vfs.NewFileInfo("vpath", true, 0, time.Now(), false), 2000)
	assert.Error(t, err, util.ErrRecursionTooDeep)
	err = conn.doRecursiveCopy("/src", "/dst", vfs.NewFileInfo("src", true, 0, time.Now(), false), false, 2000)
	assert.Error(t, err, util.ErrRecursionTooDeep)
	err = conn.checkCopy(vfs.NewFileInfo("name", true, 0, time.Unix(0, 0), false), nil, "/source", "/target")
	assert.Error(t, err)
	sourceFile := filepath.Join(os.TempDir(), "f", "source")
	err = os.MkdirAll(filepath.Dir(sourceFile), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(sourceFile, []byte(""), 0666)
	assert.NoError(t, err)
	err = conn.checkCopy(vfs.NewFileInfo("name", true, 0, time.Unix(0, 0), false), nil, "/f/source", "/target")
	assert.Error(t, err)
	err = conn.checkCopy(vfs.NewFileInfo("source", false, 0, time.Unix(0, 0), false), vfs.NewFileInfo("target", true, 0, time.Unix(0, 0), false), "/f/source", "/f/target")
	assert.Error(t, err)
	err = os.RemoveAll(filepath.Dir(sourceFile))
	assert.NoError(t, err)
}

func TestConnectionKeepAlive(t *testing.T) {
	conn := NewBaseConnection("", ProtocolWebDAV, "", "", dataprovider.User{})
	lastActivity := conn.GetLastActivity()
	done := make(chan bool)
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(done)
	}()
	keepConnectionAlive(conn, done, 50*time.Millisecond)
	assert.Greater(t, conn.GetLastActivity(), lastActivity)
}

func TestFsFileCopier(t *testing.T) {
	fs := vfs.Fs(&vfs.AzureBlobFs{})
	_, ok := fs.(vfs.FsFileCopier)
	assert.True(t, ok)
	fs = vfs.Fs(&vfs.OsFs{})
	_, ok = fs.(vfs.FsFileCopier)
	assert.False(t, ok)
	fs = vfs.Fs(&vfs.SFTPFs{})
	_, ok = fs.(vfs.FsFileCopier)
	assert.False(t, ok)
	fs = vfs.Fs(&vfs.GCSFs{})
	_, ok = fs.(vfs.FsFileCopier)
	assert.True(t, ok)
	fs = vfs.Fs(&vfs.S3Fs{})
	_, ok = fs.(vfs.FsFileCopier)
	assert.True(t, ok)
}

func TestFilePatterns(t *testing.T) {
	filters := dataprovider.UserFilters{
		BaseUserFilters: sdk.BaseUserFilters{
			FilePatterns: []sdk.PatternsFilter{
				{
					Path:            "/dir1",
					DenyPolicy:      sdk.DenyPolicyDefault,
					AllowedPatterns: []string{"*.jpg"},
				},
				{
					Path:            "/dir2",
					DenyPolicy:      sdk.DenyPolicyHide,
					AllowedPatterns: []string{"*.jpg"},
				},
				{
					Path:           "/dir3",
					DenyPolicy:     sdk.DenyPolicyDefault,
					DeniedPatterns: []string{"*.jpg"},
				},
				{
					Path:           "/dir4",
					DenyPolicy:     sdk.DenyPolicyHide,
					DeniedPatterns: []string{"*"},
				},
			},
		},
	}
	virtualFolders := []vfs.VirtualFolder{
		{
			VirtualPath: "/dir1/vdir1",
		},
		{
			VirtualPath: "/dir1/vdir2",
		},
		{
			VirtualPath: "/dir1/vdir3",
		},
		{
			VirtualPath: "/dir2/vdir1",
		},
		{
			VirtualPath: "/dir2/vdir2",
		},
		{
			VirtualPath: "/dir2/vdir3.jpg",
		},
	}
	user := dataprovider.User{
		Filters:        filters,
		VirtualFolders: virtualFolders,
	}

	getFilteredInfo := func(dirContents []os.FileInfo, virtualPath string) []os.FileInfo {
		result := user.FilterListDir(dirContents, virtualPath)
		result = append(result, user.GetVirtualFoldersInfo(virtualPath)...)
		return result
	}

	dirContents := []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}
	// dirContents are modified in place, we need to redefine them each time
	filtered := getFilteredInfo(dirContents, "/dir1")
	assert.Len(t, filtered, 5)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir1/vdir1")
	assert.Len(t, filtered, 2)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir2/vdir2")
	require.Len(t, filtered, 1)
	assert.Equal(t, "file1.jpg", filtered[0].Name())

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir2/vdir2/sub")
	require.Len(t, filtered, 1)
	assert.Equal(t, "file1.jpg", filtered[0].Name())

	res, _ := user.IsFileAllowed("/dir1/vdir1/file.txt")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir1/vdir1/sub/file.txt")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir1/vdir1/file.jpg")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir1/vdir1/sub/file.jpg")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/file.jpg")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/dir1/file.jpg")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/dir1/sub/file.jpg")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir4/file.jpg")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir4/dir1/sub/file.jpg")
	assert.False(t, res)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir4")
	require.Len(t, filtered, 0)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir4/vdir2/sub")
	require.Len(t, filtered, 0)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}

	filtered = getFilteredInfo(dirContents, "/dir2")
	assert.Len(t, filtered, 2)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}

	filtered = getFilteredInfo(dirContents, "/dir4")
	assert.Len(t, filtered, 0)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
	}

	filtered = getFilteredInfo(dirContents, "/dir4/sub")
	assert.Len(t, filtered, 0)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("vdir3.jpg", false, 123, time.Now(), false),
	}

	filtered = getFilteredInfo(dirContents, "/dir1")
	assert.Len(t, filtered, 5)

	filtered = getFilteredInfo(dirContents, "/dir2")
	if assert.Len(t, filtered, 1) {
		assert.True(t, filtered[0].IsDir())
	}

	user.VirtualFolders = nil
	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("vdir3.jpg", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir1")
	assert.Len(t, filtered, 2)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("vdir3.jpg", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir2")
	if assert.Len(t, filtered, 1) {
		assert.False(t, filtered[0].IsDir())
	}

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("vdir3.jpg", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir2")
	if assert.Len(t, filtered, 2) {
		assert.False(t, filtered[0].IsDir())
		assert.False(t, filtered[1].IsDir())
	}

	user.VirtualFolders = virtualFolders
	user.Filters = filters
	filtered = getFilteredInfo(nil, "/dir1")
	assert.Len(t, filtered, 3)
	filtered = getFilteredInfo(nil, "/dir2")
	assert.Len(t, filtered, 1)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jPg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("vdir3.jpg", false, 456, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir2")
	assert.Len(t, filtered, 2)

	user = dataprovider.User{
		Filters: dataprovider.UserFilters{
			BaseUserFilters: sdk.BaseUserFilters{
				FilePatterns: []sdk.PatternsFilter{
					{
						Path:            "/dir3",
						AllowedPatterns: []string{"ic35"},
						DeniedPatterns:  []string{"*"},
						DenyPolicy:      sdk.DenyPolicyHide,
					},
				},
			},
		},
	}
	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("vdir3.jpg", false, 456, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3")
	assert.Len(t, filtered, 0)

	dirContents = nil
	for i := 0; i < 100; i++ {
		dirContents = append(dirContents, vfs.NewFileInfo(fmt.Sprintf("ic%02d", i), i%2 == 0, int64(i), time.Now(), false))
	}
	dirContents = append(dirContents, vfs.NewFileInfo("ic350", false, 123, time.Now(), false))
	dirContents = append(dirContents, vfs.NewFileInfo(".ic35", false, 123, time.Now(), false))
	dirContents = append(dirContents, vfs.NewFileInfo("ic35.", false, 123, time.Now(), false))
	dirContents = append(dirContents, vfs.NewFileInfo("*ic35", false, 123, time.Now(), false))
	dirContents = append(dirContents, vfs.NewFileInfo("ic35*", false, 123, time.Now(), false))
	dirContents = append(dirContents, vfs.NewFileInfo("ic35.*", false, 123, time.Now(), false))
	dirContents = append(dirContents, vfs.NewFileInfo("file.jpg", false, 123, time.Now(), false))

	filtered = getFilteredInfo(dirContents, "/dir3")
	require.Len(t, filtered, 1)
	assert.Equal(t, "ic35", filtered[0].Name())

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic36")
	require.Len(t, filtered, 0)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic35")
	require.Len(t, filtered, 3)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic35/sub")
	require.Len(t, filtered, 3)

	res, _ = user.IsFileAllowed("/dir3/file.txt")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35a")
	assert.False(t, res)
	res, policy := user.IsFileAllowed("/dir3/ic35a/file")
	assert.False(t, res)
	assert.Equal(t, sdk.DenyPolicyHide, policy)
	res, _ = user.IsFileAllowed("/dir3/ic35")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/file.jpg")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/file.txt")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub/file.txt")
	assert.True(t, res)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic35/sub")
	require.Len(t, filtered, 3)

	user.Filters.FilePatterns = append(user.Filters.FilePatterns, sdk.PatternsFilter{
		Path:            "/dir3/ic35/sub1",
		AllowedPatterns: []string{"*.jpg"},
		DenyPolicy:      sdk.DenyPolicyDefault,
	})
	user.Filters.FilePatterns = append(user.Filters.FilePatterns, sdk.PatternsFilter{
		Path:           "/dir3/ic35/sub2",
		DeniedPatterns: []string{"*.jpg"},
		DenyPolicy:     sdk.DenyPolicyHide,
	})

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic35/sub1")
	require.Len(t, filtered, 3)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic35/sub2")
	require.Len(t, filtered, 2)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic35/sub2/sub1")
	require.Len(t, filtered, 2)

	res, _ = user.IsFileAllowed("/dir3/ic35/file.jpg")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/file.txt")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub/dir/file.txt")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub/dir/file.jpg")
	assert.True(t, res)

	res, _ = user.IsFileAllowed("/dir3/ic35/sub1/file.jpg")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub1/file.txt")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub1/sub/file.jpg")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub1/sub2/file.txt")
	assert.False(t, res)

	res, _ = user.IsFileAllowed("/dir3/ic35/sub2/file.jpg")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub2/file.txt")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub2/sub/file.jpg")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub2/sub1/file.txt")
	assert.True(t, res)

	user.Filters.FilePatterns = append(user.Filters.FilePatterns, sdk.PatternsFilter{
		Path:           "/dir3/ic35",
		DeniedPatterns: []string{"*.txt"},
		DenyPolicy:     sdk.DenyPolicyHide,
	})
	res, _ = user.IsFileAllowed("/dir3/ic35/file.jpg")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/file.txt")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/adir/sub/file.jpg")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/adir/file.txt")
	assert.False(t, res)

	res, _ = user.IsFileAllowed("/dir3/ic35/sub2/file.jpg")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub2/file.txt")
	assert.True(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub2/sub/file.jpg")
	assert.False(t, res)
	res, _ = user.IsFileAllowed("/dir3/ic35/sub2/sub1/file.txt")
	assert.True(t, res)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic35")
	require.Len(t, filtered, 1)

	dirContents = []os.FileInfo{
		vfs.NewFileInfo("file1.jpg", false, 123, time.Now(), false),
		vfs.NewFileInfo("file1.txt", false, 123, time.Now(), false),
		vfs.NewFileInfo("file2.txt", false, 123, time.Now(), false),
	}
	filtered = getFilteredInfo(dirContents, "/dir3/ic35/abc")
	require.Len(t, filtered, 1)
}

func TestListerAt(t *testing.T) {
	dir := t.TempDir()
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "u",
			Password: "p",
			HomeDir:  dir,
			Status:   1,
			Permissions: map[string][]string{
				"/": {"*"},
			},
		},
	}
	conn := NewBaseConnection(xid.New().String(), ProtocolSFTP, "", "", user)
	lister, err := conn.ListDir("/")
	require.NoError(t, err)
	files, err := lister.Next(1)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, files, 0)
	err = lister.Close()
	require.NoError(t, err)

	conn.User.VirtualFolders = []vfs.VirtualFolder{
		{
			VirtualPath: "p1",
		},
		{
			VirtualPath: "p2",
		},
		{
			VirtualPath: "p3",
		},
	}
	lister, err = conn.ListDir("/")
	require.NoError(t, err)
	files, err = lister.Next(2)
	// virtual directories exceeds the limit
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, files, 3)
	files, err = lister.Next(2)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, files, 0)
	_, err = lister.Next(-1)
	require.ErrorContains(t, err, "invalid limit")
	err = lister.Close()
	require.NoError(t, err)

	lister, err = conn.ListDir("/")
	require.NoError(t, err)
	_, err = lister.ListAt(nil, 0)
	require.ErrorContains(t, err, "zero size")
	err = lister.Close()
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		f, err := os.Create(filepath.Join(dir, strconv.Itoa(i)))
		require.NoError(t, err)
		err = f.Close()
		require.NoError(t, err)
	}
	lister, err = conn.ListDir("/")
	require.NoError(t, err)
	files = make([]os.FileInfo, 18)
	n, err := lister.ListAt(files, 0)
	require.NoError(t, err)
	require.Equal(t, 18, n)
	n, err = lister.ListAt(files, 0)
	require.NoError(t, err)
	require.Equal(t, 18, n)
	files = make([]os.FileInfo, 100)
	n, err = lister.ListAt(files, 0)
	require.NoError(t, err)
	require.Equal(t, 64+3, n)
	n, err = lister.ListAt(files, 0)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)
	n, err = lister.ListAt(files, 0)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)
	err = lister.Close()
	require.NoError(t, err)
	n, err = lister.ListAt(files, 0)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)
	lister, err = conn.ListDir("/")
	require.NoError(t, err)
	lister.Add(vfs.NewFileInfo("..", true, 0, time.Unix(0, 0), false))
	lister.Add(vfs.NewFileInfo(".", true, 0, time.Unix(0, 0), false))
	files = make([]os.FileInfo, 1)
	n, err = lister.ListAt(files, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	assert.Equal(t, ".", files[0].Name())
	files = make([]os.FileInfo, 2)
	n, err = lister.ListAt(files, 0)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	assert.Equal(t, "..", files[0].Name())
	vfolders := []string{files[1].Name()}
	files = make([]os.FileInfo, 200)
	n, err = lister.ListAt(files, 0)
	require.NoError(t, err)
	require.Equal(t, 102, n)
	vfolders = append(vfolders, files[0].Name())
	vfolders = append(vfolders, files[1].Name())
	assert.Contains(t, vfolders, "p1")
	assert.Contains(t, vfolders, "p2")
	assert.Contains(t, vfolders, "p3")
	err = lister.Close()
	require.NoError(t, err)
}
