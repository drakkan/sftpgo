package common

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/minio/sio"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/vfs"
)

// MockOsFs mockable OsFs
type MockOsFs struct {
	vfs.Fs
	hasVirtualFolders bool
}

// Name returns the name for the Fs implementation
func (fs MockOsFs) Name() string {
	return "mockOsFs"
}

// HasVirtualFolders returns true if folders are emulated
func (fs MockOsFs) HasVirtualFolders() bool {
	return fs.hasVirtualFolders
}

func (fs MockOsFs) IsUploadResumeSupported() bool {
	return !fs.hasVirtualFolders
}

func newMockOsFs(hasVirtualFolders bool, connectionID, rootDir string) vfs.Fs {
	return &MockOsFs{
		Fs:                vfs.NewOsFs(connectionID, rootDir, nil),
		hasVirtualFolders: hasVirtualFolders,
	}
}

func TestListDir(t *testing.T) {
	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermUpload}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir",
	})
	err := os.Mkdir(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	_, err = c.ListDir(user.GetHomeDir(), "/")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	c.User.Permissions["/"] = []string{dataprovider.PermAny}
	files, err := c.ListDir(user.GetHomeDir(), "/")
	if assert.NoError(t, err) {
		vdirFound := false
		for _, f := range files {
			if f.Name() == "vdir" {
				vdirFound = true
				break
			}
		}
		assert.True(t, vdirFound)
	}
	_, err = c.ListDir(mappedPath, "/vdir")
	assert.Error(t, err)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestCreateDir(t *testing.T) {
	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Permissions["/sub"] = []string{dataprovider.PermListItems}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir",
	})
	err := os.Mkdir(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	err = c.CreateDir("", "/sub/dir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.CreateDir("", "/vdir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.CreateDir(filepath.Join(mappedPath, "adir"), "/vdir/adir")
	assert.Error(t, err)
	err = c.CreateDir(filepath.Join(user.GetHomeDir(), "dir"), "/dir")
	assert.NoError(t, err)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRemoveFile(t *testing.T) {
	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Permissions["/sub"] = []string{dataprovider.PermListItems}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	user.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/p",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{".zip"},
		},
	}
	err := os.Mkdir(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	err = c.RemoveFile("", "/sub/file", nil)
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.RemoveFile("", "/p/file.zip", nil)
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	testFile := filepath.Join(mappedPath, "afile")
	err = ioutil.WriteFile(testFile, []byte("test data"), os.ModePerm)
	assert.NoError(t, err)
	info, err := os.Stat(testFile)
	assert.NoError(t, err)
	err = c.RemoveFile(filepath.Join(user.GetHomeDir(), "missing"), "/missing", info)
	assert.Error(t, err)
	err = c.RemoveFile(testFile, "/vdir/afile", info)
	assert.NoError(t, err)

	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRemoveDir(t *testing.T) {
	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Permissions["/sub"] = []string{dataprovider.PermListItems}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/adir/vdir",
	})
	err := os.Mkdir(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	err = c.RemoveDir(user.GetHomeDir(), "/")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.RemoveDir(mappedPath, "/adir/vdir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.RemoveDir(mappedPath, "/adir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetOpUnsupportedError().Error())
	}
	err = c.RemoveDir(mappedPath, "/adir/dir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.RemoveDir(filepath.Join(user.GetHomeDir(), "/sub/dir"), "/sub/dir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	testDir := filepath.Join(user.GetHomeDir(), "testDir")
	err = c.RemoveDir(testDir, "testDir")
	assert.Error(t, err)
	err = ioutil.WriteFile(testDir, []byte("data"), os.ModePerm)
	assert.NoError(t, err)
	err = c.RemoveDir(testDir, "testDir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetGenericError(err).Error())
	}
	err = os.Remove(testDir)
	assert.NoError(t, err)
	testDirSub := filepath.Join(testDir, "sub")
	err = os.MkdirAll(testDirSub, os.ModePerm)
	assert.NoError(t, err)
	err = c.RemoveDir(testDir, "/testDir")
	assert.Error(t, err)
	err = os.RemoveAll(testDirSub)
	assert.NoError(t, err)
	err = c.RemoveDir(testDir, "/testDir")
	assert.NoError(t, err)

	err = c.RemoveDir(testDir, "/testDir")
	assert.Error(t, err)

	fs = newMockOsFs(true, "", user.GetHomeDir())
	c.Fs = fs
	err = c.RemoveDir(testDir, "/testDir")
	assert.NoError(t, err)

	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRename(t *testing.T) {
	user := dataprovider.User{
		Username:  userTestUsername,
		HomeDir:   filepath.Join(os.TempDir(), "home"),
		QuotaSize: 10485760,
	}
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Permissions["/sub"] = []string{dataprovider.PermListItems}
	user.Permissions["/sub1"] = []string{dataprovider.PermRename}
	user.Permissions["/dir"] = []string{dataprovider.PermListItems}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1/sub",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: "/vdir2",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	err := os.MkdirAll(filepath.Join(user.GetHomeDir(), "sub"), os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(filepath.Join(user.GetHomeDir(), "dir", "sub"), os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	err = c.Rename(mappedPath1, "", "", "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.Rename("", mappedPath2, "", "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.Rename("missing", "", "", "")
	assert.Error(t, err)
	testFile := filepath.Join(user.GetHomeDir(), "file")
	err = ioutil.WriteFile(testFile, []byte("data"), os.ModePerm)
	assert.NoError(t, err)
	testSubFile := filepath.Join(user.GetHomeDir(), "sub", "file")
	err = ioutil.WriteFile(testSubFile, []byte("data"), os.ModePerm)
	assert.NoError(t, err)
	err = c.Rename(testSubFile, filepath.Join(user.GetHomeDir(), "file"), "/sub/file", "/file")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.Rename(testFile, filepath.Join(user.GetHomeDir(), "sub"), "/file", "/sub")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetOpUnsupportedError().Error())
	}
	err = c.Rename(testSubFile, testFile, "/file", "/sub1/file")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.Rename(filepath.Join(user.GetHomeDir(), "sub"), filepath.Join(user.GetHomeDir(), "adir"), "/vdir1", "/adir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetOpUnsupportedError().Error())
	}
	err = c.Rename(filepath.Join(user.GetHomeDir(), "dir"), filepath.Join(user.GetHomeDir(), "adir"), "/dir", "/adir")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = os.MkdirAll(filepath.Join(user.GetHomeDir(), "testdir"), os.ModePerm)
	assert.NoError(t, err)
	err = c.Rename(filepath.Join(user.GetHomeDir(), "testdir"), filepath.Join(user.GetHomeDir(), "tdir", "sub"), "/testdir", "/tdir/sub")
	assert.Error(t, err)
	err = os.Remove(testSubFile)
	assert.NoError(t, err)
	err = c.Rename(filepath.Join(user.GetHomeDir(), "sub"), filepath.Join(user.GetHomeDir(), "adir"), "/sub", "/adir")
	assert.NoError(t, err)
	err = os.MkdirAll(filepath.Join(user.GetHomeDir(), "adir"), os.ModePerm)
	assert.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(user.GetHomeDir(), "adir", "file"), []byte("data"), os.ModePerm)
	assert.NoError(t, err)
	err = c.Rename(filepath.Join(user.GetHomeDir(), "adir", "file"), filepath.Join(user.GetHomeDir(), "file"), "/adir/file", "/file")
	assert.NoError(t, err)
	// rename between virtual folder this should fail since the virtual folder is not found inside the data provider
	// and so the remaining space cannot be computed
	err = c.Rename(filepath.Join(user.GetHomeDir(), "adir"), filepath.Join(user.GetHomeDir(), "another"), "/vdir1/sub/a", "/vdir2/b")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetGenericError(err).Error())
	}

	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestCreateSymlink(t *testing.T) {
	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
	}
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Permissions["/sub"] = []string{dataprovider.PermListItems}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: "/vdir2",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	err := os.Mkdir(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	err = c.CreateSymlink(user.GetHomeDir(), mappedPath1, "/", "/vdir1")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.CreateSymlink(filepath.Join(user.GetHomeDir(), "a"), mappedPath1, "/a", "/vdir1")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.CreateSymlink(filepath.Join(user.GetHomeDir(), "b"), mappedPath1, "/b", "/sub/b")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.CreateSymlink(filepath.Join(user.GetHomeDir(), "b"), mappedPath1, "/vdir1/b", "/vdir2/b")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetOpUnsupportedError().Error())
	}
	err = c.CreateSymlink(mappedPath1, filepath.Join(mappedPath1, "b"), "/vdir1/a", "/vdir1/b")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.CreateSymlink(filepath.Join(mappedPath1, "b"), mappedPath1, "/vdir1/a", "/vdir1/b")
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}

	err = os.Mkdir(filepath.Join(user.GetHomeDir(), "b"), os.ModePerm)
	assert.NoError(t, err)
	err = c.CreateSymlink(filepath.Join(user.GetHomeDir(), "b"), filepath.Join(user.GetHomeDir(), "c"), "/b", "/c")
	assert.NoError(t, err)
	err = c.CreateSymlink(filepath.Join(user.GetHomeDir(), "b"), filepath.Join(user.GetHomeDir(), "c"), "/b", "/c")
	assert.Error(t, err)

	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDoStat(t *testing.T) {
	testFile := filepath.Join(os.TempDir(), "afile.txt")
	fs := vfs.NewOsFs("123", os.TempDir(), nil)
	u := dataprovider.User{
		Username: "user",
		HomeDir:  os.TempDir(),
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	err := ioutil.WriteFile(testFile, []byte("data"), os.ModePerm)
	require.NoError(t, err)
	err = os.Symlink(testFile, testFile+".sym")
	require.NoError(t, err)
	conn := NewBaseConnection(fs.ConnectionID(), ProtocolSFTP, u, fs)
	infoStat, err := conn.DoStat(testFile+".sym", 0)
	if assert.NoError(t, err) {
		assert.Equal(t, int64(4), infoStat.Size())
	}
	infoLstat, err := conn.DoStat(testFile+".sym", 1)
	if assert.NoError(t, err) {
		assert.NotEqual(t, int64(4), infoLstat.Size())
	}
	assert.False(t, os.SameFile(infoStat, infoLstat))

	fs, err = vfs.NewCryptFs(fs.ConnectionID(), os.TempDir(), vfs.CryptFsConfig{
		Passphrase: kms.NewPlainSecret("payload"),
	})
	assert.NoError(t, err)
	conn = NewBaseConnection(fs.ConnectionID(), ProtocolFTP, u, fs)
	dataSize := int64(32768)
	data := make([]byte, dataSize)
	err = ioutil.WriteFile(testFile, data, os.ModePerm)
	assert.NoError(t, err)
	infoStat, err = conn.DoStat(testFile, 0)
	assert.NoError(t, err)
	assert.Less(t, infoStat.Size(), dataSize)
	encSize, err := sio.EncryptedSize(uint64(infoStat.Size()))
	assert.NoError(t, err)
	assert.Equal(t, int64(encSize)+33, dataSize)

	err = os.Remove(testFile)
	assert.NoError(t, err)
	err = os.Remove(testFile + ".sym")
	assert.NoError(t, err)
	assert.Len(t, conn.GetTransfers(), 0)
}

func TestSetStat(t *testing.T) {
	oldSetStatMode := Config.SetstatMode
	Config.SetstatMode = 1
	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Permissions["/dir1"] = []string{dataprovider.PermChmod}
	user.Permissions["/dir2"] = []string{dataprovider.PermChown}
	user.Permissions["/dir3"] = []string{dataprovider.PermChtimes}
	dir1 := filepath.Join(user.GetHomeDir(), "dir1")
	dir2 := filepath.Join(user.GetHomeDir(), "dir2")
	dir3 := filepath.Join(user.GetHomeDir(), "dir3")
	err := os.Mkdir(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(dir1, os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(dir2, os.ModePerm)
	assert.NoError(t, err)
	err = os.Mkdir(dir3, os.ModePerm)
	assert.NoError(t, err)

	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	err = c.SetStat(user.GetHomeDir(), "/", &StatAttributes{})
	assert.NoError(t, err)

	err = c.SetStat(dir2, "/dir1/file", &StatAttributes{
		Mode:  os.ModePerm,
		Flags: StatAttrPerms,
	})
	assert.NoError(t, err)
	err = c.SetStat(dir1, "/dir2/file", &StatAttributes{
		UID:   os.Getuid(),
		GID:   os.Getgid(),
		Flags: StatAttrUIDGID,
	})
	assert.NoError(t, err)
	err = c.SetStat(dir1, "/dir3/file", &StatAttributes{
		Atime: time.Now(),
		Mtime: time.Now(),
		Flags: StatAttrTimes,
	})
	assert.NoError(t, err)

	Config.SetstatMode = 2
	assert.False(t, c.ignoreSetStat())
	c1 := NewBaseConnection("", ProtocolSFTP, user, newMockOsFs(false, fs.ConnectionID(), user.GetHomeDir()))
	assert.True(t, c1.ignoreSetStat())

	Config.SetstatMode = oldSetStatMode
	// chmod
	err = c.SetStat(dir1, "/dir1/file", &StatAttributes{
		Mode:  os.ModePerm,
		Flags: StatAttrPerms,
	})
	assert.NoError(t, err)
	err = c.SetStat(dir2, "/dir2/file", &StatAttributes{
		Mode:  os.ModePerm,
		Flags: StatAttrPerms,
	})
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.SetStat(filepath.Join(user.GetHomeDir(), "missing"), "/missing", &StatAttributes{
		Mode:  os.ModePerm,
		Flags: StatAttrPerms,
	})
	assert.Error(t, err)
	// chown
	if runtime.GOOS != osWindows {
		err = c.SetStat(dir1, "/dir2/file", &StatAttributes{
			UID:   os.Getuid(),
			GID:   os.Getgid(),
			Flags: StatAttrUIDGID,
		})
		assert.NoError(t, err)
	}

	err = c.SetStat(dir1, "/dir3/file", &StatAttributes{
		UID:   os.Getuid(),
		GID:   os.Getgid(),
		Flags: StatAttrUIDGID,
	})
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}

	err = c.SetStat(filepath.Join(user.GetHomeDir(), "missing"), "/missing", &StatAttributes{
		UID:   os.Getuid(),
		GID:   os.Getgid(),
		Flags: StatAttrUIDGID,
	})
	assert.Error(t, err)
	// chtimes
	err = c.SetStat(dir1, "/dir3/file", &StatAttributes{
		Atime: time.Now(),
		Mtime: time.Now(),
		Flags: StatAttrTimes,
	})
	assert.NoError(t, err)
	err = c.SetStat(dir1, "/dir1/file", &StatAttributes{
		Atime: time.Now(),
		Mtime: time.Now(),
		Flags: StatAttrTimes,
	})
	if assert.Error(t, err) {
		assert.EqualError(t, err, c.GetPermissionDeniedError().Error())
	}
	err = c.SetStat(filepath.Join(user.GetHomeDir(), "missing"), "/missing", &StatAttributes{
		Atime: time.Now(),
		Mtime: time.Now(),
		Flags: StatAttrTimes,
	})
	assert.Error(t, err)
	// truncate
	err = c.SetStat(filepath.Join(user.GetHomeDir(), "/missing/missing"), "/missing/missing", &StatAttributes{
		Size:  1,
		Flags: StatAttrSize,
	})
	assert.Error(t, err)
	err = c.SetStat(filepath.Join(dir3, "afile.txt"), "/dir3/afile.txt", &StatAttributes{
		Size:  1,
		Flags: StatAttrSize,
	})
	assert.Error(t, err)

	filePath := filepath.Join(user.GetHomeDir(), "afile.txt")
	err = ioutil.WriteFile(filePath, []byte("hello"), os.ModePerm)
	assert.NoError(t, err)
	err = c.SetStat(filePath, "/afile.txt", &StatAttributes{
		Flags: StatAttrSize,
		Size:  1,
	})
	assert.NoError(t, err)
	fi, err := os.Stat(filePath)
	if assert.NoError(t, err) {
		assert.Equal(t, int64(1), fi.Size())
	}

	vDir := filepath.Join(os.TempDir(), "vdir")
	err = os.MkdirAll(vDir, os.ModePerm)
	assert.NoError(t, err)
	c.User.VirtualFolders = nil
	c.User.VirtualFolders = append(c.User.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: vDir,
		},
		VirtualPath: "/vpath",
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})

	filePath = filepath.Join(vDir, "afile.txt")
	err = ioutil.WriteFile(filePath, []byte("hello"), os.ModePerm)
	assert.NoError(t, err)
	err = c.SetStat(filePath, "/vpath/afile.txt", &StatAttributes{
		Flags: StatAttrSize,
		Size:  1,
	})
	assert.NoError(t, err)
	fi, err = os.Stat(filePath)
	if assert.NoError(t, err) {
		assert.Equal(t, int64(1), fi.Size())
	}

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(vDir)
	assert.NoError(t, err)
}

func TestSpaceForCrossRename(t *testing.T) {
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	user := dataprovider.User{
		Username:    userTestUsername,
		Permissions: permissions,
		HomeDir:     filepath.Clean(os.TempDir()),
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	conn := NewBaseConnection("", ProtocolSFTP, user, fs)
	quotaResult := vfs.QuotaCheckResult{
		HasSpace: true,
	}
	assert.False(t, conn.hasSpaceForCrossRename(quotaResult, -1, filepath.Join(os.TempDir(), "a missing file")))
	if runtime.GOOS != osWindows {
		testDir := filepath.Join(os.TempDir(), "dir")
		err = os.MkdirAll(testDir, os.ModePerm)
		assert.NoError(t, err)
		err = ioutil.WriteFile(filepath.Join(testDir, "afile.txt"), []byte("content"), os.ModePerm)
		assert.NoError(t, err)
		err = os.Chmod(testDir, 0001)
		assert.NoError(t, err)
		assert.False(t, conn.hasSpaceForCrossRename(quotaResult, -1, testDir))
		err = os.Chmod(testDir, os.ModePerm)
		assert.NoError(t, err)
		err = os.RemoveAll(testDir)
		assert.NoError(t, err)
	}

	testFile := filepath.Join(os.TempDir(), "afile.txt")
	err = ioutil.WriteFile(testFile, []byte("test data"), os.ModePerm)
	assert.NoError(t, err)
	quotaResult = vfs.QuotaCheckResult{
		HasSpace:  false,
		QuotaSize: 0,
	}
	assert.True(t, conn.hasSpaceForCrossRename(quotaResult, 123, testFile))

	quotaResult = vfs.QuotaCheckResult{
		HasSpace:  false,
		QuotaSize: 124,
		UsedSize:  125,
	}
	assert.False(t, conn.hasSpaceForCrossRename(quotaResult, 8, testFile))

	quotaResult = vfs.QuotaCheckResult{
		HasSpace:  false,
		QuotaSize: 124,
		UsedSize:  124,
	}
	assert.True(t, conn.hasSpaceForCrossRename(quotaResult, 123, testFile))

	quotaResult = vfs.QuotaCheckResult{
		HasSpace:  true,
		QuotaSize: 10,
		UsedSize:  1,
	}
	assert.True(t, conn.hasSpaceForCrossRename(quotaResult, -1, testFile))

	quotaResult = vfs.QuotaCheckResult{
		HasSpace:  true,
		QuotaSize: 7,
		UsedSize:  0,
	}
	assert.False(t, conn.hasSpaceForCrossRename(quotaResult, -1, testFile))

	err = os.Remove(testFile)
	assert.NoError(t, err)

	testDir := filepath.Join(os.TempDir(), "testDir")
	err = os.MkdirAll(testDir, os.ModePerm)
	assert.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(testDir, "1"), []byte("1"), os.ModePerm)
	assert.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(testDir, "2"), []byte("2"), os.ModePerm)
	assert.NoError(t, err)
	quotaResult = vfs.QuotaCheckResult{
		HasSpace:   true,
		QuotaFiles: 2,
		UsedFiles:  1,
	}
	assert.False(t, conn.hasSpaceForCrossRename(quotaResult, -1, testDir))

	quotaResult = vfs.QuotaCheckResult{
		HasSpace:   true,
		QuotaFiles: 2,
		UsedFiles:  0,
	}
	assert.True(t, conn.hasSpaceForCrossRename(quotaResult, -1, testDir))

	err = os.RemoveAll(testDir)
	assert.NoError(t, err)
}

func TestRenamePermission(t *testing.T) {
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	permissions["/dir1"] = []string{dataprovider.PermRename}
	permissions["/dir2"] = []string{dataprovider.PermUpload}
	permissions["/dir3"] = []string{dataprovider.PermDelete}
	permissions["/dir4"] = []string{dataprovider.PermListItems}
	permissions["/dir5"] = []string{dataprovider.PermCreateDirs, dataprovider.PermUpload}
	permissions["/dir6"] = []string{dataprovider.PermCreateDirs, dataprovider.PermUpload,
		dataprovider.PermListItems, dataprovider.PermCreateSymlinks}
	permissions["/dir7"] = []string{dataprovider.PermAny}
	permissions["/dir8"] = []string{dataprovider.PermAny}

	user := dataprovider.User{
		Username:    userTestUsername,
		Permissions: permissions,
		HomeDir:     os.TempDir(),
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	conn := NewBaseConnection("", ProtocolSFTP, user, fs)
	request := sftp.NewRequest("Rename", "/testfile")
	request.Target = "/dir1/testfile"
	// rename is granted on Source and Target
	assert.True(t, conn.isRenamePermitted("", request.Filepath, request.Target, nil))
	request.Target = "/dir4/testfile"
	// rename is not granted on Target
	assert.False(t, conn.isRenamePermitted("", request.Filepath, request.Target, nil))
	request = sftp.NewRequest("Rename", "/dir1/testfile")
	request.Target = "/dir2/testfile" //nolint:goconst
	// rename is granted on Source but not on Target
	assert.False(t, conn.isRenamePermitted("", request.Filepath, request.Target, nil))
	request = sftp.NewRequest("Rename", "/dir4/testfile")
	request.Target = "/dir1/testfile"
	// rename is granted on Target but not on Source
	assert.False(t, conn.isRenamePermitted("", request.Filepath, request.Target, nil))
	request = sftp.NewRequest("Rename", "/dir4/testfile")
	request.Target = "/testfile"
	// rename is granted on Target but not on Source
	assert.False(t, conn.isRenamePermitted("", request.Filepath, request.Target, nil))
	request = sftp.NewRequest("Rename", "/dir3/testfile")
	request.Target = "/dir2/testfile"
	// delete is granted on Source and Upload on Target, the target is a file this is enough
	assert.True(t, conn.isRenamePermitted("", request.Filepath, request.Target, nil))
	request = sftp.NewRequest("Rename", "/dir2/testfile")
	request.Target = "/dir3/testfile"
	assert.False(t, conn.isRenamePermitted("", request.Filepath, request.Target, nil))
	tmpDir := filepath.Join(os.TempDir(), "dir")
	tmpDirLink := filepath.Join(os.TempDir(), "link")
	err = os.Mkdir(tmpDir, os.ModePerm)
	assert.NoError(t, err)
	err = os.Symlink(tmpDir, tmpDirLink)
	assert.NoError(t, err)
	request.Filepath = "/dir"
	request.Target = "/dir2/dir"
	// the source is a dir and the target has no createDirs perm
	info, err := os.Lstat(tmpDir)
	if assert.NoError(t, err) {
		assert.False(t, conn.isRenamePermitted(tmpDir, request.Filepath, request.Target, info))
		conn.User.Permissions["/dir2"] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
		// the source is a dir and the target has createDirs perm
		assert.True(t, conn.isRenamePermitted(tmpDir, request.Filepath, request.Target, info))

		request = sftp.NewRequest("Rename", "/testfile")
		request.Target = "/dir5/testfile"
		// the source is a dir and the target has createDirs and upload perm
		assert.True(t, conn.isRenamePermitted(tmpDir, request.Filepath, request.Target, info))
	}
	info, err = os.Lstat(tmpDirLink)
	if assert.NoError(t, err) {
		assert.True(t, info.Mode()&os.ModeSymlink != 0)
		// the source is a symlink and the target has createDirs and upload perm
		assert.False(t, conn.isRenamePermitted(tmpDir, request.Filepath, request.Target, info))
	}
	err = os.RemoveAll(tmpDir)
	assert.NoError(t, err)
	err = os.Remove(tmpDirLink)
	assert.NoError(t, err)
	conn.User.VirtualFolders = append(conn.User.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: os.TempDir(),
		},
		VirtualPath: "/dir1",
	})
	request = sftp.NewRequest("Rename", "/dir1")
	request.Target = "/dir2/testfile"
	// renaming a virtual folder is not allowed
	assert.False(t, conn.isRenamePermitted("", request.Filepath, request.Target, nil))
	err = conn.checkRecursiveRenameDirPermissions("invalid", "invalid")
	assert.Error(t, err)
	dir3 := filepath.Join(conn.User.HomeDir, "dir3")
	dir6 := filepath.Join(conn.User.HomeDir, "dir6")
	err = os.MkdirAll(filepath.Join(dir3, "subdir"), os.ModePerm)
	assert.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(dir3, "subdir", "testfile"), []byte("test"), os.ModePerm)
	assert.NoError(t, err)
	err = conn.checkRecursiveRenameDirPermissions(dir3, dir6)
	assert.NoError(t, err)
	err = os.RemoveAll(dir3)
	assert.NoError(t, err)

	dir7 := filepath.Join(conn.User.HomeDir, "dir7")
	dir8 := filepath.Join(conn.User.HomeDir, "dir8")
	err = os.MkdirAll(filepath.Join(dir8, "subdir"), os.ModePerm)
	assert.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(dir8, "subdir", "testfile"), []byte("test"), os.ModePerm)
	assert.NoError(t, err)
	err = conn.checkRecursiveRenameDirPermissions(dir8, dir7)
	assert.NoError(t, err)
	err = os.RemoveAll(dir8)
	assert.NoError(t, err)

	assert.False(t, conn.isRenamePermitted(user.GetHomeDir(), "", "", nil))

	conn.User.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/p",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{".zip"},
		},
	}
	testFile := filepath.Join(user.HomeDir, "testfile")
	err = ioutil.WriteFile(testFile, []byte("data"), os.ModePerm)
	assert.NoError(t, err)
	info, err = os.Stat(testFile)
	assert.NoError(t, err)
	assert.False(t, conn.isRenamePermitted(dir7, "/file", "/p/file.zip", info))
	err = os.Remove(testFile)
	assert.NoError(t, err)
}

func TestHasSpaceForRename(t *testing.T) {
	err := closeDataprovider()
	assert.NoError(t, err)
	_, err = initializeDataprovider(0)
	assert.NoError(t, err)

	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir1",
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir2",
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	fs, err := user.GetFilesystem("id")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	// with quota tracking disabled hasSpaceForRename will always return true
	assert.True(t, c.hasSpaceForRename("", "", 0, ""))
	quotaResult := c.HasSpace(true, "")
	assert.True(t, quotaResult.HasSpace)

	err = closeDataprovider()
	assert.NoError(t, err)
	_, err = initializeDataprovider(-1)
	assert.NoError(t, err)

	// rename inside the same mapped path
	assert.True(t, c.hasSpaceForRename("/vdir1/file", "/vdir2/file", 0, filepath.Join(mappedPath, "file")))
	// rename between user root dir and a virtual folder included in user quota
	assert.True(t, c.hasSpaceForRename("/file", "/vdir2/file", 0, filepath.Join(mappedPath, "file")))

	assert.True(t, c.isCrossFoldersRequest("/file", "/vdir2/file"))
}

func TestUpdateQuotaAfterRename(t *testing.T) {
	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
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
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	request := sftp.NewRequest("Rename", "/testfile")
	if runtime.GOOS != osWindows {
		request.Filepath = "/dir"
		request.Target = path.Join("/vdir", "dir")
		testDirPath := filepath.Join(mappedPath, "dir")
		err := os.MkdirAll(testDirPath, os.ModePerm)
		assert.NoError(t, err)
		err = os.Chmod(testDirPath, 0001)
		assert.NoError(t, err)
		err = c.updateQuotaAfterRename(request.Filepath, request.Target, testDirPath, 0)
		assert.Error(t, err)
		err = os.Chmod(testDirPath, os.ModePerm)
		assert.NoError(t, err)
	}
	testFile1 := "/testfile1"
	request.Target = testFile1
	request.Filepath = path.Join("/vdir", "file")
	err = c.updateQuotaAfterRename(request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 0)
	assert.Error(t, err)
	err = ioutil.WriteFile(filepath.Join(mappedPath, "file"), []byte("test content"), os.ModePerm)
	assert.NoError(t, err)
	request.Filepath = testFile1
	request.Target = path.Join("/vdir", "file")
	err = c.updateQuotaAfterRename(request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 12)
	assert.NoError(t, err)
	err = ioutil.WriteFile(filepath.Join(user.GetHomeDir(), "testfile1"), []byte("test content"), os.ModePerm)
	assert.NoError(t, err)
	request.Target = testFile1
	request.Filepath = path.Join("/vdir", "file")
	err = c.updateQuotaAfterRename(request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 12)
	assert.NoError(t, err)
	request.Target = path.Join("/vdir1", "file")
	request.Filepath = path.Join("/vdir", "file")
	err = c.updateQuotaAfterRename(request.Filepath, request.Target, filepath.Join(mappedPath, "file"), 12)
	assert.NoError(t, err)

	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestHasSpace(t *testing.T) {
	user := dataprovider.User{
		Username: userTestUsername,
		HomeDir:  filepath.Join(os.TempDir(), "home"),
		Password: userTestPwd,
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
	fs, err := user.GetFilesystem("id")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	quotaResult := c.HasSpace(true, "/")
	assert.True(t, quotaResult.HasSpace)

	user.VirtualFolders[0].QuotaFiles = 0
	user.VirtualFolders[0].QuotaSize = 0
	err = dataprovider.AddUser(user)
	assert.NoError(t, err)
	user, err = dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	c.User = user
	quotaResult = c.HasSpace(true, "/vdir/file")
	assert.True(t, quotaResult.HasSpace)

	user.VirtualFolders[0].QuotaFiles = 10
	user.VirtualFolders[0].QuotaSize = 1048576
	err = dataprovider.UpdateUser(user)
	assert.NoError(t, err)
	c.User = user
	quotaResult = c.HasSpace(true, "/vdir/file1")
	assert.True(t, quotaResult.HasSpace)

	quotaResult = c.HasSpace(true, "/file")
	assert.True(t, quotaResult.HasSpace)

	folder, err := dataprovider.GetFolderByPath(mappedPath)
	assert.NoError(t, err)
	err = dataprovider.UpdateVirtualFolderQuota(folder, 10, 1048576, true)
	assert.NoError(t, err)
	quotaResult = c.HasSpace(true, "/vdir/file1")
	assert.False(t, quotaResult.HasSpace)

	err = dataprovider.DeleteUser(user)
	assert.NoError(t, err)

	err = dataprovider.DeleteFolder(folder)
	assert.NoError(t, err)
}

func TestUpdateQuotaMoveVFolders(t *testing.T) {
	user := dataprovider.User{
		Username:   userTestUsername,
		HomeDir:    filepath.Join(os.TempDir(), "home"),
		Password:   userTestPwd,
		QuotaFiles: 100,
	}
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: "/vdir2",
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	err := dataprovider.AddUser(user)
	assert.NoError(t, err)
	user, err = dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	folder1, err := dataprovider.GetFolderByPath(mappedPath1)
	assert.NoError(t, err)
	folder2, err := dataprovider.GetFolderByPath(mappedPath2)
	assert.NoError(t, err)
	err = dataprovider.UpdateVirtualFolderQuota(folder1, 1, 100, true)
	assert.NoError(t, err)
	err = dataprovider.UpdateVirtualFolderQuota(folder2, 2, 150, true)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("id")
	assert.NoError(t, err)
	c := NewBaseConnection("", ProtocolSFTP, user, fs)
	c.updateQuotaMoveBetweenVFolders(user.VirtualFolders[0], user.VirtualFolders[1], -1, 100, 1)
	folder1, err = dataprovider.GetFolderByPath(mappedPath1)
	assert.NoError(t, err)
	assert.Equal(t, 0, folder1.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder1.UsedQuotaSize)
	folder2, err = dataprovider.GetFolderByPath(mappedPath2)
	assert.NoError(t, err)
	assert.Equal(t, 3, folder2.UsedQuotaFiles)
	assert.Equal(t, int64(250), folder2.UsedQuotaSize)

	c.updateQuotaMoveBetweenVFolders(user.VirtualFolders[1], user.VirtualFolders[0], 10, 100, 1)
	folder1, err = dataprovider.GetFolderByPath(mappedPath1)
	assert.NoError(t, err)
	assert.Equal(t, 0, folder1.UsedQuotaFiles)
	assert.Equal(t, int64(90), folder1.UsedQuotaSize)
	folder2, err = dataprovider.GetFolderByPath(mappedPath2)
	assert.NoError(t, err)
	assert.Equal(t, 2, folder2.UsedQuotaFiles)
	assert.Equal(t, int64(150), folder2.UsedQuotaSize)

	err = dataprovider.UpdateUserQuota(user, 1, 100, true)
	assert.NoError(t, err)
	c.updateQuotaMoveFromVFolder(user.VirtualFolders[1], -1, 50, 1)
	folder2, err = dataprovider.GetFolderByPath(mappedPath2)
	assert.NoError(t, err)
	assert.Equal(t, 1, folder2.UsedQuotaFiles)
	assert.Equal(t, int64(100), folder2.UsedQuotaSize)
	user, err = dataprovider.GetUserByID(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, 1, user.UsedQuotaFiles)
	assert.Equal(t, int64(100), user.UsedQuotaSize)

	c.updateQuotaMoveToVFolder(user.VirtualFolders[1], -1, 100, 1)
	folder2, err = dataprovider.GetFolderByPath(mappedPath2)
	assert.NoError(t, err)
	assert.Equal(t, 2, folder2.UsedQuotaFiles)
	assert.Equal(t, int64(200), folder2.UsedQuotaSize)
	user, err = dataprovider.GetUserByID(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, 1, user.UsedQuotaFiles)
	assert.Equal(t, int64(100), user.UsedQuotaSize)

	err = dataprovider.DeleteUser(user)
	assert.NoError(t, err)
	err = dataprovider.DeleteFolder(folder1)
	assert.NoError(t, err)
	err = dataprovider.DeleteFolder(folder2)
	assert.NoError(t, err)
}

func TestErrorsMapping(t *testing.T) {
	fs := vfs.NewOsFs("", os.TempDir(), nil)
	conn := NewBaseConnection("", ProtocolSFTP, dataprovider.User{}, fs)
	for _, protocol := range supportedProtocols {
		conn.SetProtocol(protocol)
		err := conn.GetFsError(os.ErrNotExist)
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxNoSuchFile.Error())
		} else if protocol == ProtocolWebDAV {
			assert.EqualError(t, err, os.ErrNotExist.Error())
		} else {
			assert.EqualError(t, err, ErrNotExist.Error())
		}
		err = conn.GetFsError(os.ErrPermission)
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxPermissionDenied.Error())
		} else {
			assert.EqualError(t, err, ErrPermissionDenied.Error())
		}
		err = conn.GetFsError(os.ErrClosed)
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxFailure.Error())
		} else {
			assert.EqualError(t, err, ErrGenericFailure.Error())
		}
		err = conn.GetFsError(ErrPermissionDenied)
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxFailure.Error())
		} else {
			assert.EqualError(t, err, ErrPermissionDenied.Error())
		}
		err = conn.GetFsError(vfs.ErrVfsUnsupported)
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxOpUnsupported.Error())
		} else {
			assert.EqualError(t, err, ErrOpUnsupported.Error())
		}
		err = conn.GetFsError(nil)
		assert.NoError(t, err)
		err = conn.GetOpUnsupportedError()
		if protocol == ProtocolSFTP {
			assert.EqualError(t, err, sftp.ErrSSHFxOpUnsupported.Error())
		} else {
			assert.EqualError(t, err, ErrOpUnsupported.Error())
		}
	}
}

func TestMaxWriteSize(t *testing.T) {
	permissions := make(map[string][]string)
	permissions["/"] = []string{dataprovider.PermAny}
	user := dataprovider.User{
		Username:    userTestUsername,
		Permissions: permissions,
		HomeDir:     filepath.Clean(os.TempDir()),
	}
	fs, err := user.GetFilesystem("123")
	assert.NoError(t, err)
	conn := NewBaseConnection("", ProtocolFTP, user, fs)
	quotaResult := vfs.QuotaCheckResult{
		HasSpace: true,
	}
	size, err := conn.GetMaxWriteSize(quotaResult, false, 0)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), size)

	conn.User.Filters.MaxUploadFileSize = 100
	size, err = conn.GetMaxWriteSize(quotaResult, false, 0)
	assert.NoError(t, err)
	assert.Equal(t, int64(100), size)

	quotaResult.QuotaSize = 1000
	size, err = conn.GetMaxWriteSize(quotaResult, false, 50)
	assert.NoError(t, err)
	assert.Equal(t, int64(100), size)

	quotaResult.QuotaSize = 1000
	quotaResult.UsedSize = 990
	size, err = conn.GetMaxWriteSize(quotaResult, false, 50)
	assert.NoError(t, err)
	assert.Equal(t, int64(60), size)

	quotaResult.QuotaSize = 0
	quotaResult.UsedSize = 0
	size, err = conn.GetMaxWriteSize(quotaResult, true, 100)
	assert.EqualError(t, err, ErrQuotaExceeded.Error())
	assert.Equal(t, int64(0), size)

	size, err = conn.GetMaxWriteSize(quotaResult, true, 10)
	assert.NoError(t, err)
	assert.Equal(t, int64(90), size)

	conn.Fs = newMockOsFs(true, fs.ConnectionID(), user.GetHomeDir())
	size, err = conn.GetMaxWriteSize(quotaResult, true, 100)
	assert.EqualError(t, err, ErrOpUnsupported.Error())
	assert.Equal(t, int64(0), size)
}
