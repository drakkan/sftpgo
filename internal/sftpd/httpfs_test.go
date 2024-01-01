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

package sftpd_test

import (
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpdtest"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	httpFsPort            = 12345
	defaultHTTPFsUsername = "httpfs_user"
)

var (
	httpFsSocketPath = filepath.Join(os.TempDir(), "httpfs.sock")
)

func TestBasicHTTPFsHandling(t *testing.T) {
	usePubKey := true
	u := getTestUserWithHTTPFs(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		expectedQuotaSize := user.UsedQuotaSize + testFileSize*2
		expectedQuotaFiles := user.UsedQuotaFiles + 2
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join("/missing_dir", testFileName), testFileSize, client)
		assert.Error(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		info, err := client.Stat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, info.Size())
		}
		contents, err := client.ReadDir("/")
		assert.NoError(t, err)
		if assert.Len(t, contents, 1) {
			assert.Equal(t, testFileName, contents[0].Name())
		}
		dirName := "test dirname"
		err = client.Mkdir(dirName)
		assert.NoError(t, err)
		contents, err = client.ReadDir(".")
		assert.NoError(t, err)
		assert.Len(t, contents, 2)
		contents, err = client.ReadDir(dirName)
		assert.NoError(t, err)
		assert.Len(t, contents, 0)
		err = sftpUploadFile(testFilePath, path.Join(dirName, testFileName), testFileSize, client)
		assert.NoError(t, err)
		contents, err = client.ReadDir(dirName)
		assert.NoError(t, err)
		assert.Len(t, contents, 1)
		dirRenamed := dirName + "_renamed"
		err = client.Rename(dirName, dirRenamed)
		assert.NoError(t, err)
		info, err = client.Stat(dirRenamed)
		if assert.NoError(t, err) {
			assert.True(t, info.IsDir())
		}
		// mode 0666 and 0444 works on Windows too
		newPerm := os.FileMode(0444)
		err = client.Chmod(testFileName, newPerm)
		assert.NoError(t, err)
		info, err = client.Stat(testFileName)
		assert.NoError(t, err)
		assert.Equal(t, newPerm, info.Mode().Perm())
		newPerm = os.FileMode(0666)
		err = client.Chmod(testFileName, newPerm)
		assert.NoError(t, err)
		info, err = client.Stat(testFileName)
		assert.NoError(t, err)
		assert.Equal(t, newPerm, info.Mode().Perm())
		// chtimes
		acmodTime := time.Now().Add(-36 * time.Hour)
		err = client.Chtimes(testFileName, acmodTime, acmodTime)
		assert.NoError(t, err)
		info, err = client.Stat(testFileName)
		if assert.NoError(t, err) {
			diff := math.Abs(info.ModTime().Sub(acmodTime).Seconds())
			assert.LessOrEqual(t, diff, float64(1))
		}
		_, err = client.StatVFS("/")
		assert.NoError(t, err)

		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		// execute a quota scan
		_, err = httpdtest.StartQuotaScan(user, http.StatusAccepted)
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			scans, _, err := httpdtest.GetQuotaScans(http.StatusOK)
			if err == nil {
				return len(scans) == 0
			}
			return false
		}, 1*time.Second, 50*time.Millisecond)

		err = client.Remove(testFileName)
		assert.NoError(t, err)
		_, err = client.Lstat(testFileName)
		assert.Error(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize-testFileSize, user.UsedQuotaSize)
		// truncate
		err = client.Truncate(path.Join(dirRenamed, testFileName), 100)
		assert.NoError(t, err)
		info, err = client.Stat(path.Join(dirRenamed, testFileName))
		if assert.NoError(t, err) {
			assert.Equal(t, int64(100), info.Size())
		}
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, int64(100), user.UsedQuotaSize)
		// update quota
		_, err = httpdtest.StartQuotaScan(user, http.StatusAccepted)
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			scans, _, err := httpdtest.GetQuotaScans(http.StatusOK)
			if err == nil {
				return len(scans) == 0
			}
			return false
		}, 1*time.Second, 50*time.Millisecond)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, int64(100), user.UsedQuotaSize)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestHTTPFsVirtualFolder(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	folderName := "httpfsfolder"
	vdirPath := "/vdir/http fs"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderName,
		},
		VirtualPath: vdirPath,
	})
	f := vfs.BaseVirtualFolder{
		Name: folderName,
		FsConfig: vfs.Filesystem{
			Provider: sdk.HTTPFilesystemProvider,
			HTTPConfig: vfs.HTTPFsConfig{
				BaseHTTPFsConfig: sdk.BaseHTTPFsConfig{
					Endpoint:          fmt.Sprintf("http://127.0.0.1:%d/api/v1", httpFsPort),
					Username:          defaultHTTPFsUsername,
					EqualityCheckMode: 1,
				},
			},
		},
	}
	_, _, err := httpdtest.AddFolder(f, http.StatusCreated)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath, testFileName), testFileSize, client)
		assert.NoError(t, err)
		_, err = client.Stat(path.Join(vdirPath, testFileName))
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(path.Join(vdirPath, testFileName), localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
}

func TestHTTPFsWalk(t *testing.T) {
	user := getTestUserWithHTTPFs(false)
	user.FsConfig.HTTPConfig.EqualityCheckMode = 1
	httpFs, err := user.GetFilesystem("")
	require.NoError(t, err)
	basePath := filepath.Join(os.TempDir(), "httpfs", user.FsConfig.HTTPConfig.Username)
	err = os.RemoveAll(basePath)
	assert.NoError(t, err)

	var walkedPaths []string
	err = httpFs.Walk("/", func(walkedPath string, _ fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		walkedPaths = append(walkedPaths, httpFs.GetRelativePath(walkedPath))
		return nil
	})
	require.NoError(t, err)
	require.Len(t, walkedPaths, 1)
	require.Contains(t, walkedPaths, "/")
	// now add some files/folders
	for i := 0; i < 10; i++ {
		err = os.WriteFile(filepath.Join(basePath, fmt.Sprintf("file%d", i)), nil, os.ModePerm)
		assert.NoError(t, err)
		err = os.Mkdir(filepath.Join(basePath, fmt.Sprintf("dir%d", i)), os.ModePerm)
		assert.NoError(t, err)
		for j := 0; j < 5; j++ {
			err = os.WriteFile(filepath.Join(basePath, fmt.Sprintf("dir%d", i), fmt.Sprintf("subfile%d", j)), nil, os.ModePerm)
			assert.NoError(t, err)
		}
	}
	walkedPaths = nil
	err = httpFs.Walk("/", func(walkedPath string, _ fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		walkedPaths = append(walkedPaths, httpFs.GetRelativePath(walkedPath))
		return nil
	})
	require.NoError(t, err)
	require.Len(t, walkedPaths, 71)
	require.Contains(t, walkedPaths, "/")
	for i := 0; i < 10; i++ {
		require.Contains(t, walkedPaths, path.Join("/", fmt.Sprintf("file%d", i)))
		require.Contains(t, walkedPaths, path.Join("/", fmt.Sprintf("dir%d", i)))
		for j := 0; j < 5; j++ {
			require.Contains(t, walkedPaths, path.Join("/", fmt.Sprintf("dir%d", i), fmt.Sprintf("subfile%d", j)))
		}
	}

	err = os.RemoveAll(basePath)
	assert.NoError(t, err)
}

func TestHTTPFsOverUNIXSocket(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("UNIX domain sockets are not supported on Windows")
	}
	assert.Eventually(t, func() bool {
		_, err := os.Stat(httpFsSocketPath)
		return err == nil
	}, 1*time.Second, 50*time.Millisecond)
	usePubKey := true
	u := getTestUserWithHTTPFs(usePubKey)
	u.FsConfig.HTTPConfig.Endpoint = fmt.Sprintf("http://unix?socket_path=%s&api_prefix=%s",
		url.QueryEscape(httpFsSocketPath), url.QueryEscape("/api/v1"))
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = client.Mkdir(testFileName)
		assert.NoError(t, err)
		err = client.RemoveDirectory(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func getTestUserWithHTTPFs(usePubKey bool) dataprovider.User {
	u := getTestUser(usePubKey)
	u.FsConfig.Provider = sdk.HTTPFilesystemProvider
	u.FsConfig.HTTPConfig = vfs.HTTPFsConfig{
		BaseHTTPFsConfig: sdk.BaseHTTPFsConfig{
			Endpoint: fmt.Sprintf("http://127.0.0.1:%d/api/v1", httpFsPort),
			Username: defaultHTTPFsUsername,
		},
	}
	return u
}

func startHTTPFs() {
	if runtime.GOOS != osWindows {
		go func() {
			if err := httpdtest.StartTestHTTPFsOverUnixSocket(httpFsSocketPath); err != nil {
				logger.ErrorToConsole("could not start HTTPfs test server over UNIX socket: %v", err)
				os.Exit(1)
			}
		}()
	}
	go func() {
		if err := httpdtest.StartTestHTTPFs(httpFsPort, nil); err != nil {
			logger.ErrorToConsole("could not start HTTPfs test server: %v", err)
			os.Exit(1)
		}
	}()
	waitTCPListening(fmt.Sprintf(":%d", httpFsPort))
}
