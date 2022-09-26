// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package common_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mhale/smtpd"
	"github.com/pkg/sftp"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/httpdtest"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	httpAddr            = "127.0.0.1:9999"
	httpProxyAddr       = "127.0.0.1:7777"
	sftpServerAddr      = "127.0.0.1:4022"
	smtpServerAddr      = "127.0.0.1:2525"
	defaultUsername     = "test_common_sftp"
	defaultPassword     = "test_password"
	defaultSFTPUsername = "test_common_sftpfs_user"
	osWindows           = "windows"
	testFileName        = "test_file_common_sftp.dat"
	testDir             = "test_dir_common"
)

var (
	configDir         = filepath.Join(".", "..", "..")
	allPerms          = []string{dataprovider.PermAny}
	homeBasePath      string
	logFilePath       string
	backupsPath       string
	testFileContent   = []byte("test data")
	lastReceivedEmail receivedEmail
)

func TestMain(m *testing.M) {
	homeBasePath = os.TempDir()
	logFilePath = filepath.Join(configDir, "common_test.log")
	backupsPath = filepath.Join(os.TempDir(), "backups")
	logger.InitLogger(logFilePath, 5, 1, 28, false, false, zerolog.DebugLevel)

	os.Setenv("SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", "1")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_USERNAME", "admin")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_PASSWORD", "password")
	err := config.LoadConfig(configDir, "")
	if err != nil {
		logger.ErrorToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	logger.InfoToConsole("Starting COMMON tests, provider: %v", providerConf.Driver)

	err = common.Initialize(config.GetCommonConfig(), 0)
	if err != nil {
		logger.WarnToConsole("error initializing common: %v", err)
		os.Exit(1)
	}

	err = dataprovider.Initialize(providerConf, configDir, true)
	if err != nil {
		logger.ErrorToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Timeout = 5
	httpConfig.RetryMax = 0
	httpConfig.Initialize(configDir) //nolint:errcheck
	kmsConfig := config.GetKMSConfig()
	err = kmsConfig.Initialize()
	if err != nil {
		logger.ErrorToConsole("error initializing kms: %v", err)
		os.Exit(1)
	}
	mfaConfig := config.GetMFAConfig()
	err = mfaConfig.Initialize()
	if err != nil {
		logger.ErrorToConsole("error initializing MFA: %v", err)
		os.Exit(1)
	}

	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Bindings[0].Port = 4022
	sftpdConf.Bindings = append(sftpdConf.Bindings, sftpd.Binding{
		Port: 4024,
	})
	sftpdConf.KeyboardInteractiveAuthentication = true

	httpdConf := config.GetHTTPDConfig()
	httpdConf.Bindings[0].Port = 4080
	httpdtest.SetBaseURL("http://127.0.0.1:4080")

	go func() {
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start SFTP server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir, 0); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(sftpdConf.Bindings[0].GetAddress())
	waitTCPListening(httpdConf.Bindings[0].GetAddress())

	go func() {
		// start a test HTTP server to receive action notifications
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "OK\n")
		})
		http.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Not found\n")
		})
		http.HandleFunc("/multipart", func(w http.ResponseWriter, r *http.Request) {
			err := r.ParseMultipartForm(1048576)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "KO\n")
				return
			}
			defer r.MultipartForm.RemoveAll() //nolint:errcheck
			fmt.Fprintf(w, "OK\n")
		})
		if err := http.ListenAndServe(httpAddr, nil); err != nil {
			logger.ErrorToConsole("could not start HTTP notification server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		common.Config.ProxyProtocol = 2
		listener, err := net.Listen("tcp", httpProxyAddr)
		if err != nil {
			logger.ErrorToConsole("error creating listener for proxy protocol server: %v", err)
			os.Exit(1)
		}
		proxyListener, err := common.Config.GetProxyListener(listener)
		if err != nil {
			logger.ErrorToConsole("error creating proxy protocol listener: %v", err)
			os.Exit(1)
		}
		common.Config.ProxyProtocol = 0

		s := &http.Server{}
		if err := s.Serve(proxyListener); err != nil {
			logger.ErrorToConsole("could not start HTTP proxy protocol server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := smtpd.ListenAndServe(smtpServerAddr, func(remoteAddr net.Addr, from string, to []string, data []byte) error {
			lastReceivedEmail.set(from, to, data)
			return nil
		}, "SFTPGo test", "localhost"); err != nil {
			logger.ErrorToConsole("could not start SMTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(httpAddr)
	waitTCPListening(httpProxyAddr)
	waitTCPListening(smtpServerAddr)

	exitCode := m.Run()
	os.Remove(logFilePath)
	os.RemoveAll(backupsPath)
	os.Exit(exitCode)
}

func TestBaseConnection(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		_, err = client.ReadDir(testDir)
		assert.ErrorIs(t, err, os.ErrNotExist)
		err = client.RemoveDirectory(testDir)
		assert.ErrorIs(t, err, os.ErrNotExist)
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = client.Mkdir(testDir)
		assert.Error(t, err)
		info, err := client.Stat(testDir)
		if assert.NoError(t, err) {
			assert.True(t, info.IsDir())
		}
		err = client.Rename(testDir, testDir)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "the rename source and target cannot be the same")
		}
		err = client.RemoveDirectory(testDir)
		assert.NoError(t, err)
		err = client.Remove(testFileName)
		assert.ErrorIs(t, err, os.ErrNotExist)
		f, err := client.Create(testFileName)
		assert.NoError(t, err)
		_, err = f.Write(testFileContent)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
		linkName := testFileName + ".link"
		err = client.Rename(testFileName, testFileName)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "the rename source and target cannot be the same")
		}
		err = client.Symlink(testFileName, linkName)
		assert.NoError(t, err)
		err = client.Symlink(testFileName, testFileName)
		assert.Error(t, err)
		info, err = client.Stat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, int64(len(testFileContent)), info.Size())
			assert.False(t, info.IsDir())
		}
		info, err = client.Lstat(linkName)
		if assert.NoError(t, err) {
			assert.NotEqual(t, int64(7), info.Size())
			assert.True(t, info.Mode()&os.ModeSymlink != 0)
			assert.False(t, info.IsDir())
		}
		err = client.RemoveDirectory(linkName)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
		}
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = client.Remove(linkName)
		assert.NoError(t, err)
		err = client.Rename(testFileName, "test")
		assert.ErrorIs(t, err, os.ErrNotExist)
		f, err = client.Create(testFileName)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+"1")
		assert.NoError(t, err)
		err = client.Remove(testFileName + "1")
		assert.NoError(t, err)
		err = client.RemoveDirectory("missing")
		assert.Error(t, err)
	} else {
		printLatestLogs(10)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestCheckFsAfterUpdate(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}
	// remove the home dir, it will not be re-created
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.Error(t, err)
	} else {
		printLatestLogs(10)
	}
	// update the user and login again, this time the home dir will be created
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSetStat(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		f, err := client.Create(testFileName)
		assert.NoError(t, err)
		_, err = f.Write(testFileContent)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
		acmodTime := time.Now().Add(36 * time.Hour)
		err = client.Chtimes(testFileName, acmodTime, acmodTime)
		assert.NoError(t, err)
		newFi, err := client.Lstat(testFileName)
		assert.NoError(t, err)
		diff := math.Abs(newFi.ModTime().Sub(acmodTime).Seconds())
		assert.LessOrEqual(t, diff, float64(1))
		if runtime.GOOS != osWindows {
			err = client.Chown(testFileName, os.Getuid(), os.Getgid())
			assert.NoError(t, err)
		}
		newPerm := os.FileMode(0666)
		err = client.Chmod(testFileName, newPerm)
		assert.NoError(t, err)
		newFi, err = client.Lstat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, newPerm, newFi.Mode().Perm())
		}
		err = client.Truncate(testFileName, 2)
		assert.NoError(t, err)
		info, err := client.Stat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, int64(2), info.Size())
		}
		err = client.Remove(testFileName)
		assert.NoError(t, err)

		err = client.Truncate(testFileName, 0)
		assert.ErrorIs(t, err, os.ErrNotExist)
		err = client.Chtimes(testFileName, acmodTime, acmodTime)
		assert.ErrorIs(t, err, os.ErrNotExist)
		if runtime.GOOS != osWindows {
			err = client.Chown(testFileName, os.Getuid(), os.Getgid())
			assert.ErrorIs(t, err, os.ErrNotExist)
		}
		err = client.Chmod(testFileName, newPerm)
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestChtimesOpenHandle(t *testing.T) {
	localUser, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	u := getCryptFsUser()
	cryptFsUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	for _, user := range []dataprovider.User{localUser, sftpUser, cryptFsUser} {
		conn, client, err := getSftpClient(user)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()

			f, err := client.Create(testFileName)
			assert.NoError(t, err, "user %v", user.Username)
			f1, err := client.Create(testFileName + "1")
			assert.NoError(t, err, "user %v", user.Username)
			acmodTime := time.Now().Add(36 * time.Hour)
			err = client.Chtimes(testFileName, acmodTime, acmodTime)
			assert.NoError(t, err, "user %v", user.Username)
			_, err = f.Write(testFileContent)
			assert.NoError(t, err, "user %v", user.Username)
			err = f.Close()
			assert.NoError(t, err, "user %v", user.Username)
			err = f1.Close()
			assert.NoError(t, err, "user %v", user.Username)
			info, err := client.Lstat(testFileName)
			assert.NoError(t, err, "user %v", user.Username)
			diff := math.Abs(info.ModTime().Sub(acmodTime).Seconds())
			assert.LessOrEqual(t, diff, float64(1), "user %v", user.Username)
			info1, err := client.Lstat(testFileName + "1")
			assert.NoError(t, err, "user %v", user.Username)
			diff = math.Abs(info1.ModTime().Sub(acmodTime).Seconds())
			assert.Greater(t, diff, float64(86400), "user %v", user.Username)
		}
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(cryptFsUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(cryptFsUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestCheckParentDirs(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	testDir := "/path/to/sub/dir"
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		_, err = client.Stat(testDir)
		assert.ErrorIs(t, err, os.ErrNotExist)
		c := common.NewBaseConnection(xid.New().String(), common.ProtocolSFTP, "", "", user)
		err = c.CheckParentDirs(testDir)
		assert.NoError(t, err)
		_, err = client.Stat(testDir)
		assert.NoError(t, err)
		err = c.CheckParentDirs(testDir)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	u := getTestUser()
	u.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermListItems, dataprovider.PermDownload}
	user, _, err = httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		c := common.NewBaseConnection(xid.New().String(), common.ProtocolSFTP, "", "", user)
		err = c.CheckParentDirs(testDir)
		assert.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermissionErrors(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	u := getTestSFTPUser()
	subDir := "/sub"
	u.Permissions[subDir] = nil
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.MkdirAll(path.Join(subDir, subDir))
		assert.NoError(t, err)
		f, err := client.Create(path.Join(subDir, subDir, testFileName))
		if assert.NoError(t, err) {
			_, err = f.Write(testFileContent)
			assert.NoError(t, err)
			err = f.Close()
			assert.NoError(t, err)
		}
	}
	conn, client, err = getSftpClient(sftpUser)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		_, err = client.ReadDir(subDir)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Mkdir(path.Join(subDir, subDir))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.RemoveDirectory(path.Join(subDir, subDir))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Symlink("test", path.Join(subDir, subDir))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Chmod(path.Join(subDir, subDir), os.ModePerm)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Chown(path.Join(subDir, subDir), os.Getuid(), os.Getgid())
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Chtimes(path.Join(subDir, subDir), time.Now(), time.Now())
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Truncate(path.Join(subDir, subDir), 0)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Remove(path.Join(subDir, subDir, testFileName))
		assert.ErrorIs(t, err, os.ErrPermission)
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestHiddenPatternFilter(t *testing.T) {
	deniedDir := "/denied_hidden"
	u := getTestUser()
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:           deniedDir,
			DeniedPatterns: []string{"*.txt", "beta*"},
			DenyPolicy:     sdk.DenyPolicyHide,
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	dirName := "beta"
	subDirName := "testDir"
	testFile := filepath.Join(u.GetHomeDir(), deniedDir, "file.txt")
	testFile1 := filepath.Join(u.GetHomeDir(), deniedDir, "beta.txt")
	testHiddenFile := filepath.Join(u.GetHomeDir(), deniedDir, dirName, subDirName, "hidden.jpg")
	err = os.MkdirAll(filepath.Join(u.GetHomeDir(), deniedDir), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(testFile, testFileContent, os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(testFile1, testFileContent, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(filepath.Join(u.GetHomeDir(), deniedDir, dirName, subDirName), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(testHiddenFile, testFileContent, os.ModePerm)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		files, err := client.ReadDir(deniedDir)
		assert.NoError(t, err)
		assert.Len(t, files, 0)
		err = client.Remove(path.Join(deniedDir, filepath.Base(testFile)))
		assert.ErrorIs(t, err, os.ErrNotExist)
		err = client.Chtimes(path.Join(deniedDir, filepath.Base(testFile)), time.Now(), time.Now())
		assert.ErrorIs(t, err, os.ErrNotExist)
		_, err = client.Stat(path.Join(deniedDir, filepath.Base(testFile1)))
		assert.ErrorIs(t, err, os.ErrNotExist)
		err = client.RemoveDirectory(path.Join(deniedDir, dirName))
		assert.ErrorIs(t, err, os.ErrNotExist)
		err = client.Rename(path.Join(deniedDir, dirName), path.Join(deniedDir, "newname"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Mkdir(path.Join(deniedDir, "beta1"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = writeSFTPFile(path.Join(deniedDir, "afile.txt"), 1024, client)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = writeSFTPFile(path.Join(deniedDir, dirName, subDirName, "afile.jpg"), 1024, client)
		assert.ErrorIs(t, err, os.ErrPermission)
		_, err = client.Open(path.Join(deniedDir, dirName, subDirName, filepath.Base(testHiddenFile)))
		assert.ErrorIs(t, err, os.ErrNotExist)
		err = client.Symlink(path.Join(deniedDir, dirName), dirName)
		assert.ErrorIs(t, err, os.ErrNotExist)
		err = writeSFTPFile(path.Join(deniedDir, testFileName), 1024, client)
		assert.NoError(t, err)
		err = client.Symlink(path.Join(deniedDir, testFileName), path.Join(deniedDir, "symlink.txt"))
		assert.ErrorIs(t, err, os.ErrPermission)
		files, err = client.ReadDir(deniedDir)
		assert.NoError(t, err)
		assert.Len(t, files, 1)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:           deniedDir,
			DeniedPatterns: []string{"*.txt", "beta*"},
			DenyPolicy:     sdk.DenyPolicyDefault,
		},
	}
	user, _, err = httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		files, err := client.ReadDir(deniedDir)
		assert.NoError(t, err)
		assert.Len(t, files, 4)
		_, err = client.Stat(path.Join(deniedDir, filepath.Base(testFile)))
		assert.NoError(t, err)
		err = client.Chtimes(path.Join(deniedDir, filepath.Base(testFile)), time.Now(), time.Now())
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Mkdir(path.Join(deniedDir, "beta2"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = writeSFTPFile(path.Join(deniedDir, "afile2.txt"), 1024, client)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Symlink(path.Join(deniedDir, testFileName), path.Join(deniedDir, "link.txt"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = writeSFTPFile(path.Join(deniedDir, dirName, subDirName, "afile.jpg"), 1024, client)
		assert.NoError(t, err)
		f, err := client.Open(path.Join(deniedDir, dirName, subDirName, filepath.Base(testHiddenFile)))
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestFileNotAllowedErrors(t *testing.T) {
	deniedDir := "/denied"
	u := getTestUser()
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:           deniedDir,
			DeniedPatterns: []string{"*.txt"},
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFile := filepath.Join(u.GetHomeDir(), deniedDir, "file.txt")
		err = os.MkdirAll(filepath.Join(u.GetHomeDir(), deniedDir), os.ModePerm)
		assert.NoError(t, err)
		err = os.WriteFile(testFile, testFileContent, os.ModePerm)
		assert.NoError(t, err)
		err = client.Remove(path.Join(deniedDir, "file.txt"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join(deniedDir, "file.txt"), path.Join(deniedDir, "file1.txt"))
		assert.ErrorIs(t, err, os.ErrPermission)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRootDirVirtualFolder(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 1000
	u.UploadDataTransfer = 1000
	u.DownloadDataTransfer = 5000
	mappedPath1 := filepath.Join(os.TempDir(), "mapped1")
	folderName1 := filepath.Base(mappedPath1)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewPlainSecret("cryptsecret"),
				},
			},
		},
		VirtualPath: "/",
		QuotaFiles:  1000,
	})
	mappedPath2 := filepath.Join(os.TempDir(), "mapped2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vmapped"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	f, err := user.GetVirtualFolderForPath("/")
	assert.NoError(t, err)
	assert.Equal(t, "/", f.VirtualPath)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		f, err := client.Create(testFileName)
		if assert.NoError(t, err) {
			_, err = f.Write(testFileContent)
			assert.NoError(t, err)
			err = f.Close()
			assert.NoError(t, err)
		}
		assert.NoFileExists(t, filepath.Join(user.HomeDir, testFileName))
		assert.FileExists(t, filepath.Join(mappedPath1, testFileName))
		entries, err := client.ReadDir(".")
		if assert.NoError(t, err) {
			assert.Len(t, entries, 2)
		}

		user, _, err := httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, user.UsedQuotaFiles)
		folder, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, folder.UsedQuotaFiles)

		f, err = client.Create(path.Join(vdirPath2, testFileName))
		if assert.NoError(t, err) {
			_, err = f.Write(testFileContent)
			assert.NoError(t, err)
			err = f.Close()
			assert.NoError(t, err)
		}
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		folder, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, folder.UsedQuotaFiles)

		err = client.Rename(testFileName, path.Join(vdirPath2, testFileName+"_rename"))
		assert.Error(t, err)
		err = client.Rename(path.Join(vdirPath2, testFileName), testFileName+"_rename")
		assert.Error(t, err)
		err = client.Rename(testFileName, testFileName+"_rename")
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath2, testFileName), path.Join(vdirPath2, testFileName+"_rename"))
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestTruncateQuotaLimits(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 20
	u.UploadDataTransfer = 1000
	u.DownloadDataTransfer = 5000
	mappedPath1 := filepath.Join(os.TempDir(), "mapped1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vmapped1"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  10,
	})
	mappedPath2 := filepath.Join(os.TempDir(), "mapped2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vmapped2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.QuotaSize = 20
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			f, err := client.OpenFile(testFileName, os.O_WRONLY|os.O_CREATE)
			if assert.NoError(t, err) {
				n, err := f.Write(testFileContent)
				assert.NoError(t, err)
				assert.Equal(t, len(testFileContent), n)
				err = f.Truncate(2)
				assert.NoError(t, err)
				expectedQuotaFiles := 0
				expectedQuotaSize := int64(2)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
				assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
				_, err = f.Seek(expectedQuotaSize, io.SeekStart)
				assert.NoError(t, err)
				n, err = f.Write(testFileContent)
				assert.NoError(t, err)
				assert.Equal(t, len(testFileContent), n)
				err = f.Truncate(5)
				assert.NoError(t, err)
				expectedQuotaSize = int64(5)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
				assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
				_, err = f.Seek(expectedQuotaSize, io.SeekStart)
				assert.NoError(t, err)
				n, err = f.Write(testFileContent)
				assert.NoError(t, err)
				assert.Equal(t, len(testFileContent), n)
				err = f.Close()
				assert.NoError(t, err)
				expectedQuotaFiles = 1
				expectedQuotaSize = int64(5) + int64(len(testFileContent))
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
				assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
			}
			// now truncate by path
			err = client.Truncate(testFileName, 5)
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 1, user.UsedQuotaFiles)
			assert.Equal(t, int64(5), user.UsedQuotaSize)
			// now open an existing file without truncate it, quota should not change
			f, err = client.OpenFile(testFileName, os.O_WRONLY)
			if assert.NoError(t, err) {
				err = f.Close()
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(5), user.UsedQuotaSize)
			}
			// open the file truncating it
			f, err = client.OpenFile(testFileName, os.O_WRONLY|os.O_TRUNC)
			if assert.NoError(t, err) {
				err = f.Close()
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(0), user.UsedQuotaSize)
			}
			// now test max write size
			f, err = client.OpenFile(testFileName, os.O_WRONLY)
			if assert.NoError(t, err) {
				n, err := f.Write(testFileContent)
				assert.NoError(t, err)
				assert.Equal(t, len(testFileContent), n)
				err = f.Truncate(11)
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(11), user.UsedQuotaSize)
				_, err = f.Seek(int64(11), io.SeekStart)
				assert.NoError(t, err)
				n, err = f.Write(testFileContent)
				assert.NoError(t, err)
				assert.Equal(t, len(testFileContent), n)
				err = f.Truncate(5)
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(5), user.UsedQuotaSize)
				_, err = f.Seek(int64(5), io.SeekStart)
				assert.NoError(t, err)
				n, err = f.Write(testFileContent)
				assert.NoError(t, err)
				assert.Equal(t, len(testFileContent), n)
				err = f.Truncate(12)
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(12), user.UsedQuotaSize)
				_, err = f.Seek(int64(12), io.SeekStart)
				assert.NoError(t, err)
				_, err = f.Write(testFileContent)
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
				}
				err = f.Close()
				assert.Error(t, err)
				// the file is deleted
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 0, user.UsedQuotaFiles)
				assert.Equal(t, int64(0), user.UsedQuotaSize)
			}

			if user.Username == defaultUsername {
				// basic test inside a virtual folder
				vfileName1 := path.Join(vdirPath1, testFileName)
				f, err = client.OpenFile(vfileName1, os.O_WRONLY|os.O_CREATE)
				if assert.NoError(t, err) {
					n, err := f.Write(testFileContent)
					assert.NoError(t, err)
					assert.Equal(t, len(testFileContent), n)
					err = f.Truncate(2)
					assert.NoError(t, err)
					expectedQuotaFiles := 0
					expectedQuotaSize := int64(2)
					fold, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
					assert.NoError(t, err)
					assert.Equal(t, expectedQuotaSize, fold.UsedQuotaSize)
					assert.Equal(t, expectedQuotaFiles, fold.UsedQuotaFiles)
					err = f.Close()
					assert.NoError(t, err)
					expectedQuotaFiles = 1
					fold, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
					assert.NoError(t, err)
					assert.Equal(t, expectedQuotaSize, fold.UsedQuotaSize)
					assert.Equal(t, expectedQuotaFiles, fold.UsedQuotaFiles)
				}
				err = client.Truncate(vfileName1, 1)
				assert.NoError(t, err)
				fold, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, int64(1), fold.UsedQuotaSize)
				assert.Equal(t, 1, fold.UsedQuotaFiles)
				// now test on vdirPath2, the folder quota is included in the user's quota
				vfileName2 := path.Join(vdirPath2, testFileName)
				f, err = client.OpenFile(vfileName2, os.O_WRONLY|os.O_CREATE)
				if assert.NoError(t, err) {
					n, err := f.Write(testFileContent)
					assert.NoError(t, err)
					assert.Equal(t, len(testFileContent), n)
					err = f.Truncate(3)
					assert.NoError(t, err)
					expectedQuotaFiles := 0
					expectedQuotaSize := int64(3)
					fold, _, err := httpdtest.GetFolderByName(folderName2, http.StatusOK)
					assert.NoError(t, err)
					assert.Equal(t, expectedQuotaSize, fold.UsedQuotaSize)
					assert.Equal(t, expectedQuotaFiles, fold.UsedQuotaFiles)
					err = f.Close()
					assert.NoError(t, err)
					expectedQuotaFiles = 1
					fold, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
					assert.NoError(t, err)
					assert.Equal(t, expectedQuotaSize, fold.UsedQuotaSize)
					assert.Equal(t, expectedQuotaFiles, fold.UsedQuotaFiles)
					user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
					assert.NoError(t, err)
					assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
					assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
				}

				// cleanup
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				if user.Username == defaultUsername {
					_, err = httpdtest.RemoveUser(user, http.StatusOK)
					assert.NoError(t, err)
					user.Password = defaultPassword
					user.QuotaSize = 0
					user.ID = 0
					user.CreatedAt = 0
					_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
					assert.NoError(t, err, string(resp))
				}
			}
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestVirtualFoldersQuotaRenameOverwrite(t *testing.T) {
	testFileSize := int64(131072)
	testFileSize1 := int64(65537)
	testFileName1 := "test_file1.dat" //nolint:goconst
	u := getTestUser()
	u.QuotaFiles = 0
	u.QuotaSize = 0
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1" //nolint:goconst
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2" //nolint:goconst
	mappedPath3 := filepath.Join(os.TempDir(), "vdir3")
	folderName3 := filepath.Base(mappedPath3)
	vdirPath3 := "/vdir3"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  2,
		QuotaSize:   0,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
			Name:       folderName2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  0,
		QuotaSize:   testFileSize + testFileSize1 + 1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName3,
			MappedPath: mappedPath3,
		},
		VirtualPath: vdirPath3,
		QuotaFiles:  2,
		QuotaSize:   testFileSize * 2,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = writeSFTPFile(path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		f, err := client.Open(path.Join(vdirPath1, testFileName))
		assert.NoError(t, err)
		contents, err := io.ReadAll(f)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
		assert.Len(t, contents, int(testFileSize))
		err = writeSFTPFile(path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath3, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath3, testFileName+"1"), testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, path.Join(vdirPath1, testFileName+".rename"))
		assert.Error(t, err)
		// we overwrite an existing file and we have unlimited size
		err = client.Rename(testFileName, path.Join(vdirPath1, testFileName))
		assert.NoError(t, err)
		// we have no space and we try to overwrite a bigger file with a smaller one, this should succeed
		err = client.Rename(testFileName1, path.Join(vdirPath2, testFileName))
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		// we have no space and we try to overwrite a smaller file with a bigger one, this should fail
		err = client.Rename(testFileName, path.Join(vdirPath2, testFileName1))
		assert.Error(t, err)
		fi, err := client.Stat(path.Join(vdirPath1, testFileName1))
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize1, fi.Size())
		}
		// we are overquota inside vdir3 size 2/2 and size 262144/262144
		err = client.Rename(path.Join(vdirPath1, testFileName1), path.Join(vdirPath3, testFileName1+".rename"))
		assert.Error(t, err)
		// we overwrite an existing file and we have enough size
		err = client.Rename(path.Join(vdirPath1, testFileName1), path.Join(vdirPath3, testFileName))
		assert.NoError(t, err)
		testFileName2 := "test_file2.dat"
		err = writeSFTPFile(testFileName2, testFileSize+testFileSize1, client)
		assert.NoError(t, err)
		// we overwrite an existing file and we haven't enough size
		err = client.Rename(testFileName2, path.Join(vdirPath3, testFileName))
		assert.Error(t, err)
		// now remove a file from vdir3, create a dir with 2 files and try to rename it in vdir3
		// this will fail since the rename will result in 3 files inside vdir3 and quota limits only
		// allow 2 total files there
		err = client.Remove(path.Join(vdirPath3, testFileName+"1"))
		assert.NoError(t, err)
		aDir := "a dir"
		err = client.Mkdir(aDir)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(aDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(aDir, testFileName1+"1"), testFileSize1, client)
		assert.NoError(t, err)
		err = client.Rename(aDir, path.Join(vdirPath3, aDir))
		assert.Error(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName3}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath3)
	assert.NoError(t, err)
}

func TestQuotaRenameOverwrite(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 100
	u.Filters.DataTransferLimits = []sdk.DataTransferLimit{
		{
			Sources:           []string{"10.8.0.0/8"},
			TotalDataTransfer: 1,
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(131072)
		testFileSize1 := int64(65537)
		testFileName1 := "test_file1.dat"
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		f, err := client.Open(testFileName)
		assert.NoError(t, err)
		contents := make([]byte, testFileSize)
		n, err := io.ReadFull(f, contents)
		assert.NoError(t, err)
		assert.Equal(t, int(testFileSize), n)
		err = f.Close()
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), user.UsedDownloadDataTransfer)
		assert.Equal(t, int64(0), user.UsedUploadDataTransfer)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		err = client.Rename(testFileName, testFileName1)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), user.UsedDownloadDataTransfer)
		assert.Equal(t, int64(0), user.UsedUploadDataTransfer)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		err = client.Remove(testFileName1)
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName1, testFileName)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestVirtualFoldersQuotaValues(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1"
	folderName1 := filepath.Base(mappedPath1)
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	folderName2 := filepath.Base(mappedPath2)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(131072)
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		// we copy the same file two times to test quota update on file overwrite
		err = writeSFTPFile(path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		expectedQuotaFiles := 2
		expectedQuotaSize := testFileSize * 2
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)

		err = client.Remove(path.Join(vdirPath1, testFileName))
		assert.NoError(t, err)
		err = client.Remove(path.Join(vdirPath2, testFileName))
		assert.NoError(t, err)

		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestQuotaRenameInsideSameVirtualFolder(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1"
	folderName1 := filepath.Base(mappedPath1)
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	folderName2 := filepath.Base(mappedPath2)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName1 := "test_file1.dat"
		testFileSize := int64(131072)
		testFileSize1 := int64(65535)
		dir1 := "dir1" //nolint:goconst
		dir2 := "dir2" //nolint:goconst
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// initial files:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		//
		// rename a file inside vdir1 it is included inside user quota, so we have:
		// - vdir1/dir1/testFileName.rename
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		err = client.Rename(path.Join(vdirPath1, dir1, testFileName), path.Join(vdirPath1, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file inside vdir2, it isn't included inside user quota, so we have:
		// - vdir1/dir1/testFileName.rename
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName.rename
		// - vdir2/dir2/testFileName1
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(vdirPath2, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file inside vdir2 overwriting an existing, we now have:
		// - vdir1/dir1/testFileName.rename
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName.rename (initial testFileName1)
		err = client.Rename(path.Join(vdirPath2, dir2, testFileName1), path.Join(vdirPath2, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file inside vdir1 overwriting an existing, we now have:
		// - vdir1/dir1/testFileName.rename (initial testFileName1)
		// - vdir2/dir1/testFileName.rename (initial testFileName1)
		err = client.Rename(path.Join(vdirPath1, dir2, testFileName1), path.Join(vdirPath1, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a directory inside the same virtual folder, quota should not change
		err = client.RemoveDirectory(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.RemoveDirectory(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath1, dir1), path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath2, dir1), path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestQuotaRenameBetweenVirtualFolder(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName1 := "test_file1.dat"
		testFileSize := int64(131072)
		testFileSize1 := int64(65535)
		dir1 := "dir1"
		dir2 := "dir2"
		err = client.Mkdir(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// initial files:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		//
		// rename a file from vdir1 to vdir2, vdir1 is included inside user quota, so we have:
		// - vdir1/dir1/testFileName
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		// - vdir2/dir1/testFileName1.rename
		err = client.Rename(path.Join(vdirPath1, dir2, testFileName1), path.Join(vdirPath2, dir1, testFileName1+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
		// rename a file from vdir2 to vdir1, vdir2 is not included inside user quota, so we have:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName.rename
		// - vdir2/dir2/testFileName1
		// - vdir2/dir1/testFileName1.rename
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(vdirPath1, dir2, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize*2, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1*2, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file from vdir1 to vdir2 overwriting an existing file, vdir1 is included inside user quota, so we have:
		// - vdir1/dir2/testFileName.rename
		// - vdir2/dir2/testFileName1 (is the initial testFileName)
		// - vdir2/dir1/testFileName1.rename
		err = client.Rename(path.Join(vdirPath1, dir1, testFileName), path.Join(vdirPath2, dir2, testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1+testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file from vdir2 to vdir1 overwriting an existing file, vdir2 is not included inside user quota, so we have:
		// - vdir1/dir2/testFileName.rename (is the initial testFileName1)
		// - vdir2/dir2/testFileName1 (is the initial testFileName)
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName1+".rename"), path.Join(vdirPath1, dir2, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)

		err = writeSFTPFile(path.Join(vdirPath1, dir2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir2, testFileName), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir2, testFileName+"1.dupl"), testFileSize1, client)
		assert.NoError(t, err)
		err = client.RemoveDirectory(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.RemoveDirectory(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		// - vdir1/dir2/testFileName.rename (initial testFileName1)
		// - vdir1/dir2/testFileName
		// - vdir2/dir2/testFileName1 (initial testFileName)
		// - vdir2/dir2/testFileName (initial testFileName1)
		// - vdir2/dir2/testFileName1.dupl
		// rename directories between the two virtual folders
		err = client.Rename(path.Join(vdirPath2, dir2), path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 5, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1*3+testFileSize*2, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1*3+testFileSize*2, f.UsedQuotaSize)
		assert.Equal(t, 5, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		// now move on vpath2
		err = client.Rename(path.Join(vdirPath1, dir2), path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1*2+testFileSize, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1*2+testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestQuotaRenameFromVirtualFolder(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName1 := "test_file1.dat"
		testFileSize := int64(131072)
		testFileSize1 := int64(65535)
		dir1 := "dir1"
		dir2 := "dir2"
		err = client.Mkdir(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// initial files:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		//
		// rename a file from vdir1 to the user home dir, vdir1 is included in user quota so we have:
		// - testFileName
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		err = client.Rename(path.Join(vdirPath1, dir1, testFileName), path.Join(testFileName))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file from vdir2 to the user home dir, vdir2 is not included in user quota so we have:
		// - testFileName
		// - testFileName1
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		err = client.Rename(path.Join(vdirPath2, dir2, testFileName1), path.Join(testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a file from vdir1 to the user home dir overwriting an existing file, vdir1 is included in user quota so we have:
		// - testFileName (initial testFileName1)
		// - testFileName1
		// - vdir2/dir1/testFileName
		err = client.Rename(path.Join(vdirPath1, dir2, testFileName1), path.Join(testFileName))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a file from vdir2 to the user home dir overwriting an existing file, vdir2 is not included in user quota so we have:
		// - testFileName (initial testFileName1)
		// - testFileName1 (initial testFileName)
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		// dir rename
		err = writeSFTPFile(path.Join(vdirPath1, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, dir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, dir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// - testFileName (initial testFileName1)
		// - testFileName1 (initial testFileName)
		// - vdir1/dir1/testFileName
		// - vdir1/dir1/testFileName1
		// - dir1/testFileName
		// - dir1/testFileName1
		err = client.Rename(path.Join(vdirPath2, dir1), dir1)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 6, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*3+testFileSize1*3, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		// - testFileName (initial testFileName1)
		// - testFileName1 (initial testFileName)
		// - dir2/testFileName
		// - dir2/testFileName1
		// - dir1/testFileName
		// - dir1/testFileName1
		err = client.Rename(path.Join(vdirPath1, dir1), dir2)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 6, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*3+testFileSize1*3, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestQuotaRenameToVirtualFolder(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	u.Permissions[vdirPath1] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload,
		dataprovider.PermOverwrite, dataprovider.PermDelete, dataprovider.PermCreateSymlinks, dataprovider.PermCreateDirs,
		dataprovider.PermRename}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName1 := "test_file1.dat"
		testFileSize := int64(131072)
		testFileSize1 := int64(65535)
		dir1 := "dir1"
		dir2 := "dir2"
		err = client.Mkdir(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		// initial files:
		// - testFileName
		// - testFileName1
		//
		// rename a file from user home dir to vdir1, vdir1 is included in user quota so we have:
		// - testFileName
		// - /vdir1/dir1/testFileName1
		err = client.Rename(testFileName1, path.Join(vdirPath1, dir1, testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a file from user home dir to vdir2, vdir2 is not included in user quota so we have:
		// - /vdir2/dir1/testFileName
		// - /vdir1/dir1/testFileName1
		err = client.Rename(testFileName, path.Join(vdirPath2, dir1, testFileName))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// upload two new files to the user home dir so we have:
		// - testFileName
		// - testFileName1
		// - /vdir1/dir1/testFileName1
		// - /vdir2/dir1/testFileName
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1+testFileSize1, user.UsedQuotaSize)
		// rename a file from user home dir to vdir1 overwriting an existing file, vdir1 is included in user quota so we have:
		// - testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName
		err = client.Rename(testFileName, path.Join(vdirPath1, dir1, testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a file from user home dir to vdir2 overwriting an existing file, vdir2 is not included in user quota so we have:
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		err = client.Rename(testFileName1, path.Join(vdirPath2, dir1, testFileName))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)

		err = client.Mkdir(dir1)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(dir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// - /dir1/testFileName
		// - /dir1/testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// - /vdir1/adir/testFileName
		// - /vdir1/adir/testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		err = client.Rename(dir1, path.Join(vdirPath1, "adir"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize*2+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		err = client.Mkdir(dir1)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(dir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// - /vdir1/adir/testFileName
		// - /vdir1/adir/testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		// - /vdir2/adir/testFileName
		// - /vdir2/adir/testFileName1
		err = client.Rename(dir1, path.Join(vdirPath2, "adir"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize*2+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1*2+testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestTransferQuotaLimits(t *testing.T) {
	u := getTestUser()
	u.TotalDataTransfer = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		testFileSize := int64(524288)
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		f, err := client.Open(testFileName)
		assert.NoError(t, err)
		contents := make([]byte, testFileSize)
		n, err := io.ReadFull(f, contents)
		assert.NoError(t, err)
		assert.Equal(t, int(testFileSize), n)
		assert.Len(t, contents, int(testFileSize))
		err = f.Close()
		assert.NoError(t, err)
		_, err = client.Open(testFileName)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
			assert.Contains(t, err.Error(), common.ErrReadQuotaExceeded.Error())
		}
		err = writeSFTPFile(testFileName, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
			assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
		}
	}
	// test the limit while uploading/downloading
	user.TotalDataTransfer = 0
	user.UploadDataTransfer = 1
	user.DownloadDataTransfer = 1
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		testFileSize := int64(450000)
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		f, err := client.Open(testFileName)
		if assert.NoError(t, err) {
			_, err = io.Copy(io.Discard, f)
			assert.NoError(t, err)
			err = f.Close()
			assert.NoError(t, err)
		}
		f, err = client.Open(testFileName)
		if assert.NoError(t, err) {
			_, err = io.Copy(io.Discard, f)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
				assert.Contains(t, err.Error(), common.ErrReadQuotaExceeded.Error())
			}
			err = f.Close()
			assert.Error(t, err)
		}

		err = writeSFTPFile(testFileName, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
			assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
		}
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestVirtualFoldersLink(t *testing.T) {
	u := getTestUser()
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(131072)
		testDir := "adir"
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, testDir))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, testDir))
		assert.NoError(t, err)
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath1, testFileName), path.Join(vdirPath1, testFileName+".link"))
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath1, testFileName), path.Join(vdirPath1, testDir, testFileName+".link"))
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath2, testFileName), path.Join(vdirPath2, testFileName+".link"))
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath2, testFileName), path.Join(vdirPath2, testDir, testFileName+".link"))
		assert.NoError(t, err)
		err = client.Symlink(testFileName, path.Join(vdirPath1, testFileName+".link1"))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink(testFileName, path.Join(vdirPath1, testDir, testFileName+".link1"))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink(testFileName, path.Join(vdirPath2, testFileName+".link1"))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink(testFileName, path.Join(vdirPath2, testDir, testFileName+".link1"))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink(path.Join(vdirPath1, testFileName), testFileName+".link1")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink(path.Join(vdirPath2, testFileName), testFileName+".link1")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink(path.Join(vdirPath1, testFileName), path.Join(vdirPath2, testDir, testFileName+".link1"))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink(path.Join(vdirPath2, testFileName), path.Join(vdirPath1, testFileName+".link1"))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink("/", "/roolink")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Symlink(testFileName, "/")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Symlink(testFileName, vdirPath1)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Symlink(vdirPath1, testFileName+".link2")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestCrossFolderRename(t *testing.T) {
	folder1 := "folder1"
	folder2 := "folder2"
	folder3 := "folder3"
	folder4 := "folder4"
	folder5 := "folder5"
	folder6 := "folder6"
	folder7 := "folder7"

	baseUser, resp, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err, string(resp))

	u := getCryptFsUser()
	u.VirtualFolders = []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       folder1,
				MappedPath: filepath.Join(os.TempDir(), folder1),
				FsConfig: vfs.Filesystem{
					Provider: sdk.CryptedFilesystemProvider,
					CryptConfig: vfs.CryptFsConfig{
						Passphrase: kms.NewPlainSecret(defaultPassword),
					},
				},
			},
			VirtualPath: path.Join("/", folder1),
			QuotaSize:   -1,
			QuotaFiles:  -1,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       folder2,
				MappedPath: filepath.Join(os.TempDir(), folder2),
				FsConfig: vfs.Filesystem{
					Provider: sdk.CryptedFilesystemProvider,
					CryptConfig: vfs.CryptFsConfig{
						Passphrase: kms.NewPlainSecret(defaultPassword),
					},
				},
			},
			VirtualPath: path.Join("/", folder2),
			QuotaSize:   -1,
			QuotaFiles:  -1,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       folder3,
				MappedPath: filepath.Join(os.TempDir(), folder3),
				FsConfig: vfs.Filesystem{
					Provider: sdk.CryptedFilesystemProvider,
					CryptConfig: vfs.CryptFsConfig{
						Passphrase: kms.NewPlainSecret(defaultPassword + "mod"),
					},
				},
			},
			VirtualPath: path.Join("/", folder3),
			QuotaSize:   -1,
			QuotaFiles:  -1,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       folder4,
				MappedPath: filepath.Join(os.TempDir(), folder4),
				FsConfig: vfs.Filesystem{
					Provider: sdk.SFTPFilesystemProvider,
					SFTPConfig: vfs.SFTPFsConfig{
						BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
							Endpoint: sftpServerAddr,
							Username: baseUser.Username,
							Prefix:   path.Join("/", folder4),
						},
						Password: kms.NewPlainSecret(defaultPassword),
					},
				},
			},
			VirtualPath: path.Join("/", folder4),
			QuotaSize:   -1,
			QuotaFiles:  -1,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       folder5,
				MappedPath: filepath.Join(os.TempDir(), folder5),
				FsConfig: vfs.Filesystem{
					Provider: sdk.SFTPFilesystemProvider,
					SFTPConfig: vfs.SFTPFsConfig{
						BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
							Endpoint: sftpServerAddr,
							Username: baseUser.Username,
							Prefix:   path.Join("/", folder5),
						},
						Password: kms.NewPlainSecret(defaultPassword),
					},
				},
			},
			VirtualPath: path.Join("/", folder5),
			QuotaSize:   -1,
			QuotaFiles:  -1,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       folder6,
				MappedPath: filepath.Join(os.TempDir(), folder6),
				FsConfig: vfs.Filesystem{
					Provider: sdk.SFTPFilesystemProvider,
					SFTPConfig: vfs.SFTPFsConfig{
						BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
							Endpoint: "127.0.0.1:4024",
							Username: baseUser.Username,
							Prefix:   path.Join("/", folder6),
						},
						Password: kms.NewPlainSecret(defaultPassword),
					},
				},
			},
			VirtualPath: path.Join("/", folder6),
			QuotaSize:   -1,
			QuotaFiles:  -1,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       folder7,
				MappedPath: filepath.Join(os.TempDir(), folder7),
				FsConfig: vfs.Filesystem{
					Provider: sdk.SFTPFilesystemProvider,
					SFTPConfig: vfs.SFTPFsConfig{
						BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
							Endpoint: sftpServerAddr,
							Username: baseUser.Username,
							Prefix:   path.Join("/", folder4),
						},
						Password: kms.NewPlainSecret(defaultPassword),
					},
				},
			},
			VirtualPath: path.Join("/", folder7),
			QuotaSize:   -1,
			QuotaFiles:  -1,
		},
	}

	user, resp, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		subDir := "testSubDir"
		err = client.Mkdir(subDir)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(subDir, "afile.bin"), 64, client)
		assert.NoError(t, err)
		err = client.Rename(subDir, path.Join("/", folder1, subDir))
		assert.NoError(t, err)
		_, err = client.Stat(path.Join("/", folder1, subDir))
		assert.NoError(t, err)
		_, err = client.Stat(path.Join("/", folder1, subDir, "afile.bin"))
		assert.NoError(t, err)
		err = client.Rename(path.Join("/", folder1, subDir), path.Join("/", folder2, subDir))
		assert.NoError(t, err)
		_, err = client.Stat(path.Join("/", folder2, subDir))
		assert.NoError(t, err)
		_, err = client.Stat(path.Join("/", folder2, subDir, "afile.bin"))
		assert.NoError(t, err)
		err = client.Rename(path.Join("/", folder2, subDir), path.Join("/", folder3, subDir))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = writeSFTPFile(path.Join("/", folder3, "file.bin"), 64, client)
		assert.NoError(t, err)
		err = client.Rename(path.Join("/", folder3, "file.bin"), "/renamed.bin")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join("/", folder3, "file.bin"), path.Join("/", folder2, "/renamed.bin"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join("/", folder3, "file.bin"), path.Join("/", folder3, "/renamed.bin"))
		assert.NoError(t, err)
		err = writeSFTPFile("/afile.bin", 64, client)
		assert.NoError(t, err)
		err = client.Rename("afile.bin", path.Join("/", folder4, "afile_renamed.bin"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = writeSFTPFile(path.Join("/", folder4, "afile.bin"), 64, client)
		assert.NoError(t, err)
		err = client.Rename(path.Join("/", folder4, "afile.bin"), path.Join("/", folder5, "afile_renamed.bin"))
		assert.NoError(t, err)
		err = client.Rename(path.Join("/", folder5, "afile_renamed.bin"), path.Join("/", folder6, "afile_renamed.bin"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = writeSFTPFile(path.Join("/", folder4, "afile.bin"), 64, client)
		assert.NoError(t, err)
		_, err = client.Stat(path.Join("/", folder7, "afile.bin"))
		assert.NoError(t, err)
		err = client.Rename(path.Join("/", folder4, "afile.bin"), path.Join("/", folder7, "afile.bin"))
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(baseUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(baseUser.GetHomeDir())
	assert.NoError(t, err)
	for _, folderName := range []string{folder1, folder2, folder3, folder4, folder5, folder6, folder7} {
		_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(filepath.Join(os.TempDir(), folderName))
		assert.NoError(t, err)
	}
}

func TestDirs(t *testing.T) {
	u := getTestUser()
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	folderName := filepath.Base(mappedPath)
	vdirPath := "/path/vdir"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	u.Permissions["/subdir"] = []string{dataprovider.PermDownload, dataprovider.PermUpload,
		dataprovider.PermDelete, dataprovider.PermCreateDirs, dataprovider.PermRename, dataprovider.PermListItems}

	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		info, err := client.ReadDir("/")
		if assert.NoError(t, err) {
			if assert.Len(t, info, 1) {
				assert.Equal(t, "path", info[0].Name())
			}
		}
		fi, err := client.Stat(path.Dir(vdirPath))
		if assert.NoError(t, err) {
			assert.True(t, fi.IsDir())
		}
		err = client.RemoveDirectory("/")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.RemoveDirectory(vdirPath)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.RemoveDirectory(path.Dir(vdirPath))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.Mkdir(vdirPath)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Mkdir("adir")
		assert.NoError(t, err)
		err = client.Rename("/adir", path.Dir(vdirPath))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = client.MkdirAll("/subdir/adir")
		assert.NoError(t, err)
		err = client.Rename("adir", "subdir/adir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		err = writeSFTPFile("/subdir/afile.bin", 64, client)
		assert.NoError(t, err)
		err = writeSFTPFile("/afile.bin", 32, client)
		assert.NoError(t, err)
		err = client.Rename("afile.bin", "subdir/afile.bin")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename("afile.bin", "subdir/afile1.bin")
		assert.NoError(t, err)
		err = client.Rename(path.Dir(vdirPath), "renamed_vdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestCryptFsStat(t *testing.T) {
	user, _, err := httpdtest.AddUser(getCryptFsUser(), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(4096)
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		info, err := client.Stat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, info.Size())
		}
		info, err = os.Stat(filepath.Join(user.HomeDir, testFileName))
		if assert.NoError(t, err) {
			assert.Greater(t, info.Size(), testFileSize)
		}
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestFsPermissionErrors(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	user, _, err := httpdtest.AddUser(getCryptFsUser(), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testDir := "tDir"
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = os.Chmod(user.GetHomeDir(), 0111)
		assert.NoError(t, err)

		err = client.RemoveDirectory(testDir)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(testDir, testDir+"1")
		assert.ErrorIs(t, err, os.ErrPermission)

		err = os.Chmod(user.GetHomeDir(), os.ModePerm)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRenameErrorOutsideHomeDir(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	oldUploadMode := common.Config.UploadMode
	oldTempPath := common.Config.TempPath

	common.Config.UploadMode = common.UploadModeAtomicWithResume
	common.Config.TempPath = filepath.Clean(os.TempDir())
	vfs.SetTempPath(common.Config.TempPath)

	u := getTestUser()
	u.QuotaFiles = 1000
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = os.Chmod(user.GetHomeDir(), 0555)
		assert.NoError(t, err)

		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		f, err := client.Create(testFileName)
		assert.NoError(t, err)
		_, err = f.Write(testFileContent)
		assert.NoError(t, err)
		err = f.Close()
		assert.ErrorIs(t, err, os.ErrPermission)

		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, user.UsedQuotaFiles)
		assert.Equal(t, int64(0), user.UsedQuotaSize)

		err = os.Chmod(user.GetHomeDir(), os.ModeDir)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.UploadMode = oldUploadMode
	common.Config.TempPath = oldTempPath
	vfs.SetTempPath(oldTempPath)
}

func TestResolvePathError(t *testing.T) {
	u := getTestUser()
	u.HomeDir = "relative_path"
	conn := common.NewBaseConnection("", common.ProtocolFTP, "", "", u)
	testPath := "apath"
	_, err := conn.ListDir(testPath)
	assert.Error(t, err)
	err = conn.CreateDir(testPath, true)
	assert.Error(t, err)
	err = conn.RemoveDir(testPath)
	assert.Error(t, err)
	err = conn.Rename(testPath, testPath+"1")
	assert.Error(t, err)
	err = conn.CreateSymlink(testPath, testPath+".sym")
	assert.Error(t, err)
	_, err = conn.DoStat(testPath, 0, false)
	assert.Error(t, err)
	err = conn.SetStat(testPath, &common.StatAttributes{
		Atime: time.Now(),
		Mtime: time.Now(),
	})
	assert.Error(t, err)

	u = getTestUser()
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: "relative_mapped_path",
		},
		VirtualPath: "/vpath",
	})
	err = os.MkdirAll(u.HomeDir, os.ModePerm)
	assert.NoError(t, err)
	conn.User = u
	err = conn.Rename(testPath, "/vpath/subpath")
	assert.Error(t, err)

	outHomePath := filepath.Join(os.TempDir(), testFileName)
	err = os.WriteFile(outHomePath, testFileContent, os.ModePerm)
	assert.NoError(t, err)
	err = os.Symlink(outHomePath, filepath.Join(u.HomeDir, testFileName+".link"))
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(u.HomeDir, testFileName), testFileContent, os.ModePerm)
	assert.NoError(t, err)
	err = conn.CreateSymlink(testFileName, testFileName+".link")
	assert.Error(t, err)

	err = os.RemoveAll(u.GetHomeDir())
	assert.NoError(t, err)
	err = os.Remove(outHomePath)
	assert.NoError(t, err)
}

func TestUserPasswordHashing(t *testing.T) {
	if config.GetProviderConf().Driver == dataprovider.MemoryDataProviderName {
		t.Skip("this test is not supported with the memory provider")
	}
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.PasswordHashing.Algo = dataprovider.HashingAlgoArgon2ID
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	currentUser, err := dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(currentUser.Password, "$2a$"))

	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	u = getTestUser()
	user, _, err = httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	currentUser, err = dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(currentUser.Password, "$argon2id$"))

	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestDbDefenderErrors(t *testing.T) {
	if !isDbDefenderSupported() {
		t.Skip("this test is not supported with the current database provider")
	}
	configCopy := common.Config
	common.Config.DefenderConfig.Enabled = true
	common.Config.DefenderConfig.Driver = common.DefenderDriverProvider
	err := common.Initialize(common.Config, 0)
	assert.NoError(t, err)

	testIP := "127.1.1.1"
	hosts, err := common.GetDefenderHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 0)
	common.AddDefenderEvent(testIP, common.HostEventLimitExceeded)
	hosts, err = common.GetDefenderHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 1)
	score, err := common.GetDefenderScore(testIP)
	assert.NoError(t, err)
	assert.Equal(t, 3, score)
	banTime, err := common.GetDefenderBanTime(testIP)
	assert.NoError(t, err)
	assert.Nil(t, banTime)

	err = dataprovider.Close()
	assert.NoError(t, err)

	common.AddDefenderEvent(testIP, common.HostEventLimitExceeded)
	_, err = common.GetDefenderHosts()
	assert.Error(t, err)
	_, err = common.GetDefenderHost(testIP)
	assert.Error(t, err)
	_, err = common.GetDefenderBanTime(testIP)
	assert.Error(t, err)
	_, err = common.GetDefenderScore(testIP)
	assert.Error(t, err)

	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	err = dataprovider.CleanupDefender(util.GetTimeAsMsSinceEpoch(time.Now().Add(1 * time.Hour)))
	assert.NoError(t, err)

	common.Config = configCopy
	err = common.Initialize(common.Config, 0)
	assert.NoError(t, err)
}

func TestDelayedQuotaUpdater(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.DelayedQuotaUpdate = 120
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	u := getTestUser()
	u.QuotaFiles = 100
	u.TotalDataTransfer = 2000
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	err = dataprovider.UpdateUserQuota(&user, 10, 6000, false)
	assert.NoError(t, err)
	err = dataprovider.UpdateUserTransferQuota(&user, 100, 200, false)
	assert.NoError(t, err)
	files, size, ulSize, dlSize, err := dataprovider.GetUsedQuota(user.Username)
	assert.NoError(t, err)
	assert.Equal(t, 10, files)
	assert.Equal(t, int64(6000), size)
	assert.Equal(t, int64(100), ulSize)
	assert.Equal(t, int64(200), dlSize)

	userGet, err := dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.Equal(t, 0, userGet.UsedQuotaFiles)
	assert.Equal(t, int64(0), userGet.UsedQuotaSize)
	assert.Equal(t, int64(0), userGet.UsedUploadDataTransfer)
	assert.Equal(t, int64(0), userGet.UsedDownloadDataTransfer)

	err = dataprovider.UpdateUserQuota(&user, 10, 6000, true)
	assert.NoError(t, err)
	err = dataprovider.UpdateUserTransferQuota(&user, 100, 200, true)
	assert.NoError(t, err)
	files, size, ulSize, dlSize, err = dataprovider.GetUsedQuota(user.Username)
	assert.NoError(t, err)
	assert.Equal(t, 10, files)
	assert.Equal(t, int64(6000), size)
	assert.Equal(t, int64(100), ulSize)
	assert.Equal(t, int64(200), dlSize)

	userGet, err = dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.Equal(t, 10, userGet.UsedQuotaFiles)
	assert.Equal(t, int64(6000), userGet.UsedQuotaSize)
	assert.Equal(t, int64(100), userGet.UsedUploadDataTransfer)
	assert.Equal(t, int64(200), userGet.UsedDownloadDataTransfer)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	folder := vfs.BaseVirtualFolder{
		Name:       "folder",
		MappedPath: filepath.Join(os.TempDir(), "p"),
	}
	err = dataprovider.AddFolder(&folder, "", "")
	assert.NoError(t, err)

	err = dataprovider.UpdateVirtualFolderQuota(&folder, 10, 6000, false)
	assert.NoError(t, err)
	files, size, err = dataprovider.GetUsedVirtualFolderQuota(folder.Name)
	assert.NoError(t, err)
	assert.Equal(t, 10, files)
	assert.Equal(t, int64(6000), size)

	folderGet, err := dataprovider.GetFolderByName(folder.Name)
	assert.NoError(t, err)
	assert.Equal(t, 0, folderGet.UsedQuotaFiles)
	assert.Equal(t, int64(0), folderGet.UsedQuotaSize)

	err = dataprovider.UpdateVirtualFolderQuota(&folder, 10, 6000, true)
	assert.NoError(t, err)
	files, size, err = dataprovider.GetUsedVirtualFolderQuota(folder.Name)
	assert.NoError(t, err)
	assert.Equal(t, 10, files)
	assert.Equal(t, int64(6000), size)

	folderGet, err = dataprovider.GetFolderByName(folder.Name)
	assert.NoError(t, err)
	assert.Equal(t, 10, folderGet.UsedQuotaFiles)
	assert.Equal(t, int64(6000), folderGet.UsedQuotaSize)

	err = dataprovider.DeleteFolder(folder.Name, "", "")
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestPasswordCaching(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	found, match := dataprovider.CheckCachedPassword(user.Username, defaultPassword)
	assert.False(t, found)
	assert.False(t, match)

	user.Password = "wrong"
	_, _, err = getSftpClient(user)
	assert.Error(t, err)
	found, match = dataprovider.CheckCachedPassword(user.Username, defaultPassword)
	assert.False(t, found)
	assert.False(t, match)
	user.Password = ""

	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}
	found, match = dataprovider.CheckCachedPassword(user.Username, defaultPassword)
	assert.True(t, found)
	assert.True(t, match)

	found, match = dataprovider.CheckCachedPassword(user.Username, defaultPassword+"_")
	assert.True(t, found)
	assert.False(t, match)

	found, match = dataprovider.CheckCachedPassword(user.Username+"_", defaultPassword)
	assert.False(t, found)
	assert.False(t, match)

	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	found, match = dataprovider.CheckCachedPassword(user.Username, defaultPassword)
	assert.False(t, found)
	assert.False(t, match)

	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	found, match = dataprovider.CheckCachedPassword(user.Username, defaultPassword)
	assert.True(t, found)
	assert.True(t, match)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	found, match = dataprovider.CheckCachedPassword(user.Username, defaultPassword)
	assert.False(t, found)
	assert.False(t, match)
}

func TestEventRule(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notification@example.com",
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize(configDir)
	require.NoError(t, err)

	a1 := dataprovider.BaseEventAction{
		Name: "action1",
		Type: dataprovider.ActionTypeHTTP,
		Options: dataprovider.BaseEventActionOptions{
			HTTPConfig: dataprovider.EventActionHTTPConfig{
				Endpoint: "http://localhost",
				Timeout:  20,
				Method:   http.MethodGet,
			},
		},
	}
	a2 := dataprovider.BaseEventAction{
		Name: "action2",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"test1@example.com", "test2@example.com"},
				Subject:    `New "{{Event}}" from "{{Name}}" status {{StatusString}}`,
				Body:       "Fs path {{FsPath}}, size: {{FileSize}}, protocol: {{Protocol}}, IP: {{IP}} Data: {{ObjectData}} {{ErrorString}}",
			},
		},
	}
	a3 := dataprovider.BaseEventAction{
		Name: "action3",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"failure@example.com"},
				Subject:    `Failed "{{Event}}" from "{{Name}}"`,
				Body:       "Fs path {{FsPath}}, protocol: {{Protocol}}, IP: {{IP}} {{ErrorString}}",
			},
		},
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)
	action2, _, err := httpdtest.AddEventAction(a2, http.StatusCreated)
	assert.NoError(t, err)
	action3, _, err := httpdtest.AddEventAction(a3, http.StatusCreated)
	assert.NoError(t, err)
	r1 := dataprovider.EventRule{
		Name:    "test rule1",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"upload"},
			Options: dataprovider.ConditionOptions{
				FsPaths: []dataprovider.ConditionPattern{
					{
						Pattern: "/subdir/*.dat",
					},
					{
						Pattern: "*.txt",
					},
				},
			},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
				Options: dataprovider.EventActionOptions{
					ExecuteSync:   true,
					StopOnFailure: true,
				},
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 2,
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action3.Name,
				},
				Order: 3,
				Options: dataprovider.EventActionOptions{
					IsFailureAction: true,
				},
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)

	r2 := dataprovider.EventRule{
		Name:    "test rule2",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"download"},
			Options: dataprovider.ConditionOptions{
				FsPaths: []dataprovider.ConditionPattern{
					{
						Pattern: "*.dat",
					},
				},
			},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 1,
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action3.Name,
				},
				Order: 2,
				Options: dataprovider.EventActionOptions{
					IsFailureAction: true,
				},
			},
		},
	}
	rule2, _, err := httpdtest.AddEventRule(r2, http.StatusCreated)
	assert.NoError(t, err)

	r3 := dataprovider.EventRule{
		Name:    "test rule3",
		Trigger: dataprovider.EventTriggerProviderEvent,
		Conditions: dataprovider.EventConditions{
			ProviderEvents: []string{"delete"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 1,
			},
		},
	}
	rule3, _, err := httpdtest.AddEventRule(r3, http.StatusCreated)
	assert.NoError(t, err)

	uploadScriptPath := filepath.Join(os.TempDir(), "upload.sh")
	u := getTestUser()
	u.DownloadDataTransfer = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	movedFileName := "moved.dat"
	movedPath := filepath.Join(user.HomeDir, movedFileName)
	err = os.WriteFile(uploadScriptPath, getUploadScriptContent(movedPath, "", 0), 0755)
	assert.NoError(t, err)

	action1.Type = dataprovider.ActionTypeCommand
	action1.Options = dataprovider.BaseEventActionOptions{
		CmdConfig: dataprovider.EventActionCommandConfig{
			Cmd:     uploadScriptPath,
			Timeout: 10,
			EnvVars: []dataprovider.KeyValue{
				{
					Key:   "SFTPGO_ACTION_PATH",
					Value: "{{FsPath}}",
				},
				{
					Key:   "CUSTOM_ENV_VAR",
					Value: "value",
				},
			},
		},
	}
	action1, _, err = httpdtest.UpdateEventAction(action1, http.StatusOK)
	assert.NoError(t, err)

	dirName := "subdir"
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		size := int64(32768)
		// rule conditions does not match
		err = writeSFTPFileNoCheck(testFileName, size, client)
		assert.NoError(t, err)
		info, err := client.Stat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, size, info.Size())
		}
		err = client.Mkdir(dirName)
		assert.NoError(t, err)
		err = client.Mkdir("subdir1")
		assert.NoError(t, err)
		// rule conditions match
		lastReceivedEmail.reset()
		err = writeSFTPFileNoCheck(path.Join(dirName, testFileName), size, client)
		assert.NoError(t, err)
		_, err = client.Stat(path.Join(dirName, testFileName))
		assert.Error(t, err)
		info, err = client.Stat(movedFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, size, info.Size())
		}
		assert.Eventually(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 3000*time.Millisecond, 100*time.Millisecond)
		email := lastReceivedEmail.get()
		assert.Len(t, email.To, 2)
		assert.True(t, util.Contains(email.To, "test1@example.com"))
		assert.True(t, util.Contains(email.To, "test2@example.com"))
		assert.Contains(t, email.Data, fmt.Sprintf(`Subject: New "upload" from "%s" status OK`, user.Username))
		// test the failure action, we download a file that exceeds the transfer quota limit
		err = writeSFTPFileNoCheck(path.Join("subdir1", testFileName), 1*1024*1024+65535, client)
		assert.NoError(t, err)
		lastReceivedEmail.reset()
		f, err := client.Open(path.Join("subdir1", testFileName))
		assert.NoError(t, err)
		_, err = io.ReadAll(f)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), common.ErrReadQuotaExceeded.Error())
		}
		err = f.Close()
		assert.Error(t, err)
		assert.Eventually(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 3000*time.Millisecond, 100*time.Millisecond)
		email = lastReceivedEmail.get()
		assert.Len(t, email.To, 2)
		assert.True(t, util.Contains(email.To, "test1@example.com"))
		assert.True(t, util.Contains(email.To, "test2@example.com"))
		assert.Contains(t, email.Data, fmt.Sprintf(`Subject: New "download" from "%s" status KO`, user.Username))
		assert.Contains(t, email.Data, `"download" failed`)
		assert.Contains(t, email.Data, common.ErrReadQuotaExceeded.Error())
		_, err = httpdtest.UpdateTransferQuotaUsage(user, "", http.StatusOK)
		assert.NoError(t, err)

		// remove the upload script to test the failure action
		err = os.Remove(uploadScriptPath)
		assert.NoError(t, err)
		lastReceivedEmail.reset()
		err = writeSFTPFileNoCheck(path.Join(dirName, testFileName), size, client)
		assert.Error(t, err)
		assert.Eventually(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 3000*time.Millisecond, 100*time.Millisecond)
		email = lastReceivedEmail.get()
		assert.Len(t, email.To, 1)
		assert.True(t, util.Contains(email.To, "failure@example.com"))
		assert.Contains(t, email.Data, fmt.Sprintf(`Subject: Failed "upload" from "%s"`, user.Username))
		assert.Contains(t, email.Data, fmt.Sprintf(`action %q failed`, action1.Name))
		// now test the download rule
		lastReceivedEmail.reset()
		f, err = client.Open(movedFileName)
		assert.NoError(t, err)
		contents, err := io.ReadAll(f)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
		assert.Len(t, contents, int(size))
		assert.Eventually(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 3000*time.Millisecond, 100*time.Millisecond)
		email = lastReceivedEmail.get()
		assert.Len(t, email.To, 2)
		assert.True(t, util.Contains(email.To, "test1@example.com"))
		assert.True(t, util.Contains(email.To, "test2@example.com"))
		assert.Contains(t, email.Data, fmt.Sprintf(`Subject: New "download" from "%s"`, user.Username))
	}
	// test upload action command with arguments
	action1.Options.CmdConfig.Args = []string{"{{Event}}", "{{VirtualPath}}", "custom_arg"}
	action1, _, err = httpdtest.UpdateEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	uploadLogFilePath := filepath.Join(os.TempDir(), "upload.log")
	err = os.WriteFile(uploadScriptPath, getUploadScriptContent(movedPath, uploadLogFilePath, 0), 0755)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = writeSFTPFileNoCheck(path.Join(dirName, testFileName), 123, client)
		assert.NoError(t, err)

		logContent, err := os.ReadFile(uploadLogFilePath)
		assert.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("upload %s custom_arg", util.CleanPath(path.Join(dirName, testFileName))),
			strings.TrimSpace(string(logContent)))

		err = os.Remove(uploadLogFilePath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventRule(rule2, http.StatusOK)
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		return lastReceivedEmail.get().From != ""
	}, 3000*time.Millisecond, 100*time.Millisecond)
	email := lastReceivedEmail.get()
	assert.Len(t, email.To, 2)
	assert.True(t, util.Contains(email.To, "test1@example.com"))
	assert.True(t, util.Contains(email.To, "test2@example.com"))
	assert.Contains(t, email.Data, `Subject: New "delete" from "admin"`)
	_, err = httpdtest.RemoveEventRule(rule3, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action3, http.StatusOK)
	assert.NoError(t, err)
	lastReceivedEmail.reset()
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)
}

func TestEventRuleProviderEvents(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notification@example.com",
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize(configDir)
	require.NoError(t, err)

	saveObjectScriptPath := filepath.Join(os.TempDir(), "provider.sh")
	outPath := filepath.Join(os.TempDir(), "provider_out.json")
	err = os.WriteFile(saveObjectScriptPath, getSaveProviderObjectScriptContent(outPath, 0), 0755)
	assert.NoError(t, err)

	a1 := dataprovider.BaseEventAction{
		Name: "a1",
		Type: dataprovider.ActionTypeCommand,
		Options: dataprovider.BaseEventActionOptions{
			CmdConfig: dataprovider.EventActionCommandConfig{
				Cmd:     saveObjectScriptPath,
				Timeout: 10,
				EnvVars: []dataprovider.KeyValue{
					{
						Key:   "SFTPGO_OBJECT_DATA",
						Value: "{{ObjectData}}",
					},
				},
			},
		},
	}
	a2 := dataprovider.BaseEventAction{
		Name: "a2",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"test3@example.com"},
				Subject:    `New "{{Event}}" from "{{Name}}"`,
				Body:       "Object name: {{ObjectName}} object type: {{ObjectType}} Data: {{ObjectData}}",
			},
		},
	}

	a3 := dataprovider.BaseEventAction{
		Name: "a3",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"failure@example.com"},
				Subject:    `Failed "{{Event}}" from "{{Name}}"`,
				Body:       "Object name: {{ObjectName}} object type: {{ObjectType}}, IP: {{IP}}",
			},
		},
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)
	action2, _, err := httpdtest.AddEventAction(a2, http.StatusCreated)
	assert.NoError(t, err)
	action3, _, err := httpdtest.AddEventAction(a3, http.StatusCreated)
	assert.NoError(t, err)

	r := dataprovider.EventRule{
		Name:    "rule",
		Trigger: dataprovider.EventTriggerProviderEvent,
		Conditions: dataprovider.EventConditions{
			ProviderEvents: []string{"update"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
				Options: dataprovider.EventActionOptions{
					StopOnFailure: true,
				},
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 2,
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action3.Name,
				},
				Order: 3,
				Options: dataprovider.EventActionOptions{
					IsFailureAction: true,
					StopOnFailure:   true,
				},
			},
		},
	}
	rule, _, err := httpdtest.AddEventRule(r, http.StatusCreated)
	assert.NoError(t, err)

	lastReceivedEmail.reset()
	// create and update a folder to trigger the rule
	folder := vfs.BaseVirtualFolder{
		Name:       "ftest rule",
		MappedPath: filepath.Join(os.TempDir(), "p"),
	}
	folder, _, err = httpdtest.AddFolder(folder, http.StatusCreated)
	assert.NoError(t, err)
	// no action is triggered on add
	assert.NoFileExists(t, outPath)
	// update the folder
	_, _, err = httpdtest.UpdateFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	if assert.Eventually(t, func() bool {
		_, err := os.Stat(outPath)
		return err == nil
	}, 2*time.Second, 100*time.Millisecond) {
		content, err := os.ReadFile(outPath)
		assert.NoError(t, err)
		var folderGet vfs.BaseVirtualFolder
		err = json.Unmarshal(content, &folderGet)
		assert.NoError(t, err)
		assert.Equal(t, folder, folderGet)
		err = os.Remove(outPath)
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 3000*time.Millisecond, 100*time.Millisecond)
		email := lastReceivedEmail.get()
		assert.Len(t, email.To, 1)
		assert.True(t, util.Contains(email.To, "test3@example.com"))
		assert.Contains(t, email.Data, `Subject: New "update" from "admin"`)
	}
	// now delete the script to generate an error
	lastReceivedEmail.reset()
	err = os.Remove(saveObjectScriptPath)
	assert.NoError(t, err)
	_, _, err = httpdtest.UpdateFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	assert.NoFileExists(t, outPath)
	assert.Eventually(t, func() bool {
		return lastReceivedEmail.get().From != ""
	}, 3000*time.Millisecond, 100*time.Millisecond)
	email := lastReceivedEmail.get()
	assert.Len(t, email.To, 1)
	assert.True(t, util.Contains(email.To, "failure@example.com"))
	assert.Contains(t, email.Data, `Subject: Failed "update" from "admin"`)
	assert.Contains(t, email.Data, fmt.Sprintf("Object name: %s object type: folder", folder.Name))
	lastReceivedEmail.reset()
	// generate an error for the failure action
	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)
	_, _, err = httpdtest.UpdateFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	assert.NoFileExists(t, outPath)
	email = lastReceivedEmail.get()
	assert.Len(t, email.To, 0)

	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveEventRule(rule, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action3, http.StatusOK)
	assert.NoError(t, err)
}

func TestEventRuleFsActions(t *testing.T) {
	dirsToCreate := []string{
		"/basedir/1",
		"/basedir/sub/2",
		"/basedir/3",
	}
	a1 := dataprovider.BaseEventAction{
		Name: "a1",
		Type: dataprovider.ActionTypeFilesystem,
		Options: dataprovider.BaseEventActionOptions{
			FsConfig: dataprovider.EventActionFilesystemConfig{
				Type:   dataprovider.FilesystemActionMkdirs,
				MkDirs: dirsToCreate,
			},
		},
	}
	a2 := dataprovider.BaseEventAction{
		Name: "a2",
		Type: dataprovider.ActionTypeFilesystem,
		Options: dataprovider.BaseEventActionOptions{
			FsConfig: dataprovider.EventActionFilesystemConfig{
				Type: dataprovider.FilesystemActionRename,
				Renames: []dataprovider.KeyValue{
					{
						Key:   "/{{VirtualPath}}",
						Value: "/{{ObjectName}}_renamed",
					},
				},
			},
		},
	}
	a3 := dataprovider.BaseEventAction{
		Name: "a3",
		Type: dataprovider.ActionTypeFilesystem,
		Options: dataprovider.BaseEventActionOptions{
			FsConfig: dataprovider.EventActionFilesystemConfig{
				Type:    dataprovider.FilesystemActionDelete,
				Deletes: []string{"/{{ObjectName}}_renamed"},
			},
		},
	}
	a4 := dataprovider.BaseEventAction{
		Name: "a4",
		Type: dataprovider.ActionTypeFolderQuotaReset,
	}
	a5 := dataprovider.BaseEventAction{
		Name: "a5",
		Type: dataprovider.ActionTypeUserQuotaReset,
	}
	a6 := dataprovider.BaseEventAction{
		Name: "a6",
		Type: dataprovider.ActionTypeFilesystem,
		Options: dataprovider.BaseEventActionOptions{
			FsConfig: dataprovider.EventActionFilesystemConfig{
				Type:  dataprovider.FilesystemActionExist,
				Exist: []string{"/{{VirtualPath}}"},
			},
		},
	}
	action1, resp, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	action2, resp, err := httpdtest.AddEventAction(a2, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	action3, resp, err := httpdtest.AddEventAction(a3, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	action4, resp, err := httpdtest.AddEventAction(a4, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	action5, resp, err := httpdtest.AddEventAction(a5, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	action6, resp, err := httpdtest.AddEventAction(a6, http.StatusCreated)
	assert.NoError(t, err, string(resp))

	r1 := dataprovider.EventRule{
		Name:    "r1",
		Trigger: dataprovider.EventTriggerProviderEvent,
		Conditions: dataprovider.EventConditions{
			ProviderEvents: []string{"add"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
		},
	}
	r2 := dataprovider.EventRule{
		Name:    "r2",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"upload"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 1,
				Options: dataprovider.EventActionOptions{
					ExecuteSync: true,
				},
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action5.Name,
				},
				Order: 2,
			},
		},
	}
	r3 := dataprovider.EventRule{
		Name:    "r3",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"mkdir"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action3.Name,
				},
				Order: 1,
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action6.Name,
				},
				Order: 2,
			},
		},
	}
	r4 := dataprovider.EventRule{
		Name:    "r4",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"rmdir"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action4.Name,
				},
				Order: 1,
			},
		},
	}
	r5 := dataprovider.EventRule{
		Name:    "r5",
		Trigger: dataprovider.EventTriggerProviderEvent,
		Conditions: dataprovider.EventConditions{
			ProviderEvents: []string{"add"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action4.Name,
				},
				Order: 1,
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)
	rule2, _, err := httpdtest.AddEventRule(r2, http.StatusCreated)
	assert.NoError(t, err)
	rule3, _, err := httpdtest.AddEventRule(r3, http.StatusCreated)
	assert.NoError(t, err)
	rule4, _, err := httpdtest.AddEventRule(r4, http.StatusCreated)
	assert.NoError(t, err)
	rule5, _, err := httpdtest.AddEventRule(r5, http.StatusCreated)
	assert.NoError(t, err)

	folderMappedPath := filepath.Join(os.TempDir(), "folder")
	err = os.MkdirAll(folderMappedPath, os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(folderMappedPath, "file.txt"), []byte("1"), 0666)
	assert.NoError(t, err)

	folder, _, err := httpdtest.AddFolder(vfs.BaseVirtualFolder{
		Name:       "test folder",
		MappedPath: folderMappedPath,
	}, http.StatusCreated)
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		folderGet, _, err := httpdtest.GetFolderByName(folder.Name, http.StatusOK)
		if err != nil {
			return false
		}
		return folderGet.UsedQuotaFiles == 1 && folderGet.UsedQuotaSize == 1
	}, 2*time.Second, 100*time.Millisecond)

	u := getTestUser()
	u.Filters.DisableFsChecks = true
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		// check initial directories creation
		for _, dir := range dirsToCreate {
			assert.Eventually(t, func() bool {
				_, err := client.Stat(dir)
				return err == nil
			}, 2*time.Second, 100*time.Millisecond)
		}
		// upload a file and check the sync rename
		size := int64(32768)
		err = writeSFTPFileNoCheck(path.Join("basedir", testFileName), size, client)
		assert.NoError(t, err)
		_, err = client.Stat(path.Join("basedir", testFileName))
		assert.Error(t, err)
		info, err := client.Stat(testFileName + "_renamed")
		if assert.NoError(t, err) {
			assert.Equal(t, size, info.Size())
		}
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			userGet, _, err := httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			if err != nil {
				return false
			}
			return userGet.UsedQuotaFiles == 1 && userGet.UsedQuotaSize == size
		}, 2*time.Second, 100*time.Millisecond)

		for i := 0; i < 2; i++ {
			err = client.Mkdir(testFileName)
			assert.NoError(t, err)
			assert.Eventually(t, func() bool {
				_, err = client.Stat(testFileName + "_renamed")
				return err != nil
			}, 2*time.Second, 100*time.Millisecond)
			err = client.RemoveDirectory(testFileName)
			assert.NoError(t, err)
		}
		err = client.Mkdir(testFileName + "_renamed")
		assert.NoError(t, err)
		err = client.Mkdir(testFileName)
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			_, err = client.Stat(testFileName + "_renamed")
			return err != nil
		}, 2*time.Second, 100*time.Millisecond)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(folderMappedPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventRule(rule2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventRule(rule3, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventRule(rule4, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventRule(rule5, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action3, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action4, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action5, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action6, http.StatusOK)
	assert.NoError(t, err)
}

func TestEventFsActionsGroupFilters(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notification@example.com",
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize(configDir)
	require.NoError(t, err)

	a1 := dataprovider.BaseEventAction{
		Name: "a1",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"example@example.net"},
				Subject:    `New "{{Event}}" from "{{Name}}" status {{StatusString}}`,
				Body:       "Fs path {{FsPath}}, size: {{FileSize}}, protocol: {{Protocol}}, IP: {{IP}} {{ErrorString}}",
			},
		},
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)

	r1 := dataprovider.EventRule{
		Name:    "rule1",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"upload"},
			Options: dataprovider.ConditionOptions{
				GroupNames: []dataprovider.ConditionPattern{
					{
						Pattern: "group*",
					},
				},
			},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
				Options: dataprovider.EventActionOptions{
					ExecuteSync: true,
				},
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		// the user has no group, so the rule does not match
		lastReceivedEmail.reset()
		err = writeSFTPFile(testFileName, 32, client)
		assert.NoError(t, err)
		assert.Empty(t, lastReceivedEmail.get().From)
	}
	g1 := dataprovider.Group{
		BaseGroup: sdk.BaseGroup{
			Name: "agroup1",
		},
	}
	group1, _, err := httpdtest.AddGroup(g1, http.StatusCreated)
	assert.NoError(t, err)

	g2 := dataprovider.Group{
		BaseGroup: sdk.BaseGroup{
			Name: "group2",
		},
	}
	group2, _, err := httpdtest.AddGroup(g2, http.StatusCreated)
	assert.NoError(t, err)
	user.Groups = []sdk.GroupMapping{
		{
			Name: group1.Name,
			Type: sdk.GroupTypePrimary,
		},
	}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		// the group does not match
		lastReceivedEmail.reset()
		err = writeSFTPFile(testFileName, 32, client)
		assert.NoError(t, err)
		assert.Empty(t, lastReceivedEmail.get().From)
	}
	user.Groups = append(user.Groups, sdk.GroupMapping{
		Name: group2.Name,
		Type: sdk.GroupTypeSecondary,
	})
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		// the group matches
		lastReceivedEmail.reset()
		err = writeSFTPFile(testFileName, 32, client)
		assert.NoError(t, err)
		assert.NotEmpty(t, lastReceivedEmail.get().From)
	}
	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveGroup(group1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveGroup(group2, http.StatusOK)
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)
}

func TestEventActionHTTPMultipart(t *testing.T) {
	a1 := dataprovider.BaseEventAction{
		Name: "action1",
		Type: dataprovider.ActionTypeHTTP,
		Options: dataprovider.BaseEventActionOptions{
			HTTPConfig: dataprovider.EventActionHTTPConfig{
				Endpoint: fmt.Sprintf("http://%s/multipart", httpAddr),
				Method:   http.MethodPut,
				Parts: []dataprovider.HTTPPart{
					{
						Name: "part1",
						Headers: []dataprovider.KeyValue{
							{
								Key:   "Content-Type",
								Value: "application/json",
							},
						},
						Body: `{"FilePath": "{{VirtualPath}}"}`,
					},
					{
						Name:     "file",
						Filepath: "/{{VirtualPath}}",
					},
				},
			},
		},
	}
	action1, resp, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	r1 := dataprovider.EventRule{
		Name:    "test http multipart",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"upload"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Options: dataprovider.EventActionOptions{
					ExecuteSync: true,
				},
				Order: 1,
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		f, err := client.Create(testFileName)
		assert.NoError(t, err)
		_, err = f.Write(testFileContent)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
		// now add an missing file to the http multipart action
		action1.Options.HTTPConfig.Parts = append(action1.Options.HTTPConfig.Parts, dataprovider.HTTPPart{
			Name:     "file1",
			Filepath: "/missing",
		})
		_, resp, err = httpdtest.UpdateEventAction(action1, http.StatusOK)
		assert.NoError(t, err, string(resp))

		f, err = client.Create("testfile.txt")
		assert.NoError(t, err)
		_, err = f.Write(testFileContent)
		assert.NoError(t, err)
		err = f.Close()
		assert.Error(t, err)
	}

	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestEventActionEmailAttachments(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notify@example.com",
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize(configDir)
	require.NoError(t, err)

	a1 := dataprovider.BaseEventAction{
		Name: "action1",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients:  []string{"test@example.com"},
				Subject:     `"{{Event}}" from "{{Name}}"`,
				Body:        "Fs path {{FsPath}}, size: {{FileSize}}, protocol: {{Protocol}}, IP: {{IP}}",
				Attachments: []string{"/{{VirtualPath}}"},
			},
		},
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)
	r1 := dataprovider.EventRule{
		Name:    "test email with attachment",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"upload"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)
	localUser, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	u := getTestSFTPUser()
	u.FsConfig.SFTPConfig.BufferSize = 1
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	cryptFsUser, _, err := httpdtest.AddUser(getCryptFsUser(), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser, cryptFsUser} {
		conn, client, err := getSftpClient(user)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()

			lastReceivedEmail.reset()
			f, err := client.Create(testFileName)
			assert.NoError(t, err)
			_, err = f.Write(testFileContent)
			assert.NoError(t, err)
			err = f.Close()
			assert.NoError(t, err)
			assert.Eventually(t, func() bool {
				return lastReceivedEmail.get().From != ""
			}, 1500*time.Millisecond, 100*time.Millisecond)
			email := lastReceivedEmail.get()
			assert.Len(t, email.To, 1)
			assert.True(t, util.Contains(email.To, "test@example.com"))
			assert.Contains(t, email.Data, fmt.Sprintf(`Subject: "upload" from "%s"`, user.Username))
			assert.Contains(t, email.Data, "Content-Disposition: attachment")
		}
	}

	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(cryptFsUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(cryptFsUser.GetHomeDir())
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)
}

func TestEventActionsRetentionReports(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notify@example.com",
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize(configDir)
	require.NoError(t, err)

	testDir := "/d"
	a1 := dataprovider.BaseEventAction{
		Name: "action1",
		Type: dataprovider.ActionTypeDataRetentionCheck,
		Options: dataprovider.BaseEventActionOptions{
			RetentionConfig: dataprovider.EventActionDataRetentionConfig{
				Folders: []dataprovider.FolderRetention{
					{
						Path:                  testDir,
						Retention:             1,
						DeleteEmptyDirs:       true,
						IgnoreUserPermissions: true,
					},
				},
			},
		},
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)
	a2 := dataprovider.BaseEventAction{
		Name: "action2",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients:  []string{"test@example.com"},
				Subject:     `"{{Event}}" from "{{Name}}"`,
				Body:        "Fs path {{FsPath}}, size: {{FileSize}}, protocol: {{Protocol}}, IP: {{IP}}",
				Attachments: []string{dataprovider.RetentionReportPlaceHolder},
			},
		},
	}
	action2, _, err := httpdtest.AddEventAction(a2, http.StatusCreated)
	assert.NoError(t, err)
	a3 := dataprovider.BaseEventAction{
		Name: "action3",
		Type: dataprovider.ActionTypeHTTP,
		Options: dataprovider.BaseEventActionOptions{
			HTTPConfig: dataprovider.EventActionHTTPConfig{
				Endpoint: fmt.Sprintf("http://%s/", httpAddr),
				Timeout:  20,
				Method:   http.MethodPost,
				Body:     dataprovider.RetentionReportPlaceHolder,
			},
		},
	}
	action3, _, err := httpdtest.AddEventAction(a3, http.StatusCreated)
	assert.NoError(t, err)
	a4 := dataprovider.BaseEventAction{
		Name: "action4",
		Type: dataprovider.ActionTypeHTTP,
		Options: dataprovider.BaseEventActionOptions{
			HTTPConfig: dataprovider.EventActionHTTPConfig{
				Endpoint: fmt.Sprintf("http://%s/multipart", httpAddr),
				Timeout:  20,
				Method:   http.MethodPost,
				Parts: []dataprovider.HTTPPart{
					{
						Name:     "reports.zip",
						Filepath: dataprovider.RetentionReportPlaceHolder,
					},
				},
			},
		},
	}
	action4, _, err := httpdtest.AddEventAction(a4, http.StatusCreated)
	assert.NoError(t, err)
	r1 := dataprovider.EventRule{
		Name:    "test rule1",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"upload"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
				Options: dataprovider.EventActionOptions{
					ExecuteSync:   true,
					StopOnFailure: true,
				},
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 2,
				Options: dataprovider.EventActionOptions{
					ExecuteSync:   true,
					StopOnFailure: true,
				},
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action3.Name,
				},
				Order: 3,
				Options: dataprovider.EventActionOptions{
					ExecuteSync:   true,
					StopOnFailure: true,
				},
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action4.Name,
				},
				Order: 4,
				Options: dataprovider.EventActionOptions{
					ExecuteSync:   true,
					StopOnFailure: true,
				},
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		subdir := path.Join(testDir, "sub")
		err = client.MkdirAll(subdir)
		assert.NoError(t, err)

		lastReceivedEmail.reset()
		f, err := client.Create(testFileName)
		assert.NoError(t, err)
		_, err = f.Write(testFileContent)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)

		email := lastReceivedEmail.get()
		assert.Len(t, email.To, 1)
		assert.True(t, util.Contains(email.To, "test@example.com"))
		assert.Contains(t, email.Data, fmt.Sprintf(`Subject: "upload" from "%s"`, user.Username))
		assert.Contains(t, email.Data, "Content-Disposition: attachment")
		_, err = client.Stat(testDir)
		assert.NoError(t, err)
		_, err = client.Stat(subdir)
		assert.ErrorIs(t, err, os.ErrNotExist)

		err = client.Mkdir(subdir)
		assert.NoError(t, err)
		newName := path.Join(testDir, testFileName)
		err = client.Rename(testFileName, newName)
		assert.NoError(t, err)
		err = client.Chtimes(newName, time.Now().Add(-24*time.Hour), time.Now().Add(-24*time.Hour))
		assert.NoError(t, err)

		lastReceivedEmail.reset()
		f, err = client.Create(testFileName)
		assert.NoError(t, err)
		_, err = f.Write(testFileContent)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
		email = lastReceivedEmail.get()
		assert.Len(t, email.To, 1)
		_, err = client.Stat(subdir)
		assert.ErrorIs(t, err, os.ErrNotExist)
		_, err = client.Stat(subdir)
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	// now remove the retention check to test errors
	rule1.Actions = []dataprovider.EventAction{
		{
			BaseEventAction: dataprovider.BaseEventAction{
				Name: action2.Name,
			},
			Order: 2,
			Options: dataprovider.EventActionOptions{
				ExecuteSync:   true,
				StopOnFailure: false,
			},
		},
		{
			BaseEventAction: dataprovider.BaseEventAction{
				Name: action3.Name,
			},
			Order: 3,
			Options: dataprovider.EventActionOptions{
				ExecuteSync:   true,
				StopOnFailure: false,
			},
		},
		{
			BaseEventAction: dataprovider.BaseEventAction{
				Name: action4.Name,
			},
			Order: 4,
			Options: dataprovider.EventActionOptions{
				ExecuteSync:   true,
				StopOnFailure: false,
			},
		},
	}
	_, _, err = httpdtest.UpdateEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		f, err := client.Create(testFileName)
		assert.NoError(t, err)
		_, err = f.Write(testFileContent)
		assert.NoError(t, err)
		err = f.Close()
		assert.Error(t, err)
	}

	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action3, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action4, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)
}

func TestEventRuleFirstUploadDownloadActions(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notify@example.com",
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize(configDir)
	require.NoError(t, err)
	a1 := dataprovider.BaseEventAction{
		Name: "action1",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"test@example.com"},
				Subject:    `"{{Event}}" from "{{Name}}"`,
				Body:       "Fs path {{FsPath}}, size: {{FileSize}}, protocol: {{Protocol}}, IP: {{IP}}",
			},
		},
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)
	r1 := dataprovider.EventRule{
		Name:    "test first upload rule",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"first-upload"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)
	r2 := dataprovider.EventRule{
		Name:    "test first download rule",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{"first-download"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
		},
	}
	rule2, _, err := httpdtest.AddEventRule(r2, http.StatusCreated)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		testFileSize := int64(32768)
		lastReceivedEmail.reset()
		err = writeSFTPFileNoCheck(testFileName, testFileSize, client)
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 1500*time.Millisecond, 100*time.Millisecond)
		email := lastReceivedEmail.get()
		assert.Len(t, email.To, 1)
		assert.True(t, util.Contains(email.To, "test@example.com"))
		assert.Contains(t, email.Data, fmt.Sprintf(`Subject: "first-upload" from "%s"`, user.Username))
		lastReceivedEmail.reset()
		// a new upload will not produce a new notification
		err = writeSFTPFileNoCheck(testFileName+"_1", 32768, client)
		assert.NoError(t, err)
		assert.Never(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 1000*time.Millisecond, 100*time.Millisecond)
		// the same for download
		f, err := client.Open(testFileName)
		assert.NoError(t, err)
		contents := make([]byte, testFileSize)
		n, err := io.ReadFull(f, contents)
		assert.NoError(t, err)
		assert.Equal(t, int(testFileSize), n)
		err = f.Close()
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 1500*time.Millisecond, 100*time.Millisecond)
		email = lastReceivedEmail.get()
		assert.Len(t, email.To, 1)
		assert.True(t, util.Contains(email.To, "test@example.com"))
		assert.Contains(t, email.Data, fmt.Sprintf(`Subject: "first-download" from "%s"`, user.Username))
		// download again
		lastReceivedEmail.reset()
		f, err = client.Open(testFileName)
		assert.NoError(t, err)
		contents = make([]byte, testFileSize)
		n, err = io.ReadFull(f, contents)
		assert.NoError(t, err)
		assert.Equal(t, int(testFileSize), n)
		err = f.Close()
		assert.NoError(t, err)
		assert.Never(t, func() bool {
			return lastReceivedEmail.get().From != ""
		}, 1000*time.Millisecond, 100*time.Millisecond)
	}

	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventRule(rule2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)
}

func TestEventRuleCertificate(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notify@example.com",
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize(configDir)
	require.NoError(t, err)
	lastReceivedEmail.reset()

	a1 := dataprovider.BaseEventAction{
		Name: "action1",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"test@example.com"},
				Subject:    `"{{Event}} {{StatusString}}"`,
				Body:       "Domain: {{Name}} Timestamp: {{Timestamp}} {{ErrorString}}",
			},
		},
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)

	a2 := dataprovider.BaseEventAction{
		Name: "action2",
		Type: dataprovider.ActionTypeFolderQuotaReset,
	}
	action2, _, err := httpdtest.AddEventAction(a2, http.StatusCreated)
	assert.NoError(t, err)

	r1 := dataprovider.EventRule{
		Name:    "test rule certificate",
		Trigger: dataprovider.EventTriggerCertificate,
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)
	r2 := dataprovider.EventRule{
		Name:    "test rule 2",
		Trigger: dataprovider.EventTriggerCertificate,
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 2,
			},
		},
	}
	rule2, _, err := httpdtest.AddEventRule(r2, http.StatusCreated)
	assert.NoError(t, err)

	renewalEvent := "Certificate renewal"

	common.HandleCertificateEvent(common.EventParams{
		Name:      "example.com",
		Timestamp: time.Now().UnixNano(),
		Status:    1,
		Event:     renewalEvent,
	})
	assert.Eventually(t, func() bool {
		return lastReceivedEmail.get().From != ""
	}, 3000*time.Millisecond, 100*time.Millisecond)
	email := lastReceivedEmail.get()
	assert.Len(t, email.To, 1)
	assert.True(t, util.Contains(email.To, "test@example.com"))
	assert.Contains(t, email.Data, fmt.Sprintf(`Subject: "%s OK"`, renewalEvent))
	assert.Contains(t, email.Data, `Domain: example.com Timestamp`)

	lastReceivedEmail.reset()
	params := common.EventParams{
		Name:      "example.com",
		Timestamp: time.Now().UnixNano(),
		Status:    2,
		Event:     renewalEvent,
	}
	errRenew := errors.New("generic renew error")
	params.AddError(errRenew)
	common.HandleCertificateEvent(params)
	assert.Eventually(t, func() bool {
		return lastReceivedEmail.get().From != ""
	}, 3000*time.Millisecond, 100*time.Millisecond)
	email = lastReceivedEmail.get()
	assert.Len(t, email.To, 1)
	assert.True(t, util.Contains(email.To, "test@example.com"))
	assert.Contains(t, email.Data, fmt.Sprintf(`Subject: "%s KO"`, renewalEvent))
	assert.Contains(t, email.Data, `Domain: example.com Timestamp`)
	assert.Contains(t, email.Data, errRenew.Error())

	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventRule(rule2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action2, http.StatusOK)
	assert.NoError(t, err)
	// ignored no more certificate rules
	common.HandleCertificateEvent(common.EventParams{
		Name:      "example.com",
		Timestamp: time.Now().UnixNano(),
		Status:    1,
		Event:     renewalEvent,
	})

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)
}

func TestEventRuleIPBlocked(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	cfg := config.GetCommonConfig()
	cfg.DefenderConfig.Enabled = true
	cfg.DefenderConfig.Threshold = 3
	cfg.DefenderConfig.ScoreLimitExceeded = 2

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notification@example.com",
		TemplatesPath: "templates",
	}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)

	a1 := dataprovider.BaseEventAction{
		Name: "action1",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"test3@example.com", "test4@example.com"},
				Subject:    `New "{{Event}}"`,
				Body:       "IP: {{IP}} Timestamp: {{Timestamp}}",
			},
		},
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)

	a2 := dataprovider.BaseEventAction{
		Name: "action2",
		Type: dataprovider.ActionTypeFolderQuotaReset,
	}
	action2, _, err := httpdtest.AddEventAction(a2, http.StatusCreated)
	assert.NoError(t, err)

	r1 := dataprovider.EventRule{
		Name:    "test rule ip blocked",
		Trigger: dataprovider.EventTriggerIPBlocked,
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)
	r2 := dataprovider.EventRule{
		Name:    "test rule 2",
		Trigger: dataprovider.EventTriggerIPBlocked,
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 2,
			},
		},
	}
	rule2, _, err := httpdtest.AddEventRule(r2, http.StatusCreated)
	assert.NoError(t, err)

	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	lastReceivedEmail.reset()
	time.Sleep(300 * time.Millisecond)
	assert.Empty(t, lastReceivedEmail.get().From, lastReceivedEmail.get().Data)

	for i := 0; i < 3; i++ {
		user.Password = "wrong_pwd"
		_, _, err = getSftpClient(user)
		assert.Error(t, err)
	}
	// the client is now banned
	user.Password = defaultPassword
	_, _, err = getSftpClient(user)
	assert.Error(t, err)
	// check the email notification
	assert.Eventually(t, func() bool {
		return lastReceivedEmail.get().From != ""
	}, 3000*time.Millisecond, 100*time.Millisecond)
	email := lastReceivedEmail.get()
	assert.Len(t, email.To, 2)
	assert.True(t, util.Contains(email.To, "test3@example.com"))
	assert.True(t, util.Contains(email.To, "test4@example.com"))
	assert.Contains(t, email.Data, `Subject: New "IP Blocked"`)

	err = dataprovider.DeleteEventRule(rule1.Name, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteEventRule(rule2.Name, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteEventAction(action1.Name, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteEventAction(action2.Name, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)

	err = common.Initialize(oldConfig, 0)
	assert.NoError(t, err)
}

func TestSyncUploadAction(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	uploadScriptPath := filepath.Join(os.TempDir(), "upload.sh")
	common.Config.Actions.ExecuteOn = []string{"upload"}
	common.Config.Actions.ExecuteSync = []string{"upload"}
	common.Config.Actions.Hook = uploadScriptPath

	u := getTestUser()
	u.QuotaFiles = 1000
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	movedFileName := "moved.dat"
	movedPath := filepath.Join(user.HomeDir, movedFileName)
	err = os.WriteFile(uploadScriptPath, getUploadScriptContent(movedPath, "", 0), 0755)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		size := int64(32768)
		err = writeSFTPFileNoCheck(testFileName, size, client)
		assert.NoError(t, err)
		_, err = client.Stat(testFileName)
		assert.Error(t, err)
		info, err := client.Stat(movedFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, size, info.Size())
		}
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, size, user.UsedQuotaSize)
		// test some hook failure
		// the uploaded file is moved and the hook fails, it will be not removed from the quota
		err = os.WriteFile(uploadScriptPath, getUploadScriptContent(movedPath, "", 1), 0755)
		assert.NoError(t, err)
		err = writeSFTPFileNoCheck(testFileName+"_1", size, client)
		assert.Error(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, size*2, user.UsedQuotaSize)

		// the uploaded file is not moved and the hook fails, the uploaded file will be deleted
		// and removed from the quota
		movedPath = filepath.Join(user.HomeDir, "missing dir", movedFileName)
		err = os.WriteFile(uploadScriptPath, getUploadScriptContent(movedPath, "", 1), 0755)
		assert.NoError(t, err)
		err = writeSFTPFileNoCheck(testFileName+"_2", size, client)
		assert.Error(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, size*2, user.UsedQuotaSize)
		// overwrite an existing file
		_, err = client.Stat(movedFileName)
		assert.NoError(t, err)
		err = writeSFTPFileNoCheck(movedFileName, size, client)
		assert.Error(t, err)
		_, err = client.Stat(movedFileName)
		assert.Error(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, size, user.UsedQuotaSize)
	}

	err = os.Remove(uploadScriptPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.Actions.ExecuteOn = nil
	common.Config.Actions.ExecuteSync = nil
	common.Config.Actions.Hook = uploadScriptPath
}

func TestQuotaTrackDisabled(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.TrackQuota = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = writeSFTPFile(testFileName, 32, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+"1")
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestGetQuotaError(t *testing.T) {
	if dataprovider.GetProviderStatus().Driver == "memory" {
		t.Skip("this test is not available with the memory provider")
	}
	u := getTestUser()
	u.TotalDataTransfer = 2000
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	folderName := filepath.Base(mappedPath)
	vdirPath := "/vpath"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
		QuotaSize:   0,
		QuotaFiles:  10,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = writeSFTPFile(testFileName, 32, client)
		assert.NoError(t, err)

		err = dataprovider.Close()
		assert.NoError(t, err)

		err = client.Rename(testFileName, path.Join(vdirPath, testFileName))
		assert.Error(t, err)

		err = config.LoadConfig(configDir, "")
		assert.NoError(t, err)
		providerConf := config.GetProviderConf()
		err = dataprovider.Initialize(providerConf, configDir, true)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestRetentionAPI(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	uploadPath := path.Join(testDir, testFileName)

	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = writeSFTPFile(uploadPath, 32, client)
		assert.NoError(t, err)

		folderRetention := []dataprovider.FolderRetention{
			{
				Path:            "/",
				Retention:       24,
				DeleteEmptyDirs: true,
			},
		}
		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		_, err = client.Stat(uploadPath)
		assert.NoError(t, err)

		err = client.Chtimes(uploadPath, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
		assert.NoError(t, err)

		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		_, err = client.Stat(uploadPath)
		assert.ErrorIs(t, err, os.ErrNotExist)

		_, err = client.Stat(testDir)
		assert.ErrorIs(t, err, os.ErrNotExist)

		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = writeSFTPFile(uploadPath, 32, client)
		assert.NoError(t, err)

		folderRetention[0].DeleteEmptyDirs = false
		err = client.Chtimes(uploadPath, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
		assert.NoError(t, err)

		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		_, err = client.Stat(uploadPath)
		assert.ErrorIs(t, err, os.ErrNotExist)

		_, err = client.Stat(testDir)
		assert.NoError(t, err)

		err = writeSFTPFile(uploadPath, 32, client)
		assert.NoError(t, err)
		err = client.Chtimes(uploadPath, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
		assert.NoError(t, err)
	}

	// remove delete permissions to the user
	user.Permissions["/"+testDir] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermCreateDirs, dataprovider.PermChtimes}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		innerUploadFilePath := path.Join("/"+testDir, testDir, testFileName)
		err = client.Mkdir(path.Join(testDir, testDir))
		assert.NoError(t, err)

		err = writeSFTPFile(innerUploadFilePath, 32, client)
		assert.NoError(t, err)
		err = client.Chtimes(innerUploadFilePath, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
		assert.NoError(t, err)

		folderRetention := []dataprovider.FolderRetention{
			{
				Path:      "/missing",
				Retention: 24,
			},
			{
				Path:            "/" + testDir,
				Retention:       24,
				DeleteEmptyDirs: true,
			},
			{
				Path:                  path.Dir(innerUploadFilePath),
				Retention:             0,
				IgnoreUserPermissions: true,
			},
		}
		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		_, err = client.Stat(uploadPath)
		assert.NoError(t, err)
		_, err = client.Stat(innerUploadFilePath)
		assert.NoError(t, err)

		folderRetention[1].IgnoreUserPermissions = true
		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		_, err = client.Stat(uploadPath)
		assert.ErrorIs(t, err, os.ErrNotExist)
		_, err = client.Stat(innerUploadFilePath)
		assert.NoError(t, err)

		folderRetention = []dataprovider.FolderRetention{

			{
				Path:                  "/" + testDir,
				Retention:             24,
				DeleteEmptyDirs:       true,
				IgnoreUserPermissions: true,
			},
		}

		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		_, err = client.Stat(innerUploadFilePath)
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	// finally test some errors removing files or folders
	if runtime.GOOS != osWindows {
		dirPath := filepath.Join(user.HomeDir, "adir", "sub")
		err := os.MkdirAll(dirPath, os.ModePerm)
		assert.NoError(t, err)
		filePath := filepath.Join(dirPath, "f.dat")
		err = os.WriteFile(filePath, nil, os.ModePerm)
		assert.NoError(t, err)

		err = os.Chtimes(filePath, time.Now().Add(-72*time.Hour), time.Now().Add(-72*time.Hour))
		assert.NoError(t, err)

		err = os.Chmod(dirPath, 0001)
		assert.NoError(t, err)

		folderRetention := []dataprovider.FolderRetention{

			{
				Path:                  "/adir",
				Retention:             24,
				DeleteEmptyDirs:       true,
				IgnoreUserPermissions: true,
			},
		}

		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		err = os.Chmod(dirPath, 0555)
		assert.NoError(t, err)

		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		err = os.Chmod(dirPath, os.ModePerm)
		assert.NoError(t, err)

		_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
		assert.NoError(t, err)

		assert.Eventually(t, func() bool {
			return len(common.RetentionChecks.Get()) == 0
		}, 1000*time.Millisecond, 50*time.Millisecond)

		assert.NoDirExists(t, dirPath)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRenameDir(t *testing.T) {
	u := getTestUser()
	testDir := "/dir-to-rename"
	u.Permissions[testDir] = []string{dataprovider.PermListItems, dataprovider.PermUpload}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(testDir, testFileName), 32, client)
		assert.NoError(t, err)
		err = client.Rename(testDir, testDir+"_rename")
		assert.ErrorIs(t, err, os.ErrPermission)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestBuiltinKeyboardInteractiveAuthentication(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	authMethods := []ssh.AuthMethod{
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			return []string{defaultPassword}, nil
		}),
	}
	conn, client, err := getCustomAuthSftpClient(user, authMethods)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		err = writeSFTPFile(testFileName, 4096, client)
		assert.NoError(t, err)
	}
	// add multi-factor authentication
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH},
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	passcode, err := generateTOTPPasscode(secret, otp.AlgorithmSHA1)
	assert.NoError(t, err)
	passwordAsked := false
	passcodeAsked := false
	authMethods = []ssh.AuthMethod{
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			var answers []string
			if strings.HasPrefix(questions[0], "Password") {
				answers = append(answers, defaultPassword)
				passwordAsked = true
			} else {
				answers = append(answers, passcode)
				passcodeAsked = true
			}
			return answers, nil
		}),
	}
	conn, client, err = getCustomAuthSftpClient(user, authMethods)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		err = writeSFTPFile(testFileName, 4096, client)
		assert.NoError(t, err)
	}
	assert.True(t, passwordAsked)
	assert.True(t, passcodeAsked)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRenameSymlink(t *testing.T) {
	u := getTestUser()
	testDir := "/dir-no-create-links"
	otherDir := "otherdir"
	u.Permissions[testDir] = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermCreateDirs}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir(otherDir)
		assert.NoError(t, err)
		err = client.Symlink(otherDir, otherDir+".link")
		assert.NoError(t, err)
		err = client.Rename(otherDir+".link", path.Join(testDir, "symlink"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(otherDir+".link", "allowed_link")
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSplittedDeletePerms(t *testing.T) {
	u := getTestUser()
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermDeleteDirs,
		dataprovider.PermCreateDirs}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = writeSFTPFile(testFileName, 4096, client)
		assert.NoError(t, err)
		err = client.Remove(testFileName)
		assert.Error(t, err)
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = client.RemoveDirectory(testDir)
		assert.NoError(t, err)
	}
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermDeleteFiles,
		dataprovider.PermCreateDirs, dataprovider.PermOverwrite}
	_, _, err = httpdtest.UpdateUser(u, http.StatusOK, "")
	assert.NoError(t, err)

	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = writeSFTPFile(testFileName, 4096, client)
		assert.NoError(t, err)
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = client.RemoveDirectory(testDir)
		assert.Error(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSplittedRenamePerms(t *testing.T) {
	u := getTestUser()
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermRenameDirs,
		dataprovider.PermCreateDirs}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = writeSFTPFile(testFileName, 4096, client)
		assert.NoError(t, err)
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+"_renamed")
		assert.Error(t, err)
		err = client.Rename(testDir, testDir+"_renamed")
		assert.NoError(t, err)
	}
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermRenameFiles,
		dataprovider.PermCreateDirs, dataprovider.PermOverwrite}
	_, _, err = httpdtest.UpdateUser(u, http.StatusOK, "")
	assert.NoError(t, err)

	conn, client, err = getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = writeSFTPFile(testFileName, 4096, client)
		assert.NoError(t, err)
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+"_renamed")
		assert.NoError(t, err)
		err = client.Rename(testDir, testDir+"_renamed")
		assert.Error(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSFTPLoopError(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          2525,
		From:          "notification@example.com",
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize(configDir)
	require.NoError(t, err)

	user1 := getTestUser()
	user2 := getTestUser()
	user1.Username += "1"
	user2.Username += "2"
	// user1 is a local account with a virtual SFTP folder to user2
	// user2 has user1 as SFTP fs
	user1.VirtualFolders = append(user1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: "sftp",
			FsConfig: vfs.Filesystem{
				Provider: sdk.SFTPFilesystemProvider,
				SFTPConfig: vfs.SFTPFsConfig{
					BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
						Endpoint: sftpServerAddr,
						Username: user2.Username,
					},
					Password: kms.NewPlainSecret(defaultPassword),
				},
			},
		},
		VirtualPath: "/vdir",
	})

	user2.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user2.FsConfig.SFTPConfig = vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: sftpServerAddr,
			Username: user1.Username,
		},
		Password: kms.NewPlainSecret(defaultPassword),
	}

	user1, resp, err := httpdtest.AddUser(user1, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	user2, resp, err = httpdtest.AddUser(user2, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	// test metadata check event error
	a1 := dataprovider.BaseEventAction{
		Name: "a1",
		Type: dataprovider.ActionTypeMetadataCheck,
	}
	action1, _, err := httpdtest.AddEventAction(a1, http.StatusCreated)
	assert.NoError(t, err)
	a2 := dataprovider.BaseEventAction{
		Name: "a2",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients: []string{"failure@example.com"},
				Subject:    `Failed action"`,
				Body:       "Test body",
			},
		},
	}
	action2, _, err := httpdtest.AddEventAction(a2, http.StatusCreated)
	assert.NoError(t, err)
	r1 := dataprovider.EventRule{
		Name:    "rule1",
		Trigger: dataprovider.EventTriggerProviderEvent,
		Conditions: dataprovider.EventConditions{
			ProviderEvents: []string{"update"},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action1.Name,
				},
				Order: 1,
			},
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action2.Name,
				},
				Order: 2,
				Options: dataprovider.EventActionOptions{
					IsFailureAction: true,
				},
			},
		},
	}
	rule1, _, err := httpdtest.AddEventRule(r1, http.StatusCreated)
	assert.NoError(t, err)

	lastReceivedEmail.reset()
	_, _, err = httpdtest.UpdateUser(user2, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		return lastReceivedEmail.get().From != ""
	}, 3000*time.Millisecond, 100*time.Millisecond)
	email := lastReceivedEmail.get()
	assert.Len(t, email.To, 1)
	assert.True(t, util.Contains(email.To, "failure@example.com"))
	assert.Contains(t, email.Data, `Subject: Failed action`)

	user1.VirtualFolders[0].FsConfig.SFTPConfig.Password = kms.NewPlainSecret(defaultPassword)
	user2.FsConfig.SFTPConfig.Password = kms.NewPlainSecret(defaultPassword)

	conn := common.NewBaseConnection("", common.ProtocolWebDAV, "", "", user1)
	_, _, err = conn.GetFsAndResolvedPath(user1.VirtualFolders[0].VirtualPath)
	assert.ErrorIs(t, err, os.ErrPermission)

	conn = common.NewBaseConnection("", common.ProtocolSFTP, "", "", user1)
	_, _, err = conn.GetFsAndResolvedPath(user1.VirtualFolders[0].VirtualPath)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "SFTP loop")
	}
	conn = common.NewBaseConnection("", common.ProtocolFTP, "", "", user1)
	_, _, err = conn.GetFsAndResolvedPath(user1.VirtualFolders[0].VirtualPath)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "SFTP loop")
	}

	_, err = httpdtest.RemoveEventRule(rule1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveEventAction(action2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user2.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: "sftp"}, http.StatusOK)
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize(configDir)
	require.NoError(t, err)
}

func TestNonLocalCrossRename(t *testing.T) {
	baseUser, resp, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err, string(resp))
	u := getTestUser()
	u.HomeDir += "_folders"
	u.Username += "_folders"
	mappedPathSFTP := filepath.Join(os.TempDir(), "sftp")
	folderNameSFTP := filepath.Base(mappedPathSFTP)
	vdirSFTPPath := "/vdir/sftp"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderNameSFTP,
			FsConfig: vfs.Filesystem{
				Provider: sdk.SFTPFilesystemProvider,
				SFTPConfig: vfs.SFTPFsConfig{
					BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
						Endpoint: sftpServerAddr,
						Username: baseUser.Username,
					},
					Password: kms.NewPlainSecret(defaultPassword),
				},
			},
		},
		VirtualPath: vdirSFTPPath,
	})
	mappedPathCrypt := filepath.Join(os.TempDir(), "crypt")
	folderNameCrypt := filepath.Base(mappedPathCrypt)
	vdirCryptPath := "/vdir/crypt"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderNameCrypt,
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewPlainSecret(defaultPassword),
				},
			},
			MappedPath: mappedPathCrypt,
		},
		VirtualPath: vdirCryptPath,
	})
	user, resp, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		err = writeSFTPFile(testFileName, 4096, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirSFTPPath, testFileName), 8192, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirCryptPath, testFileName), 16384, client)
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirSFTPPath, testFileName), path.Join(vdirCryptPath, testFileName+".rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join(vdirCryptPath, testFileName), path.Join(vdirSFTPPath, testFileName+".rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(testFileName, path.Join(vdirCryptPath, testFileName+".rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(testFileName, path.Join(vdirSFTPPath, testFileName+".rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join(vdirSFTPPath, testFileName), testFileName+".rename")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join(vdirCryptPath, testFileName), testFileName+".rename")
		assert.ErrorIs(t, err, os.ErrPermission)
		// rename on local fs or on the same folder must work
		err = client.Rename(testFileName, testFileName+".rename")
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirSFTPPath, testFileName), path.Join(vdirSFTPPath, testFileName+"_rename"))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirCryptPath, testFileName), path.Join(vdirCryptPath, testFileName+"_rename"))
		assert.NoError(t, err)
		// renaming a virtual folder is not allowed
		err = client.Rename(vdirSFTPPath, vdirSFTPPath+"_rename")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(vdirCryptPath, vdirCryptPath+"_rename")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(vdirCryptPath, path.Join(vdirCryptPath, "rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Mkdir(path.Join(vdirCryptPath, "subcryptdir"))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirCryptPath, "subcryptdir"), vdirCryptPath)
		assert.ErrorIs(t, err, os.ErrPermission)
		// renaming root folder is not allowed
		err = client.Rename("/", "new_name")
		assert.ErrorIs(t, err, os.ErrPermission)
		// renaming a path to a virtual folder is not allowed
		err = client.Rename("/vdir", "new_vdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameCrypt}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameSFTP}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(baseUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(baseUser.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathCrypt)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathSFTP)
	assert.NoError(t, err)
}

func TestNonLocalCrossRenameNonLocalBaseUser(t *testing.T) {
	baseUser, resp, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err, string(resp))
	u := getTestSFTPUser()
	mappedPathLocal := filepath.Join(os.TempDir(), "local")
	folderNameLocal := filepath.Base(mappedPathLocal)
	vdirLocalPath := "/vdir/local"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderNameLocal,
			MappedPath: mappedPathLocal,
		},
		VirtualPath: vdirLocalPath,
	})
	mappedPathCrypt := filepath.Join(os.TempDir(), "crypt")
	folderNameCrypt := filepath.Base(mappedPathCrypt)
	vdirCryptPath := "/vdir/crypt"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderNameCrypt,
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewPlainSecret(defaultPassword),
				},
			},
			MappedPath: mappedPathCrypt,
		},
		VirtualPath: vdirCryptPath,
	})
	user, resp, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	conn, client, err := getSftpClient(user)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		err = writeSFTPFile(testFileName, 4096, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirLocalPath, testFileName), 8192, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirCryptPath, testFileName), 16384, client)
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirLocalPath, testFileName), path.Join(vdirCryptPath, testFileName+".rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join(vdirCryptPath, testFileName), path.Join(vdirLocalPath, testFileName+".rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(testFileName, path.Join(vdirCryptPath, testFileName+".rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(testFileName, path.Join(vdirLocalPath, testFileName+".rename"))
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join(vdirLocalPath, testFileName), testFileName+".rename")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(path.Join(vdirCryptPath, testFileName), testFileName+".rename")
		assert.ErrorIs(t, err, os.ErrPermission)
		// rename on local fs or on the same folder must work
		err = client.Rename(testFileName, testFileName+".rename")
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirLocalPath, testFileName), path.Join(vdirLocalPath, testFileName+"_rename"))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirCryptPath, testFileName), path.Join(vdirCryptPath, testFileName+"_rename"))
		assert.NoError(t, err)
		// renaming a virtual folder is not allowed
		err = client.Rename(vdirLocalPath, vdirLocalPath+"_rename")
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Rename(vdirCryptPath, vdirCryptPath+"_rename")
		assert.ErrorIs(t, err, os.ErrPermission)
		// renaming root folder is not allowed
		err = client.Rename("/", "new_name")
		assert.ErrorIs(t, err, os.ErrPermission)
		// renaming a path to a virtual folder is not allowed
		err = client.Rename("/vdir", "new_vdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameCrypt}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameLocal}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(baseUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(baseUser.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathCrypt)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathLocal)
	assert.NoError(t, err)
}

func TestProxyProtocol(t *testing.T) {
	resp, err := httpclient.Get(fmt.Sprintf("http://%v", httpProxyAddr))
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}
}

func TestSetProtocol(t *testing.T) {
	conn := common.NewBaseConnection("id", "sshd_exec", "", "", dataprovider.User{BaseUser: sdk.BaseUser{HomeDir: os.TempDir()}})
	conn.SetProtocol(common.ProtocolSCP)
	require.Equal(t, "SCP_id", conn.GetID())
}

func TestGetFsError(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("invalid JSON for credentials")
	conn := common.NewBaseConnection("", common.ProtocolFTP, "", "", u)
	_, _, err := conn.GetFsAndResolvedPath("/vpath")
	assert.Error(t, err)
}

func waitTCPListening(address string) {
	for {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			logger.WarnToConsole("tcp server %v not listening: %v", address, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		logger.InfoToConsole("tcp server %v now listening", address)
		conn.Close()
		break
	}
}

func checkBasicSFTP(client *sftp.Client) error {
	_, err := client.Getwd()
	if err != nil {
		return err
	}
	_, err = client.ReadDir(".")
	return err
}

func getCustomAuthSftpClient(user dataprovider.User, authMethods []ssh.AuthMethod) (*ssh.Client, *sftp.Client, error) {
	var sftpClient *sftp.Client
	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Auth: authMethods,
	}
	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if err != nil {
		return conn, sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	if err != nil {
		conn.Close()
	}
	return conn, sftpClient, err
}

func getSftpClient(user dataprovider.User) (*ssh.Client, *sftp.Client, error) {
	var sftpClient *sftp.Client
	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	if user.Password != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(user.Password)}
	} else {
		config.Auth = []ssh.AuthMethod{ssh.Password(defaultPassword)}
	}

	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if err != nil {
		return conn, sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	if err != nil {
		conn.Close()
	}
	return conn, sftpClient, err
}

func getTestUser() dataprovider.User {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:       defaultUsername,
			Password:       defaultPassword,
			HomeDir:        filepath.Join(homeBasePath, defaultUsername),
			Status:         1,
			ExpirationDate: 0,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = allPerms
	return user
}

func getTestSFTPUser() dataprovider.User {
	u := getTestUser()
	u.Username = defaultSFTPUsername
	u.FsConfig.Provider = sdk.SFTPFilesystemProvider
	u.FsConfig.SFTPConfig.Endpoint = sftpServerAddr
	u.FsConfig.SFTPConfig.Username = defaultUsername
	u.FsConfig.SFTPConfig.Password = kms.NewPlainSecret(defaultPassword)
	return u
}

func getCryptFsUser() dataprovider.User {
	u := getTestUser()
	u.Username += "_crypt"
	u.FsConfig.Provider = sdk.CryptedFilesystemProvider
	u.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret(defaultPassword)
	return u
}

func writeSFTPFile(name string, size int64, client *sftp.Client) error {
	err := writeSFTPFileNoCheck(name, size, client)
	if err != nil {
		return err
	}
	info, err := client.Stat(name)
	if err != nil {
		return err
	}
	if info.Size() != size {
		return fmt.Errorf("file size mismatch, wanted %v, actual %v", size, info.Size())
	}
	return nil
}

func writeSFTPFileNoCheck(name string, size int64, client *sftp.Client) error {
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	f, err := client.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, bytes.NewBuffer(content))
	if err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func getUploadScriptContent(movedPath, logFilePath string, exitStatus int) []byte {
	content := []byte("#!/bin/sh\n\n")
	content = append(content, []byte("sleep 1\n")...)
	if logFilePath != "" {
		content = append(content, []byte(fmt.Sprintf("echo $@ > %v\n", logFilePath))...)
	}
	content = append(content, []byte(fmt.Sprintf("mv ${SFTPGO_ACTION_PATH} %v\n", movedPath))...)
	content = append(content, []byte(fmt.Sprintf("exit %d", exitStatus))...)
	return content
}

func getSaveProviderObjectScriptContent(outFilePath string, exitStatus int) []byte {
	content := []byte("#!/bin/sh\n\n")
	content = append(content, []byte(fmt.Sprintf("echo ${SFTPGO_OBJECT_DATA} > %v\n", outFilePath))...)
	content = append(content, []byte(fmt.Sprintf("exit %d", exitStatus))...)
	return content
}

func generateTOTPPasscode(secret string, algo otp.Algorithm) (string, error) {
	return totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: algo,
	})
}

func isDbDefenderSupported() bool {
	// SQLite shares the implementation with other SQL-based provider but it makes no sense
	// to use it outside test cases
	switch dataprovider.GetProviderStatus().Driver {
	case dataprovider.MySQLDataProviderName, dataprovider.PGSQLDataProviderName,
		dataprovider.CockroachDataProviderName, dataprovider.SQLiteDataProviderName:
		return true
	default:
		return false
	}
}

func printLatestLogs(maxNumberOfLines int) {
	var lines []string
	f, err := os.Open(logFilePath)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text()+"\r\n")
		for len(lines) > maxNumberOfLines {
			lines = lines[1:]
		}
	}
	if scanner.Err() != nil {
		logger.WarnToConsole("Unable to print latest logs: %v", scanner.Err())
		return
	}
	for _, line := range lines {
		logger.DebugToConsole(line)
	}
}

type receivedEmail struct {
	sync.RWMutex
	From string
	To   []string
	Data string
}

func (e *receivedEmail) set(from string, to []string, data []byte) {
	e.Lock()
	defer e.Unlock()

	e.From = from
	e.To = to
	e.Data = strings.ReplaceAll(string(data), "=\r\n", "")
}

func (e *receivedEmail) reset() {
	e.Lock()
	defer e.Unlock()

	e.From = ""
	e.To = nil
	e.Data = ""
}

func (e *receivedEmail) get() receivedEmail {
	e.RLock()
	defer e.RUnlock()

	return receivedEmail{
		From: e.From,
		To:   e.To,
		Data: e.Data,
	}
}
