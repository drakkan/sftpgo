package ftpd_test

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/ftpd"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	logSender       = "ftpdTesting"
	ftpServerAddr   = "127.0.0.1:2121"
	defaultUsername = "test_user_ftp"
	defaultPassword = "test_password"
	configDir       = ".."
	osWindows       = "windows"
	ftpsCert        = `-----BEGIN CERTIFICATE-----
MIICHTCCAaKgAwIBAgIUHnqw7QnB1Bj9oUsNpdb+ZkFPOxMwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAyMDQwOTUzMDRaFw0zMDAyMDEw
OTUzMDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAARCjRMqJ85rzMC998X5z761nJ+xL3bkmGVqWvrJ51t5OxV0v25NsOgR82CA
NXUgvhVYs7vNFN+jxtb2aj6Xg+/2G/BNxkaFspIVCzgWkxiz7XE4lgUwX44FCXZM
3+JeUbKjUzBRMB0GA1UdDgQWBBRhLw+/o3+Z02MI/d4tmaMui9W16jAfBgNVHSME
GDAWgBRhLw+/o3+Z02MI/d4tmaMui9W16jAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA2kAMGYCMQDqLt2lm8mE+tGgtjDmtFgdOcI72HSbRQ74D5rYTzgST1rY
/8wTi5xl8TiFUyLMUsICMQC5ViVxdXbhuG7gX6yEqSkMKZICHpO8hqFwOD/uaFVI
dV4vKmHUzwK/eIx+8Ay3neE=
-----END CERTIFICATE-----`
	ftpsKey = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCfMNsN6miEE3rVyUPwElfiJSWaR5huPCzUenZOfJT04GAcQdWvEju3
UM2lmBLIXpGgBwYFK4EEACKhZANiAARCjRMqJ85rzMC998X5z761nJ+xL3bkmGVq
WvrJ51t5OxV0v25NsOgR82CANXUgvhVYs7vNFN+jxtb2aj6Xg+/2G/BNxkaFspIV
CzgWkxiz7XE4lgUwX44FCXZM3+JeUbI=
-----END EC PRIVATE KEY-----`
	testFileName   = "test_file_ftp.dat"
	testDLFileName = "test_download_ftp.dat"
)

var (
	allPerms        = []string{dataprovider.PermAny}
	homeBasePath    string
	hookCmdPath     string
	extAuthPath     string
	preLoginPath    string
	postConnectPath string
	logFilePath     string
)

func TestMain(m *testing.M) {
	logFilePath = filepath.Join(configDir, "sftpgo_ftpd_test.log")
	bannerFileName := "banner_file"
	bannerFile := filepath.Join(configDir, bannerFileName)
	logger.InitLogger(logFilePath, 5, 1, 28, false, zerolog.DebugLevel)
	err := ioutil.WriteFile(bannerFile, []byte("SFTPGo test ready\nsimple banner line\n"), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error creating banner file: %v", err)
	}
	err = config.LoadConfig(configDir, "")
	if err != nil {
		logger.ErrorToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()
	logger.InfoToConsole("Starting FTPD tests, provider: %v", providerConf.Driver)

	commonConf := config.GetCommonConfig()
	// we run the test cases with UploadMode atomic and resume support. The non atomic code path
	// simply does not execute some code so if it works in atomic mode will
	// work in non atomic mode too
	commonConf.UploadMode = 2
	homeBasePath = os.TempDir()
	if runtime.GOOS != osWindows {
		commonConf.Actions.ExecuteOn = []string{"download", "upload", "rename", "delete"}
		commonConf.Actions.Hook = hookCmdPath
		hookCmdPath, err = exec.LookPath("true")
		if err != nil {
			logger.Warn(logSender, "", "unable to get hook command: %v", err)
			logger.WarnToConsole("unable to get hook command: %v", err)
		}
	}

	certPath := filepath.Join(os.TempDir(), "test_ftpd.crt")
	keyPath := filepath.Join(os.TempDir(), "test_ftpd.key")
	err = ioutil.WriteFile(certPath, []byte(ftpsCert), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing FTPS certificate: %v", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(keyPath, []byte(ftpsKey), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing FTPS private key: %v", err)
		os.Exit(1)
	}

	common.Initialize(commonConf)

	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		logger.ErrorToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Initialize(configDir)

	kmsConfig := config.GetKMSConfig()
	err = kmsConfig.Initialize()
	if err != nil {
		logger.ErrorToConsole("error initializing kms: %v", err)
		os.Exit(1)
	}

	httpdConf := config.GetHTTPDConfig()
	httpdConf.BindPort = 8079
	httpd.SetBaseURLAndCredentials("http://127.0.0.1:8079", "", "")

	ftpdConf := config.GetFTPDConfig()
	ftpdConf.BindPort = 2121
	ftpdConf.PassivePortRange.Start = 0
	ftpdConf.PassivePortRange.End = 0
	ftpdConf.BannerFile = bannerFileName
	ftpdConf.CertificateFile = certPath
	ftpdConf.CertificateKeyFile = keyPath

	extAuthPath = filepath.Join(homeBasePath, "extauth.sh")
	preLoginPath = filepath.Join(homeBasePath, "prelogin.sh")
	postConnectPath = filepath.Join(homeBasePath, "postconnect.sh")

	status := ftpd.GetStatus()
	if status.IsActive {
		logger.ErrorToConsole("ftpd is already active")
		os.Exit(1)
	}

	go func() {
		logger.Debug(logSender, "", "initializing FTP server with config %+v", ftpdConf)
		if err := ftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start FTP server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir, false); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", ftpdConf.BindAddress, ftpdConf.BindPort))
	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))
	ftpd.ReloadTLSCertificate() //nolint:errcheck

	exitCode := m.Run()
	os.Remove(logFilePath)
	os.Remove(bannerFile)
	os.Remove(extAuthPath)
	os.Remove(preLoginPath)
	os.Remove(postConnectPath)
	os.Remove(certPath)
	os.Remove(keyPath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	ftpdConf := config.GetFTPDConfig()
	ftpdConf.BindPort = 2121
	ftpdConf.CertificateFile = filepath.Join(os.TempDir(), "test_ftpd.crt")
	ftpdConf.CertificateKeyFile = filepath.Join(os.TempDir(), "test_ftpd.key")
	ftpdConf.TLSMode = 1
	err := ftpdConf.Initialize(configDir)
	assert.Error(t, err)
	status := ftpd.GetStatus()
	assert.True(t, status.IsActive)
}

func TestBasicFTPHandling(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 6553600
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		assert.Len(t, common.Connections.GetStats(), 1)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		expectedQuotaSize := user.UsedQuotaSize + testFileSize
		expectedQuotaFiles := user.UsedQuotaFiles + 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)

		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join("/missing_dir", testFileName), testFileSize, client, 0)
		assert.Error(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		// overwrite an existing file
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		err = client.Rename(testFileName, testFileName+"1")
		assert.NoError(t, err)
		err = client.Delete(testFileName)
		assert.Error(t, err)
		err = client.Delete(testFileName + "1")
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize-testFileSize, user.UsedQuotaSize)
		curDir, err := client.CurrentDir()
		if assert.NoError(t, err) {
			assert.Equal(t, "/", curDir)
		}
		testDir := "testDir"
		err = client.MakeDir(testDir)
		assert.NoError(t, err)
		err = client.ChangeDir(testDir)
		assert.NoError(t, err)
		curDir, err = client.CurrentDir()
		if assert.NoError(t, err) {
			assert.Equal(t, path.Join("/", testDir), curDir)
		}
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		size, err := client.FileSize(path.Join("/", testDir, testFileName))
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, size)
		err = client.ChangeDirToParent()
		assert.NoError(t, err)
		curDir, err = client.CurrentDir()
		if assert.NoError(t, err) {
			assert.Equal(t, "/", curDir)
		}
		err = client.Delete(path.Join("/", testDir, testFileName))
		assert.NoError(t, err)
		err = client.Delete(testDir)
		assert.Error(t, err)
		err = client.RemoveDir(testDir)
		assert.NoError(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 }, 1*time.Second, 50*time.Millisecond)
}

func TestLoginInvalidPwd(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	user.Password = "wrong"
	_, err = getFTPClient(user, false)
	assert.Error(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestLoginExternalAuth(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	client, err := getFTPClient(u, true)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}
	u.Username = defaultUsername + "1"
	client, err = getFTPClient(u, true)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}

	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, users, 1) {
		user := users[0]
		assert.Equal(t, defaultUsername, user.Username)
		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestPreLoginHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), os.ModePerm)
	assert.NoError(t, err)
	providerConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(users))
	client, err := getFTPClient(u, false)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	users, _, err = httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	user := users[0]

	// test login with an existing user
	client, err = getFTPClient(user, true)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(user, true), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(u, false)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}
	user.Status = 0
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(u, false)
	if !assert.Error(t, err, "pre-login script returned a disabled user, login must fail") {
		err := client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	err = os.Remove(preLoginPath)
	assert.NoError(t, err)
}

func TestPostConnectHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	common.Config.PostConnectHook = postConnectPath

	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = ioutil.WriteFile(postConnectPath, getPostConnectScriptContent(0), os.ModePerm)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}
	err = ioutil.WriteFile(postConnectPath, getPostConnectScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(user, true)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}

	common.Config.PostConnectHook = "http://127.0.0.1:8079/api/v1/version"

	client, err = getFTPClient(user, false)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	common.Config.PostConnectHook = "http://127.0.0.1:8079/notfound"

	client, err = getFTPClient(user, true)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.PostConnectHook = ""
}

func TestMaxSessions(t *testing.T) {
	u := getTestUser()
	u.MaxSessions = 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		_, err = getFTPClient(user, false)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestZeroBytesTransfers(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	for _, useTLS := range []bool{true, false} {
		client, err := getFTPClient(user, useTLS)
		if assert.NoError(t, err) {
			testFileName := "testfilename"
			err = checkBasicFTP(client)
			assert.NoError(t, err)
			localDownloadPath := filepath.Join(homeBasePath, "empty_download")
			err = ioutil.WriteFile(localDownloadPath, []byte(""), os.ModePerm)
			assert.NoError(t, err)
			err = ftpUploadFile(localDownloadPath, testFileName, 0, client, 0)
			assert.NoError(t, err)
			size, err := client.FileSize(testFileName)
			assert.NoError(t, err)
			assert.Equal(t, int64(0), size)
			err = os.Remove(localDownloadPath)
			assert.NoError(t, err)
			assert.NoFileExists(t, localDownloadPath)
			err = ftpDownloadFile(testFileName, localDownloadPath, 0, client, 0)
			assert.NoError(t, err)
			assert.FileExists(t, localDownloadPath)
			err = client.Quit()
			assert.NoError(t, err)
			err = os.Remove(localDownloadPath)
			assert.NoError(t, err)
		}
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDownloadErrors(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 1
	subDir1 := "sub1"
	subDir2 := "sub2"
	u.Permissions[path.Join("/", subDir1)] = []string{dataprovider.PermListItems}
	u.Permissions[path.Join("/", subDir2)] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermDelete, dataprovider.PermDownload}
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/sub2",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{".zip"},
		},
	}
	u.Filters.FilePatterns = []dataprovider.PatternsFilter{
		{
			Path:            "/sub2",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{"*.jpg"},
		},
	}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		testFilePath1 := filepath.Join(user.HomeDir, subDir1, "file.zip")
		testFilePath2 := filepath.Join(user.HomeDir, subDir2, "file.zip")
		testFilePath3 := filepath.Join(user.HomeDir, subDir2, "file.jpg")
		err = os.MkdirAll(filepath.Dir(testFilePath1), os.ModePerm)
		assert.NoError(t, err)
		err = os.MkdirAll(filepath.Dir(testFilePath2), os.ModePerm)
		assert.NoError(t, err)
		err = ioutil.WriteFile(testFilePath1, []byte("file1"), os.ModePerm)
		assert.NoError(t, err)
		err = ioutil.WriteFile(testFilePath2, []byte("file2"), os.ModePerm)
		assert.NoError(t, err)
		err = ioutil.WriteFile(testFilePath3, []byte("file3"), os.ModePerm)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(path.Join("/", subDir1, "file.zip"), localDownloadPath, 5, client, 0)
		assert.Error(t, err)
		err = ftpDownloadFile(path.Join("/", subDir2, "file.zip"), localDownloadPath, 5, client, 0)
		assert.Error(t, err)
		err = ftpDownloadFile(path.Join("/", subDir2, "file.jpg"), localDownloadPath, 5, client, 0)
		assert.Error(t, err)
		err = ftpDownloadFile("/missing.zip", localDownloadPath, 5, client, 0)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadErrors(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 65535
	subDir1 := "sub1"
	subDir2 := "sub2"
	u.Permissions[path.Join("/", subDir1)] = []string{dataprovider.PermListItems}
	u.Permissions[path.Join("/", subDir2)] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermDelete}
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/sub2",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{".zip"},
		},
	}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := user.QuotaSize
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = client.MakeDir(subDir1)
		assert.NoError(t, err)
		err = client.MakeDir(subDir2)
		assert.NoError(t, err)
		err = client.ChangeDir(subDir1)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.Error(t, err)
		err = client.ChangeDirToParent()
		assert.NoError(t, err)
		err = client.ChangeDir(subDir2)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName+".zip", testFileSize, client, 0)
		assert.Error(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.Error(t, err)
		err = client.ChangeDir("/")
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, subDir1, testFileSize, client, 0)
		assert.Error(t, err)
		// overquota
		err = ftpUploadFile(testFilePath, testFileName+"1", testFileSize, client, 0)
		assert.Error(t, err)
		err = client.Delete(path.Join("/", subDir2, testFileName))
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestResume(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		data := []byte("test data")
		err = ioutil.WriteFile(testFilePath, data, os.ModePerm)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)+5), client, 5)
		assert.NoError(t, err)
		readed, err := ioutil.ReadFile(filepath.Join(user.GetHomeDir(), testFileName))
		assert.NoError(t, err)
		assert.Equal(t, "test test data", string(readed))
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, int64(len(data)), client, 5)
		assert.NoError(t, err)
		readed, err = ioutil.ReadFile(localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, data, readed)
		err = client.Delete(testFileName)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
		assert.NoError(t, err)
		// now append to a file
		srcFile, err := os.Open(testFilePath)
		if assert.NoError(t, err) {
			err = client.Append(testFileName, srcFile)
			assert.NoError(t, err)
			err = srcFile.Close()
			assert.NoError(t, err)
			size, err := client.FileSize(testFileName)
			assert.NoError(t, err)
			assert.Equal(t, int64(2*len(data)), size)
			err = ftpDownloadFile(testFileName, localDownloadPath, int64(2*len(data)), client, 0)
			assert.NoError(t, err)
			readed, err = ioutil.ReadFile(localDownloadPath)
			assert.NoError(t, err)
			expected := append(data, data...)
			assert.Equal(t, expected, readed)
		}
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestDeniedLoginMethod(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	_, err = getFTPClient(user, false)
	assert.Error(t, err)
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.SSHLoginMethodKeyAndPassword}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		assert.NoError(t, checkBasicFTP(client))
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestDeniedProtocols(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedProtocols = []string{common.ProtocolFTP}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	_, err = getFTPClient(user, false)
	assert.Error(t, err)
	user.Filters.DeniedProtocols = []string{common.ProtocolSSH, common.ProtocolWebDAV}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		assert.NoError(t, checkBasicFTP(client))
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaLimits(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	testFileSize1 := int64(131072)
	testFileName1 := "test_file1.dat"
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	err = createTestFile(testFilePath1, testFileSize1)
	assert.NoError(t, err)
	testFileSize2 := int64(32768)
	testFileName2 := "test_file2.dat"
	testFilePath2 := filepath.Join(homeBasePath, testFileName2)
	err = createTestFile(testFilePath2, testFileSize2)
	assert.NoError(t, err)
	// test quota files
	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		err = ftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName+".quota1", testFileSize, client, 0)
		assert.Error(t, err)
		err = client.Rename(testFileName+".quota", testFileName)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	// test quota size
	user.QuotaSize = testFileSize - 1
	user.QuotaFiles = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, true)
	if assert.NoError(t, err) {
		err = ftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client, 0)
		assert.Error(t, err)
		err = client.Rename(testFileName, testFileName+".quota")
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	// now test quota limits while uploading the current file, we have 1 bytes remaining
	user.QuotaSize = testFileSize + 1
	user.QuotaFiles = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false)
	if assert.NoError(t, err) {
		err = ftpUploadFile(testFilePath1, testFileName1, testFileSize1, client, 0)
		assert.Error(t, err)
		_, err = client.FileSize(testFileName1)
		assert.Error(t, err)
		err = client.Rename(testFileName+".quota", testFileName)
		assert.NoError(t, err)
		// overwriting an existing file will work if the resulting size is lesser or equal than the current one
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath2, testFileName, testFileSize2, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath1, testFileName, testFileSize1, client, 0)
		assert.Error(t, err)
		err = ftpUploadFile(testFilePath1, testFileName, testFileSize1, client, 10)
		assert.Error(t, err)
		err = ftpUploadFile(testFilePath2, testFileName, testFileSize2, client, 0)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	err = os.Remove(testFilePath2)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadMaxSize(t *testing.T) {
	testFileSize := int64(65535)
	u := getTestUser()
	u.Filters.MaxUploadFileSize = testFileSize + 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	testFileSize1 := int64(131072)
	testFileName1 := "test_file1.dat"
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	err = createTestFile(testFilePath1, testFileSize1)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		err = ftpUploadFile(testFilePath1, testFileName1, testFileSize1, client, 0)
		assert.Error(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		// now test overwrite an existing file with a size bigger than the allowed one
		err = createTestFile(filepath.Join(user.GetHomeDir(), testFileName1), testFileSize1)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath1, testFileName1, testFileSize1, client, 0)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithIPilters(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedIP = []string{"192.167.0.0/24", "172.18.0.0/16"}
	u.Filters.AllowedIP = []string{"172.19.0.0/16"}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if !assert.Error(t, err) {
		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithDatabaseCredentials(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret(`{ "type": "service_account" }`)

	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = true
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	assert.NoError(t, dataprovider.Close())

	err := dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	if _, err = os.Stat(credentialsFile); err == nil {
		// remove the credentials file
		assert.NoError(t, os.Remove(credentialsFile))
	}

	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user.FsConfig.GCSConfig.Credentials.GetPayload())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetKey())

	assert.NoFileExists(t, credentialsFile)

	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	assert.NoError(t, dataprovider.Close())
	assert.NoError(t, config.LoadConfig(configDir, ""))
	providerConf = config.GetProviderConf()
	assert.NoError(t, dataprovider.Initialize(providerConf, configDir))
}

func TestLoginInvalidFs(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("invalid JSON for credentials")
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)

	providerConf := config.GetProviderConf()
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	// now remove the credentials file so the filesystem creation will fail
	err = os.Remove(credentialsFile)
	assert.NoError(t, err)

	client, err := getFTPClient(user, false)
	if !assert.Error(t, err) {
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestClientClose(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		stats := common.Connections.GetStats()
		if assert.Len(t, stats, 1) {
			common.Connections.Close(stats[0].ConnectionID)
			assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 },
				1*time.Second, 50*time.Millisecond)
		}
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRename(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testDir := "adir"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = client.MakeDir(testDir)
		assert.NoError(t, err)
		err = client.Rename(testFileName, path.Join("missing", testFileName))
		assert.Error(t, err)
		err = client.Rename(testFileName, path.Join(testDir, testFileName))
		assert.NoError(t, err)
		size, err := client.FileSize(path.Join(testDir, testFileName))
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, size)
		if runtime.GOOS != osWindows {
			otherDir := "dir"
			err = client.MakeDir(otherDir)
			assert.NoError(t, err)
			err = client.MakeDir(path.Join(otherDir, testDir))
			assert.NoError(t, err)
			code, response, err := client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 0001 %v", otherDir))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusCommandOK, code)
			assert.Equal(t, "SITE CHMOD command successful", response)
			err = client.Rename(testDir, path.Join(otherDir, testDir))
			assert.Error(t, err)

			code, response, err = client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 755 %v", otherDir))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusCommandOK, code)
			assert.Equal(t, "SITE CHMOD command successful", response)
		}
		err = client.Quit()
		assert.NoError(t, err)
	}
	user.Permissions[path.Join("/", testDir)] = []string{dataprovider.PermListItems}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false)
	if assert.NoError(t, err) {
		err = client.Rename(path.Join(testDir, testFileName), testFileName)
		assert.Error(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSymlink(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		code, _, err := client.SendCustomCommand(fmt.Sprintf("SITE SYMLINK %v %v", testFileName, testFileName+".link"))
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)

		if runtime.GOOS != osWindows {
			testDir := "adir"
			otherDir := "dir"
			err = client.MakeDir(otherDir)
			assert.NoError(t, err)
			err = client.MakeDir(path.Join(otherDir, testDir))
			assert.NoError(t, err)
			code, response, err := client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 0001 %v", otherDir))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusCommandOK, code)
			assert.Equal(t, "SITE CHMOD command successful", response)
			code, _, err = client.SendCustomCommand(fmt.Sprintf("SITE SYMLINK %v %v", testDir, path.Join(otherDir, testDir)))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusFileUnavailable, code)

			code, response, err = client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 755 %v", otherDir))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusCommandOK, code)
			assert.Equal(t, "SITE CHMOD command successful", response)
		}
		err = client.Quit()
		assert.NoError(t, err)
	}
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestStat(t *testing.T) {
	u := getTestUser()
	u.Permissions["/subdir"] = []string{dataprovider.PermUpload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		subDir := "subdir"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = client.MakeDir(subDir)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join("/", subDir, testFileName), testFileSize, client, 0)
		assert.Error(t, err)
		size, err := client.FileSize(testFileName)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, size)
		_, err = client.FileSize(path.Join("/", subDir, testFileName))
		assert.Error(t, err)
		_, err = client.FileSize("missing file")
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadOverwriteVfolder(t *testing.T) {
	u := getTestUser()
	vdir := "/vdir"
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: vdir,
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join(vdir, testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		err = ftpUploadFile(testFilePath, path.Join(vdir, testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestAllocate(t *testing.T) {
	u := getTestUser()
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir",
		QuotaSize:   110,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("allo 2000000")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)
		err = client.Quit()
		assert.NoError(t, err)
	}
	user.QuotaSize = 100
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := user.QuotaSize - 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		code, response, err := client.SendCustomCommand("allo 99")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)
		code, response, err = client.SendCustomCommand("allo 100")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)
		code, response, err = client.SendCustomCommand("allo 150")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFileUnavailable, code)
		assert.Contains(t, response, common.ErrQuotaExceeded.Error())

		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		// we still have space in vdir
		code, response, err = client.SendCustomCommand("allo 50")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)
		err = ftpUploadFile(testFilePath, path.Join("/vdir", testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		code, response, err = client.SendCustomCommand("allo 50")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFileUnavailable, code)
		assert.Contains(t, response, common.ErrQuotaExceeded.Error())

		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}

	user.Filters.MaxUploadFileSize = 100
	user.QuotaSize = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("allo 99")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)
		code, response, err = client.SendCustomCommand("allo 150")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFileUnavailable, code)
		assert.Contains(t, response, common.ErrQuotaExceeded.Error())

		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestChtimes(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)

		mtime := time.Now().Format("20060102150405")
		code, response, err := client.SendCustomCommand(fmt.Sprintf("MFMT %v %v", mtime, testFileName))
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, fmt.Sprintf("Modify=%v; %v", mtime, testFileName), response)
		err = client.Quit()
		assert.NoError(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestChmod(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("chmod is partially supported on Windows")
	}
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(131072)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)

		code, response, err := client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 600 %v", testFileName))
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "SITE CHMOD command successful", response)

		fi, err := os.Stat(filepath.Join(user.HomeDir, testFileName))
		if assert.NoError(t, err) {
			assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
		}
		err = client.Quit()
		assert.NoError(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func checkBasicFTP(client *ftp.ServerConn) error {
	_, err := client.CurrentDir()
	if err != nil {
		return err
	}
	err = client.NoOp()
	if err != nil {
		return err
	}
	_, err = client.List(".")
	if err != nil {
		return err
	}
	return nil
}

func ftpUploadFile(localSourcePath string, remoteDestPath string, expectedSize int64, client *ftp.ServerConn, offset uint64) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	if offset > 0 {
		err = client.StorFrom(remoteDestPath, srcFile, offset)
	} else {
		err = client.Stor(remoteDestPath, srcFile)
	}
	if err != nil {
		return err
	}
	if expectedSize > 0 {
		size, err := client.FileSize(remoteDestPath)
		if err != nil {
			return err
		}
		if size != expectedSize {
			return fmt.Errorf("uploaded file size does not match, actual: %v, expected: %v", size, expectedSize)
		}
	}
	return nil
}

func ftpDownloadFile(remoteSourcePath string, localDestPath string, expectedSize int64, client *ftp.ServerConn, offset uint64) error {
	downloadDest, err := os.Create(localDestPath)
	if err != nil {
		return err
	}
	defer downloadDest.Close()
	var r *ftp.Response
	if offset > 0 {
		r, err = client.RetrFrom(remoteSourcePath, offset)
	} else {
		r, err = client.Retr(remoteSourcePath)
	}
	if err != nil {
		return err
	}
	defer r.Close()

	written, err := io.Copy(downloadDest, r)
	if err != nil {
		return err
	}
	if written != expectedSize {
		return fmt.Errorf("downloaded file size does not match, actual: %v, expected: %v", written, expectedSize)
	}
	return nil
}

func getFTPClient(user dataprovider.User, useTLS bool) (*ftp.ServerConn, error) {
	ftpOptions := []ftp.DialOption{ftp.DialWithTimeout(5 * time.Second)}
	if useTLS {
		tlsConfig := &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, // use this for tests only
			MinVersion:         tls.VersionTLS12,
		}
		ftpOptions = append(ftpOptions, ftp.DialWithExplicitTLS(tlsConfig))
	}
	client, err := ftp.Dial(ftpServerAddr, ftpOptions...)
	if err != nil {
		return nil, err
	}
	pwd := defaultPassword
	if len(user.Password) > 0 {
		pwd = user.Password
	}
	err = client.Login(user.Username, pwd)
	if err != nil {
		return nil, err
	}
	return client, err
}

func waitTCPListening(address string) {
	for {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			logger.WarnToConsole("tcp server %v not listening: %v\n", address, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		logger.InfoToConsole("tcp server %v now listening\n", address)
		conn.Close()
		break
	}
}

func getTestUser() dataprovider.User {
	user := dataprovider.User{
		Username:       defaultUsername,
		Password:       defaultPassword,
		HomeDir:        filepath.Join(homeBasePath, defaultUsername),
		Status:         1,
		ExpirationDate: 0,
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = allPerms
	return user
}

func getExtAuthScriptContent(user dataprovider.User, nonJSONResponse bool, username string) []byte {
	extAuthContent := []byte("#!/bin/sh\n\n")
	extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("if test \"$SFTPGO_AUTHD_USERNAME\" = \"%v\"; then\n", user.Username))...)
	if len(username) > 0 {
		user.Username = username
	}
	u, _ := json.Marshal(user)
	if nonJSONResponse {
		extAuthContent = append(extAuthContent, []byte("echo 'text response'\n")...)
	} else {
		extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("echo '%v'\n", string(u)))...)
	}
	extAuthContent = append(extAuthContent, []byte("else\n")...)
	if nonJSONResponse {
		extAuthContent = append(extAuthContent, []byte("echo 'text response'\n")...)
	} else {
		extAuthContent = append(extAuthContent, []byte("echo '{\"username\":\"\"}'\n")...)
	}
	extAuthContent = append(extAuthContent, []byte("fi\n")...)
	return extAuthContent
}

func getPreLoginScriptContent(user dataprovider.User, nonJSONResponse bool) []byte {
	content := []byte("#!/bin/sh\n\n")
	if nonJSONResponse {
		content = append(content, []byte("echo 'text response'\n")...)
		return content
	}
	if len(user.Username) > 0 {
		u, _ := json.Marshal(user)
		content = append(content, []byte(fmt.Sprintf("echo '%v'\n", string(u)))...)
	}
	return content
}

func getPostConnectScriptContent(exitCode int) []byte {
	content := []byte("#!/bin/sh\n\n")
	content = append(content, []byte(fmt.Sprintf("exit %v", exitCode))...)
	return content
}

func createTestFile(path string, size int64) error {
	baseDir := filepath.Dir(path)
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		err = os.MkdirAll(baseDir, os.ModePerm)
		if err != nil {
			return err
		}
	}
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, content, os.ModePerm)
}
