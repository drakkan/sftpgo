package webdavd_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/sio"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/studio-b12/gowebdav"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
	"github.com/drakkan/sftpgo/webdavd"
)

const (
	logSender        = "webavdTesting"
	webDavServerAddr = "127.0.0.1:9090"
	webDavServerPort = 9090
	defaultUsername  = "test_user_dav"
	defaultPassword  = "test_password"
	configDir        = ".."
	osWindows        = "windows"
	webDavCert       = `-----BEGIN CERTIFICATE-----
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
	webDavKey = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCfMNsN6miEE3rVyUPwElfiJSWaR5huPCzUenZOfJT04GAcQdWvEju3
UM2lmBLIXpGgBwYFK4EEACKhZANiAARCjRMqJ85rzMC998X5z761nJ+xL3bkmGVq
WvrJ51t5OxV0v25NsOgR82CANXUgvhVYs7vNFN+jxtb2aj6Xg+/2G/BNxkaFspIV
CzgWkxiz7XE4lgUwX44FCXZM3+JeUbI=
-----END EC PRIVATE KEY-----`
	testFileName   = "test_file_dav.dat"
	testDLFileName = "test_download_dav.dat"
)

var (
	allPerms        = []string{dataprovider.PermAny}
	homeBasePath    string
	hookCmdPath     string
	extAuthPath     string
	preLoginPath    string
	postConnectPath string
	logFilePath     string
	certPath        string
	keyPath         string
)

func TestMain(m *testing.M) {
	logFilePath = filepath.Join(configDir, "sftpgo_webdavd_test.log")
	logger.InitLogger(logFilePath, 5, 1, 28, false, zerolog.DebugLevel)
	err := config.LoadConfig(configDir, "")
	if err != nil {
		logger.ErrorToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()
	logger.InfoToConsole("Starting WebDAVD tests, provider: %v", providerConf.Driver)
	commonConf := config.GetCommonConfig()
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

	certPath = filepath.Join(os.TempDir(), "test_dav.crt")
	keyPath = filepath.Join(os.TempDir(), "test_dav.key")
	err = ioutil.WriteFile(certPath, []byte(webDavCert), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing WebDAV certificate: %v", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(keyPath, []byte(webDavKey), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing WebDAV private key: %v", err)
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
	httpdConf.BindPort = 8078
	httpd.SetBaseURLAndCredentials("http://127.0.0.1:8078", "", "")

	webDavConf := config.GetWebDAVDConfig()
	webDavConf.BindPort = webDavServerPort
	webDavConf.Cors = webdavd.Cors{
		Enabled:        true,
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}

	status := webdavd.GetStatus()
	if status.IsActive {
		logger.ErrorToConsole("webdav server is already active")
		os.Exit(1)
	}

	extAuthPath = filepath.Join(homeBasePath, "extauth.sh")
	preLoginPath = filepath.Join(homeBasePath, "prelogin.sh")
	postConnectPath = filepath.Join(homeBasePath, "postconnect.sh")

	go func() {
		logger.Debug(logSender, "", "initializing WebDAV server with config %+v", webDavConf)
		if err := webDavConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start WebDAV server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir, false); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", webDavConf.BindAddress, webDavConf.BindPort))
	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))
	webdavd.ReloadTLSCertificate() //nolint:errcheck

	exitCode := m.Run()
	os.Remove(logFilePath)
	os.Remove(extAuthPath)
	os.Remove(preLoginPath)
	os.Remove(postConnectPath)
	os.Remove(certPath)
	os.Remove(keyPath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	cfg := webdavd.Configuration{
		BindPort:           1234,
		CertificateFile:    "missing path",
		CertificateKeyFile: "bad path",
	}
	err := cfg.Initialize(configDir)
	assert.Error(t, err)

	cfg.Cache = config.GetWebDAVDConfig().Cache
	cfg.BindPort = webDavServerPort
	cfg.CertificateFile = certPath
	cfg.CertificateKeyFile = keyPath
	err = cfg.Initialize(configDir)
	assert.Error(t, err)
	err = webdavd.ReloadTLSCertificate()
	assert.NoError(t, err)
}

func TestBasicHandling(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 6553600
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	expectedQuotaSize := user.UsedQuotaSize + testFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.NoError(t, err)
	// overwrite an existing file
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	err = client.Rename(testFileName, testFileName+"1", false)
	assert.NoError(t, err)
	_, err = client.Stat(testFileName)
	assert.Error(t, err)
	// the webdav client hide the error we check the quota
	err = client.Remove(testFileName)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	err = client.Remove(testFileName + "1")
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize-testFileSize, user.UsedQuotaSize)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.Error(t, err)
	testDir := "testdir"
	err = client.Mkdir(testDir, os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub", "sub"), os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub1", "sub1"), os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub2", "sub2"), os.ModePerm)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(testDir, testFileName+".txt"), testFileSize, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(testDir, testFileName), testFileSize, client)
	assert.NoError(t, err)
	files, err := client.ReadDir(testDir)
	assert.NoError(t, err)
	assert.Len(t, files, 5)
	err = client.Copy(testDir, testDir+"_copy", false)
	assert.NoError(t, err)
	err = client.RemoveAll(testDir)
	assert.NoError(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 0)
	status := webdavd.GetStatus()
	assert.True(t, status.IsActive)
}

func TestBasicHandlingCryptFs(t *testing.T) {
	u := getTestUserWithCryptFs()
	u.QuotaSize = 6553600
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	encryptedFileSize, err := getEncryptedFileSize(testFileSize)
	assert.NoError(t, err)
	expectedQuotaSize := user.UsedQuotaSize + encryptedFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.NoError(t, err)
	// overwrite an existing file
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	files, err := client.ReadDir("/")
	assert.NoError(t, err)
	if assert.Len(t, files, 1) {
		assert.Equal(t, testFileSize, files[0].Size())
	}
	err = client.Remove(testFileName)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize-encryptedFileSize, user.UsedQuotaSize)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.Error(t, err)
	testDir := "testdir"
	err = client.Mkdir(testDir, os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub", "sub"), os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub1", "sub1"), os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub2", "sub2"), os.ModePerm)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(testDir, testFileName+".txt"), testFileSize, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(testDir, testFileName), testFileSize, client)
	assert.NoError(t, err)
	files, err = client.ReadDir(testDir)
	assert.NoError(t, err)
	assert.Len(t, files, 5)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), testFileName) {
			assert.Equal(t, testFileSize, f.Size())
		} else {
			assert.True(t, f.IsDir())
		}
	}
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 0)
}

func TestPropPatch(t *testing.T) {
	for _, u := range []dataprovider.User{getTestUser(), getTestUserWithCryptFs()} {
		user, _, err := httpd.AddUser(u, http.StatusOK)
		assert.NoError(t, err)
		client := getWebDavClient(user)
		assert.NoError(t, checkBasicFunc(client))

		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = uploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		httpClient := httpclient.GetHTTPClient()
		propatchBody := `<?xml version="1.0" encoding="utf-8" ?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop><Z:Win32CreationTime>Wed, 04 Nov 2020 13:25:51 GMT</Z:Win32CreationTime><Z:Win32LastAccessTime>Sat, 05 Dec 2020 21:16:12 GMT</Z:Win32LastAccessTime><Z:Win32LastModifiedTime>Wed, 04 Nov 2020 13:25:51 GMT</Z:Win32LastModifiedTime><Z:Win32FileAttributes>00000000</Z:Win32FileAttributes></D:prop></D:set></D:propertyupdate>`
		req, err := http.NewRequest("PROPPATCH", fmt.Sprintf("http://%v/%v/%v", webDavServerAddr, user.Username, testFileName), bytes.NewReader([]byte(propatchBody)))
		assert.NoError(t, err)
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, 207, resp.StatusCode)
		err = resp.Body.Close()
		assert.NoError(t, err)
		info, err := client.Stat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, info.Size())
		}
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
		assert.Len(t, common.Connections.GetStats(), 0)
	}
}

func TestLoginInvalidPwd(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))
	user.Password = "wrong"
	client = getWebDavClient(user)
	assert.Error(t, checkBasicFunc(client))
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestLoginInvalidURL(t *testing.T) {
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	u1 := getTestUser()
	u1.Username = user.Username + "1"
	user1, _, err := httpd.AddUser(u1, http.StatusOK)
	assert.NoError(t, err)
	rootPath := fmt.Sprintf("http://%v/%v", webDavServerAddr, user.Username+"1")
	client := gowebdav.NewClient(rootPath, user.Username, defaultPassword)
	client.SetTimeout(5 * time.Second)
	assert.Error(t, checkBasicFunc(client))
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
}

func TestRootRedirect(t *testing.T) {
	errRedirect := errors.New("redirect error")
	u := getTestUser()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))
	rootPath := fmt.Sprintf("http://%v/", webDavServerAddr)
	httpClient := httpclient.GetHTTPClient()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return errRedirect
	}
	req, err := http.NewRequest(http.MethodOptions, rootPath, nil)
	assert.NoError(t, err)
	req.SetBasicAuth(u.Username, u.Password)
	resp, err := httpClient.Do(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), errRedirect.Error())
	}
	err = resp.Body.Close()
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, rootPath, nil)
	assert.NoError(t, err)
	req.SetBasicAuth(u.Username, u.Password)
	resp, err = httpClient.Do(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), errRedirect.Error())
	}
	err = resp.Body.Close()
	assert.NoError(t, err)
	req, err = http.NewRequest("PROPFIND", rootPath, nil)
	assert.NoError(t, err)
	req.SetBasicAuth(u.Username, u.Password)
	resp, err = httpClient.Do(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), errRedirect.Error())
	}
	err = resp.Body.Close()
	assert.NoError(t, err)

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
	client := getWebDavClient(u)
	assert.NoError(t, checkBasicFunc(client))
	u.Username = defaultUsername + "1"
	client = getWebDavClient(u)
	assert.Error(t, checkBasicFunc(client))
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
	client := getWebDavClient(u)
	assert.NoError(t, checkBasicFunc(client))

	users, _, err = httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	user := users[0]
	// test login with an existing user
	client = getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(user, true), os.ModePerm)
	assert.NoError(t, err)
	// update the user to remove it from the cache
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user)
	assert.Error(t, checkBasicFunc(client))
	// update the user to remove it from the cache
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	user.Status = 0
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), os.ModePerm)
	assert.NoError(t, err)
	client = getWebDavClient(user)
	assert.Error(t, checkBasicFunc(client))

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
	client := getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))
	err = ioutil.WriteFile(postConnectPath, getPostConnectScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	assert.Error(t, checkBasicFunc(client))

	common.Config.PostConnectHook = "http://127.0.0.1:8078/api/v1/version"
	assert.NoError(t, checkBasicFunc(client))

	common.Config.PostConnectHook = "http://127.0.0.1:8078/notfound"
	assert.Error(t, checkBasicFunc(client))

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
	client := getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))
	// now add a fake connection
	fs := vfs.NewOsFs("id", os.TempDir(), nil)
	connection := &webdavd.Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, user, fs),
	}
	common.Connections.Add(connection)
	assert.Error(t, checkBasicFunc(client))
	common.Connections.Remove(connection.GetID())
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 0)
}

func TestLoginWithIPilters(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedIP = []string{"192.167.0.0/24", "172.18.0.0/16"}
	u.Filters.AllowedIP = []string{"172.19.0.0/16"}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	assert.Error(t, checkBasicFunc(client))

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
	// use an unknown mime to trigger content type detection
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/sub2",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{".zipp"},
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
	client := getWebDavClient(user)
	testFilePath1 := filepath.Join(user.HomeDir, subDir1, "file.zipp")
	testFilePath2 := filepath.Join(user.HomeDir, subDir2, "file.zipp")
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
	err = downloadFile(path.Join("/", subDir1, "file.zipp"), localDownloadPath, 5, client)
	assert.Error(t, err)
	err = downloadFile(path.Join("/", subDir2, "file.zipp"), localDownloadPath, 5, client)
	assert.Error(t, err)
	err = downloadFile(path.Join("/", subDir2, "file.jpg"), localDownloadPath, 5, client)
	assert.Error(t, err)
	err = downloadFile(path.Join("missing.zip"), localDownloadPath, 5, client)
	assert.Error(t, err)

	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
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
	// we need download permission to get size since PROPFIND will open the file
	u.Permissions[path.Join("/", subDir1)] = []string{dataprovider.PermListItems, dataprovider.PermDownload}
	u.Permissions[path.Join("/", subDir2)] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermDelete, dataprovider.PermDownload}
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/sub2",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{".zip"},
		},
	}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := user.QuotaSize
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = client.Mkdir(subDir1, os.ModePerm)
	assert.NoError(t, err)
	err = client.Mkdir(subDir2, os.ModePerm)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(subDir1, testFileName), testFileSize, client)
	assert.Error(t, err)
	err = uploadFile(testFilePath, path.Join(subDir2, testFileName+".zip"), testFileSize, client)
	assert.Error(t, err)
	err = uploadFile(testFilePath, path.Join(subDir2, testFileName), testFileSize, client)
	assert.NoError(t, err)
	err = client.Rename(path.Join(subDir2, testFileName), path.Join(subDir1, testFileName), false)
	assert.Error(t, err)
	err = uploadFile(testFilePath, path.Join(subDir2, testFileName), testFileSize, client)
	assert.Error(t, err)
	err = uploadFile(testFilePath, subDir1, testFileSize, client)
	assert.Error(t, err)
	// overquota
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.Error(t, err)
	err = client.Remove(path.Join(subDir2, testFileName))
	assert.NoError(t, err)
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.Error(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDeniedLoginMethod(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	assert.Error(t, checkBasicFunc(client))

	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.SSHLoginMethodKeyAndKeyboardInt}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDeniedProtocols(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedProtocols = []string{common.ProtocolWebDAV}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	assert.Error(t, checkBasicFunc(client))

	user.Filters.DeniedProtocols = []string{common.ProtocolSSH, common.ProtocolFTP}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))

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
	client := getWebDavClient(user)
	// test quota files
	err = uploadFile(testFilePath, testFileName+".quota", testFileSize, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, testFileName+".quota1", testFileSize, client)
	assert.Error(t, err)
	err = client.Rename(testFileName+".quota", testFileName, false)
	assert.NoError(t, err)
	files, err := client.ReadDir("/")
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	// test quota size
	user.QuotaSize = testFileSize - 1
	user.QuotaFiles = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	err = uploadFile(testFilePath, testFileName+".quota", testFileSize, client)
	assert.Error(t, err)
	err = client.Rename(testFileName, testFileName+".quota", false)
	assert.NoError(t, err)
	// now test quota limits while uploading the current file, we have 1 bytes remaining
	user.QuotaSize = testFileSize + 1
	user.QuotaFiles = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	err = uploadFile(testFilePath1, testFileName1, testFileSize1, client)
	assert.Error(t, err)
	_, err = client.Stat(testFileName1)
	assert.Error(t, err)
	err = client.Rename(testFileName+".quota", testFileName, false)
	assert.NoError(t, err)
	// overwriting an existing file will work if the resulting size is lesser or equal than the current one
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath2, testFileName, testFileSize2, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath1, testFileName, testFileSize1, client)
	assert.Error(t, err)
	err = uploadFile(testFilePath2, testFileName, testFileSize2, client)
	assert.NoError(t, err)

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
	testFileName1 := "test_file_dav1.dat"
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	err = createTestFile(testFilePath1, testFileSize1)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	err = uploadFile(testFilePath1, testFileName1, testFileSize1, client)
	assert.Error(t, err)
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.NoError(t, err)
	// now test overwrite an existing file with a size bigger than the allowed one
	err = createTestFile(filepath.Join(user.GetHomeDir(), testFileName1), testFileSize1)
	assert.NoError(t, err)
	err = uploadFile(testFilePath1, testFileName1, testFileSize1, client)
	assert.Error(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestClientClose(t *testing.T) {
	u := getTestUser()
	u.UploadBandwidth = 64
	u.DownloadBandwidth = 64
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileSize := int64(1048576)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	assert.NoError(t, checkBasicFunc(client))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		err = uploadFile(testFilePath, testFileName, testFileSize, client)
		assert.Error(t, err)
		wg.Done()
	}()

	assert.Eventually(t, func() bool {
		for _, stat := range common.Connections.GetStats() {
			if len(stat.Transfers) > 0 {
				return true
			}
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)

	for _, stat := range common.Connections.GetStats() {
		common.Connections.Close(stat.ConnectionID)
	}
	wg.Wait()
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 },
		1*time.Second, 100*time.Millisecond)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	testFilePath = filepath.Join(user.HomeDir, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)

	wg.Add(1)
	go func() {
		err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.Error(t, err)
		wg.Done()
	}()

	assert.Eventually(t, func() bool {
		for _, stat := range common.Connections.GetStats() {
			if len(stat.Transfers) > 0 {
				return true
			}
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)

	for _, stat := range common.Connections.GetStats() {
		common.Connections.Close(stat.ConnectionID)
	}
	wg.Wait()
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 },
		1*time.Second, 100*time.Millisecond)

	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)

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

	client := getWebDavClient(user)

	err = client.Connect()
	assert.NoError(t, err)

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

	client := getWebDavClient(user)
	assert.Error(t, checkBasicFunc(client))

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestBytesRangeRequests(t *testing.T) {
	for _, u := range []dataprovider.User{getTestUser(), getTestUserWithCryptFs()} {
		user, _, err := httpd.AddUser(u, http.StatusOK)
		assert.NoError(t, err)
		testFileName := "test_file.txt"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		fileContent := []byte("test file contents")
		err = ioutil.WriteFile(testFilePath, fileContent, os.ModePerm)
		assert.NoError(t, err)
		client := getWebDavClient(user)
		err = uploadFile(testFilePath, testFileName, int64(len(fileContent)), client)
		assert.NoError(t, err)
		remotePath := fmt.Sprintf("http://%v/%v/%v", webDavServerAddr, user.Username, testFileName)
		req, err := http.NewRequest(http.MethodGet, remotePath, nil)
		if assert.NoError(t, err) {
			httpClient := httpclient.GetHTTPClient()
			req.SetBasicAuth(user.Username, defaultPassword)
			req.Header.Set("Range", "bytes=5-")
			resp, err := httpClient.Do(req)
			if assert.NoError(t, err) {
				defer resp.Body.Close()
				assert.Equal(t, http.StatusPartialContent, resp.StatusCode)
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				assert.NoError(t, err)
				assert.Equal(t, "file contents", string(bodyBytes))
			}
			req.Header.Set("Range", "bytes=5-8")
			resp, err = httpClient.Do(req)
			if assert.NoError(t, err) {
				defer resp.Body.Close()
				assert.Equal(t, http.StatusPartialContent, resp.StatusCode)
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				assert.NoError(t, err)
				assert.Equal(t, "file", string(bodyBytes))
			}
		}

		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}
}

func TestGETAsPROPFIND(t *testing.T) {
	u := getTestUser()
	subDir1 := "/sub1"
	u.Permissions[subDir1] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	rootPath := fmt.Sprintf("http://%v/%v", webDavServerAddr, user.Username)
	httpClient := httpclient.GetHTTPClient()
	req, err := http.NewRequest(http.MethodGet, rootPath, nil)
	if assert.NoError(t, err) {
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)
			resp.Body.Close()
		}
	}
	client := getWebDavClient(user)
	err = client.MkdirAll(path.Join(subDir1, "sub", "sub1"), os.ModePerm)
	assert.NoError(t, err)
	subPath := fmt.Sprintf("http://%v/%v", webDavServerAddr, path.Join(user.Username, subDir1))
	req, err = http.NewRequest(http.MethodGet, subPath, nil)
	if assert.NoError(t, err) {
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			// before the performance patch we have a 500 here, now we have 207 but an empty list
			//assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
			assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)
			resp.Body.Close()
		}
	}
	// we cannot stat the sub at all
	subPath1 := fmt.Sprintf("http://%v/%v", webDavServerAddr, path.Join(user.Username, subDir1, "sub"))
	req, err = http.NewRequest(http.MethodGet, subPath1, nil)
	if assert.NoError(t, err) {
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			// here the stat will fail, so the request will not be changed in propfind
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			resp.Body.Close()
		}
	}

	// we have no permission, we get an empty list
	files, err := client.ReadDir(subDir1)
	assert.NoError(t, err)
	assert.Len(t, files, 0)
	// if we grant the permissions the files are listed
	user.Permissions[subDir1] = []string{dataprovider.PermDownload, dataprovider.PermListItems}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	files, err = client.ReadDir(subDir1)
	assert.NoError(t, err)
	assert.Len(t, files, 1)

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestStat(t *testing.T) {
	u := getTestUser()
	u.Permissions["/subdir"] = []string{dataprovider.PermUpload, dataprovider.PermListItems, dataprovider.PermDownload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client := getWebDavClient(user)
	subDir := "subdir"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = client.Mkdir(subDir, os.ModePerm)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, testFileName, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join("/", subDir, testFileName), testFileSize, client)
	assert.NoError(t, err)
	user.Permissions["/subdir"] = []string{dataprovider.PermUpload, dataprovider.PermDownload}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = client.Stat(testFileName)
	assert.NoError(t, err)
	_, err = client.Stat(path.Join("/", subDir, testFileName))
	assert.Error(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadOverwriteVfolder(t *testing.T) {
	u := getTestUser()
	vdir := "/vdir"
	mappedPath := filepath.Join(os.TempDir(), "mappedDir")
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
	client := getWebDavClient(user)
	files, err := client.ReadDir(".")
	assert.NoError(t, err)
	vdirFound := false
	for _, info := range files {
		if info.Name() == path.Base(vdir) {
			vdirFound = true
			break
		}
	}
	assert.True(t, vdirFound)
	info, err := client.Stat(vdir)
	if assert.NoError(t, err) {
		assert.Equal(t, path.Base(vdir), info.Name())
	}

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(vdir, testFileName), testFileSize, client)
	assert.NoError(t, err)
	folder, _, err := httpd.GetFolders(0, 0, mappedPath, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folder, 1) {
		f := folder[0]
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
	}
	err = uploadFile(testFilePath, path.Join(vdir, testFileName), testFileSize, client)
	assert.NoError(t, err)
	folder, _, err = httpd.GetFolders(0, 0, mappedPath, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folder, 1) {
		f := folder[0]
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
	}
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestMiscCommands(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 100
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	dir := "testDir"
	client := getWebDavClient(user)
	err = client.MkdirAll(path.Join(dir, "sub1", "sub2"), os.ModePerm)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(dir, testFileName), testFileSize, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(dir, "sub1", testFileName), testFileSize, client)
	assert.NoError(t, err)
	err = uploadFile(testFilePath, path.Join(dir, "sub1", "sub2", testFileName), testFileSize, client)
	assert.NoError(t, err)
	err = client.Copy(dir, dir+"_copy", false)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 6, user.UsedQuotaFiles)
	assert.Equal(t, 6*testFileSize, user.UsedQuotaSize)
	err = client.Copy(dir, dir+"_copy1", false)
	assert.NoError(t, err)
	err = client.Copy(dir+"_copy", dir+"_copy1", false)
	assert.Error(t, err)
	err = client.Copy(dir+"_copy", dir+"_copy1", true)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 9, user.UsedQuotaFiles)
	assert.Equal(t, 9*testFileSize, user.UsedQuotaSize)
	err = client.Rename(dir+"_copy1", dir+"_copy2", false)
	assert.NoError(t, err)
	err = client.Remove(path.Join(dir+"_copy", testFileName))
	assert.NoError(t, err)
	err = client.Rename(dir+"_copy2", dir+"_copy", true)
	assert.NoError(t, err)
	err = client.Copy(dir+"_copy", dir+"_copy1", false)
	assert.NoError(t, err)
	err = client.RemoveAll(dir + "_copy1")
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 6, user.UsedQuotaFiles)
	assert.Equal(t, 6*testFileSize, user.UsedQuotaSize)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func checkBasicFunc(client *gowebdav.Client) error {
	err := client.Connect()
	if err != nil {
		return err
	}
	_, err = client.ReadDir("/")
	return err
}

func uploadFile(localSourcePath string, remoteDestPath string, expectedSize int64, client *gowebdav.Client) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	err = client.WriteStream(remoteDestPath, srcFile, os.ModePerm)
	if err != nil {
		return err
	}
	if expectedSize > 0 {
		info, err := client.Stat(remoteDestPath)
		if err != nil {
			return err
		}
		if info.Size() != expectedSize {
			return fmt.Errorf("uploaded file size does not match, actual: %v, expected: %v", info.Size(), expectedSize)
		}
	}
	return nil
}

func downloadFile(remoteSourcePath string, localDestPath string, expectedSize int64, client *gowebdav.Client) error {
	downloadDest, err := os.Create(localDestPath)
	if err != nil {
		return err
	}
	defer downloadDest.Close()

	reader, err := client.ReadStream(remoteSourcePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	written, err := io.Copy(downloadDest, reader)
	if err != nil {
		return err
	}
	if written != expectedSize {
		return fmt.Errorf("downloaded file size does not match, actual: %v, expected: %v", written, expectedSize)
	}
	return nil
}

func getWebDavClient(user dataprovider.User) *gowebdav.Client {
	rootPath := fmt.Sprintf("http://%v/%v", webDavServerAddr, user.Username)
	pwd := defaultPassword
	if len(user.Password) > 0 {
		pwd = user.Password
	}
	client := gowebdav.NewClient(rootPath, user.Username, pwd)
	client.SetTimeout(5 * time.Second)
	return client
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

func getTestUserWithCryptFs() dataprovider.User {
	user := getTestUser()
	user.FsConfig.Provider = dataprovider.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("testPassphrase")
	return user
}

func getEncryptedFileSize(size int64) (int64, error) {
	encSize, err := sio.EncryptedSize(uint64(size))
	return int64(encSize) + 33, err
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
