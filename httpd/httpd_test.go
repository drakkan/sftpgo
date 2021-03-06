package httpd_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/render"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/httpdtest"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	defaultUsername           = "test_user"
	defaultPassword           = "test_password"
	testPubKey                = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	defaultTokenAuthUser      = "admin"
	defaultTokenAuthPass      = "password"
	altAdminUsername          = "newTestAdmin"
	altAdminPassword          = "password1"
	csrfFormToken             = "_form_token"
	userPath                  = "/api/v2/users"
	adminPath                 = "/api/v2/admins"
	adminPwdPath              = "/api/v2/changepwd/admin"
	folderPath                = "/api/v2/folders"
	activeConnectionsPath     = "/api/v2/connections"
	serverStatusPath          = "/api/v2/status"
	quotaScanPath             = "/api/v2/quota-scans"
	quotaScanVFolderPath      = "/api/v2/folder-quota-scans"
	updateUsedQuotaPath       = "/api/v2/quota-update"
	updateFolderUsedQuotaPath = "/api/v2/folder-quota-update"
	defenderUnban             = "/api/v2/defender/unban"
	versionPath               = "/api/v2/version"
	logoutPath                = "/api/v2/logout"
	healthzPath               = "/healthz"
	webBasePath               = "/web"
	webLoginPath              = "/web/login"
	webLogoutPath             = "/web/logout"
	webUsersPath              = "/web/users"
	webUserPath               = "/web/user"
	webFoldersPath            = "/web/folders"
	webFolderPath             = "/web/folder"
	webConnectionsPath        = "/web/connections"
	webStatusPath             = "/web/status"
	webAdminsPath             = "/web/admins"
	webAdminPath              = "/web/admin"
	webMaintenancePath        = "/web/maintenance"
	webRestorePath            = "/web/restore"
	webChangeAdminPwdPath     = "/web/changepwd/admin"
	webTemplateUser           = "/web/template/user"
	webTemplateFolder         = "/web/template/folder"
	httpBaseURL               = "http://127.0.0.1:8081"
	configDir                 = ".."
	httpsCert                 = `-----BEGIN CERTIFICATE-----
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
	httpsKey = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCfMNsN6miEE3rVyUPwElfiJSWaR5huPCzUenZOfJT04GAcQdWvEju3
UM2lmBLIXpGgBwYFK4EEACKhZANiAARCjRMqJ85rzMC998X5z761nJ+xL3bkmGVq
WvrJ51t5OxV0v25NsOgR82CANXUgvhVYs7vNFN+jxtb2aj6Xg+/2G/BNxkaFspIV
CzgWkxiz7XE4lgUwX44FCXZM3+JeUbI=
-----END EC PRIVATE KEY-----`
	sftpPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB+RB4yNTZz9mHOkawwUibNdemijVV3ErMeLxWUBlCN/gAAAJA7DjpfOw46
XwAAAAtzc2gtZWQyNTUxOQAAACB+RB4yNTZz9mHOkawwUibNdemijVV3ErMeLxWUBlCN/g
AAAEA0E24gi8ab/XRSvJ85TGZJMe6HVmwxSG4ExPfTMwwe2n5EHjI1NnP2Yc6RrDBSJs11
6aKNVXcSsx4vFZQGUI3+AAAACW5pY29sYUBwMQECAwQ=
-----END OPENSSH PRIVATE KEY-----`
	sftpPkeyFingerprint = "SHA256:QVQ06XHZZbYZzqfrsZcf3Yozy2WTnqQPeLOkcJCdbP0"
	redactedSecret      = "[**redacted**]"
)

var (
	defaultPerms       = []string{dataprovider.PermAny}
	homeBasePath       string
	backupsPath        string
	credentialsPath    string
	testServer         *httptest.Server
	providerDriverName string
)

type fakeConnection struct {
	*common.BaseConnection
	command string
}

func (c *fakeConnection) Disconnect() error {
	common.Connections.Remove(c.GetID())
	return nil
}

func (c *fakeConnection) GetClientVersion() string {
	return ""
}

func (c *fakeConnection) GetCommand() string {
	return c.command
}

func (c *fakeConnection) GetRemoteAddress() string {
	return ""
}

func TestMain(m *testing.M) {
	homeBasePath = os.TempDir()
	logfilePath := filepath.Join(configDir, "sftpgo_api_test.log")
	logger.InitLogger(logfilePath, 5, 1, 28, false, zerolog.DebugLevel)
	err := config.LoadConfig(configDir, "")
	if err != nil {
		logger.WarnToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()
	credentialsPath = filepath.Join(os.TempDir(), "test_credentials")
	providerConf.CredentialsPath = credentialsPath
	providerDriverName = providerConf.Driver
	os.RemoveAll(credentialsPath) //nolint:errcheck
	logger.InfoToConsole("Starting HTTPD tests, provider: %v", providerConf.Driver)

	err = common.Initialize(config.GetCommonConfig())
	if err != nil {
		logger.WarnToConsole("error initializing common: %v", err)
		os.Exit(1)
	}

	err = dataprovider.Initialize(providerConf, configDir, true)
	if err != nil {
		logger.WarnToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Initialize(configDir) //nolint:errcheck
	kmsConfig := config.GetKMSConfig()
	err = kmsConfig.Initialize()
	if err != nil {
		logger.ErrorToConsole("error initializing kms: %v", err)
		os.Exit(1)
	}

	httpdConf := config.GetHTTPDConfig()

	httpdConf.Bindings[0].Port = 8081
	httpdtest.SetBaseURL(httpBaseURL)
	backupsPath = filepath.Join(os.TempDir(), "test_backups")
	httpdConf.BackupsPath = backupsPath
	err = os.MkdirAll(backupsPath, os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error creating backups path: %v", err)
		os.Exit(1)
	}

	go func() {
		if err := httpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(httpdConf.Bindings[0].GetAddress())
	httpd.ReloadCertificateMgr() //nolint:errcheck
	// now start an https server
	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	err = os.WriteFile(certPath, []byte(httpsCert), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing HTTPS certificate: %v", err)
		os.Exit(1)
	}
	err = os.WriteFile(keyPath, []byte(httpsKey), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing HTTPS private key: %v", err)
		os.Exit(1)
	}
	httpdConf.Bindings[0].Port = 8443
	httpdConf.Bindings[0].EnableHTTPS = true
	httpdConf.CertificateFile = certPath
	httpdConf.CertificateKeyFile = keyPath
	httpdConf.Bindings = append(httpdConf.Bindings, httpd.Binding{})

	go func() {
		if err := httpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start HTTPS server: %v", err)
			os.Exit(1)
		}
	}()
	waitTCPListening(httpdConf.Bindings[0].GetAddress())
	httpd.ReloadCertificateMgr() //nolint:errcheck

	testServer = httptest.NewServer(httpd.GetHTTPRouter())
	defer testServer.Close()

	exitCode := m.Run()
	os.Remove(logfilePath)        //nolint:errcheck
	os.RemoveAll(backupsPath)     //nolint:errcheck
	os.RemoveAll(credentialsPath) //nolint:errcheck
	os.Remove(certPath)           //nolint:errcheck
	os.Remove(keyPath)            //nolint:errcheck
	os.Exit(exitCode)             //nolint:errcheck
}

func TestInitialization(t *testing.T) {
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	invalidFile := "invalid file"
	httpdConf := config.GetHTTPDConfig()
	httpdConf.BackupsPath = backupsPath
	httpdConf.CertificateFile = invalidFile
	httpdConf.CertificateKeyFile = invalidFile
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)
	httpdConf.CertificateFile = ""
	httpdConf.CertificateKeyFile = ""
	httpdConf.TemplatesPath = "."
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)
	httpdConf = config.GetHTTPDConfig()
	httpdConf.BackupsPath = ".."
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)
	httpdConf.BackupsPath = backupsPath
	httpdConf.CertificateFile = invalidFile
	httpdConf.CertificateKeyFile = invalidFile
	httpdConf.StaticFilesPath = ""
	httpdConf.TemplatesPath = ""
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)
	httpdConf.CertificateFile = filepath.Join(os.TempDir(), "test.crt")
	httpdConf.CertificateKeyFile = filepath.Join(os.TempDir(), "test.key")
	httpdConf.CACertificates = append(httpdConf.CACertificates, invalidFile)
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)
	httpdConf.CACertificates = nil
	httpdConf.CARevocationLists = append(httpdConf.CARevocationLists, invalidFile)
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)
	httpdConf.CARevocationLists = nil
	httpdConf.Bindings[0].Port = 8081
	httpdConf.Bindings[0].EnableHTTPS = true
	httpdConf.Bindings[0].ClientAuthType = 1
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)
}

func TestBasicUserHandling(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.MaxSessions = 10
	user.QuotaSize = 4096
	user.QuotaFiles = 2
	user.UploadBandwidth = 128
	user.DownloadBandwidth = 64
	user.ExpirationDate = utils.GetTimeAsMsSinceEpoch(time.Now())
	user.AdditionalInfo = "some free text"
	user.Filters.TLSUsername = dataprovider.TLSUsernameCN
	originalUser := user
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, originalUser.ID, user.ID)

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestBasicAdminHandling(t *testing.T) {
	// we have one admin by default
	admins, _, err := httpdtest.GetAdmins(0, 0, http.StatusOK)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(admins), 1)
	admin := getTestAdmin()
	// the default admin already exists
	_, _, err = httpdtest.AddAdmin(admin, http.StatusInternalServerError)
	assert.NoError(t, err)

	admin.Username = altAdminUsername
	admin, _, err = httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)

	admin.AdditionalInfo = "test info"
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, "test info", admin.AdditionalInfo)

	admins, _, err = httpdtest.GetAdmins(1, 0, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, admins, 1)
	assert.NotEqual(t, admin.Username, admins[0].Username)

	admins, _, err = httpdtest.GetAdmins(1, 1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, admins, 1)
	assert.Equal(t, admin.Username, admins[0].Username)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusNotFound)
	assert.NoError(t, err)

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username+"123", http.StatusNotFound)
	assert.NoError(t, err)

	admin.Username = defaultTokenAuthUser
	_, err = httpdtest.RemoveAdmin(admin, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestChangeAdminPassword(t *testing.T) {
	_, err := httpdtest.ChangeAdminPassword("wrong", defaultTokenAuthPass, http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpdtest.ChangeAdminPassword(defaultTokenAuthPass, defaultTokenAuthPass, http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpdtest.ChangeAdminPassword(defaultTokenAuthPass, defaultTokenAuthPass+"1", http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.ChangeAdminPassword(defaultTokenAuthPass+"1", defaultTokenAuthPass, http.StatusUnauthorized)
	assert.NoError(t, err)
	admin, err := dataprovider.AdminExists(defaultTokenAuthUser)
	assert.NoError(t, err)
	admin.Password = defaultTokenAuthPass
	err = dataprovider.UpdateAdmin(&admin)
	assert.NoError(t, err)
}

func TestAdminAllowList(t *testing.T) {
	a := getTestAdmin()
	a.Username = altAdminUsername
	a.Password = altAdminPassword

	admin, _, err := httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)

	token, _, err := httpdtest.GetToken(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)
	httpdtest.SetJWTToken(token)
	_, _, err = httpdtest.GetStatus(http.StatusOK)
	assert.NoError(t, err)

	httpdtest.SetJWTToken("")

	admin.Password = altAdminPassword
	admin.Filters.AllowList = []string{"10.6.6.0/32"}
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	_, _, err = httpdtest.GetToken(altAdminUsername, altAdminPassword)
	assert.EqualError(t, err, "wrong status code: got 401 want 200")

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserStatus(t *testing.T) {
	u := getTestUser()
	u.Status = 3
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Status = 0
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user.Status = 2
	_, _, err = httpdtest.UpdateUser(user, http.StatusBadRequest, "")
	assert.NoError(t, err)
	user.Status = 1
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestAddUserNoCredentials(t *testing.T) {
	u := getTestUser()
	u.Password = ""
	u.PublicKeys = []string{}
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserNoUsername(t *testing.T) {
	u := getTestUser()
	u.Username = ""
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserNoHomeDir(t *testing.T) {
	u := getTestUser()
	u.HomeDir = ""
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidHomeDir(t *testing.T) {
	u := getTestUser()
	u.HomeDir = "relative_path" //nolint:goconst
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserNoPerms(t *testing.T) {
	u := getTestUser()
	u.Permissions = make(map[string][]string)
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Permissions["/"] = []string{}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidPerms(t *testing.T) {
	u := getTestUser()
	u.Permissions["/"] = []string{"invalidPerm"}
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	// permissions for root dir are mandatory
	u.Permissions["/"] = []string{}
	u.Permissions["/somedir"] = []string{dataprovider.PermAny}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir/.."] = []string{dataprovider.PermAny}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidFilters(t *testing.T) {
	u := getTestUser()
	u.Filters.AllowedIP = []string{"192.168.1.0/24", "192.168.2.0"}
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.AllowedIP = []string{}
	u.Filters.DeniedIP = []string{"192.168.3.0/16", "invalid"}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedIP = []string{}
	u.Filters.DeniedLoginMethods = []string{"invalid"}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedLoginMethods = dataprovider.ValidLoginMethods
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedLoginMethods = []string{}
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "relative",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/subdir",
			AllowedExtensions: []string{".zip"},
			DeniedExtensions:  []string{},
		},
		{
			Path:              "/subdir",
			AllowedExtensions: []string{".rar"},
			DeniedExtensions:  []string{".jpg"},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FileExtensions = nil
	u.Filters.FilePatterns = []dataprovider.PatternsFilter{
		{
			Path:            "relative",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []dataprovider.PatternsFilter{
		{
			Path:            "/",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []dataprovider.PatternsFilter{
		{
			Path:            "/subdir",
			AllowedPatterns: []string{"*.zip"},
		},
		{
			Path:            "/subdir",
			AllowedPatterns: []string{"*.rar"},
			DeniedPatterns:  []string{"*.jpg"},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []dataprovider.PatternsFilter{
		{
			Path:            "/subdir",
			AllowedPatterns: []string{"a\\"},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedProtocols = []string{"invalid"}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedProtocols = dataprovider.ValidProtocols
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedProtocols = nil
	u.Filters.TLSUsername = "not a supported attribute"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidFsConfig(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = dataprovider.S3FilesystemProvider
	u.FsConfig.S3Config.Bucket = ""
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = os.MkdirAll(credentialsPath, 0700)
	assert.NoError(t, err)
	u.FsConfig.S3Config.Bucket = "testbucket"
	u.FsConfig.S3Config.Region = "eu-west-1"
	u.FsConfig.S3Config.AccessKey = "access-key"
	u.FsConfig.S3Config.AccessSecret = kms.NewSecret(kms.SecretStatusRedacted, "access-secret", "", "")
	u.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/path?a=b"
	u.FsConfig.S3Config.StorageClass = "Standard" //nolint:goconst
	u.FsConfig.S3Config.KeyPrefix = "/adir/subdir/"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.S3Config.AccessSecret.SetStatus(kms.SecretStatusPlain)
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.S3Config.KeyPrefix = ""
	u.FsConfig.S3Config.UploadPartSize = 3
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.S3Config.UploadPartSize = 5001
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.S3Config.UploadPartSize = 0
	u.FsConfig.S3Config.UploadConcurrency = -1
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u = getTestUser()
	u.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = ""
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.Bucket = "abucket"
	u.FsConfig.GCSConfig.StorageClass = "Standard"
	u.FsConfig.GCSConfig.KeyPrefix = "/somedir/subdir/"
	u.FsConfig.GCSConfig.Credentials = kms.NewSecret(kms.SecretStatusRedacted, "test", "", "") //nolint:goconst
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.Credentials.SetStatus(kms.SecretStatusPlain)
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.KeyPrefix = "somedir/subdir/" //nolint:goconst
	u.FsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
	u.FsConfig.GCSConfig.AutomaticCredentials = 0
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.Credentials = kms.NewSecret(kms.SecretStatusSecretBox, "invalid", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)

	u = getTestUser()
	u.FsConfig.Provider = dataprovider.AzureBlobFilesystemProvider
	u.FsConfig.AzBlobConfig.SASURL = "http://foo\x7f.com/"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.SASURL = ""
	u.FsConfig.AzBlobConfig.AccountName = "name"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.Container = "container"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.AccountKey = kms.NewSecret(kms.SecretStatusRedacted, "key", "", "")
	u.FsConfig.AzBlobConfig.KeyPrefix = "/amedir/subdir/"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.AccountKey.SetStatus(kms.SecretStatusPlain)
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.KeyPrefix = "amedir/subdir/"
	u.FsConfig.AzBlobConfig.UploadPartSize = -1
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.UploadPartSize = 101
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)

	u = getTestUser()
	u.FsConfig.Provider = dataprovider.CryptedFilesystemProvider
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.CryptConfig.Passphrase = kms.NewSecret(kms.SecretStatusRedacted, "akey", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u = getTestUser()
	u.FsConfig.Provider = dataprovider.SFTPFilesystemProvider
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.SFTPConfig.Password = kms.NewSecret(kms.SecretStatusRedacted, "randompkey", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.SFTPConfig.Password = kms.NewEmptySecret()
	u.FsConfig.SFTPConfig.PrivateKey = kms.NewSecret(kms.SecretStatusRedacted, "keyforpkey", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidVirtualFolders(t *testing.T) {
	u := getTestUser()
	folderName := "fname"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
			Name:       folderName,
		},
		VirtualPath: "vdir", // invalid
	})
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
			Name:       folderName,
		},
		VirtualPath: "/", // invalid
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(u.GetHomeDir(), "mapped_dir"), // invalid, inside home dir
			Name:       folderName,
		},
		VirtualPath: "/vdir",
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: u.GetHomeDir(), // invalid
			Name:       folderName,
		},
		VirtualPath: "/vdir",
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(u.GetHomeDir(), ".."), // invalid, contains home dir
			Name:       "tmp",
		},
		VirtualPath: "/vdir",
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
			Name:       folderName,
		},
		VirtualPath: "/vdir",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
			Name:       folderName + "1",
		},
		VirtualPath: "/vdir", // invalid, already defined
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
			Name:       folderName,
		},
		VirtualPath: "/vdir1",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"), // invalid, already defined
			Name:       folderName,
		},
		VirtualPath: "/vdir2",
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir", "subdir"),
			Name:       folderName + "2",
		},
		VirtualPath: "/vdir1",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"), // invalid, contains mapped_dir/subdir
			Name:       folderName,
		},
		VirtualPath: "/vdir2",
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
			Name:       folderName,
		},
		VirtualPath: "/vdir1",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir", "subdir"), // invalid, contained in mapped_dir
			Name:       folderName + "3",
		},
		VirtualPath: "/vdir2",
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
			Name:       folderName + "1",
		},
		VirtualPath: "/vdir1/subdir",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir2"),
			Name:       folderName + "2",
		},
		VirtualPath: "/vdir1/../vdir1", // invalid, overlaps with /vdir1/subdir
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
			Name:       folderName + "1",
		},
		VirtualPath: "/vdir1/",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir2"),
			Name:       folderName + "2",
		},
		VirtualPath: "/vdir1/subdir", // invalid, contained inside /vdir1
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
			Name:       folderName + "1",
		},
		VirtualPath: "/vdir1/",
		QuotaSize:   -1,
		QuotaFiles:  1, // invvalid, we cannot have -1 and > 0
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
			Name:       folderName + "1",
		},
		VirtualPath: "/vdir1/",
		QuotaSize:   1,
		QuotaFiles:  -1,
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
			Name:       folderName + "1",
		},
		VirtualPath: "/vdir1/",
		QuotaSize:   -2, // invalid
		QuotaFiles:  0,
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
			Name:       folderName + "1",
		},
		VirtualPath: "/vdir1/",
		QuotaSize:   0,
		QuotaFiles:  -2, // invalid
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "/vdir1",
	})
	// folder name is mandatory
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       "aa=a", // char not allowed
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "/vdir1",
	})
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestUserPublicKey(t *testing.T) {
	u := getTestUser()
	u.Password = ""
	invalidPubKey := "invalid"
	u.PublicKeys = []string{invalidPubKey}
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.PublicKeys = []string{testPubKey}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	dbUser, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	assert.Empty(t, dbUser.Password)
	assert.False(t, dbUser.IsPasswordHashed())

	user.PublicKeys = []string{testPubKey, invalidPubKey}
	_, _, err = httpdtest.UpdateUser(user, http.StatusBadRequest, "")
	assert.NoError(t, err)
	user.PublicKeys = []string{testPubKey, testPubKey, testPubKey}
	user.Password = defaultPassword
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	dbUser, err = dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, dbUser.Password)
	assert.True(t, dbUser.IsPasswordHashed())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUserEmptyPassword(t *testing.T) {
	u := getTestUser()
	u.PublicKeys = []string{testPubKey}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	// the password is not empty
	dbUser, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, dbUser.Password)
	assert.True(t, dbUser.IsPasswordHashed())
	// now update the user and set an empty password
	customUser := make(map[string]interface{})
	customUser["password"] = ""
	asJSON, err := json.Marshal(customUser)
	assert.NoError(t, err)
	userNoPwd, _, err := httpdtest.UpdateUserWithJSON(user, http.StatusOK, "", asJSON)
	assert.NoError(t, err)
	assert.Equal(t, user, userNoPwd) // the password is hidden so the user must be equal
	// check the password within the data provider
	dbUser, err = dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	assert.Empty(t, dbUser.Password)
	assert.False(t, dbUser.IsPasswordHashed())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUser(t *testing.T) {
	u := getTestUser()
	u.UsedQuotaFiles = 1
	u.UsedQuotaSize = 2
	u.Filters.TLSUsername = dataprovider.TLSUsernameCN
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, 0, user.UsedQuotaFiles)
	assert.Equal(t, int64(0), user.UsedQuotaSize)
	user.HomeDir = filepath.Join(homeBasePath, "testmod")
	user.UID = 33
	user.GID = 101
	user.MaxSessions = 10
	user.QuotaSize = 4096
	user.QuotaFiles = 2
	user.Permissions["/"] = []string{dataprovider.PermCreateDirs, dataprovider.PermDelete, dataprovider.PermDownload}
	user.Permissions["/subdir"] = []string{dataprovider.PermListItems, dataprovider.PermUpload}
	user.Filters.AllowedIP = []string{"192.168.1.0/24", "192.168.2.0/24"}
	user.Filters.DeniedIP = []string{"192.168.3.0/24", "192.168.4.0/24"}
	user.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	user.Filters.DeniedProtocols = []string{common.ProtocolWebDAV}
	user.Filters.TLSUsername = dataprovider.TLSUsernameNone
	user.Filters.FileExtensions = append(user.Filters.FileExtensions, dataprovider.ExtensionsFilter{
		Path:              "/subdir",
		AllowedExtensions: []string{".zip", ".rar"},
		DeniedExtensions:  []string{".jpg", ".png"},
	})
	user.Filters.FilePatterns = append(user.Filters.FilePatterns, dataprovider.PatternsFilter{
		Path:            "/subdir",
		AllowedPatterns: []string{"*.zip", "*.rar"},
		DeniedPatterns:  []string{"*.jpg", "*.png"},
	})
	user.Filters.MaxUploadFileSize = 4096
	user.UploadBandwidth = 1024
	user.DownloadBandwidth = 512
	user.VirtualFolders = nil
	mappedPath1 := filepath.Join(os.TempDir(), "mapped_dir1")
	mappedPath2 := filepath.Join(os.TempDir(), "mapped_dir2")
	folderName1 := filepath.Base(mappedPath1)
	folderName2 := filepath.Base(mappedPath2)
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1",
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: "/vdir12/subdir",
		QuotaSize:   123,
		QuotaFiles:  2,
	})
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, _, err = httpdtest.UpdateUser(user, http.StatusBadRequest, "invalid")
	assert.NoError(t, err)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "0")
	assert.NoError(t, err)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "1")
	assert.NoError(t, err)
	user.Permissions["/subdir"] = []string{}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Len(t, user.Permissions["/subdir"], 0)
	assert.Len(t, user.VirtualFolders, 2)
	for _, folder := range user.VirtualFolders {
		assert.Greater(t, folder.ID, int64(0))
		if folder.VirtualPath == "/vdir12/subdir" {
			assert.Equal(t, int64(123), folder.QuotaSize)
			assert.Equal(t, 2, folder.QuotaFiles)
		}
	}
	folder, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 1)
	assert.Contains(t, folder.Users, user.Username)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	// removing the user must remove folder mapping
	folder, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 0)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 0)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUserQuotaUsage(t *testing.T) {
	u := getTestUser()
	usedQuotaFiles := 1
	usedQuotaSize := int64(65535)
	u.UsedQuotaFiles = usedQuotaFiles
	u.UsedQuotaSize = usedQuotaSize
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpdtest.UpdateQuotaUsage(u, "invalid_mode", http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpdtest.UpdateQuotaUsage(u, "", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize, user.UsedQuotaSize)
	_, err = httpdtest.UpdateQuotaUsage(u, "add", http.StatusBadRequest)
	assert.NoError(t, err, "user has no quota restrictions add mode should fail")
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize, user.UsedQuotaSize)
	user.QuotaFiles = 100
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = httpdtest.UpdateQuotaUsage(u, "add", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 2*usedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, 2*usedQuotaSize, user.UsedQuotaSize)
	u.UsedQuotaFiles = -1
	_, err = httpdtest.UpdateQuotaUsage(u, "", http.StatusBadRequest)
	assert.NoError(t, err)
	u.UsedQuotaFiles = usedQuotaFiles
	u.Username = u.Username + "1"
	_, err = httpdtest.UpdateQuotaUsage(u, "", http.StatusNotFound)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserFolderMapping(t *testing.T) {
	mappedPath1 := filepath.Join(os.TempDir(), "mapped_dir1")
	mappedPath2 := filepath.Join(os.TempDir(), "mapped_dir2")
	folderName1 := filepath.Base(mappedPath1)
	folderName2 := filepath.Base(mappedPath2)
	u1 := getTestUser()
	u1.VirtualFolders = append(u1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:           folderName1,
			MappedPath:     mappedPath1,
			UsedQuotaFiles: 2,
			UsedQuotaSize:  123,
		},
		VirtualPath: "/vdir",
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	user1, _, err := httpdtest.AddUser(u1, http.StatusCreated)
	assert.NoError(t, err)
	// virtual folder must be auto created
	folder, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 1)
	assert.Contains(t, folder.Users, user1.Username)
	assert.Equal(t, 0, folder.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder.UsedQuotaSize)

	u2 := getTestUser()
	u2.Username = defaultUsername + "2"
	u2.VirtualFolders = append(u2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1",
		QuotaSize:   0,
		QuotaFiles:  0,
	})
	u2.VirtualFolders = append(u2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: "/vdir2",
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	user2, _, err := httpdtest.AddUser(u2, http.StatusCreated)
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 1)
	assert.Contains(t, folder.Users, user2.Username)
	folder, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 2)
	assert.Contains(t, folder.Users, user1.Username)
	assert.Contains(t, folder.Users, user2.Username)
	// now update user2 removing mappedPath1
	user2.VirtualFolders = nil
	user2.VirtualFolders = append(user2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:           folderName2,
			MappedPath:     mappedPath2,
			UsedQuotaFiles: 2,
			UsedQuotaSize:  123,
		},
		VirtualPath: "/vdir",
		QuotaSize:   0,
		QuotaFiles:  0,
	})
	user2, _, err = httpdtest.UpdateUser(user2, http.StatusOK, "")
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 1)
	assert.Contains(t, folder.Users, user2.Username)
	assert.Equal(t, 0, folder.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder.UsedQuotaSize)
	folder, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 1)
	assert.Contains(t, folder.Users, user1.Username)
	// add mappedPath1 again to user2
	user2.VirtualFolders = append(user2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1",
	})
	user2, _, err = httpdtest.UpdateUser(user2, http.StatusOK, "")
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 1)
	assert.Contains(t, folder.Users, user2.Username)
	// removing virtual folders should clear relations on both side
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	user2, _, err = httpdtest.GetUserByUsername(user2.Username, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, user2.VirtualFolders, 1) {
		folder := user2.VirtualFolders[0]
		assert.Equal(t, mappedPath1, folder.MappedPath)
		assert.Equal(t, folderName1, folder.Name)
	}
	user1, _, err = httpdtest.GetUserByUsername(user1.Username, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, user2.VirtualFolders, 1) {
		folder := user2.VirtualFolders[0]
		assert.Equal(t, mappedPath1, folder.MappedPath)
	}

	folder, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 2)
	// removing a user should clear virtual folder mapping
	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 1)
	assert.Contains(t, folder.Users, user2.Username)
	// removing a folder should clear mapping on the user side too
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	user2, _, err = httpdtest.GetUserByUsername(user2.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user2.VirtualFolders, 0)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserS3Config(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test"      //nolint:goconst
	user.FsConfig.S3Config.Region = "us-east-1" //nolint:goconst
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key"
	user.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("Server-Access-Secret")
	user.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000"
	user.FsConfig.S3Config.UploadPartSize = 8
	user, body, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(body))
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, user.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetKey())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	secret := kms.NewSecret(kms.SecretStatusSecretBox, "Server-Access-Secret", "", "")
	user.FsConfig.S3Config.AccessSecret = secret
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.S3Config.AccessSecret.SetStatus(kms.SecretStatusPlain)
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	initialSecretPayload := user.FsConfig.S3Config.AccessSecret.GetPayload()
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, initialSecretPayload)
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetKey())
	user.FsConfig.Provider = dataprovider.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test-bucket"
	user.FsConfig.S3Config.Region = "us-east-1" //nolint:goconst
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key1"
	user.FsConfig.S3Config.Endpoint = "http://localhost:9000"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir" //nolint:goconst
	user.FsConfig.S3Config.UploadConcurrency = 5
	user, bb, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.Equal(t, initialSecretPayload, user.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetKey())
	// test user without access key and access secret (shared config state)
	user.FsConfig.Provider = dataprovider.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "testbucket"
	user.FsConfig.S3Config.Region = "us-east-1"
	user.FsConfig.S3Config.AccessKey = ""
	user.FsConfig.S3Config.AccessSecret = kms.NewEmptySecret()
	user.FsConfig.S3Config.Endpoint = ""
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir"
	user.FsConfig.S3Config.UploadPartSize = 6
	user.FsConfig.S3Config.UploadConcurrency = 4
	user, body, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(body))
	assert.True(t, user.FsConfig.S3Config.AccessSecret.IsEmpty())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	// shared credential test for add instead of update
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	assert.True(t, user.FsConfig.S3Config.AccessSecret.IsEmpty())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserGCSConfig(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = os.MkdirAll(credentialsPath, 0700)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	user.FsConfig.GCSConfig.Bucket = "test"
	user.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("fake credentials") //nolint:goconst
	user, bb, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	credentialFile := filepath.Join(credentialsPath, fmt.Sprintf("%v_gcs_credentials.json", user.Username))
	assert.FileExists(t, credentialFile)
	creds, err := os.ReadFile(credentialFile)
	assert.NoError(t, err)
	secret := kms.NewEmptySecret()
	err = json.Unmarshal(creds, secret)
	assert.NoError(t, err)
	err = secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, "fake credentials", secret.GetPayload())
	user.FsConfig.GCSConfig.Credentials = kms.NewSecret(kms.SecretStatusSecretBox, "fake encrypted credentials", "", "")
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.FileExists(t, credentialFile)
	creds, err = os.ReadFile(credentialFile)
	assert.NoError(t, err)
	secret = kms.NewEmptySecret()
	err = json.Unmarshal(creds, secret)
	assert.NoError(t, err)
	err = secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, "fake credentials", secret.GetPayload())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	user.FsConfig.GCSConfig.Credentials = kms.NewSecret(kms.SecretStatusSecretBox, "fake credentials", "", "")
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.GCSConfig.Credentials.SetStatus(kms.SecretStatusPlain)
	user, body, err := httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err, string(body))
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = os.MkdirAll(credentialsPath, 0700)
	assert.NoError(t, err)
	user.FsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
	user.FsConfig.GCSConfig.AutomaticCredentials = 1
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.NoFileExists(t, credentialFile)
	user.FsConfig.GCSConfig = vfs.GCSFsConfig{}
	user.FsConfig.Provider = dataprovider.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test1"
	user.FsConfig.S3Config.Region = "us-east-1"
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key1"
	user.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("secret")
	user.FsConfig.S3Config.Endpoint = "http://localhost:9000"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir"
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	user.FsConfig.S3Config = vfs.S3FsConfig{}
	user.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	user.FsConfig.GCSConfig.Bucket = "test1"
	user.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("fake credentials")
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserAzureBlobConfig(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.Container = "test"
	user.FsConfig.AzBlobConfig.AccountName = "Server-Account-Name"
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("Server-Account-Key")
	user.FsConfig.AzBlobConfig.Endpoint = "http://127.0.0.1:9000"
	user.FsConfig.AzBlobConfig.UploadPartSize = 8
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	initialPayload := user.FsConfig.AzBlobConfig.AccountKey.GetPayload()
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetKey())
	user.FsConfig.AzBlobConfig.AccountKey.SetStatus(kms.SecretStatusSecretBox)
	user.FsConfig.AzBlobConfig.AccountKey.SetAdditionalData("data")
	user.FsConfig.AzBlobConfig.AccountKey.SetKey("fake key")
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.Equal(t, initialPayload, user.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetKey())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	secret := kms.NewSecret(kms.SecretStatusSecretBox, "Server-Account-Key", "", "")
	user.FsConfig.AzBlobConfig.AccountKey = secret
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("Server-Account-Key-Test")
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	initialPayload = user.FsConfig.AzBlobConfig.AccountKey.GetPayload()
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetKey())
	user.FsConfig.Provider = dataprovider.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.Container = "test-container"
	user.FsConfig.AzBlobConfig.Endpoint = "http://localhost:9001"
	user.FsConfig.AzBlobConfig.KeyPrefix = "somedir/subdir"
	user.FsConfig.AzBlobConfig.UploadConcurrency = 5
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Equal(t, initialPayload, user.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetKey())
	// test user without access key and access secret (sas)
	user.FsConfig.Provider = dataprovider.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.SASURL = "https://myaccount.blob.core.windows.net/pictures/profile.jpg?sv=2012-02-12&st=2009-02-09&se=2009-02-10&sr=c&sp=r&si=YWJjZGVmZw%3d%3d&sig=dD80ihBh5jfNpymO5Hg1IdiJIEvHcJpCMiCMnN%2fRnbI%3d"
	user.FsConfig.AzBlobConfig.KeyPrefix = "somedir/subdir"
	user.FsConfig.AzBlobConfig.AccountName = ""
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewEmptySecret()
	user.FsConfig.AzBlobConfig.UploadPartSize = 6
	user.FsConfig.AzBlobConfig.UploadConcurrency = 4
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.True(t, user.FsConfig.AzBlobConfig.AccountKey.IsEmpty())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	// sas test for add instead of update
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	assert.True(t, user.FsConfig.AzBlobConfig.AccountKey.IsEmpty())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserCryptFs(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("crypt passphrase")
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	initialPayload := user.FsConfig.CryptConfig.Passphrase.GetPayload()
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetKey())
	user.FsConfig.CryptConfig.Passphrase.SetStatus(kms.SecretStatusSecretBox)
	user.FsConfig.CryptConfig.Passphrase.SetAdditionalData("data")
	user.FsConfig.CryptConfig.Passphrase.SetKey("fake pass key")
	user, bb, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.Equal(t, initialPayload, user.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetKey())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	secret := kms.NewSecret(kms.SecretStatusSecretBox, "invalid encrypted payload", "", "")
	user.FsConfig.CryptConfig.Passphrase = secret
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("passphrase test")
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	initialPayload = user.FsConfig.CryptConfig.Passphrase.GetPayload()
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetKey())
	user.FsConfig.Provider = dataprovider.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase.SetKey("pass")
	user, bb, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Equal(t, initialPayload, user.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetKey())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserSFTPFs(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.SFTPFilesystemProvider
	user.FsConfig.SFTPConfig.Endpoint = "127.0.0.1" // missing port
	user.FsConfig.SFTPConfig.Username = "sftp_user"
	user.FsConfig.SFTPConfig.Password = kms.NewPlainSecret("sftp_pwd")
	user.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret(sftpPrivateKey)
	user.FsConfig.SFTPConfig.Fingerprints = []string{sftpPkeyFingerprint}
	_, resp, err := httpdtest.UpdateUser(user, http.StatusBadRequest, "")
	assert.NoError(t, err)
	assert.Contains(t, string(resp), "invalid endpoint")

	user.FsConfig.SFTPConfig.Endpoint = "127.0.0.1:2022"
	user.FsConfig.SFTPConfig.DisableCouncurrentReads = true
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, "/", user.FsConfig.SFTPConfig.Prefix)
	assert.True(t, user.FsConfig.SFTPConfig.DisableCouncurrentReads)
	initialPwdPayload := user.FsConfig.SFTPConfig.Password.GetPayload()
	initialPkeyPayload := user.FsConfig.SFTPConfig.PrivateKey.GetPayload()
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.Password.GetStatus())
	assert.NotEmpty(t, initialPwdPayload)
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetKey())
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, initialPkeyPayload)
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetKey())
	user.FsConfig.SFTPConfig.Password.SetStatus(kms.SecretStatusSecretBox)
	user.FsConfig.SFTPConfig.Password.SetAdditionalData("adata")
	user.FsConfig.SFTPConfig.Password.SetKey("fake pwd key")
	user.FsConfig.SFTPConfig.PrivateKey.SetStatus(kms.SecretStatusSecretBox)
	user.FsConfig.SFTPConfig.PrivateKey.SetAdditionalData("adata")
	user.FsConfig.SFTPConfig.PrivateKey.SetKey("fake key")
	user.FsConfig.SFTPConfig.DisableCouncurrentReads = false
	user, bb, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.Password.GetStatus())
	assert.Equal(t, initialPwdPayload, user.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetKey())
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.Equal(t, initialPkeyPayload, user.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.False(t, user.FsConfig.SFTPConfig.DisableCouncurrentReads)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	secret := kms.NewSecret(kms.SecretStatusSecretBox, "invalid encrypted payload", "", "")
	user.FsConfig.SFTPConfig.Password = secret
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.SFTPConfig.Password = kms.NewEmptySecret()
	user.FsConfig.SFTPConfig.PrivateKey = secret
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)

	user.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret(sftpPrivateKey)
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	initialPkeyPayload = user.FsConfig.SFTPConfig.PrivateKey.GetPayload()
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetStatus())
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, initialPkeyPayload)
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetKey())
	user.FsConfig.Provider = dataprovider.SFTPFilesystemProvider
	user.FsConfig.SFTPConfig.PrivateKey.SetKey("k")
	user, bb, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, initialPkeyPayload)
	assert.Equal(t, initialPkeyPayload, user.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetKey())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserHiddenFields(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = true
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	// sensitive data must be hidden but not deleted from the dataprovider
	usernames := []string{"user1", "user2", "user3", "user4", "user5"}
	u1 := getTestUser()
	u1.Username = usernames[0]
	u1.FsConfig.Provider = dataprovider.S3FilesystemProvider
	u1.FsConfig.S3Config.Bucket = "test"
	u1.FsConfig.S3Config.Region = "us-east-1"
	u1.FsConfig.S3Config.AccessKey = "S3-Access-Key"
	u1.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("S3-Access-Secret")
	user1, _, err := httpdtest.AddUser(u1, http.StatusCreated)
	assert.NoError(t, err)

	u2 := getTestUser()
	u2.Username = usernames[1]
	u2.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	u2.FsConfig.GCSConfig.Bucket = "test"
	u2.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("fake credentials")
	user2, _, err := httpdtest.AddUser(u2, http.StatusCreated)
	assert.NoError(t, err)

	u3 := getTestUser()
	u3.Username = usernames[2]
	u3.FsConfig.Provider = dataprovider.AzureBlobFilesystemProvider
	u3.FsConfig.AzBlobConfig.Container = "test"
	u3.FsConfig.AzBlobConfig.AccountName = "Server-Account-Name"
	u3.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("Server-Account-Key")
	user3, _, err := httpdtest.AddUser(u3, http.StatusCreated)
	assert.NoError(t, err)

	u4 := getTestUser()
	u4.Username = usernames[3]
	u4.FsConfig.Provider = dataprovider.CryptedFilesystemProvider
	u4.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("test passphrase")
	user4, _, err := httpdtest.AddUser(u4, http.StatusCreated)
	assert.NoError(t, err)

	u5 := getTestUser()
	u5.Username = usernames[4]
	u5.FsConfig.Provider = dataprovider.SFTPFilesystemProvider
	u5.FsConfig.SFTPConfig.Endpoint = "127.0.0.1:2022"
	u5.FsConfig.SFTPConfig.Username = "sftp_user"
	u5.FsConfig.SFTPConfig.Password = kms.NewPlainSecret("apassword")
	u5.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret(sftpPrivateKey)
	u5.FsConfig.SFTPConfig.Fingerprints = []string{sftpPkeyFingerprint}
	u5.FsConfig.SFTPConfig.Prefix = "/prefix"
	user5, _, err := httpdtest.AddUser(u5, http.StatusCreated)
	assert.NoError(t, err)

	users, _, err := httpdtest.GetUsers(0, 0, http.StatusOK)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(users), 5)
	for _, username := range usernames {
		user, _, err := httpdtest.GetUserByUsername(username, http.StatusOK)
		assert.NoError(t, err)
		assert.Empty(t, user.Password)
	}
	user1, _, err = httpdtest.GetUserByUsername(user1.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Empty(t, user1.Password)
	assert.Empty(t, user1.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, user1.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.NotEmpty(t, user1.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, user1.FsConfig.S3Config.AccessSecret.GetPayload())

	user2, _, err = httpdtest.GetUserByUsername(user2.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Empty(t, user2.Password)
	assert.Empty(t, user2.FsConfig.GCSConfig.Credentials.GetKey())
	assert.Empty(t, user2.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.NotEmpty(t, user2.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user2.FsConfig.GCSConfig.Credentials.GetPayload())

	user3, _, err = httpdtest.GetUserByUsername(user3.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Empty(t, user3.Password)
	assert.Empty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetKey())
	assert.Empty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.NotEmpty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetPayload())

	user4, _, err = httpdtest.GetUserByUsername(user4.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Empty(t, user4.Password)
	assert.Empty(t, user4.FsConfig.CryptConfig.Passphrase.GetKey())
	assert.Empty(t, user4.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.NotEmpty(t, user4.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, user4.FsConfig.CryptConfig.Passphrase.GetPayload())

	user5, _, err = httpdtest.GetUserByUsername(user5.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Empty(t, user5.Password)
	assert.Empty(t, user5.FsConfig.SFTPConfig.Password.GetKey())
	assert.Empty(t, user5.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.Password.GetStatus())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.Empty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Equal(t, "/prefix", user5.FsConfig.SFTPConfig.Prefix)

	// finally check that we have all the data inside the data provider
	user1, err = dataprovider.UserExists(user1.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, user1.Password)
	assert.NotEmpty(t, user1.FsConfig.S3Config.AccessSecret.GetKey())
	assert.NotEmpty(t, user1.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.NotEmpty(t, user1.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, user1.FsConfig.S3Config.AccessSecret.GetPayload())
	err = user1.FsConfig.S3Config.AccessSecret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusPlain, user1.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.Equal(t, u1.FsConfig.S3Config.AccessSecret.GetPayload(), user1.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, user1.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, user1.FsConfig.S3Config.AccessSecret.GetAdditionalData())

	user2, err = dataprovider.UserExists(user2.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, user2.Password)
	assert.NotEmpty(t, user2.FsConfig.GCSConfig.Credentials.GetKey())
	assert.NotEmpty(t, user2.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.NotEmpty(t, user2.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user2.FsConfig.GCSConfig.Credentials.GetPayload())
	err = user2.FsConfig.GCSConfig.Credentials.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusPlain, user2.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.Equal(t, u2.FsConfig.GCSConfig.Credentials.GetPayload(), user2.FsConfig.GCSConfig.Credentials.GetPayload())
	assert.Empty(t, user2.FsConfig.GCSConfig.Credentials.GetKey())
	assert.Empty(t, user2.FsConfig.GCSConfig.Credentials.GetAdditionalData())

	user3, err = dataprovider.UserExists(user3.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, user3.Password)
	assert.NotEmpty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetKey())
	assert.NotEmpty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.NotEmpty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	err = user3.FsConfig.AzBlobConfig.AccountKey.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusPlain, user3.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.Equal(t, u3.FsConfig.AzBlobConfig.AccountKey.GetPayload(), user3.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	assert.Empty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetKey())
	assert.Empty(t, user3.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())

	user4, err = dataprovider.UserExists(user4.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, user4.Password)
	assert.NotEmpty(t, user4.FsConfig.CryptConfig.Passphrase.GetKey())
	assert.NotEmpty(t, user4.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.NotEmpty(t, user4.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, user4.FsConfig.CryptConfig.Passphrase.GetPayload())
	err = user4.FsConfig.CryptConfig.Passphrase.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusPlain, user4.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.Equal(t, u4.FsConfig.CryptConfig.Passphrase.GetPayload(), user4.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, user4.FsConfig.CryptConfig.Passphrase.GetKey())
	assert.Empty(t, user4.FsConfig.CryptConfig.Passphrase.GetAdditionalData())

	user5, err = dataprovider.UserExists(user5.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, user5.Password)
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.Password.GetKey())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.Password.GetStatus())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.Password.GetPayload())
	err = user5.FsConfig.SFTPConfig.Password.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusPlain, user5.FsConfig.SFTPConfig.Password.GetStatus())
	assert.Equal(t, u5.FsConfig.SFTPConfig.Password.GetPayload(), user5.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, user5.FsConfig.SFTPConfig.Password.GetKey())
	assert.Empty(t, user5.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	err = user5.FsConfig.SFTPConfig.PrivateKey.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusPlain, user5.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.Equal(t, u5.FsConfig.SFTPConfig.PrivateKey.GetPayload(), user5.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Empty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.Empty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())

	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user3, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user4, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user5, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestSecretObject(t *testing.T) {
	s := kms.NewPlainSecret("test data")
	s.SetAdditionalData("username")
	require.True(t, s.IsValid())
	err := s.Encrypt()
	require.NoError(t, err)
	require.Equal(t, kms.SecretStatusSecretBox, s.GetStatus())
	require.NotEmpty(t, s.GetPayload())
	require.NotEmpty(t, s.GetKey())
	require.True(t, s.IsValid())
	err = s.Decrypt()
	require.NoError(t, err)
	require.Equal(t, kms.SecretStatusPlain, s.GetStatus())
	require.Equal(t, "test data", s.GetPayload())
	require.Empty(t, s.GetKey())

	oldFormat := "$aes$5b97e3a3324a2f53e2357483383367c0$0ed3132b584742ab217866219da633266782b69b13e50ebc6ddfb7c4fbf2f2a414c6d5f813"
	s, err = kms.GetSecretFromCompatString(oldFormat)
	require.NoError(t, err)
	require.True(t, s.IsValid())
	require.Equal(t, kms.SecretStatusPlain, s.GetStatus())
	require.Equal(t, "test data", s.GetPayload())
	require.Empty(t, s.GetKey())
}

func TestSecretObjectCompatibility(t *testing.T) {
	// this is manually tested against vault too
	testPayload := "test payload"
	s := kms.NewPlainSecret(testPayload)
	require.True(t, s.IsValid())
	err := s.Encrypt()
	require.NoError(t, err)
	localAsJSON, err := json.Marshal(s)
	assert.NoError(t, err)

	for _, secretStatus := range []string{kms.SecretStatusSecretBox} {
		kmsConfig := config.GetKMSConfig()
		assert.Empty(t, kmsConfig.Secrets.MasterKeyPath)
		if secretStatus == kms.SecretStatusVaultTransit {
			os.Setenv("VAULT_SERVER_URL", "http://127.0.0.1:8200")
			os.Setenv("VAULT_SERVER_TOKEN", "s.9lYGq83MbgG5KR5kfebXVyhJ")
			kmsConfig.Secrets.URL = "hashivault://mykey"
		}
		err := kmsConfig.Initialize()
		assert.NoError(t, err)
		// encrypt without a master key
		secret := kms.NewPlainSecret(testPayload)
		secret.SetAdditionalData("add data")
		err = secret.Encrypt()
		assert.NoError(t, err)
		assert.Equal(t, 0, secret.GetMode())
		secretClone := secret.Clone()
		err = secretClone.Decrypt()
		assert.NoError(t, err)
		assert.Equal(t, testPayload, secretClone.GetPayload())
		if secretStatus == kms.SecretStatusVaultTransit {
			// decrypt the local secret now that the provider is vault
			secretLocal := kms.NewEmptySecret()
			err = json.Unmarshal(localAsJSON, secretLocal)
			assert.NoError(t, err)
			assert.Equal(t, kms.SecretStatusSecretBox, secretLocal.GetStatus())
			assert.Equal(t, 0, secretLocal.GetMode())
			err = secretLocal.Decrypt()
			assert.NoError(t, err)
			assert.Equal(t, testPayload, secretLocal.GetPayload())
			assert.Equal(t, kms.SecretStatusPlain, secretLocal.GetStatus())
			err = secretLocal.Encrypt()
			assert.NoError(t, err)
			assert.Equal(t, kms.SecretStatusSecretBox, secretLocal.GetStatus())
			assert.Equal(t, 0, secretLocal.GetMode())
		}

		asJSON, err := json.Marshal(secret)
		assert.NoError(t, err)

		masterKeyPath := filepath.Join(os.TempDir(), "mkey")
		err = os.WriteFile(masterKeyPath, []byte("test key"), os.ModePerm)
		assert.NoError(t, err)
		config := kms.Configuration{
			Secrets: kms.Secrets{
				MasterKeyPath: masterKeyPath,
			},
		}
		if secretStatus == kms.SecretStatusVaultTransit {
			config.Secrets.URL = "hashivault://mykey"
		}
		err = config.Initialize()
		assert.NoError(t, err)

		// now build the secret from JSON
		secret = kms.NewEmptySecret()
		err = json.Unmarshal(asJSON, secret)
		assert.NoError(t, err)
		assert.Equal(t, 0, secret.GetMode())
		err = secret.Decrypt()
		assert.NoError(t, err)
		assert.Equal(t, testPayload, secret.GetPayload())
		err = secret.Encrypt()
		assert.NoError(t, err)
		assert.Equal(t, 1, secret.GetMode())
		err = secret.Decrypt()
		assert.NoError(t, err)
		assert.Equal(t, testPayload, secret.GetPayload())
		if secretStatus == kms.SecretStatusVaultTransit {
			// decrypt the local secret encryped without a master key now that
			// the provider is vault and a master key is set.
			// The provider will not change, the master key will be used
			secretLocal := kms.NewEmptySecret()
			err = json.Unmarshal(localAsJSON, secretLocal)
			assert.NoError(t, err)
			assert.Equal(t, kms.SecretStatusSecretBox, secretLocal.GetStatus())
			assert.Equal(t, 0, secretLocal.GetMode())
			err = secretLocal.Decrypt()
			assert.NoError(t, err)
			assert.Equal(t, testPayload, secretLocal.GetPayload())
			assert.Equal(t, kms.SecretStatusPlain, secretLocal.GetStatus())
			err = secretLocal.Encrypt()
			assert.NoError(t, err)
			assert.Equal(t, kms.SecretStatusSecretBox, secretLocal.GetStatus())
			assert.Equal(t, 1, secretLocal.GetMode())
		}

		err = kmsConfig.Initialize()
		assert.NoError(t, err)
		err = os.Remove(masterKeyPath)
		assert.NoError(t, err)
		if secretStatus == kms.SecretStatusVaultTransit {
			os.Unsetenv("VAULT_SERVER_URL")
			os.Unsetenv("VAULT_SERVER_TOKEN")
		}
	}
}

func TestUpdateUserNoCredentials(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.Password = ""
	user.PublicKeys = []string{}
	// password and public key will be omitted from json serialization if empty and so they will remain unchanged
	// and no validation error will be raised
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUserEmptyHomeDir(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.HomeDir = ""
	_, _, err = httpdtest.UpdateUser(user, http.StatusBadRequest, "")
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUserInvalidHomeDir(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.HomeDir = "relative_path"
	_, _, err = httpdtest.UpdateUser(user, http.StatusBadRequest, "")
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateNonExistentUser(t *testing.T) {
	_, _, err := httpdtest.UpdateUser(getTestUser(), http.StatusNotFound, "")
	assert.NoError(t, err)
}

func TestGetNonExistentUser(t *testing.T) {
	_, _, err := httpdtest.GetUserByUsername("na", http.StatusNotFound)
	assert.NoError(t, err)
}

func TestDeleteNonExistentUser(t *testing.T) {
	_, err := httpdtest.RemoveUser(getTestUser(), http.StatusNotFound)
	assert.NoError(t, err)
}

func TestAddDuplicateUser(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	_, _, err = httpdtest.AddUser(getTestUser(), http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.Error(t, err, "adding a duplicate user must fail")
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestGetUsers(t *testing.T) {
	user1, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	u := getTestUser()
	u.Username = defaultUsername + "1"
	user2, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	users, _, err := httpdtest.GetUsers(0, 0, http.StatusOK)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(users), 2)
	users, _, err = httpdtest.GetUsers(1, 0, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	users, _, err = httpdtest.GetUsers(1, 1, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	_, _, err = httpdtest.GetUsers(1, 1, http.StatusInternalServerError)
	assert.Error(t, err)
	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
}

func TestGetQuotaScans(t *testing.T) {
	_, _, err := httpdtest.GetQuotaScans(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetQuotaScans(http.StatusInternalServerError)
	assert.Error(t, err)
	_, _, err = httpdtest.GetFoldersQuotaScans(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetFoldersQuotaScans(http.StatusInternalServerError)
	assert.Error(t, err)
}

func TestStartQuotaScan(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpdtest.StartQuotaScan(user, http.StatusAccepted)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	folder := vfs.BaseVirtualFolder{
		Name:        "vfolder",
		MappedPath:  filepath.Join(os.TempDir(), "folder"),
		Description: "virtual folder",
	}
	_, _, err = httpdtest.AddFolder(folder, http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpdtest.StartFolderQuotaScan(folder, http.StatusAccepted)
	assert.NoError(t, err)
	for {
		quotaScan, _, err := httpdtest.GetFoldersQuotaScans(http.StatusOK)
		if !assert.NoError(t, err, "Error getting active scans") {
			break
		}
		if len(quotaScan) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
}

func TestEmbeddedFolders(t *testing.T) {
	u := getTestUser()
	mappedPath := filepath.Join(os.TempDir(), "mapped_path")
	name := filepath.Base(mappedPath)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:            name,
			UsedQuotaFiles:  1000,
			UsedQuotaSize:   8192,
			LastQuotaUpdate: 123,
		},
		VirtualPath: "/vdir",
		QuotaSize:   4096,
		QuotaFiles:  1,
	})
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders[0].MappedPath = mappedPath
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	// check that the folder was created
	folder, _, err := httpdtest.GetFolderByName(name, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath, folder.MappedPath)
	assert.Equal(t, 0, folder.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder.UsedQuotaSize)
	assert.Equal(t, int64(0), folder.LastQuotaUpdate)
	if assert.Len(t, user.VirtualFolders, 1) {
		assert.Equal(t, mappedPath, user.VirtualFolders[0].MappedPath)
		assert.Equal(t, u.VirtualFolders[0].VirtualPath, user.VirtualFolders[0].VirtualPath)
		assert.Equal(t, u.VirtualFolders[0].QuotaFiles, user.VirtualFolders[0].QuotaFiles)
		assert.Equal(t, u.VirtualFolders[0].QuotaSize, user.VirtualFolders[0].QuotaSize)
	}
	// if the folder already exists we can just reference it by name while adding/updating a user
	u.Username = u.Username + "1"
	u.VirtualFolders[0].MappedPath = ""
	user1, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.EqualError(t, err, "Virtual folders mismatch")
	if assert.Len(t, user1.VirtualFolders, 1) {
		assert.Equal(t, mappedPath, user1.VirtualFolders[0].MappedPath)
		assert.Equal(t, u.VirtualFolders[0].VirtualPath, user1.VirtualFolders[0].VirtualPath)
		assert.Equal(t, u.VirtualFolders[0].QuotaFiles, user1.VirtualFolders[0].QuotaFiles)
		assert.Equal(t, u.VirtualFolders[0].QuotaSize, user1.VirtualFolders[0].QuotaSize)
	}
	user1.VirtualFolders = u.VirtualFolders
	user1, _, err = httpdtest.UpdateUser(user1, http.StatusOK, "")
	assert.EqualError(t, err, "Virtual folders mismatch")
	if assert.Len(t, user1.VirtualFolders, 1) {
		assert.Equal(t, mappedPath, user1.VirtualFolders[0].MappedPath)
		assert.Equal(t, u.VirtualFolders[0].VirtualPath, user1.VirtualFolders[0].VirtualPath)
		assert.Equal(t, u.VirtualFolders[0].QuotaFiles, user1.VirtualFolders[0].QuotaFiles)
		assert.Equal(t, u.VirtualFolders[0].QuotaSize, user1.VirtualFolders[0].QuotaSize)
	}
	// now the virtual folder contains all the required paths
	user1, _, err = httpdtest.UpdateUser(user1, http.StatusOK, "")
	assert.NoError(t, err)
	if assert.Len(t, user1.VirtualFolders, 1) {
		assert.Equal(t, mappedPath, user1.VirtualFolders[0].MappedPath)
		assert.Equal(t, u.VirtualFolders[0].VirtualPath, user1.VirtualFolders[0].VirtualPath)
		assert.Equal(t, u.VirtualFolders[0].QuotaFiles, user1.VirtualFolders[0].QuotaFiles)
		assert.Equal(t, u.VirtualFolders[0].QuotaSize, user1.VirtualFolders[0].QuotaSize)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: name}, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateFolderQuotaUsage(t *testing.T) {
	f := vfs.BaseVirtualFolder{
		Name:       "vdir",
		MappedPath: filepath.Join(os.TempDir(), "folder"),
	}
	usedQuotaFiles := 1
	usedQuotaSize := int64(65535)
	f.UsedQuotaFiles = usedQuotaFiles
	f.UsedQuotaSize = usedQuotaSize
	folder, _, err := httpdtest.AddFolder(f, http.StatusCreated)
	if assert.NoError(t, err) {
		assert.Equal(t, usedQuotaFiles, folder.UsedQuotaFiles)
		assert.Equal(t, usedQuotaSize, folder.UsedQuotaSize)
	}
	_, err = httpdtest.UpdateFolderQuotaUsage(folder, "invalid mode", http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpdtest.UpdateFolderQuotaUsage(f, "reset", http.StatusOK)
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(f.Name, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, folder.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize, folder.UsedQuotaSize)
	_, err = httpdtest.UpdateFolderQuotaUsage(f, "add", http.StatusOK)
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(f.Name, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 2*usedQuotaFiles, folder.UsedQuotaFiles)
	assert.Equal(t, 2*usedQuotaSize, folder.UsedQuotaSize)
	f.UsedQuotaSize = -1
	_, err = httpdtest.UpdateFolderQuotaUsage(f, "", http.StatusBadRequest)
	assert.NoError(t, err)
	f.UsedQuotaSize = usedQuotaSize
	f.Name = f.Name + "1"
	_, err = httpdtest.UpdateFolderQuotaUsage(f, "", http.StatusNotFound)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
}

func TestGetVersion(t *testing.T) {
	_, _, err := httpdtest.GetVersion(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetVersion(http.StatusInternalServerError)
	assert.Error(t, err, "get version request must succeed, we requested to check a wrong status code")
}

func TestGetStatus(t *testing.T) {
	_, _, err := httpdtest.GetStatus(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetStatus(http.StatusBadRequest)
	assert.Error(t, err, "get provider status request must succeed, we requested to check a wrong status code")
}

func TestGetConnections(t *testing.T) {
	_, _, err := httpdtest.GetConnections(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetConnections(http.StatusInternalServerError)
	assert.Error(t, err, "get sftp connections request must succeed, we requested to check a wrong status code")
}

func TestCloseActiveConnection(t *testing.T) {
	_, err := httpdtest.CloseConnection("non_existent_id", http.StatusNotFound)
	assert.NoError(t, err)
	user := getTestUser()
	c := common.NewBaseConnection("connID", common.ProtocolSFTP, user, nil)
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	common.Connections.Add(fakeConn)
	_, err = httpdtest.CloseConnection(c.GetID(), http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 0)
}

func TestCloseConnectionAfterUserUpdateDelete(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	c := common.NewBaseConnection("connID", common.ProtocolFTP, user, nil)
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	common.Connections.Add(fakeConn)
	c1 := common.NewBaseConnection("connID1", common.ProtocolSFTP, user, nil)
	fakeConn1 := &fakeConnection{
		BaseConnection: c1,
	}
	common.Connections.Add(fakeConn1)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "0")
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 2)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "1")
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 0)

	common.Connections.Add(fakeConn)
	common.Connections.Add(fakeConn1)
	assert.Len(t, common.Connections.GetStats(), 2)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 0)
}

func TestSkipNaturalKeysValidation(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.SkipNaturalKeysValidation = true
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	u := getTestUser()
	u.Username = "user@example.com"
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user.AdditionalInfo = "info"
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	a := getTestAdmin()
	a.Username = "admin@example.com"
	admin, _, err := httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)
	admin.Email = admin.Username
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	f := vfs.BaseVirtualFolder{
		Name:       "文件夹",
		MappedPath: filepath.Clean(os.TempDir()),
	}
	folder, resp, err := httpdtest.AddFolder(f, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	folder.Description = folder.Name
	folder, resp, err = httpdtest.UpdateFolder(folder, http.StatusOK)
	assert.NoError(t, err, string(resp))
	folder, resp, err = httpdtest.GetFolderByName(folder.Name, http.StatusOK)
	assert.NoError(t, err, string(resp))
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestUserBaseDir(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.UsersBaseDir = homeBasePath
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	u := getTestUser()
	u.HomeDir = ""
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	if assert.Error(t, err) {
		assert.EqualError(t, err, "HomeDir mismatch")
	}
	assert.Equal(t, filepath.Join(providerConf.UsersBaseDir, u.Username), user.HomeDir)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestQuotaTrackingDisabled(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.TrackQuota = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	// user quota scan must fail
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpdtest.StartQuotaScan(user, http.StatusForbidden)
	assert.NoError(t, err)
	_, err = httpdtest.UpdateQuotaUsage(user, "", http.StatusForbidden)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	// folder quota scan must fail
	folder := vfs.BaseVirtualFolder{
		Name:       "folder_quota_test",
		MappedPath: filepath.Clean(os.TempDir()),
	}
	folder, resp, err := httpdtest.AddFolder(folder, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	_, err = httpdtest.StartFolderQuotaScan(folder, http.StatusForbidden)
	assert.NoError(t, err)
	_, err = httpdtest.UpdateFolderQuotaUsage(folder, "", http.StatusForbidden)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestProviderErrors(t *testing.T) {
	token, _, err := httpdtest.GetToken(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	testServerToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	httpdtest.SetJWTToken(token)
	err = dataprovider.Close()
	assert.NoError(t, err)
	_, _, err = httpdtest.GetUserByUsername("na", http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetUsers(1, 0, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetAdmins(1, 0, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpdtest.UpdateUser(dataprovider.User{Username: "auser"}, http.StatusInternalServerError, "")
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(dataprovider.User{Username: "auser"}, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: "aname"}, http.StatusInternalServerError)
	assert.NoError(t, err)
	status, _, err := httpdtest.GetStatus(http.StatusOK)
	if assert.NoError(t, err) {
		assert.False(t, status.DataProvider.IsActive)
	}
	_, _, err = httpdtest.Dumpdata("backup.json", "", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetFolders(0, 0, http.StatusInternalServerError)
	assert.NoError(t, err)
	user := getTestUser()
	user.ID = 1
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupContent, err := json.Marshal(backupData)
	assert.NoError(t, err)
	backupFilePath := filepath.Join(backupsPath, "backup.json")
	err = os.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	backupData.Folders = append(backupData.Folders, vfs.BaseVirtualFolder{Name: "testFolder", MappedPath: filepath.Clean(os.TempDir())})
	backupContent, err = json.Marshal(backupData)
	assert.NoError(t, err)
	err = os.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	backupData.Users = nil
	backupData.Folders = nil
	backupData.Admins = append(backupData.Admins, getTestAdmin())
	backupContent, err = json.Marshal(backupData)
	assert.NoError(t, err)
	err = os.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, webUserPath+"?clone-from=user", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, testServerToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	req, err = http.NewRequest(http.MethodGet, webTemplateUser+"?from=auser", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, testServerToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	req, err = http.NewRequest(http.MethodGet, webTemplateFolder+"?from=afolder", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, testServerToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	httpdtest.SetJWTToken("")
}

func TestFolders(t *testing.T) {
	folder := vfs.BaseVirtualFolder{
		Name:       "name",
		MappedPath: "relative path",
		Users:      []string{"1", "2", "3"},
	}
	_, _, err := httpdtest.AddFolder(folder, http.StatusBadRequest)
	assert.NoError(t, err)
	folder.MappedPath = filepath.Clean(os.TempDir())
	folder1, resp, err := httpdtest.AddFolder(folder, http.StatusCreated)
	assert.EqualError(t, err, "folder users mismatch", string(resp))
	assert.Equal(t, folder.Name, folder1.Name)
	assert.Equal(t, folder.MappedPath, folder1.MappedPath)
	assert.Equal(t, 0, folder1.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder1.UsedQuotaSize)
	assert.Equal(t, int64(0), folder1.LastQuotaUpdate)
	assert.Len(t, folder1.Users, 0)
	// adding a duplicate folder must fail
	_, _, err = httpdtest.AddFolder(folder, http.StatusCreated)
	assert.Error(t, err)
	folder.MappedPath = filepath.Join(os.TempDir(), "vfolder")
	folder.Name = filepath.Base(folder.MappedPath)
	folder.UsedQuotaFiles = 1
	folder.UsedQuotaSize = 345
	folder.LastQuotaUpdate = 10
	folder2, _, err := httpdtest.AddFolder(folder, http.StatusCreated)
	assert.EqualError(t, err, "folder users mismatch", string(resp))
	assert.Equal(t, 1, folder2.UsedQuotaFiles)
	assert.Equal(t, int64(345), folder2.UsedQuotaSize)
	assert.Equal(t, int64(10), folder2.LastQuotaUpdate)
	assert.Len(t, folder2.Users, 0)
	folders, _, err := httpdtest.GetFolders(0, 0, http.StatusOK)
	assert.NoError(t, err)
	numResults := len(folders)
	assert.GreaterOrEqual(t, numResults, 2)
	folders, _, err = httpdtest.GetFolders(0, 1, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folders, numResults-1)
	folders, _, err = httpdtest.GetFolders(1, 0, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folders, 1)
	f, _, err := httpdtest.GetFolderByName(folder1.Name, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, folder1.Name, f.Name)
	assert.Equal(t, folder1.MappedPath, f.MappedPath)
	f, _, err = httpdtest.GetFolderByName(folder2.Name, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, folder2.Name, f.Name)
	assert.Equal(t, folder2.MappedPath, f.MappedPath)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{
		Name: "invalid",
	}, http.StatusNotFound)
	assert.NoError(t, err)
	_, _, err = httpdtest.UpdateFolder(vfs.BaseVirtualFolder{Name: "notfound"}, http.StatusNotFound)
	assert.NoError(t, err)
	folder1.MappedPath = "a/relative/path"
	_, _, err = httpdtest.UpdateFolder(folder1, http.StatusBadRequest)
	assert.NoError(t, err)
	folder1.MappedPath = filepath.Join(os.TempDir(), "updated")
	folder1.Description = "updated folder description"
	f, _, err = httpdtest.UpdateFolder(folder1, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, folder1.MappedPath, f.MappedPath)
	assert.Equal(t, folder1.Description, f.Description)

	_, err = httpdtest.RemoveFolder(folder1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(folder2, http.StatusOK)
	assert.NoError(t, err)
}

func TestDumpdata(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	_, _, err = httpdtest.Dumpdata("", "", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.Dumpdata(filepath.Join(backupsPath, "backup.json"), "", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.Dumpdata("../backup.json", "", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.Dumpdata("backup.json", "", "0", http.StatusOK)
	assert.NoError(t, err)
	response, _, err := httpdtest.Dumpdata("", "1", "0", http.StatusOK)
	assert.NoError(t, err)
	_, ok := response["admins"]
	assert.True(t, ok)
	_, ok = response["users"]
	assert.True(t, ok)
	_, ok = response["folders"]
	assert.True(t, ok)
	_, ok = response["version"]
	assert.True(t, ok)
	_, _, err = httpdtest.Dumpdata("backup.json", "", "1", http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(filepath.Join(backupsPath, "backup.json"))
	assert.NoError(t, err)
	if runtime.GOOS != "windows" {
		err = os.Chmod(backupsPath, 0001)
		assert.NoError(t, err)
		_, _, err = httpdtest.Dumpdata("bck.json", "", "", http.StatusInternalServerError)
		assert.NoError(t, err)
		// subdir cannot be created
		_, _, err = httpdtest.Dumpdata(filepath.Join("subdir", "bck.json"), "", "", http.StatusInternalServerError)
		assert.NoError(t, err)
		err = os.Chmod(backupsPath, 0755)
		assert.NoError(t, err)
	}
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestDefenderAPI(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	cfg := config.GetCommonConfig()
	cfg.DefenderConfig.Enabled = true
	cfg.DefenderConfig.Threshold = 3

	err := common.Initialize(cfg)
	require.NoError(t, err)

	ip := "::1"

	response, _, err := httpdtest.GetBanTime(ip, http.StatusOK)
	require.NoError(t, err)
	banTime, ok := response["date_time"]
	require.True(t, ok)
	assert.Nil(t, banTime)

	response, _, err = httpdtest.GetScore(ip, http.StatusOK)
	require.NoError(t, err)
	score, ok := response["score"]
	require.True(t, ok)
	assert.Equal(t, float64(0), score)

	err = httpdtest.UnbanIP(ip, http.StatusNotFound)
	require.NoError(t, err)

	common.AddDefenderEvent(ip, common.HostEventNoLoginTried)
	response, _, err = httpdtest.GetScore(ip, http.StatusOK)
	require.NoError(t, err)
	score, ok = response["score"]
	require.True(t, ok)
	assert.Equal(t, float64(2), score)

	common.AddDefenderEvent(ip, common.HostEventNoLoginTried)
	response, _, err = httpdtest.GetBanTime(ip, http.StatusOK)
	require.NoError(t, err)
	banTime, ok = response["date_time"]
	require.True(t, ok)
	assert.NotNil(t, banTime)

	err = httpdtest.UnbanIP(ip, http.StatusOK)
	require.NoError(t, err)

	err = httpdtest.UnbanIP(ip, http.StatusNotFound)
	require.NoError(t, err)

	err = common.Initialize(oldConfig)
	require.NoError(t, err)
}

func TestDefenderAPIErrors(t *testing.T) {
	_, _, err := httpdtest.GetBanTime("", http.StatusBadRequest)
	require.NoError(t, err)

	_, _, err = httpdtest.GetBanTime("invalid", http.StatusBadRequest)
	require.NoError(t, err)

	_, _, err = httpdtest.GetScore("", http.StatusBadRequest)
	require.NoError(t, err)

	err = httpdtest.UnbanIP("", http.StatusBadRequest)
	require.NoError(t, err)
}

func TestLoaddataFromPostBody(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "restored_folder")
	folderName := filepath.Base(mappedPath)
	user := getTestUser()
	user.ID = 1
	user.Username = "test_user_restored"
	admin := getTestAdmin()
	admin.ID = 1
	admin.Username = "test_admin_restored"
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupData.Admins = append(backupData.Admins, admin)
	backupData.Folders = []vfs.BaseVirtualFolder{
		{
			Name:            folderName,
			MappedPath:      mappedPath,
			UsedQuotaSize:   123,
			UsedQuotaFiles:  456,
			LastQuotaUpdate: 789,
			Users:           []string{"user"},
		},
		{
			Name:       folderName,
			MappedPath: mappedPath + "1",
		},
	}
	backupContent, err := json.Marshal(backupData)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(nil, "0", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(backupContent, "a", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody([]byte("invalid content"), "0", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(backupContent, "0", "0", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	folder, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath+"1", folder.MappedPath)
	assert.Equal(t, int64(123), folder.UsedQuotaSize)
	assert.Equal(t, 456, folder.UsedQuotaFiles)
	assert.Equal(t, int64(789), folder.LastQuotaUpdate)
	assert.Len(t, folder.Users, 0)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
}

func TestLoaddata(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "restored_folder")
	folderName := filepath.Base(mappedPath)
	foldeDesc := "restored folder desc"
	user := getTestUser()
	user.ID = 1
	user.Username = "test_user_restore"
	admin := getTestAdmin()
	admin.ID = 1
	admin.Username = "test_admin_restore"
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupData.Admins = append(backupData.Admins, admin)
	backupData.Folders = []vfs.BaseVirtualFolder{
		{
			Name:            folderName,
			MappedPath:      mappedPath + "1",
			UsedQuotaSize:   123,
			UsedQuotaFiles:  456,
			LastQuotaUpdate: 789,
			Users:           []string{"user"},
		},
		{
			MappedPath:  mappedPath,
			Name:        folderName,
			Description: foldeDesc,
		},
	}
	backupContent, err := json.Marshal(backupData)
	assert.NoError(t, err)
	backupFilePath := filepath.Join(backupsPath, "backup.json")
	err = os.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "a", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "", "a", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata("backup.json", "1", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath+"a", "1", "", http.StatusBadRequest)
	assert.NoError(t, err)
	if runtime.GOOS != "windows" {
		err = os.Chmod(backupFilePath, 0111)
		assert.NoError(t, err)
		_, _, err = httpdtest.Loaddata(backupFilePath, "1", "", http.StatusInternalServerError)
		assert.NoError(t, err)
		err = os.Chmod(backupFilePath, 0644)
		assert.NoError(t, err)
	}
	// add user, folder, admin from backup
	_, _, err = httpdtest.Loaddata(backupFilePath, "1", "", http.StatusOK)
	assert.NoError(t, err)
	// update from backup
	_, _, err = httpdtest.Loaddata(backupFilePath, "2", "", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	folder, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath, folder.MappedPath)
	assert.Equal(t, int64(123), folder.UsedQuotaSize)
	assert.Equal(t, 456, folder.UsedQuotaFiles)
	assert.Equal(t, int64(789), folder.LastQuotaUpdate)
	assert.Equal(t, foldeDesc, folder.Description)
	assert.Len(t, folder.Users, 0)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
	err = createTestFile(backupFilePath, 10485761)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "1", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
	err = createTestFile(backupFilePath, 65535)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "1", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
}

func TestLoaddataMode(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "restored_fold")
	folderName := filepath.Base(mappedPath)
	user := getTestUser()
	user.ID = 1
	user.Username = "test_user_restore"
	admin := getTestAdmin()
	admin.ID = 1
	admin.Username = "test_admin_restore"
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupData.Admins = append(backupData.Admins, admin)
	backupData.Folders = []vfs.BaseVirtualFolder{
		{
			Name:            folderName,
			MappedPath:      mappedPath,
			UsedQuotaSize:   123,
			UsedQuotaFiles:  456,
			LastQuotaUpdate: 789,
			Users:           []string{"user"},
		},
		{
			MappedPath: mappedPath + "1",
			Name:       folderName,
		},
	}
	backupContent, _ := json.Marshal(backupData)
	backupFilePath := filepath.Join(backupsPath, "backup.json")
	err := os.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "0", "0", http.StatusOK)
	assert.NoError(t, err)
	folder, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath+"1", folder.MappedPath)
	assert.Equal(t, int64(123), folder.UsedQuotaSize)
	assert.Equal(t, 456, folder.UsedQuotaFiles)
	assert.Equal(t, int64(789), folder.LastQuotaUpdate)
	assert.Len(t, folder.Users, 0)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	oldUploadBandwidth := user.UploadBandwidth
	user.UploadBandwidth = oldUploadBandwidth + 128
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	oldInfo := admin.AdditionalInfo
	oldDesc := admin.Description
	admin.AdditionalInfo = "newInfo"
	admin.Description = "newDesc"
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	backupData.Folders = []vfs.BaseVirtualFolder{
		{
			MappedPath: mappedPath,
			Name:       folderName,
		},
	}
	_, _, err = httpdtest.Loaddata(backupFilePath, "0", "1", http.StatusOK)
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath+"1", folder.MappedPath)
	assert.Equal(t, int64(123), folder.UsedQuotaSize)
	assert.Equal(t, 456, folder.UsedQuotaFiles)
	assert.Equal(t, int64(789), folder.LastQuotaUpdate)
	assert.Len(t, folder.Users, 0)

	c := common.NewBaseConnection("connID", common.ProtocolFTP, user, nil)
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	common.Connections.Add(fakeConn)
	assert.Len(t, common.Connections.GetStats(), 1)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.NotEqual(t, oldUploadBandwidth, user.UploadBandwidth)
	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.NotEqual(t, oldInfo, admin.AdditionalInfo)
	assert.NotEqual(t, oldDesc, admin.Description)

	_, _, err = httpdtest.Loaddata(backupFilePath, "0", "2", http.StatusOK)
	assert.NoError(t, err)
	// mode 2 will update the user and close the previous connection
	assert.Len(t, common.Connections.GetStats(), 0)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, oldUploadBandwidth, user.UploadBandwidth)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
}

func TestHTTPSConnection(t *testing.T) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://localhost:8443" + healthzPath)
	if assert.Error(t, err) {
		if !strings.Contains(err.Error(), "certificate is not valid") &&
			!strings.Contains(err.Error(), "certificate signed by unknown authority") {
			assert.Fail(t, err.Error())
		}
	} else {
		resp.Body.Close()
	}
}

// test using mock http server

func TestBasicUserHandlingMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, err := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	user.MaxSessions = 10
	user.UploadBandwidth = 128
	user.Permissions["/"] = []string{dataprovider.PermAny, dataprovider.PermDelete, dataprovider.PermDownload}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+user.Username, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, userPath+"/"+user.Username, nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	var updatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updatedUser)
	assert.NoError(t, err)
	assert.Equal(t, user.MaxSessions, updatedUser.MaxSessions)
	assert.Equal(t, user.UploadBandwidth, updatedUser.UploadBandwidth)
	assert.Equal(t, 1, len(updatedUser.Permissions["/"]))
	assert.True(t, utils.IsStringInSlice(dataprovider.PermAny, updatedUser.Permissions["/"]))
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+user.Username, nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestAddUserNoUsernameMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	user.Username = ""
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestAddUserInvalidHomeDirMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	user.HomeDir = "relative_path"
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestAddUserInvalidPermsMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	user.Permissions["/"] = []string{}
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestAddFolderInvalidJsonMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer([]byte("invalid json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestUpdateFolderInvalidJsonMock(t *testing.T) {
	folder := vfs.BaseVirtualFolder{
		Name:       "name",
		MappedPath: filepath.Clean(os.TempDir()),
	}
	folder, resp, err := httpdtest.AddFolder(folder, http.StatusCreated)
	assert.NoError(t, err, string(resp))

	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPut, path.Join(folderPath, folder.Name), bytes.NewBuffer([]byte("not a json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
}

func TestUnbanInvalidJsonMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, defenderUnban, bytes.NewBuffer([]byte("invalid json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestAddUserInvalidJsonMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer([]byte("invalid json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestAddAdminInvalidJsonMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, adminPath, bytes.NewBuffer([]byte("...")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestAddAdminNoPasswordMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	admin := getTestAdmin()
	admin.Password = ""
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, adminPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "please set a password")
}

func TestChangeAdminPwdInvalidJsonMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPut, adminPwdPath, bytes.NewBuffer([]byte("{")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestLoginInvalidPasswordMock(t *testing.T) {
	_, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass+"1")
	assert.Error(t, err)
	// now a login with no credentials
	req, _ := http.NewRequest(http.MethodGet, "/api/v2/token", nil)
	rr := executeRequest(req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestChangeAdminPwdMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin.Permissions = []string{dataprovider.PermAdminAddUsers, dataprovider.PermAdminDeleteUsers}
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, adminPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	altToken, err := getJWTAPITokenFromTestServer(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, _ = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	pwd := make(map[string]string)
	pwd["current_password"] = altAdminPassword
	pwd["new_password"] = defaultTokenAuthPass
	asJSON, err = json.Marshal(pwd)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, adminPwdPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = getJWTAPITokenFromTestServer(altAdminUsername, altAdminPassword)
	assert.Error(t, err)

	altToken, err = getJWTAPITokenFromTestServer(altAdminUsername, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, adminPwdPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr) // current password does not match

	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(adminPath, altAdminUsername), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestUpdateAdminMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Permissions = []string{dataprovider.PermAdminManageAdmins}
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, adminPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	req, _ = http.NewRequest(http.MethodPut, path.Join(adminPath, "abc"), bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	req, _ = http.NewRequest(http.MethodPut, path.Join(adminPath, altAdminUsername), bytes.NewBuffer([]byte("no json")))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	admin.Permissions = nil
	asJSON, err = json.Marshal(admin)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(adminPath, altAdminUsername), bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	admin = getTestAdmin()
	admin.Status = 0
	asJSON, err = json.Marshal(admin)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(adminPath, defaultTokenAuthUser), bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	admin.Status = 1
	admin.Permissions = []string{dataprovider.PermAdminAddUsers}
	asJSON, err = json.Marshal(admin)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(adminPath, defaultTokenAuthUser), bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	altToken, err := getJWTAPITokenFromTestServer(altAdminUsername, defaultTokenAuthPass)
	assert.NoError(t, err)
	admin.Permissions = []string{dataprovider.PermAdminManageAdmins, dataprovider.PermAdminCloseConnections}
	asJSON, err = json.Marshal(admin)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(adminPath, altAdminUsername), bytes.NewBuffer(asJSON))
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(adminPath, altAdminUsername), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestUpdateUserMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	// permissions should not change if empty or nil
	permissions := user.Permissions
	user.Permissions = make(map[string][]string)
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+user.Username, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, userPath+"/"+user.Username, nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updatedUser)
	assert.NoError(t, err)
	for dir, perms := range permissions {
		if actualPerms, ok := updatedUser.Permissions[dir]; ok {
			for _, v := range actualPerms {
				assert.True(t, utils.IsStringInSlice(v, perms))
			}
		} else {
			assert.Fail(t, "Permissions directories mismatch")
		}
	}
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestUpdateUserQuotaUsageMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	var user dataprovider.User
	u := getTestUser()
	usedQuotaFiles := 1
	usedQuotaSize := int64(65535)
	u.UsedQuotaFiles = usedQuotaFiles
	u.UsedQuotaSize = usedQuotaSize
	userAsJSON := getUserAsJSON(t, u)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, updateUsedQuotaPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize, user.UsedQuotaSize)
	req, _ = http.NewRequest(http.MethodPut, updateUsedQuotaPath, bytes.NewBuffer([]byte("string")))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.True(t, common.QuotaScans.AddUserQuotaScan(user.Username))
	req, _ = http.NewRequest(http.MethodPut, updateUsedQuotaPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr)
	assert.True(t, common.QuotaScans.RemoveUserQuotaScan(user.Username))
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestUserPermissionsMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	user.Permissions = make(map[string][]string)
	user.Permissions["/somedir"] = []string{dataprovider.PermAny}
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Permissions[".."] = []string{dataprovider.PermAny}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.Permissions["/somedir"] = []string{"invalid"}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	delete(user.Permissions, "/somedir")
	user.Permissions["/somedir/.."] = []string{dataprovider.PermAny}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	delete(user.Permissions, "/somedir/..")
	user.Permissions["not_abs_path"] = []string{dataprovider.PermAny}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	delete(user.Permissions, "not_abs_path")
	user.Permissions["/somedir/../otherdir/"] = []string{dataprovider.PermListItems}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updatedUser)
	assert.NoError(t, err)
	if val, ok := updatedUser.Permissions["/otherdir"]; ok {
		assert.True(t, utils.IsStringInSlice(dataprovider.PermListItems, val))
		assert.Equal(t, 1, len(val))
	} else {
		assert.Fail(t, "expected dir not found in permissions")
	}
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestUpdateUserInvalidJsonMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer([]byte("Invalid json")))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestUpdateUserInvalidParamsMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.HomeDir = ""
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	userID := user.ID
	user.ID = 0
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	user.ID = userID
	req, _ = http.NewRequest(http.MethodPut, userPath+"/0", bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestGetAdminsMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, adminPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, _ = http.NewRequest(http.MethodGet, adminPath+"?limit=510&offset=0&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var admins []dataprovider.Admin
	err = render.DecodeJSON(rr.Body, &admins)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(admins), 1)
	firtAdmin := admins[0].Username
	req, _ = http.NewRequest(http.MethodGet, adminPath+"?limit=510&offset=0&order=DESC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	admins = nil
	err = render.DecodeJSON(rr.Body, &admins)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(admins), 1)
	assert.NotEqual(t, firtAdmin, admins[0].Username)

	req, _ = http.NewRequest(http.MethodGet, adminPath+"?limit=510&offset=1&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	admins = nil
	err = render.DecodeJSON(rr.Body, &admins)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(admins), 1)
	assert.NotEqual(t, firtAdmin, admins[0].Username)

	req, _ = http.NewRequest(http.MethodGet, adminPath+"?limit=a&offset=0&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodGet, adminPath+"?limit=1&offset=a&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodGet, adminPath+"?limit=1&offset=0&order=ASCa", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(adminPath, admin.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestGetUsersMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=510&offset=0&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var users []dataprovider.User
	err = render.DecodeJSON(rr.Body, &users)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(users), 1)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=a&offset=0&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=a&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=0&order=ASCa", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestDeleteUserInvalidParamsMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodDelete, userPath+"/0", nil)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestGetQuotaScansMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, err := http.NewRequest("GET", quotaScanPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestStartQuotaScanMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	_, err = os.Stat(user.HomeDir)
	if err == nil {
		err = os.Remove(user.HomeDir)
		assert.NoError(t, err)
	}
	// simulate a duplicate quota scan
	userAsJSON = getUserAsJSON(t, user)
	common.QuotaScans.AddUserQuotaScan(user.Username)
	req, _ = http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr)
	assert.True(t, common.QuotaScans.RemoveUserQuotaScan(user.Username))

	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)

	for {
		var scans []common.ActiveQuotaScan
		req, _ = http.NewRequest(http.MethodGet, quotaScanPath, nil)
		setBearerForReq(req, token)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
		err = render.DecodeJSON(rr.Body, &scans)
		if !assert.NoError(t, err, "Error getting active scans") {
			break
		}
		if len(scans) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, err = os.Stat(user.HomeDir)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(user.HomeDir, os.ModePerm)
		assert.NoError(t, err)
	}
	req, _ = http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)

	for {
		var scans []common.ActiveQuotaScan
		req, _ = http.NewRequest(http.MethodGet, quotaScanPath, nil)
		setBearerForReq(req, token)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
		err = render.DecodeJSON(rr.Body, &scans)
		if !assert.NoError(t, err) {
			assert.Fail(t, err.Error(), "Error getting active scans")
			break
		}
		if len(scans) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUpdateFolderQuotaUsageMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	mappedPath := filepath.Join(os.TempDir(), "vfolder")
	folderName := filepath.Base(mappedPath)
	f := vfs.BaseVirtualFolder{
		MappedPath: mappedPath,
		Name:       folderName,
	}
	usedQuotaFiles := 1
	usedQuotaSize := int64(65535)
	f.UsedQuotaFiles = usedQuotaFiles
	f.UsedQuotaSize = usedQuotaSize
	var folder vfs.BaseVirtualFolder
	folderAsJSON, err := json.Marshal(f)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &folder)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, updateFolderUsedQuotaPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	var folderGet vfs.BaseVirtualFolder
	req, _ = http.NewRequest(http.MethodGet, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &folderGet)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, folderGet.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize, folderGet.UsedQuotaSize)
	req, _ = http.NewRequest(http.MethodPut, updateFolderUsedQuotaPath, bytes.NewBuffer([]byte("string")))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	assert.True(t, common.QuotaScans.AddVFolderQuotaScan(folderName))
	req, _ = http.NewRequest(http.MethodPut, updateFolderUsedQuotaPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr)
	assert.True(t, common.QuotaScans.RemoveVFolderQuotaScan(folderName))

	req, _ = http.NewRequest(http.MethodDelete, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestStartFolderQuotaScanMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	mappedPath := filepath.Join(os.TempDir(), "vfolder")
	folderName := filepath.Base(mappedPath)
	folder := vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: mappedPath,
	}
	folderAsJSON, err := json.Marshal(folder)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	_, err = os.Stat(mappedPath)
	if err == nil {
		err = os.Remove(mappedPath)
		assert.NoError(t, err)
	}
	// simulate a duplicate quota scan
	common.QuotaScans.AddVFolderQuotaScan(folderName)
	req, _ = http.NewRequest(http.MethodPost, quotaScanVFolderPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr)
	assert.True(t, common.QuotaScans.RemoveVFolderQuotaScan(folderName))
	// and now a real quota scan
	_, err = os.Stat(mappedPath)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(mappedPath, os.ModePerm)
		assert.NoError(t, err)
	}
	req, _ = http.NewRequest(http.MethodPost, quotaScanVFolderPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)
	var scans []common.ActiveVirtualFolderQuotaScan
	for {
		req, _ = http.NewRequest(http.MethodGet, quotaScanVFolderPath, nil)
		setBearerForReq(req, token)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
		err = render.DecodeJSON(rr.Body, &scans)
		if !assert.NoError(t, err, "Error getting active folders scans") {
			break
		}
		if len(scans) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// cleanup

	req, _ = http.NewRequest(http.MethodDelete, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = os.RemoveAll(folderPath)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestStartQuotaScanNonExistentUserMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestStartQuotaScanBadUserMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer([]byte("invalid json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestStartQuotaScanBadFolderMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, quotaScanVFolderPath, bytes.NewBuffer([]byte("invalid json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestStartQuotaScanNonExistentFolderMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	folder := vfs.BaseVirtualFolder{
		MappedPath: os.TempDir(),
		Name:       "afolder",
	}
	folderAsJSON, err := json.Marshal(folder)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, quotaScanVFolderPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestGetFoldersMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	mappedPath := filepath.Join(os.TempDir(), "vfolder")
	folderName := filepath.Base(mappedPath)
	folder := vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: mappedPath,
	}
	folderAsJSON, err := json.Marshal(folder)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &folder)
	assert.NoError(t, err)

	var folders []vfs.BaseVirtualFolder
	url, err := url.Parse(folderPath + "?limit=510&offset=0&order=DESC")
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, url.String(), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &folders)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(folders), 1)
	req, _ = http.NewRequest(http.MethodGet, folderPath+"?limit=a&offset=0&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodGet, folderPath+"?limit=1&offset=a&order=ASC", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodGet, folderPath+"?limit=1&offset=0&order=ASCa", nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestGetVersionMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, versionPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, versionPath, nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, versionPath, nil)
	setBearerForReq(req, "abcde")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
}

func TestGetConnectionsMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, activeConnectionsPath, nil)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestGetStatusMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestDeleteActiveConnectionMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodDelete, activeConnectionsPath+"/connectionID", nil)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestNotFoundMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, "/non/existing/path", nil)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestMethodNotAllowedMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, activeConnectionsPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusMethodNotAllowed, rr)
}

func TestHealthCheck(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/healthz", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "ok", rr.Body.String())
}

func TestGetWebRootMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusMovedPermanently, rr)
	req, _ = http.NewRequest(http.MethodGet, webBasePath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusMovedPermanently, rr)
}

func TestWebNotFoundURI(t *testing.T) {
	urlString := httpBaseURL + webBasePath + "/a"
	req, err := http.NewRequest(http.MethodGet, urlString, nil)
	assert.NoError(t, err)
	resp, err := httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, urlString, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, "invalid token")
	resp, err = httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestLogout(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, logoutPath, nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "Your token is no longer valid")
}

func TestTokenHeaderCookie(t *testing.T) {
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setJWTCookieForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "no token found")

	req, _ = http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webStatusPath, nil)
	setBearerForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))

	req, _ = http.NewRequest(http.MethodGet, webStatusPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestTokenAudience(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "Your token audience is not valid")

	req, _ = http.NewRequest(http.MethodGet, webStatusPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webStatusPath, nil)
	setJWTCookieForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))
}

func TestWebLoginMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webStatusPath+"notfound", nil)
	req.RequestURI = webStatusPath + "notfound"
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, _ = http.NewRequest(http.MethodGet, webStatusPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webLogoutPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	cookie := rr.Header().Get("Cookie")
	assert.Empty(t, cookie)

	req, _ = http.NewRequest(http.MethodGet, logoutPath, nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "Your token is no longer valid")

	req, _ = http.NewRequest(http.MethodGet, webStatusPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)

	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	// now try using wrong credentials
	form := getAdminLoginForm(defaultTokenAuthUser, "wrong pwd", csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// try from an ip not allowed
	a := getTestAdmin()
	a.Username = altAdminUsername
	a.Password = altAdminPassword
	a.Filters.AllowList = []string{"10.0.0.0/8"}

	_, _, err = httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)

	form = getAdminLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.1.1.1:1234"
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "login from IP 127.1.1.1 not allowed")

	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.9.9.9:1234"
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)

	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.1.1:4567"
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Login from IP 127.0.1.1:4567 is not allowed")

	// invalid csrf token
	form = getAdminLoginForm(altAdminUsername, altAdminPassword, "invalid csrf")
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.9.9.8:1234"
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	req, _ = http.NewRequest(http.MethodGet, webLoginPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = httpdtest.RemoveAdmin(a, http.StatusOK)
	assert.NoError(t, err)
}

func TestAdminNoToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, webChangeAdminPwdPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))

	req, _ = http.NewRequest(http.MethodGet, webUserPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))

	req, _ = http.NewRequest(http.MethodGet, userPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	req, _ = http.NewRequest(http.MethodGet, activeConnectionsPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
}

func TestWebAdminPwdChange(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	token, err := getJWTWebTokenFromTestServer(admin.Username, altAdminPassword)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, webChangeAdminPwdPath, nil)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form := make(url.Values)
	form.Set("current_password", altAdminPassword)
	form.Set("new_password1", altAdminPassword)
	form.Set("new_password2", altAdminPassword)
	// no csrf token
	req, _ = http.NewRequest(http.MethodPost, webChangeAdminPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webChangeAdminPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "the new password must be different from the current one")

	form.Set("new_password1", altAdminPassword+"1")
	form.Set("new_password2", altAdminPassword+"1")
	req, _ = http.NewRequest(http.MethodPost, webChangeAdminPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestBasicWebUsersMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user1 := getTestUser()
	user1.Username += "1"
	user1AsJSON := getUserAsJSON(t, user1)
	req, _ = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(user1AsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user1)
	assert.NoError(t, err)
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, webUsersPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, webUsersPath+"?qlimit=a", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, webUsersPath+"?qlimit=1", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, webUserPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(webUserPath, user.Username), nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, webUserPath+"/0", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("username", user.Username)
	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/0", &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/aaa", &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	req, _ = http.NewRequest(http.MethodDelete, path.Join(webUserPath, user.Username), nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid token")
	req, _ = http.NewRequest(http.MethodDelete, path.Join(webUserPath, user.Username), nil)
	setJWTCookieForReq(req, webToken)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodDelete, path.Join(webUserPath, user1.Username), nil)
	setJWTCookieForReq(req, webToken)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestWebAdminBasicMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("username", admin.Username)
	form.Set("password", "")
	form.Set("status", "1")
	form.Set("permissions", "*")
	form.Set("description", admin.Description)
	req, _ := http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("status", "a")
	req, _ = http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("status", "1")
	req, _ = http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("password", admin.Password)
	req, _ = http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	_, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)

	req, _ = http.NewRequest(http.MethodGet, webAdminsPath+"?qlimit=a", nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, webAdminsPath+"?qlimit=1", nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webAdminPath, nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("password", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	form.Set(csrfFormToken, "invalid csrf")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("email", "not-an-email")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("email", "")
	form.Set("status", "b")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("email", "admin@example.com")
	form.Set("status", "0")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername+"1"), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, _ = http.NewRequest(http.MethodGet, path.Join(webAdminPath, altAdminUsername), nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, path.Join(webAdminPath, altAdminUsername+"1"), nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webAdminPath, altAdminUsername), nil)
	setJWTCookieForReq(req, token)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusNotFound)
	assert.NoError(t, err)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webAdminPath, defaultTokenAuthUser), nil)
	setJWTCookieForReq(req, token)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "You cannot delete yourself")

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webAdminPath, defaultTokenAuthUser), nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid token")
}

func TestWebAdminPermissions(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin.Permissions = []string{dataprovider.PermAdminAddUsers}
	_, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	token, err := getJWTWebToken(altAdminUsername, altAdminPassword)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, httpBaseURL+webUserPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	resp, err := httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, httpBaseURL+path.Join(webUserPath, "auser"), nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	resp, err = httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, httpBaseURL+webFolderPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	resp, err = httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, httpBaseURL+webStatusPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	resp, err = httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, httpBaseURL+webConnectionsPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	resp, err = httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, httpBaseURL+webAdminPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	resp, err = httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, httpBaseURL+path.Join(webAdminPath, "a"), nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	resp, err = httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestAdminUpdateSelfMock(t *testing.T) {
	admin, _, err := httpdtest.GetAdminByUsername(defaultTokenAuthUser, http.StatusOK)
	assert.NoError(t, err)
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("username", admin.Username)
	form.Set("password", admin.Password)
	form.Set("status", "0")
	form.Set("permissions", dataprovider.PermAdminAddUsers)
	form.Set("permissions", dataprovider.PermAdminCloseConnections)
	form.Set(csrfFormToken, csrfToken)
	req, _ := http.NewRequest(http.MethodPost, path.Join(webAdminPath, defaultTokenAuthUser), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "You cannot remove these permissions to yourself")

	form.Set("permissions", dataprovider.PermAdminAny)
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, defaultTokenAuthUser), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "You cannot disable yourself")
}

func TestWebMaintenanceMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, webMaintenancePath, nil)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)

	form := make(url.Values)
	form.Set("mode", "a")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webRestorePath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webRestorePath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("mode", "0")
	form.Set("quota", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webRestorePath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("quota", "0")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webRestorePath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodPost, webRestorePath+"?a=%3", &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	backupFilePath := filepath.Join(os.TempDir(), "backup.json")
	err = createTestFile(backupFilePath, 0)
	assert.NoError(t, err)

	b, contentType, _ = getMultipartFormData(form, "backup_file", backupFilePath)
	req, _ = http.NewRequest(http.MethodPost, webRestorePath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	err = createTestFile(backupFilePath, 10)
	assert.NoError(t, err)

	b, contentType, _ = getMultipartFormData(form, "backup_file", backupFilePath)
	req, _ = http.NewRequest(http.MethodPost, webRestorePath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user := getTestUser()
	user.ID = 1
	user.Username = "test_user_web_restore"
	admin := getTestAdmin()
	admin.ID = 1
	admin.Username = "test_admin_web_restore"
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupData.Admins = append(backupData.Admins, admin)
	backupContent, err := json.Marshal(backupData)
	assert.NoError(t, err)
	err = os.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)

	b, contentType, _ = getMultipartFormData(form, "backup_file", backupFilePath)
	req, _ = http.NewRequest(http.MethodPost, webRestorePath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Your backup was successfully restored")

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestWebUserAddMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	user := getTestUser()
	user.UploadBandwidth = 32
	user.DownloadBandwidth = 64
	user.UID = 1000
	user.AdditionalInfo = "info"
	user.Description = "user dsc"
	mappedDir := filepath.Join(os.TempDir(), "mapped")
	folderName := filepath.Base(mappedDir)
	f := vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: mappedDir,
	}
	folderAsJSON, err := json.Marshal(f)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	form.Set("home_dir", user.HomeDir)
	form.Set("password", user.Password)
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", " /subdir::list ,download ")
	form.Set("virtual_folders", fmt.Sprintf(" /vdir:: %v :: 2 :: 1024", folderName))
	form.Set("allowed_extensions", "/dir2::.jpg,.png\n/dir2::.ico\n/dir1::.rar")
	form.Set("denied_extensions", "/dir2::.webp,.webp\n/dir2::.tiff\n/dir1::.zip")
	form.Set("allowed_patterns", "/dir2::*.jpg,*.png\n/dir1::*.png")
	form.Set("denied_patterns", "/dir1::*.zip\n/dir3::*.rar\n/dir2::*.mkv")
	form.Set("additional_info", user.AdditionalInfo)
	form.Set("description", user.Description)
	b, contentType, _ := getMultipartFormData(form, "", "")
	// test invalid url escape
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"?a=%2", &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("public_keys", testPubKey)
	form.Set("uid", strconv.FormatInt(int64(user.UID), 10))
	form.Set("gid", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid gid
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("gid", "0")
	form.Set("max_sessions", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid max sessions
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("max_sessions", "0")
	form.Set("quota_size", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid quota size
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("quota_size", "0")
	form.Set("quota_files", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid quota files
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("quota_files", "0")
	form.Set("upload_bandwidth", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid upload bandwidth
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("upload_bandwidth", strconv.FormatInt(user.UploadBandwidth, 10))
	form.Set("download_bandwidth", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid download bandwidth
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("download_bandwidth", strconv.FormatInt(user.DownloadBandwidth, 10))
	form.Set("status", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid status
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "123")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid expiration date
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("expiration_date", "")
	form.Set("allowed_ip", "invalid,ip")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid allowed_ip
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "192.168.1.2") // it should be 192.168.1.2/32
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid denied_ip
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("denied_ip", "")
	// test invalid max file upload size
	form.Set("max_upload_file_size", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("max_upload_file_size", "1000")
	// test invalid tls username
	form.Set("tls_username", "username")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: invalid TLS username")
	form.Set("tls_username", string(dataprovider.TLSUsernameNone))
	form.Set(csrfFormToken, "invalid form token")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	dbUser, err := dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, dbUser.Password)
	assert.True(t, dbUser.IsPasswordHashed())
	// the user already exists, was created with the above request
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	newUser := dataprovider.User{}
	err = render.DecodeJSON(rr.Body, &newUser)
	assert.NoError(t, err)
	assert.Equal(t, user.UID, newUser.UID)
	assert.Equal(t, user.UploadBandwidth, newUser.UploadBandwidth)
	assert.Equal(t, user.DownloadBandwidth, newUser.DownloadBandwidth)
	assert.Equal(t, int64(1000), newUser.Filters.MaxUploadFileSize)
	assert.Equal(t, user.AdditionalInfo, newUser.AdditionalInfo)
	assert.Equal(t, user.Description, newUser.Description)
	assert.True(t, utils.IsStringInSlice(testPubKey, newUser.PublicKeys))
	if val, ok := newUser.Permissions["/subdir"]; ok {
		assert.True(t, utils.IsStringInSlice(dataprovider.PermListItems, val))
		assert.True(t, utils.IsStringInSlice(dataprovider.PermDownload, val))
	} else {
		assert.Fail(t, "user permissions must contain /somedir", "actual: %v", newUser.Permissions)
	}
	assert.Len(t, newUser.VirtualFolders, 1)
	for _, v := range newUser.VirtualFolders {
		assert.Equal(t, v.VirtualPath, "/vdir")
		assert.Equal(t, v.Name, folderName)
		assert.Equal(t, v.MappedPath, mappedDir)
		assert.Equal(t, v.QuotaFiles, 2)
		assert.Equal(t, v.QuotaSize, int64(1024))
	}
	assert.Len(t, newUser.Filters.FileExtensions, 2)
	for _, filter := range newUser.Filters.FileExtensions {
		if filter.Path == "/dir1" {
			assert.Len(t, filter.DeniedExtensions, 1)
			assert.Len(t, filter.AllowedExtensions, 1)
			assert.True(t, utils.IsStringInSlice(".zip", filter.DeniedExtensions))
			assert.True(t, utils.IsStringInSlice(".rar", filter.AllowedExtensions))
		}
		if filter.Path == "/dir2" {
			assert.Len(t, filter.DeniedExtensions, 2)
			assert.Len(t, filter.AllowedExtensions, 3)
			assert.True(t, utils.IsStringInSlice(".jpg", filter.AllowedExtensions))
			assert.True(t, utils.IsStringInSlice(".png", filter.AllowedExtensions))
			assert.True(t, utils.IsStringInSlice(".ico", filter.AllowedExtensions))
			assert.True(t, utils.IsStringInSlice(".webp", filter.DeniedExtensions))
			assert.True(t, utils.IsStringInSlice(".tiff", filter.DeniedExtensions))
		}
	}
	assert.Len(t, newUser.Filters.FilePatterns, 3)
	for _, filter := range newUser.Filters.FilePatterns {
		if filter.Path == "/dir1" {
			assert.Len(t, filter.DeniedPatterns, 1)
			assert.Len(t, filter.AllowedPatterns, 1)
			assert.True(t, utils.IsStringInSlice("*.png", filter.AllowedPatterns))
			assert.True(t, utils.IsStringInSlice("*.zip", filter.DeniedPatterns))
		}
		if filter.Path == "/dir2" {
			assert.Len(t, filter.DeniedPatterns, 1)
			assert.Len(t, filter.AllowedPatterns, 2)
			assert.True(t, utils.IsStringInSlice("*.jpg", filter.AllowedPatterns))
			assert.True(t, utils.IsStringInSlice("*.png", filter.AllowedPatterns))
			assert.True(t, utils.IsStringInSlice("*.mkv", filter.DeniedPatterns))
		}
		if filter.Path == "/dir3" {
			assert.Len(t, filter.DeniedPatterns, 1)
			assert.Len(t, filter.AllowedPatterns, 0)
			assert.True(t, utils.IsStringInSlice("*.rar", filter.DeniedPatterns))
		}
	}
	assert.Equal(t, dataprovider.TLSUsernameNone, newUser.Filters.TLSUsername)
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, newUser.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodDelete, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestWebUserUpdateMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	dbUser, err := dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, dbUser.Password)
	assert.True(t, dbUser.IsPasswordHashed())
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.MaxSessions = 1
	user.QuotaFiles = 2
	user.QuotaSize = 3
	user.GID = 1000
	user.AdditionalInfo = "new additional info"
	form := make(url.Values)
	form.Set("username", user.Username)
	form.Set("password", "")
	form.Set("public_keys", testPubKey)
	form.Set("home_dir", user.HomeDir)
	form.Set("uid", "0")
	form.Set("gid", strconv.FormatInt(int64(user.GID), 10))
	form.Set("max_sessions", strconv.FormatInt(int64(user.MaxSessions), 10))
	form.Set("quota_size", strconv.FormatInt(user.QuotaSize, 10))
	form.Set("quota_files", strconv.FormatInt(int64(user.QuotaFiles), 10))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", "/otherdir :: list ,upload ")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", " 192.168.1.3/32, 192.168.2.0/24 ")
	form.Set("denied_ip", " 10.0.0.2/32 ")
	form.Set("denied_extensions", "/dir1::.zip")
	form.Set("ssh_login_methods", dataprovider.SSHLoginMethodKeyboardInteractive)
	form.Set("denied_protocols", common.ProtocolFTP)
	form.Set("max_upload_file_size", "100")
	form.Set("disconnect", "1")
	form.Set("additional_info", user.AdditionalInfo)
	form.Set("description", user.Description)
	form.Set("tls_username", string(dataprovider.TLSUsernameCN))
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	dbUser, err = dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.Empty(t, dbUser.Password)
	assert.False(t, dbUser.IsPasswordHashed())

	form.Set("password", defaultPassword)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	dbUser, err = dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, dbUser.Password)
	assert.True(t, dbUser.IsPasswordHashed())
	prevPwd := dbUser.Password

	form.Set("password", redactedSecret)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	dbUser, err = dataprovider.UserExists(user.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, dbUser.Password)
	assert.True(t, dbUser.IsPasswordHashed())
	assert.Equal(t, prevPwd, dbUser.Password)

	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updateUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updateUser)
	assert.NoError(t, err)
	assert.Equal(t, user.HomeDir, updateUser.HomeDir)
	assert.Equal(t, user.MaxSessions, updateUser.MaxSessions)
	assert.Equal(t, user.QuotaFiles, updateUser.QuotaFiles)
	assert.Equal(t, user.QuotaSize, updateUser.QuotaSize)
	assert.Equal(t, user.UID, updateUser.UID)
	assert.Equal(t, user.GID, updateUser.GID)
	assert.Equal(t, user.AdditionalInfo, updateUser.AdditionalInfo)
	assert.Equal(t, user.Description, updateUser.Description)
	assert.Equal(t, int64(100), updateUser.Filters.MaxUploadFileSize)
	assert.Equal(t, dataprovider.TLSUsernameCN, updateUser.Filters.TLSUsername)

	if val, ok := updateUser.Permissions["/otherdir"]; ok {
		assert.True(t, utils.IsStringInSlice(dataprovider.PermListItems, val))
		assert.True(t, utils.IsStringInSlice(dataprovider.PermUpload, val))
	} else {
		assert.Fail(t, "user permissions must contains /otherdir", "actual: %v", updateUser.Permissions)
	}
	assert.True(t, utils.IsStringInSlice("192.168.1.3/32", updateUser.Filters.AllowedIP))
	assert.True(t, utils.IsStringInSlice("10.0.0.2/32", updateUser.Filters.DeniedIP))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, updateUser.Filters.DeniedLoginMethods))
	assert.True(t, utils.IsStringInSlice(common.ProtocolFTP, updateUser.Filters.DeniedProtocols))
	assert.True(t, utils.IsStringInSlice(".zip", updateUser.Filters.FileExtensions[0].DeniedExtensions))
	req, err = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestRenderFolderTemplateMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, webTemplateFolder, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	folder := vfs.BaseVirtualFolder{
		Name:        "templatefolder",
		MappedPath:  filepath.Join(os.TempDir(), "mapped"),
		Description: "template folder desc",
	}
	folder, _, err = httpdtest.AddFolder(folder, http.StatusCreated)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webTemplateFolder+fmt.Sprintf("?from=%v", folder.Name), nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webTemplateFolder+"?from=unknown-folder", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
}

func TestRenderUserTemplateMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, webTemplateUser, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webTemplateUser+fmt.Sprintf("?from=%v", user.Username), nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webTemplateUser+"?from=unknown", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestRenderWebCloneUserMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webUserPath+fmt.Sprintf("?clone-from=%v", user.Username), nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webUserPath+fmt.Sprintf("?clone-from=%v", altAdminPassword), nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserTemplateWithFoldersMock(t *testing.T) {
	folder := vfs.BaseVirtualFolder{
		Name:        "vfolder",
		MappedPath:  filepath.Join(os.TempDir(), "mapped"),
		Description: "vfolder desc with spéciàl ch@rs",
	}

	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	user := getTestUser()
	form := make(url.Values)
	form.Set("username", user.Username)
	form.Set("home_dir", filepath.Join(os.TempDir(), "%username%"))
	form.Set("uid", strconv.FormatInt(int64(user.UID), 10))
	form.Set("gid", strconv.FormatInt(int64(user.GID), 10))
	form.Set("max_sessions", strconv.FormatInt(int64(user.MaxSessions), 10))
	form.Set("quota_size", strconv.FormatInt(user.QuotaSize, 10))
	form.Set("quota_files", strconv.FormatInt(int64(user.QuotaFiles), 10))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", "")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("fs_provider", "0")
	form.Set("max_upload_file_size", "0")
	form.Set("description", "desc %username% %password%")
	form.Set("virtual_folders", "/vdir%username%::"+folder.Name+"::-1::-1")
	form.Set("users", "auser1::password1\nauser2::password2::"+testPubKey+"\nauser1::password")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ := http.NewRequest(http.MethodPost, path.Join(webTemplateUser), &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	require.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webTemplateUser), &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	require.Contains(t, rr.Body.String(), "invalid folder mapped path")

	folder, resp, err := httpdtest.AddFolder(folder, http.StatusCreated)
	assert.NoError(t, err, string(resp))

	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webTemplateUser), &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	var dump dataprovider.BackupData
	err = json.Unmarshal(rr.Body.Bytes(), &dump)
	assert.NoError(t, err)
	assert.Len(t, dump.Users, 2)
	assert.Len(t, dump.Folders, 1)
	user1 := dump.Users[0]
	user2 := dump.Users[1]
	folder1 := dump.Folders[0]
	assert.Equal(t, "auser1", user1.Username)
	assert.Equal(t, "auser2", user2.Username)
	assert.Equal(t, "desc auser1 password1", user1.Description)
	assert.Equal(t, "desc auser2 password2", user2.Description)
	assert.Equal(t, filepath.Join(os.TempDir(), user1.Username), user1.HomeDir)
	assert.Equal(t, filepath.Join(os.TempDir(), user2.Username), user2.HomeDir)
	assert.Equal(t, folder.Name, folder1.Name)
	assert.Equal(t, folder.MappedPath, folder1.MappedPath)
	assert.Equal(t, folder.Description, folder1.Description)
	assert.Len(t, user1.PublicKeys, 0)
	assert.Len(t, user2.PublicKeys, 1)
	assert.Len(t, user1.VirtualFolders, 1)
	assert.Len(t, user2.VirtualFolders, 1)
	assert.Equal(t, "/vdirauser1", user1.VirtualFolders[0].VirtualPath)
	assert.Equal(t, "/vdirauser2", user2.VirtualFolders[0].VirtualPath)

	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserTemplateMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	user.FsConfig.Provider = dataprovider.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test"
	user.FsConfig.S3Config.Region = "eu-central-1"
	user.FsConfig.S3Config.AccessKey = "%username%"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir/"
	user.FsConfig.S3Config.UploadPartSize = 5
	user.FsConfig.S3Config.UploadConcurrency = 4
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	form.Set("home_dir", filepath.Join(os.TempDir(), "%username%"))
	form.Set("uid", "0")
	form.Set("gid", strconv.FormatInt(int64(user.GID), 10))
	form.Set("max_sessions", strconv.FormatInt(int64(user.MaxSessions), 10))
	form.Set("quota_size", strconv.FormatInt(user.QuotaSize, 10))
	form.Set("quota_files", strconv.FormatInt(int64(user.QuotaFiles), 10))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", "")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "1")
	form.Set("s3_bucket", user.FsConfig.S3Config.Bucket)
	form.Set("s3_region", user.FsConfig.S3Config.Region)
	form.Set("s3_access_key", "%username%")
	form.Set("s3_access_secret", "%password%")
	form.Set("s3_key_prefix", "base/%username%")
	form.Set("allowed_extensions", "/dir1::.jpg,.png")
	form.Set("denied_extensions", "/dir2::.zip")
	form.Set("max_upload_file_size", "0")
	// test invalid s3_upload_part_size
	form.Set("s3_upload_part_size", "a")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ := http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	form.Set("s3_upload_part_size", strconv.FormatInt(user.FsConfig.S3Config.UploadPartSize, 10))
	form.Set("s3_upload_concurrency", strconv.Itoa(user.FsConfig.S3Config.UploadConcurrency))

	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	form.Set("users", "user1::password1::invalid-pkey")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	require.Contains(t, rr.Body.String(), "Error validating user")

	form.Set("users", "user1:password1")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	require.Contains(t, rr.Body.String(), "No valid users found, export is not possible")

	form.Set("users", "user1::password1\nuser2::password2::"+testPubKey+"\nuser3::::")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	var dump dataprovider.BackupData
	err = json.Unmarshal(rr.Body.Bytes(), &dump)
	require.NoError(t, err)
	require.Len(t, dump.Users, 2)
	require.Len(t, dump.Admins, 0)
	require.Len(t, dump.Folders, 0)
	user1 := dump.Users[0]
	user2 := dump.Users[1]
	require.Equal(t, "user1", user1.Username)
	require.Equal(t, dataprovider.S3FilesystemProvider, user1.FsConfig.Provider)
	require.Equal(t, "user2", user2.Username)
	require.Equal(t, dataprovider.S3FilesystemProvider, user2.FsConfig.Provider)
	require.Len(t, user2.PublicKeys, 1)
	require.Equal(t, filepath.Join(os.TempDir(), user1.Username), user1.HomeDir)
	require.Equal(t, filepath.Join(os.TempDir(), user2.Username), user2.HomeDir)
	require.Equal(t, user1.Username, user1.FsConfig.S3Config.AccessKey)
	require.Equal(t, user2.Username, user2.FsConfig.S3Config.AccessKey)
	require.Equal(t, path.Join("base", user1.Username)+"/", user1.FsConfig.S3Config.KeyPrefix)
	require.Equal(t, path.Join("base", user2.Username)+"/", user2.FsConfig.S3Config.KeyPrefix)
	require.True(t, user1.FsConfig.S3Config.AccessSecret.IsEncrypted())
	err = user1.FsConfig.S3Config.AccessSecret.Decrypt()
	require.NoError(t, err)
	require.Equal(t, "password1", user1.FsConfig.S3Config.AccessSecret.GetPayload())
	require.True(t, user2.FsConfig.S3Config.AccessSecret.IsEncrypted())
	err = user2.FsConfig.S3Config.AccessSecret.Decrypt()
	require.NoError(t, err)
	require.Equal(t, "password2", user2.FsConfig.S3Config.AccessSecret.GetPayload())
}

func TestFolderTemplateMock(t *testing.T) {
	folderName := "vfolder-template"
	mappedPath := filepath.Join(os.TempDir(), "%name%mapped%name%path")
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("name", folderName)
	form.Set("mapped_path", mappedPath)
	form.Set("description", "desc folder %name%")
	form.Set("folders", "folder1\nfolder2\nfolder3\nfolder1\n\n\n")
	contentType := "application/x-www-form-urlencoded"
	req, _ := http.NewRequest(http.MethodPost, webTemplateFolder, bytes.NewBuffer([]byte(form.Encode())))
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)

	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder+"?param=p%C3%AO%GG", bytes.NewBuffer([]byte(form.Encode())))
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Error parsing folders fields")

	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder, bytes.NewBuffer([]byte(form.Encode())))
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	var dump dataprovider.BackupData
	err = json.Unmarshal(rr.Body.Bytes(), &dump)
	require.NoError(t, err)
	require.Len(t, dump.Users, 0)
	require.Len(t, dump.Admins, 0)
	require.Len(t, dump.Folders, 3)
	require.Equal(t, "folder1", dump.Folders[0].Name)
	require.Equal(t, "desc folder folder1", dump.Folders[0].Description)
	require.True(t, strings.HasSuffix(dump.Folders[0].MappedPath, "folder1mappedfolder1path"))
	require.Equal(t, "folder2", dump.Folders[1].Name)
	require.Equal(t, "desc folder folder2", dump.Folders[1].Description)
	require.True(t, strings.HasSuffix(dump.Folders[1].MappedPath, "folder2mappedfolder2path"))
	require.Equal(t, "folder3", dump.Folders[2].Name)
	require.Equal(t, "desc folder folder3", dump.Folders[2].Description)
	require.True(t, strings.HasSuffix(dump.Folders[2].MappedPath, "folder3mappedfolder3path"))

	form.Set("folders", "\n\n\n")
	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder, bytes.NewBuffer([]byte(form.Encode())))
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "No folders to export")

	form.Set("folders", "name")
	form.Set("mapped_path", "relative-path")
	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder, bytes.NewBuffer([]byte(form.Encode())))
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Error validating folder")
}

func TestWebUserS3Mock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test"
	user.FsConfig.S3Config.Region = "eu-west-1"
	user.FsConfig.S3Config.AccessKey = "access-key"
	user.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("access-secret")
	user.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/path?a=b"
	user.FsConfig.S3Config.StorageClass = "Standard"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir/"
	user.FsConfig.S3Config.UploadPartSize = 5
	user.FsConfig.S3Config.UploadConcurrency = 4
	user.Description = "s3 tèst user"
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	form.Set("password", redactedSecret)
	form.Set("home_dir", user.HomeDir)
	form.Set("uid", "0")
	form.Set("gid", strconv.FormatInt(int64(user.GID), 10))
	form.Set("max_sessions", strconv.FormatInt(int64(user.MaxSessions), 10))
	form.Set("quota_size", strconv.FormatInt(user.QuotaSize, 10))
	form.Set("quota_files", strconv.FormatInt(int64(user.QuotaFiles), 10))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", "")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "1")
	form.Set("s3_bucket", user.FsConfig.S3Config.Bucket)
	form.Set("s3_region", user.FsConfig.S3Config.Region)
	form.Set("s3_access_key", user.FsConfig.S3Config.AccessKey)
	form.Set("s3_access_secret", user.FsConfig.S3Config.AccessSecret.GetPayload())
	form.Set("s3_storage_class", user.FsConfig.S3Config.StorageClass)
	form.Set("s3_endpoint", user.FsConfig.S3Config.Endpoint)
	form.Set("s3_key_prefix", user.FsConfig.S3Config.KeyPrefix)
	form.Set("allowed_extensions", "/dir1::.jpg,.png")
	form.Set("denied_extensions", "/dir2::.zip")
	form.Set("max_upload_file_size", "0")
	form.Set("description", user.Description)
	// test invalid s3_upload_part_size
	form.Set("s3_upload_part_size", "a")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test invalid s3_concurrency
	form.Set("s3_upload_part_size", strconv.FormatInt(user.FsConfig.S3Config.UploadPartSize, 10))
	form.Set("s3_upload_concurrency", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now add the user
	form.Set("s3_upload_concurrency", strconv.Itoa(user.FsConfig.S3Config.UploadConcurrency))
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updateUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updateUser)
	assert.NoError(t, err)
	assert.Equal(t, int64(1577836800000), updateUser.ExpirationDate)
	assert.Equal(t, updateUser.FsConfig.S3Config.Bucket, user.FsConfig.S3Config.Bucket)
	assert.Equal(t, updateUser.FsConfig.S3Config.Region, user.FsConfig.S3Config.Region)
	assert.Equal(t, updateUser.FsConfig.S3Config.AccessKey, user.FsConfig.S3Config.AccessKey)
	assert.Equal(t, updateUser.FsConfig.S3Config.StorageClass, user.FsConfig.S3Config.StorageClass)
	assert.Equal(t, updateUser.FsConfig.S3Config.Endpoint, user.FsConfig.S3Config.Endpoint)
	assert.Equal(t, updateUser.FsConfig.S3Config.KeyPrefix, user.FsConfig.S3Config.KeyPrefix)
	assert.Equal(t, updateUser.FsConfig.S3Config.UploadPartSize, user.FsConfig.S3Config.UploadPartSize)
	assert.Equal(t, updateUser.FsConfig.S3Config.UploadConcurrency, user.FsConfig.S3Config.UploadConcurrency)
	assert.Equal(t, 2, len(updateUser.Filters.FileExtensions))
	assert.Equal(t, kms.SecretStatusSecretBox, updateUser.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, updateUser.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, updateUser.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.Equal(t, user.Description, updateUser.Description)
	// now check that a redacted password is not saved
	form.Set("s3_access_secret", redactedSecret)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	var lastUpdatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &lastUpdatedUser)
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.Equal(t, updateUser.FsConfig.S3Config.AccessSecret.GetPayload(), lastUpdatedUser.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, lastUpdatedUser.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, lastUpdatedUser.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	// now clear credentials
	form.Set("s3_access_key", "")
	form.Set("s3_access_secret", "")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var userGet dataprovider.User
	err = render.DecodeJSON(rr.Body, &userGet)
	assert.NoError(t, err)
	assert.True(t, userGet.FsConfig.S3Config.AccessSecret.IsEmpty())

	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestWebUserGCSMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, err := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	credentialsFilePath := filepath.Join(os.TempDir(), "gcs.json")
	err = createTestFile(credentialsFilePath, 0)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	user.FsConfig.GCSConfig.Bucket = "test"
	user.FsConfig.GCSConfig.KeyPrefix = "somedir/subdir/"
	user.FsConfig.GCSConfig.StorageClass = "standard"
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	form.Set("password", redactedSecret)
	form.Set("home_dir", user.HomeDir)
	form.Set("uid", "0")
	form.Set("gid", strconv.FormatInt(int64(user.GID), 10))
	form.Set("max_sessions", strconv.FormatInt(int64(user.MaxSessions), 10))
	form.Set("quota_size", strconv.FormatInt(user.QuotaSize, 10))
	form.Set("quota_files", strconv.FormatInt(int64(user.QuotaFiles), 10))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", "")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "2")
	form.Set("gcs_bucket", user.FsConfig.GCSConfig.Bucket)
	form.Set("gcs_storage_class", user.FsConfig.GCSConfig.StorageClass)
	form.Set("gcs_key_prefix", user.FsConfig.GCSConfig.KeyPrefix)
	form.Set("allowed_extensions", "/dir1::.jpg,.png")
	form.Set("max_upload_file_size", "0")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	b, contentType, _ = getMultipartFormData(form, "gcs_credential_file", credentialsFilePath)
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = createTestFile(credentialsFilePath, 4096)
	assert.NoError(t, err)
	b, contentType, _ = getMultipartFormData(form, "gcs_credential_file", credentialsFilePath)
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updateUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updateUser)
	assert.NoError(t, err)
	assert.Equal(t, int64(1577836800000), updateUser.ExpirationDate)
	assert.Equal(t, user.FsConfig.Provider, updateUser.FsConfig.Provider)
	assert.Equal(t, user.FsConfig.GCSConfig.Bucket, updateUser.FsConfig.GCSConfig.Bucket)
	assert.Equal(t, user.FsConfig.GCSConfig.StorageClass, updateUser.FsConfig.GCSConfig.StorageClass)
	assert.Equal(t, user.FsConfig.GCSConfig.KeyPrefix, updateUser.FsConfig.GCSConfig.KeyPrefix)
	assert.Equal(t, "/dir1", updateUser.Filters.FileExtensions[0].Path)
	form.Set("gcs_auto_credentials", "on")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	updateUser = dataprovider.User{}
	err = render.DecodeJSON(rr.Body, &updateUser)
	assert.NoError(t, err)
	assert.Equal(t, 1, updateUser.FsConfig.GCSConfig.AutomaticCredentials)
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = os.Remove(credentialsFilePath)
	assert.NoError(t, err)
}
func TestWebUserAzureBlobMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.Container = "container"
	user.FsConfig.AzBlobConfig.AccountName = "aname"
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("access-skey")
	user.FsConfig.AzBlobConfig.Endpoint = "http://127.0.0.1:9000/path?b=c"
	user.FsConfig.AzBlobConfig.KeyPrefix = "somedir/subdir/"
	user.FsConfig.AzBlobConfig.UploadPartSize = 5
	user.FsConfig.AzBlobConfig.UploadConcurrency = 4
	user.FsConfig.AzBlobConfig.UseEmulator = true
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	form.Set("password", redactedSecret)
	form.Set("home_dir", user.HomeDir)
	form.Set("uid", "0")
	form.Set("gid", strconv.FormatInt(int64(user.GID), 10))
	form.Set("max_sessions", strconv.FormatInt(int64(user.MaxSessions), 10))
	form.Set("quota_size", strconv.FormatInt(user.QuotaSize, 10))
	form.Set("quota_files", strconv.FormatInt(int64(user.QuotaFiles), 10))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", "")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "3")
	form.Set("az_container", user.FsConfig.AzBlobConfig.Container)
	form.Set("az_account_name", user.FsConfig.AzBlobConfig.AccountName)
	form.Set("az_account_key", user.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	form.Set("az_sas_url", user.FsConfig.AzBlobConfig.SASURL)
	form.Set("az_endpoint", user.FsConfig.AzBlobConfig.Endpoint)
	form.Set("az_key_prefix", user.FsConfig.AzBlobConfig.KeyPrefix)
	form.Set("az_use_emulator", "checked")
	form.Set("allowed_extensions", "/dir1::.jpg,.png")
	form.Set("denied_extensions", "/dir2::.zip")
	form.Set("max_upload_file_size", "0")
	// test invalid az_upload_part_size
	form.Set("az_upload_part_size", "a")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test invalid az_upload_concurrency
	form.Set("az_upload_part_size", strconv.FormatInt(user.FsConfig.AzBlobConfig.UploadPartSize, 10))
	form.Set("az_upload_concurrency", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now add the user
	form.Set("az_upload_concurrency", strconv.Itoa(user.FsConfig.AzBlobConfig.UploadConcurrency))
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updateUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updateUser)
	assert.NoError(t, err)
	assert.Equal(t, int64(1577836800000), updateUser.ExpirationDate)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.Container, user.FsConfig.AzBlobConfig.Container)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.AccountName, user.FsConfig.AzBlobConfig.AccountName)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.Endpoint, user.FsConfig.AzBlobConfig.Endpoint)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.SASURL, user.FsConfig.AzBlobConfig.SASURL)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.KeyPrefix, user.FsConfig.AzBlobConfig.KeyPrefix)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.UploadPartSize, user.FsConfig.AzBlobConfig.UploadPartSize)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.UploadConcurrency, user.FsConfig.AzBlobConfig.UploadConcurrency)
	assert.Equal(t, 2, len(updateUser.Filters.FileExtensions))
	assert.Equal(t, kms.SecretStatusSecretBox, updateUser.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	assert.Empty(t, updateUser.FsConfig.AzBlobConfig.AccountKey.GetKey())
	assert.Empty(t, updateUser.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	// now check that a redacted password is not saved
	form.Set("az_account_key", redactedSecret+" ")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var lastUpdatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &lastUpdatedUser)
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.AccountKey.GetPayload(), lastUpdatedUser.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	assert.Empty(t, lastUpdatedUser.FsConfig.AzBlobConfig.AccountKey.GetKey())
	assert.Empty(t, lastUpdatedUser.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestWebUserCryptMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("crypted passphrase")
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	form.Set("password", redactedSecret)
	form.Set("home_dir", user.HomeDir)
	form.Set("uid", "0")
	form.Set("gid", strconv.FormatInt(int64(user.GID), 10))
	form.Set("max_sessions", strconv.FormatInt(int64(user.MaxSessions), 10))
	form.Set("quota_size", strconv.FormatInt(user.QuotaSize, 10))
	form.Set("quota_files", strconv.FormatInt(int64(user.QuotaFiles), 10))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", "")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "4")
	form.Set("crypt_passphrase", "")
	form.Set("allowed_extensions", "/dir1::.jpg,.png")
	form.Set("denied_extensions", "/dir2::.zip")
	form.Set("max_upload_file_size", "0")
	// passphrase cannot be empty
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("crypt_passphrase", user.FsConfig.CryptConfig.Passphrase.GetPayload())
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updateUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updateUser)
	assert.NoError(t, err)
	assert.Equal(t, int64(1577836800000), updateUser.ExpirationDate)
	assert.Equal(t, 2, len(updateUser.Filters.FileExtensions))
	assert.Equal(t, kms.SecretStatusSecretBox, updateUser.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, updateUser.FsConfig.CryptConfig.Passphrase.GetKey())
	assert.Empty(t, updateUser.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	// now check that a redacted password is not saved
	form.Set("crypt_passphrase", redactedSecret+" ")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var lastUpdatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &lastUpdatedUser)
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.Equal(t, updateUser.FsConfig.CryptConfig.Passphrase.GetPayload(), lastUpdatedUser.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, lastUpdatedUser.FsConfig.CryptConfig.Passphrase.GetKey())
	assert.Empty(t, lastUpdatedUser.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestWebUserSFTPFsMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = dataprovider.SFTPFilesystemProvider
	user.FsConfig.SFTPConfig.Endpoint = "127.0.0.1:22"
	user.FsConfig.SFTPConfig.Username = "sftpuser"
	user.FsConfig.SFTPConfig.Password = kms.NewPlainSecret("pwd")
	user.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret(sftpPrivateKey)
	user.FsConfig.SFTPConfig.Fingerprints = []string{sftpPkeyFingerprint}
	user.FsConfig.SFTPConfig.Prefix = "/home/sftpuser"
	user.FsConfig.SFTPConfig.DisableCouncurrentReads = true
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	form.Set("password", redactedSecret)
	form.Set("home_dir", user.HomeDir)
	form.Set("uid", "0")
	form.Set("gid", strconv.FormatInt(int64(user.GID), 10))
	form.Set("max_sessions", strconv.FormatInt(int64(user.MaxSessions), 10))
	form.Set("quota_size", strconv.FormatInt(user.QuotaSize, 10))
	form.Set("quota_files", strconv.FormatInt(int64(user.QuotaFiles), 10))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", "")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "5")
	form.Set("crypt_passphrase", "")
	form.Set("allowed_extensions", "/dir1::.jpg,.png")
	form.Set("denied_extensions", "/dir2::.zip")
	form.Set("max_upload_file_size", "0")
	// empty sftpconfig
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("sftp_endpoint", user.FsConfig.SFTPConfig.Endpoint)
	form.Set("sftp_username", user.FsConfig.SFTPConfig.Username)
	form.Set("sftp_password", user.FsConfig.SFTPConfig.Password.GetPayload())
	form.Set("sftp_private_key", user.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	form.Set("sftp_fingerprints", user.FsConfig.SFTPConfig.Fingerprints[0])
	form.Set("sftp_prefix", user.FsConfig.SFTPConfig.Prefix)
	form.Set("sftp_disable_concurrent_reads", "true")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updateUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updateUser)
	assert.NoError(t, err)
	assert.Equal(t, int64(1577836800000), updateUser.ExpirationDate)
	assert.Equal(t, 2, len(updateUser.Filters.FileExtensions))
	assert.Equal(t, kms.SecretStatusSecretBox, updateUser.FsConfig.SFTPConfig.Password.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, updateUser.FsConfig.SFTPConfig.Password.GetKey())
	assert.Empty(t, updateUser.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.Equal(t, kms.SecretStatusSecretBox, updateUser.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Empty(t, updateUser.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.Empty(t, updateUser.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.Prefix, user.FsConfig.SFTPConfig.Prefix)
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.Username, user.FsConfig.SFTPConfig.Username)
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.Endpoint, user.FsConfig.SFTPConfig.Endpoint)
	assert.True(t, updateUser.FsConfig.SFTPConfig.DisableCouncurrentReads)
	assert.Len(t, updateUser.FsConfig.SFTPConfig.Fingerprints, 1)
	assert.Contains(t, updateUser.FsConfig.SFTPConfig.Fingerprints, sftpPkeyFingerprint)
	// now check that a redacted credentials are not saved
	form.Set("sftp_password", redactedSecret+" ")
	form.Set("sftp_private_key", redactedSecret)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var lastUpdatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &lastUpdatedUser)
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.SFTPConfig.Password.GetStatus())
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.Password.GetPayload(), lastUpdatedUser.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, lastUpdatedUser.FsConfig.SFTPConfig.Password.GetKey())
	assert.Empty(t, lastUpdatedUser.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.Equal(t, kms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.PrivateKey.GetPayload(), lastUpdatedUser.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Empty(t, lastUpdatedUser.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.Empty(t, lastUpdatedUser.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestAddWebFoldersMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	mappedPath := filepath.Clean(os.TempDir())
	folderName := filepath.Base(mappedPath)
	folderDesc := "a simple desc"
	form := make(url.Values)
	form.Set("mapped_path", mappedPath)
	form.Set("name", folderName)
	form.Set("description", folderDesc)
	req, err := http.NewRequest(http.MethodPost, webFolderPath, strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webFolderPath, strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	// adding the same folder will fail since the name must be unique
	req, err = http.NewRequest(http.MethodPost, webFolderPath, strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// invalid form
	req, err = http.NewRequest(http.MethodPost, webFolderPath, strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "text/plain; boundary=")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	// now render the add folder page
	req, err = http.NewRequest(http.MethodGet, webFolderPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	var folder vfs.BaseVirtualFolder
	req, _ = http.NewRequest(http.MethodGet, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &folder)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath, folder.MappedPath)
	assert.Equal(t, folderName, folder.Name)
	assert.Equal(t, folderDesc, folder.Description)
	// cleanup
	req, _ = http.NewRequest(http.MethodDelete, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestUpdateWebFolderMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	folderName := "vfolderupdate"
	folderDesc := "updated desc"
	folder := vfs.BaseVirtualFolder{
		Name:        folderName,
		MappedPath:  filepath.Join(os.TempDir(), "folderupdate"),
		Description: "dsc",
	}
	_, _, err = httpdtest.AddFolder(folder, http.StatusCreated)
	newMappedPath := folder.MappedPath + "1"
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("mapped_path", newMappedPath)
	form.Set("name", folderName)
	form.Set("description", folderDesc)
	form.Set(csrfFormToken, "")
	req, err := http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	req, _ = http.NewRequest(http.MethodGet, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &folder)
	assert.NoError(t, err)
	assert.Equal(t, newMappedPath, folder.MappedPath)
	assert.Equal(t, folderName, folder.Name)
	assert.Equal(t, folderDesc, folder.Description)

	// parse form error
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName)+"??a=a%B3%A2%G3", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName+"1"), strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	form.Set("mapped_path", "arelative/path")
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	// render update folder page
	req, err = http.NewRequest(http.MethodGet, path.Join(webFolderPath, folderName), nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(webFolderPath, folderName+"1"), nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webFolderPath, folderName), nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid token")

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webFolderPath, folderName), nil)
	setJWTCookieForReq(req, apiToken) // api token is not accepted
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webFolderPath, folderName), nil)
	setJWTCookieForReq(req, webToken)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestWebFoldersMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	mappedPath1 := filepath.Join(os.TempDir(), "vfolder1")
	mappedPath2 := filepath.Join(os.TempDir(), "vfolder2")
	folderName1 := filepath.Base(mappedPath1)
	folderName2 := filepath.Base(mappedPath2)
	folderDesc1 := "vfolder1 desc"
	folderDesc2 := "vfolder2 desc"
	folders := []vfs.BaseVirtualFolder{
		{
			Name:        folderName1,
			MappedPath:  mappedPath1,
			Description: folderDesc1,
		},
		{
			Name:        folderName2,
			MappedPath:  mappedPath2,
			Description: folderDesc2,
		},
	}
	for _, folder := range folders {
		folderAsJSON, err := json.Marshal(folder)
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
		assert.NoError(t, err)
		setBearerForReq(req, apiToken)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusCreated, rr)
	}

	req, err := http.NewRequest(http.MethodGet, folderPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var foldersGet []vfs.BaseVirtualFolder
	err = render.DecodeJSON(rr.Body, &foldersGet)
	assert.NoError(t, err)
	numFound := 0
	for _, f := range foldersGet {
		if f.Name == folderName1 {
			assert.Equal(t, mappedPath1, f.MappedPath)
			assert.Equal(t, folderDesc1, f.Description)
			numFound++
		}
		if f.Name == folderName2 {
			assert.Equal(t, mappedPath2, f.MappedPath)
			assert.Equal(t, folderDesc2, f.Description)
			numFound++
		}
	}
	assert.Equal(t, 2, numFound)

	req, err = http.NewRequest(http.MethodGet, webFoldersPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, err = http.NewRequest(http.MethodGet, webFoldersPath+"?qlimit=a", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, err = http.NewRequest(http.MethodGet, webFoldersPath+"?qlimit=1", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	for _, folder := range folders {
		req, _ := http.NewRequest(http.MethodDelete, path.Join(folderPath, folder.Name), nil)
		setBearerForReq(req, apiToken)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
	}
}

func TestProviderClosedMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	dataprovider.Close()
	req, _ := http.NewRequest(http.MethodGet, webFoldersPath, nil)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	req, _ = http.NewRequest(http.MethodGet, webUsersPath, nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	req, _ = http.NewRequest(http.MethodGet, webUserPath+"/0", nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", "test")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/0", strings.NewReader(form.Encode()))
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(webAdminPath, defaultTokenAuthUser), nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, defaultTokenAuthUser), strings.NewReader(form.Encode()))
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	req, _ = http.NewRequest(http.MethodGet, webAdminsPath, nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	req, _ = http.NewRequest(http.MethodGet, path.Join(webFolderPath, defaultTokenAuthUser), nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	req, _ = http.NewRequest(http.MethodPost, path.Join(webFolderPath, defaultTokenAuthUser), strings.NewReader(form.Encode()))
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestWebConnectionsMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, webConnectionsPath, nil)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webConnectionsPath, "id"), nil)
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid token")

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webConnectionsPath, "id"), nil)
	setJWTCookieForReq(req, token)
	setCSRFHeaderForReq(req, "csrfToken")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid token")

	csrfToken, err := getCSRFToken()
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodDelete, path.Join(webConnectionsPath, "id"), nil)
	setJWTCookieForReq(req, token)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestGetWebStatusMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, webStatusPath, nil)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestStaticFilesMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/static/favicon.ico", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
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

func getTestAdmin() dataprovider.Admin {
	return dataprovider.Admin{
		Username:    defaultTokenAuthUser,
		Password:    defaultTokenAuthPass,
		Status:      1,
		Permissions: []string{dataprovider.PermAdminAny},
		Email:       "admin@example.com",
		Description: "test admin",
	}
}

func getTestUser() dataprovider.User {
	user := dataprovider.User{
		Username:    defaultUsername,
		Password:    defaultPassword,
		HomeDir:     filepath.Join(homeBasePath, defaultUsername),
		Status:      1,
		Description: "test user",
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = defaultPerms
	return user
}

func getUserAsJSON(t *testing.T, user dataprovider.User) []byte {
	json, err := json.Marshal(user)
	assert.NoError(t, err)
	return json
}

func getCSRFToken() (string, error) {
	req, err := http.NewRequest(http.MethodGet, httpBaseURL+webLoginPath, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpclient.GetHTTPClient().Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return "", err
	}

	var csrfToken string
	var f func(*html.Node)

	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				if attr.Key == "value" {
					value = attr.Val
				}
				if attr.Key == "name" {
					name = attr.Val
				}
			}
			if name == csrfFormToken {
				csrfToken = value
				return
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}

	f(doc)

	return csrfToken, nil
}

func getAdminLoginForm(username, password, csrfToken string) url.Values {
	form := make(url.Values)
	form.Set("username", username)
	form.Set("password", password)
	form.Set(csrfFormToken, csrfToken)
	return form
}

func setCSRFHeaderForReq(req *http.Request, csrfToken string) {
	req.Header.Set("X-CSRF-TOKEN", csrfToken)
}

func setBearerForReq(req *http.Request, jwtToken string) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", jwtToken))
}

func setJWTCookieForReq(req *http.Request, jwtToken string) {
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", jwtToken))
}

func getJWTAPITokenFromTestServer(username, password string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, "/api/v2/token", nil)
	req.SetBasicAuth(username, password)
	rr := executeRequest(req)
	if rr.Code != http.StatusOK {
		return "", fmt.Errorf("unexpected  status code %v", rr)
	}
	responseHolder := make(map[string]interface{})
	err := render.DecodeJSON(rr.Body, &responseHolder)
	if err != nil {
		return "", err
	}
	return responseHolder["access_token"].(string), nil
}

func getJWTWebToken(username, password string) (string, error) {
	csrfToken, err := getCSRFToken()
	if err != nil {
		return "", err
	}
	form := getAdminLoginForm(username, password, csrfToken)
	req, _ := http.NewRequest(http.MethodPost, httpBaseURL+webLoginPath,
		bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("unexpected  status code %v", resp.StatusCode)
	}
	cookie := resp.Header.Get("Set-Cookie")
	if strings.HasPrefix(cookie, "jwt=") {
		return cookie[4:], nil
	}
	return "", errors.New("no cookie found")
}

func getJWTWebTokenFromTestServer(username, password string) (string, error) {
	csrfToken, err := getCSRFToken()
	if err != nil {
		return "", err
	}
	form := getAdminLoginForm(username, password, csrfToken)
	req, _ := http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	if rr.Code != http.StatusFound {
		return "", fmt.Errorf("unexpected  status code %v", rr)
	}
	cookie := strings.Split(rr.Header().Get("Set-Cookie"), ";")
	if strings.HasPrefix(cookie[0], "jwt=") {
		return cookie[0][4:], nil
	}
	return "", errors.New("no cookie found")
}

func executeRequest(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	return rr
}

func checkResponseCode(t *testing.T, expected int, rr *httptest.ResponseRecorder) {
	assert.Equal(t, expected, rr.Code, rr.Body.String())
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
	if size > 0 {
		_, err := rand.Read(content)
		if err != nil {
			return err
		}
	}
	return os.WriteFile(path, content, os.ModePerm)
}

func getMultipartFormData(values url.Values, fileFieldName, filePath string) (bytes.Buffer, string, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range values {
		for _, s := range v {
			if err := w.WriteField(k, s); err != nil {
				return b, "", err
			}
		}
	}
	if len(fileFieldName) > 0 && len(filePath) > 0 {
		fw, err := w.CreateFormFile(fileFieldName, filepath.Base(filePath))
		if err != nil {
			return b, "", err
		}
		f, err := os.Open(filePath)
		if err != nil {
			return b, "", err
		}
		defer f.Close()
		if _, err = io.Copy(fw, f); err != nil {
			return b, "", err
		}
	}
	err := w.Close()
	return b, w.FormDataContentType(), err
}

func BenchmarkSecretDecryption(b *testing.B) {
	s := kms.NewPlainSecret("test data")
	s.SetAdditionalData("username")
	err := s.Encrypt()
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		err = s.Clone().Decrypt()
		require.NoError(b, err)
	}
}
