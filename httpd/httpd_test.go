package httpd_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/render"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/lithammer/shortuuid/v3"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mhale/smtpd"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/sftpgo/sdk"
	sdkkms "github.com/sftpgo/sdk/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/html"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/httpd"
	"github.com/drakkan/sftpgo/v2/httpdtest"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/sftpd"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	defaultUsername                 = "test_user"
	defaultPassword                 = "test_password"
	testPubKey                      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	testPubKey1                     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCd60+/j+y8f0tLftihWV1YN9RSahMI9btQMDIMqts/jeNbD8jgoogM3nhF7KxfcaMKURuD47KC4Ey6iAJUJ0sWkSNNxOcIYuvA+5MlspfZDsa8Ag76Fe1vyz72WeHMHMeh/hwFo2TeIeIXg480T1VI6mzfDrVp2GzUx0SS0dMsQBjftXkuVR8YOiOwMCAH2a//M1OrvV7d/NBk6kBN0WnuIBb2jKm15PAA7+jQQG7tzwk2HedNH3jeL5GH31xkSRwlBczRK0xsCQXehAlx6cT/e/s44iJcJTHfpPKoSk6UAhPJYe7Z1QnuoawY9P9jQaxpyeImBZxxUEowhjpj2avBxKdRGBVK8R7EL8tSOeLbhdyWe5Mwc1+foEbq9Zz5j5Kd+hn3Wm1UnsGCrXUUUoZp1jnlNl0NakCto+5KmqnT9cHxaY+ix2RLUWAZyVFlRq71OYux1UHJnEJPiEI1/tr4jFBSL46qhQZv/TfpkfVW8FLz0lErfqu0gQEZnNHr3Fc= nicola@p1"
	defaultTokenAuthUser            = "admin"
	defaultTokenAuthPass            = "password"
	altAdminUsername                = "newTestAdmin"
	altAdminPassword                = "password1"
	csrfFormToken                   = "_form_token"
	tokenPath                       = "/api/v2/token"
	userTokenPath                   = "/api/v2/user/token"
	userLogoutPath                  = "/api/v2/user/logout"
	userPath                        = "/api/v2/users"
	adminPath                       = "/api/v2/admins"
	adminPwdPath                    = "/api/v2/admin/changepwd"
	folderPath                      = "/api/v2/folders"
	activeConnectionsPath           = "/api/v2/connections"
	serverStatusPath                = "/api/v2/status"
	quotasBasePath                  = "/api/v2/quotas"
	quotaScanPath                   = "/api/v2/quotas/users/scans"
	quotaScanVFolderPath            = "/api/v2/quotas/folders/scans"
	quotaScanCompatPath             = "/api/v2/quota-scans"
	quotaScanVFolderCompatPath      = "/api/v2/folder-quota-scans"
	updateUsedQuotaCompatPath       = "/api/v2/quota-update"
	updateFolderUsedQuotaCompatPath = "/api/v2/folder-quota-update"
	defenderHosts                   = "/api/v2/defender/hosts"
	defenderBanTime                 = "/api/v2/defender/bantime"
	defenderUnban                   = "/api/v2/defender/unban"
	defenderScore                   = "/api/v2/defender/score"
	versionPath                     = "/api/v2/version"
	logoutPath                      = "/api/v2/logout"
	userPwdPath                     = "/api/v2/user/changepwd"
	userPublicKeysPath              = "/api/v2/user/publickeys"
	userDirsPath                    = "/api/v2/user/dirs"
	userFilesPath                   = "/api/v2/user/files"
	userStreamZipPath               = "/api/v2/user/streamzip"
	userUploadFilePath              = "/api/v2/user/files/upload"
	userFilesDirsMetadataPath       = "/api/v2/user/files/metadata"
	apiKeysPath                     = "/api/v2/apikeys"
	adminTOTPConfigsPath            = "/api/v2/admin/totp/configs"
	adminTOTPGeneratePath           = "/api/v2/admin/totp/generate"
	adminTOTPValidatePath           = "/api/v2/admin/totp/validate"
	adminTOTPSavePath               = "/api/v2/admin/totp/save"
	admin2FARecoveryCodesPath       = "/api/v2/admin/2fa/recoverycodes"
	adminProfilePath                = "/api/v2/admin/profile"
	userTOTPConfigsPath             = "/api/v2/user/totp/configs"
	userTOTPGeneratePath            = "/api/v2/user/totp/generate"
	userTOTPValidatePath            = "/api/v2/user/totp/validate"
	userTOTPSavePath                = "/api/v2/user/totp/save"
	user2FARecoveryCodesPath        = "/api/v2/user/2fa/recoverycodes"
	userProfilePath                 = "/api/v2/user/profile"
	userSharesPath                  = "/api/v2/user/shares"
	retentionBasePath               = "/api/v2/retention/users"
	metadataBasePath                = "/api/v2/metadata/users"
	fsEventsPath                    = "/api/v2/events/fs"
	providerEventsPath              = "/api/v2/events/provider"
	sharesPath                      = "/api/v2/shares"
	healthzPath                     = "/healthz"
	webBasePath                     = "/web"
	webBasePathAdmin                = "/web/admin"
	webAdminSetupPath               = "/web/admin/setup"
	webLoginPath                    = "/web/admin/login"
	webLogoutPath                   = "/web/admin/logout"
	webUsersPath                    = "/web/admin/users"
	webUserPath                     = "/web/admin/user"
	webFoldersPath                  = "/web/admin/folders"
	webFolderPath                   = "/web/admin/folder"
	webConnectionsPath              = "/web/admin/connections"
	webStatusPath                   = "/web/admin/status"
	webAdminsPath                   = "/web/admin/managers"
	webAdminPath                    = "/web/admin/manager"
	webMaintenancePath              = "/web/admin/maintenance"
	webRestorePath                  = "/web/admin/restore"
	webChangeAdminPwdPath           = "/web/admin/changepwd"
	webAdminProfilePath             = "/web/admin/profile"
	webTemplateUser                 = "/web/admin/template/user"
	webTemplateFolder               = "/web/admin/template/folder"
	webDefenderPath                 = "/web/admin/defender"
	webAdminTwoFactorPath           = "/web/admin/twofactor"
	webAdminTwoFactorRecoveryPath   = "/web/admin/twofactor-recovery"
	webAdminMFAPath                 = "/web/admin/mfa"
	webAdminTOTPSavePath            = "/web/admin/totp/save"
	webAdminForgotPwdPath           = "/web/admin/forgot-password"
	webAdminResetPwdPath            = "/web/admin/reset-password"
	webBasePathClient               = "/web/client"
	webClientLoginPath              = "/web/client/login"
	webClientFilesPath              = "/web/client/files"
	webClientEditFilePath           = "/web/client/editfile"
	webClientDirsPath               = "/web/client/dirs"
	webClientDownloadZipPath        = "/web/client/downloadzip"
	webChangeClientPwdPath          = "/web/client/changepwd"
	webClientProfilePath            = "/web/client/profile"
	webClientTwoFactorPath          = "/web/client/twofactor"
	webClientTwoFactorRecoveryPath  = "/web/client/twofactor-recovery"
	webClientLogoutPath             = "/web/client/logout"
	webClientMFAPath                = "/web/client/mfa"
	webClientTOTPSavePath           = "/web/client/totp/save"
	webClientSharesPath             = "/web/client/shares"
	webClientSharePath              = "/web/client/share"
	webClientPubSharesPath          = "/web/client/pubshares"
	webClientForgotPwdPath          = "/web/client/forgot-password"
	webClientResetPwdPath           = "/web/client/reset-password"
	webClientViewPDFPath            = "/web/client/viewpdf"
	httpBaseURL                     = "http://127.0.0.1:8081"
	defaultRemoteAddr               = "127.0.0.1:1234"
	sftpServerAddr                  = "127.0.0.1:8022"
	smtpServerAddr                  = "127.0.0.1:3525"
	configDir                       = ".."
	httpsCert                       = `-----BEGIN CERTIFICATE-----
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
	osWindows           = "windows"
	oidcMockAddr        = "127.0.0.1:11111"
)

var (
	defaultPerms       = []string{dataprovider.PermAny}
	homeBasePath       string
	backupsPath        string
	credentialsPath    string
	testServer         *httptest.Server
	providerDriverName string
	postConnectPath    string
	preActionPath      string
	lastResetCode      string
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

func (c *fakeConnection) GetLocalAddress() string {
	return ""
}

func (c *fakeConnection) GetRemoteAddress() string {
	return ""
}

type generateTOTPRequest struct {
	ConfigName string `json:"config_name"`
}

type generateTOTPResponse struct {
	ConfigName string `json:"config_name"`
	Issuer     string `json:"issuer"`
	Secret     string `json:"secret"`
	QRCode     []byte `json:"qr_code"`
}

type validateTOTPRequest struct {
	ConfigName string `json:"config_name"`
	Passcode   string `json:"passcode"`
	Secret     string `json:"secret"`
}

type recoveryCode struct {
	Code string `json:"code"`
	Used bool   `json:"used"`
}

func TestMain(m *testing.M) {
	homeBasePath = os.TempDir()
	logfilePath := filepath.Join(configDir, "sftpgo_api_test.log")
	logger.InitLogger(logfilePath, 5, 1, 28, false, false, zerolog.DebugLevel)
	os.Setenv("SFTPGO_COMMON__UPLOAD_MODE", "2")
	os.Setenv("SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", "1")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_USERNAME", "admin")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_PASSWORD", "password")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__0__WEB_CLIENT_INTEGRATIONS__0__URL", "http://127.0.0.1/test.html")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__0__WEB_CLIENT_INTEGRATIONS__0__FILE_EXTENSIONS", ".pdf,.txt")
	err := config.LoadConfig(configDir, "")
	if err != nil {
		logger.WarnToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	wdPath, err := os.Getwd()
	if err != nil {
		logger.WarnToConsole("error getting exe path: %v", err)
		os.Exit(1)
	}
	pluginsConfig := []plugin.Config{
		{
			Type:     "eventsearcher",
			Cmd:      filepath.Join(wdPath, "..", "tests", "eventsearcher", "eventsearcher"),
			AutoMTLS: true,
		},
	}
	if runtime.GOOS == osWindows {
		pluginsConfig[0].Cmd += ".exe"
	}
	providerConf := config.GetProviderConf()
	credentialsPath = filepath.Join(os.TempDir(), "test_credentials")
	providerConf.CredentialsPath = credentialsPath
	providerDriverName = providerConf.Driver
	os.RemoveAll(credentialsPath) //nolint:errcheck
	logger.InfoToConsole("Starting HTTPD tests, provider: %v", providerConf.Driver)

	err = common.Initialize(config.GetCommonConfig(), 0)
	if err != nil {
		logger.WarnToConsole("error initializing common: %v", err)
		os.Exit(1)
	}

	backupsPath = filepath.Join(os.TempDir(), "test_backups")
	providerConf.BackupsPath = backupsPath
	err = os.MkdirAll(backupsPath, os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error creating backups path: %v", err)
		os.Exit(1)
	}

	err = dataprovider.Initialize(providerConf, configDir, true)
	if err != nil {
		logger.WarnToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	postConnectPath = filepath.Join(homeBasePath, "postconnect.sh")
	preActionPath = filepath.Join(homeBasePath, "preaction.sh")

	httpConfig := config.GetHTTPConfig()
	httpConfig.RetryMax = 1
	httpConfig.Timeout = 5
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
	err = plugin.Initialize(pluginsConfig, true)
	if err != nil {
		logger.ErrorToConsole("error initializing plugin: %v", err)
		os.Exit(1)
	}

	httpdConf := config.GetHTTPDConfig()

	httpdConf.Bindings[0].Port = 8081
	httpdConf.Bindings[0].Security = httpd.SecurityConf{
		Enabled: true,
		HTTPSProxyHeaders: []httpd.HTTPSProxyHeader{
			{
				Key:   "X-Forwarded-Proto",
				Value: "https",
			},
		},
	}
	httpdtest.SetBaseURL(httpBaseURL)
	// required to test sftpfs
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port: 8022,
		},
	}
	hostKeyPath := filepath.Join(os.TempDir(), "id_rsa")
	sftpdConf.HostKeys = []string{hostKeyPath}

	go func() {
		if err := httpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start SFTP server: %v", err)
			os.Exit(1)
		}
	}()

	startSMTPServer()
	startOIDCMockServer()

	waitTCPListening(httpdConf.Bindings[0].GetAddress())
	waitTCPListening(sftpdConf.Bindings[0].GetAddress())
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

	testServer = httptest.NewServer(httpd.GetHTTPRouter(httpdConf.Bindings[0]))
	defer testServer.Close()

	exitCode := m.Run()
	os.Remove(logfilePath)
	os.RemoveAll(backupsPath)
	os.RemoveAll(credentialsPath)
	os.Remove(certPath)
	os.Remove(keyPath)
	os.Remove(hostKeyPath)
	os.Remove(hostKeyPath + ".pub")
	os.Remove(postConnectPath)
	os.Remove(preActionPath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	invalidFile := "invalid file"
	httpdConf := config.GetHTTPDConfig()
	defaultTemplatesPath := httpdConf.TemplatesPath
	defaultStaticPath := httpdConf.StaticFilesPath
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
	httpdConf.TemplatesPath = defaultTemplatesPath
	httpdConf.CertificateFile = invalidFile
	httpdConf.CertificateKeyFile = invalidFile
	httpdConf.StaticFilesPath = ""
	httpdConf.TemplatesPath = ""
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)
	httpdConf.StaticFilesPath = defaultStaticPath
	httpdConf.TemplatesPath = defaultTemplatesPath
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
	httpdConf.Bindings[0].ProxyAllowed = []string{"invalid ip/network"}
	err = httpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is not a valid IP range")
	}
	httpdConf.Bindings[0].ProxyAllowed = nil
	httpdConf.Bindings[0].EnableWebAdmin = false
	httpdConf.Bindings[0].EnableWebClient = false
	httpdConf.Bindings[0].Port = 8081
	httpdConf.Bindings[0].EnableHTTPS = true
	httpdConf.Bindings[0].ClientAuthType = 1
	err = httpdConf.Initialize(configDir)
	assert.Error(t, err)

	httpdConf.Bindings[0].OIDC = httpd.OIDC{
		ClientID:     "123",
		ClientSecret: "secret",
		ConfigURL:    "http://127.0.0.1:11111",
	}
	err = httpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "oidc")
	}
	httpdConf.Bindings[0].OIDC.UsernameField = "preferred_username"
	err = httpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "oidc")
	}
}

func TestBasicUserHandling(t *testing.T) {
	u := getTestUser()
	u.Email = "user@user.com"
	user, resp, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	user.MaxSessions = 10
	user.QuotaSize = 4096
	user.QuotaFiles = 2
	user.UploadBandwidth = 128
	user.DownloadBandwidth = 64
	user.ExpirationDate = util.GetTimeAsMsSinceEpoch(time.Now())
	user.AdditionalInfo = "some free text"
	user.Filters.TLSUsername = sdk.TLSUsernameCN
	user.Email = "user@example.net"
	user.Filters.WebClient = append(user.Filters.WebClient, sdk.WebClientPubKeyChangeDisabled,
		sdk.WebClientWriteDisabled)
	originalUser := user
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, originalUser.ID, user.ID)

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)

	user.Email = "invalid@email"
	_, body, err := httpdtest.UpdateUser(user, http.StatusBadRequest, "")
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Validation error: email")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserTransferLimits(t *testing.T) {
	u := getTestUser()
	u.TotalDataTransfer = 100
	u.Filters.DataTransferLimits = []sdk.DataTransferLimit{
		{
			Sources: nil,
		},
	}
	_, resp, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err, string(resp))
	assert.Contains(t, string(resp), "Validation error: no data transfer limit source specified")
	u.Filters.DataTransferLimits = []sdk.DataTransferLimit{
		{
			Sources: []string{"a"},
		},
	}
	_, resp, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err, string(resp))
	assert.Contains(t, string(resp), "Validation error: could not parse data transfer limit source")
	u.Filters.DataTransferLimits = []sdk.DataTransferLimit{
		{
			Sources:              []string{"127.0.0.1/32"},
			UploadDataTransfer:   120,
			DownloadDataTransfer: 140,
		},
		{
			Sources:           []string{"192.168.0.0/24", "192.168.1.0/24"},
			TotalDataTransfer: 400,
		},
		{
			Sources: []string{"10.0.0.0/8"},
		},
	}
	user, resp, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	assert.Len(t, user.Filters.DataTransferLimits, 3)
	assert.Equal(t, u.Filters.DataTransferLimits, user.Filters.DataTransferLimits)
	up, down, total := user.GetDataTransferLimits("1.1.1.1")
	assert.Equal(t, user.TotalDataTransfer*1024*1024, total)
	assert.Equal(t, user.UploadDataTransfer*1024*1024, up)
	assert.Equal(t, user.DownloadDataTransfer*1024*1024, down)
	up, down, total = user.GetDataTransferLimits("127.0.0.1")
	assert.Equal(t, user.Filters.DataTransferLimits[0].TotalDataTransfer*1024*1024, total)
	assert.Equal(t, user.Filters.DataTransferLimits[0].UploadDataTransfer*1024*1024, up)
	assert.Equal(t, user.Filters.DataTransferLimits[0].DownloadDataTransfer*1024*1024, down)
	up, down, total = user.GetDataTransferLimits("192.168.1.6")
	assert.Equal(t, user.Filters.DataTransferLimits[1].TotalDataTransfer*1024*1024, total)
	assert.Equal(t, user.Filters.DataTransferLimits[1].UploadDataTransfer*1024*1024, up)
	assert.Equal(t, user.Filters.DataTransferLimits[1].DownloadDataTransfer*1024*1024, down)
	up, down, total = user.GetDataTransferLimits("10.1.2.3")
	assert.Equal(t, user.Filters.DataTransferLimits[2].TotalDataTransfer*1024*1024, total)
	assert.Equal(t, user.Filters.DataTransferLimits[2].UploadDataTransfer*1024*1024, up)
	assert.Equal(t, user.Filters.DataTransferLimits[2].DownloadDataTransfer*1024*1024, down)

	connID := xid.New().String()
	localAddr := "::1"
	conn := common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "1.1.1.2", user)
	transferQuota := conn.GetTransferQuota()
	assert.Equal(t, user.TotalDataTransfer*1024*1024, transferQuota.AllowedTotalSize)
	assert.Equal(t, user.UploadDataTransfer*1024*1024, transferQuota.AllowedULSize)
	assert.Equal(t, user.DownloadDataTransfer*1024*1024, transferQuota.AllowedDLSize)

	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "127.0.0.1", user)
	transferQuota = conn.GetTransferQuota()
	assert.Equal(t, user.Filters.DataTransferLimits[0].TotalDataTransfer*1024*1024, transferQuota.AllowedTotalSize)
	assert.Equal(t, user.Filters.DataTransferLimits[0].UploadDataTransfer*1024*1024, transferQuota.AllowedULSize)
	assert.Equal(t, user.Filters.DataTransferLimits[0].DownloadDataTransfer*1024*1024, transferQuota.AllowedDLSize)

	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "192.168.1.5", user)
	transferQuota = conn.GetTransferQuota()
	assert.Equal(t, user.Filters.DataTransferLimits[1].TotalDataTransfer*1024*1024, transferQuota.AllowedTotalSize)
	assert.Equal(t, user.Filters.DataTransferLimits[1].UploadDataTransfer*1024*1024, transferQuota.AllowedULSize)
	assert.Equal(t, user.Filters.DataTransferLimits[1].DownloadDataTransfer*1024*1024, transferQuota.AllowedDLSize)

	u.UsedDownloadDataTransfer = 10 * 1024 * 1024
	u.UsedUploadDataTransfer = 5 * 1024 * 1024
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "", http.StatusOK)
	assert.NoError(t, err)

	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "192.168.1.6", user)
	transferQuota = conn.GetTransferQuota()
	assert.Equal(t, (user.Filters.DataTransferLimits[1].TotalDataTransfer-15)*1024*1024, transferQuota.AllowedTotalSize)
	assert.Equal(t, user.Filters.DataTransferLimits[1].UploadDataTransfer*1024*1024, transferQuota.AllowedULSize)
	assert.Equal(t, user.Filters.DataTransferLimits[1].DownloadDataTransfer*1024*1024, transferQuota.AllowedDLSize)

	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "10.8.3.4", user)
	transferQuota = conn.GetTransferQuota()
	assert.Equal(t, int64(0), transferQuota.AllowedTotalSize)
	assert.Equal(t, int64(0), transferQuota.AllowedULSize)
	assert.Equal(t, int64(0), transferQuota.AllowedDLSize)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserBandwidthLimits(t *testing.T) {
	u := getTestUser()
	u.UploadBandwidth = 128
	u.DownloadBandwidth = 96
	u.Filters.BandwidthLimits = []sdk.BandwidthLimit{
		{
			Sources: []string{"1"},
		},
	}
	_, resp, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err, string(resp))
	assert.Contains(t, string(resp), "Validation error: could not parse bandwidth limit source")
	u.Filters.BandwidthLimits = []sdk.BandwidthLimit{
		{
			Sources: nil,
		},
	}
	_, resp, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err, string(resp))
	assert.Contains(t, string(resp), "Validation error: no bandwidth limit source specified")
	u.Filters.BandwidthLimits = []sdk.BandwidthLimit{
		{
			Sources:         []string{"127.0.0.0/8", "::1/128"},
			UploadBandwidth: 256,
		},
		{
			Sources:           []string{"10.0.0.0/8"},
			UploadBandwidth:   512,
			DownloadBandwidth: 256,
		},
	}
	user, resp, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	assert.Len(t, user.Filters.BandwidthLimits, 2)
	assert.Equal(t, u.Filters.BandwidthLimits, user.Filters.BandwidthLimits)

	connID := xid.New().String()
	localAddr := "127.0.0.1"
	up, down := user.GetBandwidthForIP("127.0.1.1", connID)
	assert.Equal(t, int64(256), up)
	assert.Equal(t, int64(0), down)
	conn := common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "127.0.1.1", user)
	assert.Equal(t, int64(256), conn.User.UploadBandwidth)
	assert.Equal(t, int64(0), conn.User.DownloadBandwidth)
	up, down = user.GetBandwidthForIP("10.1.2.3", connID)
	assert.Equal(t, int64(512), up)
	assert.Equal(t, int64(256), down)
	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "10.2.1.4:1234", user)
	assert.Equal(t, int64(512), conn.User.UploadBandwidth)
	assert.Equal(t, int64(256), conn.User.DownloadBandwidth)
	up, down = user.GetBandwidthForIP("192.168.1.2", connID)
	assert.Equal(t, int64(128), up)
	assert.Equal(t, int64(96), down)
	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "172.16.0.1", user)
	assert.Equal(t, int64(128), conn.User.UploadBandwidth)
	assert.Equal(t, int64(96), conn.User.DownloadBandwidth)
	up, down = user.GetBandwidthForIP("invalid", connID)
	assert.Equal(t, int64(128), up)
	assert.Equal(t, int64(96), down)
	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "172.16.0", user)
	assert.Equal(t, int64(128), conn.User.UploadBandwidth)
	assert.Equal(t, int64(96), conn.User.DownloadBandwidth)

	user.Filters.BandwidthLimits = []sdk.BandwidthLimit{
		{
			Sources:           []string{"10.0.0.0/24"},
			UploadBandwidth:   256,
			DownloadBandwidth: 512,
		},
	}
	user, resp, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(resp))
	if assert.Len(t, user.Filters.BandwidthLimits, 1) {
		bwLimit := user.Filters.BandwidthLimits[0]
		assert.Equal(t, []string{"10.0.0.0/24"}, bwLimit.Sources)
		assert.Equal(t, int64(256), bwLimit.UploadBandwidth)
		assert.Equal(t, int64(512), bwLimit.DownloadBandwidth)
	}
	up, down = user.GetBandwidthForIP("10.1.2.3", connID)
	assert.Equal(t, int64(128), up)
	assert.Equal(t, int64(96), down)
	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "172.16.0.2", user)
	assert.Equal(t, int64(128), conn.User.UploadBandwidth)
	assert.Equal(t, int64(96), conn.User.DownloadBandwidth)
	up, down = user.GetBandwidthForIP("10.0.0.26", connID)
	assert.Equal(t, int64(256), up)
	assert.Equal(t, int64(512), down)
	conn = common.NewBaseConnection(connID, common.ProtocolHTTP, localAddr, "10.0.0.28", user)
	assert.Equal(t, int64(256), conn.User.UploadBandwidth)
	assert.Equal(t, int64(512), conn.User.DownloadBandwidth)

	// this works if we remove the omitempty tag from BandwidthLimits
	/*user.Filters.BandwidthLimits = nil
	user, resp, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(resp))
	assert.Len(t, user.Filters.BandwidthLimits, 0)*/

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserTimestamps(t *testing.T) {
	user, resp, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err, string(resp))
	createdAt := user.CreatedAt
	updatedAt := user.UpdatedAt
	assert.Equal(t, int64(0), user.LastLogin)
	assert.Greater(t, createdAt, int64(0))
	assert.Greater(t, updatedAt, int64(0))
	mappedPath := filepath.Join(os.TempDir(), "mapped_dir")
	folderName := filepath.Base(mappedPath)
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir",
	})
	time.Sleep(10 * time.Millisecond)
	user, resp, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(resp))
	assert.Equal(t, int64(0), user.LastLogin)
	assert.Equal(t, createdAt, user.CreatedAt)
	assert.Greater(t, user.UpdatedAt, updatedAt)
	updatedAt = user.UpdatedAt
	// after a folder update or delete the user updated_at field should change
	folder, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folder.Users, 1)
	time.Sleep(10 * time.Millisecond)
	_, _, err = httpdtest.UpdateFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), user.LastLogin)
	assert.Equal(t, createdAt, user.CreatedAt)
	assert.Greater(t, user.UpdatedAt, updatedAt)
	updatedAt = user.UpdatedAt
	time.Sleep(10 * time.Millisecond)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), user.LastLogin)
	assert.Equal(t, createdAt, user.CreatedAt)
	assert.Greater(t, user.UpdatedAt, updatedAt)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestAdminTimestamps(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)
	createdAt := admin.CreatedAt
	updatedAt := admin.UpdatedAt
	assert.Equal(t, int64(0), admin.LastLogin)
	assert.Greater(t, createdAt, int64(0))
	assert.Greater(t, updatedAt, int64(0))
	time.Sleep(10 * time.Millisecond)
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), admin.LastLogin)
	assert.Equal(t, createdAt, admin.CreatedAt)
	assert.Greater(t, admin.UpdatedAt, updatedAt)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestHTTPUserAuthentication(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	c := httpclient.GetHTTPClient()
	resp, err := c.Do(req)
	c.CloseIdleConnections()
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	responseHolder := make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	assert.NoError(t, err)
	userToken := responseHolder["access_token"].(string)
	assert.NotEmpty(t, userToken)
	err = resp.Body.Close()
	assert.NoError(t, err)
	// login with wrong credentials
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, "")
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, "wrong pwd")
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	respBody, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(respBody), "invalid credentials")
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth("wrong username", defaultPassword)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	respBody, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(respBody), "invalid credentials")
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, tokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultTokenAuthUser, defaultTokenAuthPass)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	responseHolder = make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	assert.NoError(t, err)
	adminToken := responseHolder["access_token"].(string)
	assert.NotEmpty(t, adminToken)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, versionPath), nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", adminToken))
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)
	// using the user token should not work
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, versionPath), nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", userToken))
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userPublicKeysPath), nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", userToken))
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)
	// using the admin token should not work
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userPublicKeysPath), nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", adminToken))
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userLogoutPath), nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", adminToken))
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userLogoutPath), nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", userToken))
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userPublicKeysPath), nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", userToken))
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermMFADisabled(t *testing.T) {
	u := getTestUser()
	u.Filters.WebClient = []string{sdk.WebClientMFADisabled}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	userTOTPConfig := dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH},
	}
	asJSON, err := json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr) // MFA is disabled for this user

	user.Filters.WebClient = []string{sdk.WebClientWriteDisabled}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	token, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now we cannot disable MFA for this user
	user.Filters.WebClient = []string{sdk.WebClientMFADisabled}
	_, resp, err := httpdtest.UpdateUser(user, http.StatusBadRequest, "")
	assert.NoError(t, err)
	assert.Contains(t, string(resp), "two-factor authentication cannot be disabled for a user with an active configuration")

	saveReq := make(map[string]bool)
	saveReq["enabled"] = false
	asJSON, err = json.Marshal(saveReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user.Filters.RecoveryCodes = []dataprovider.RecoveryCode{
		{
			Secret: kms.NewPlainSecret(util.GenerateUniqueID()),
		},
	}
	user, resp, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(resp))
	assert.Contains(t, user.Filters.WebClient, sdk.WebClientMFADisabled)
	assert.Len(t, user.Filters.RecoveryCodes, 12)

	req, err = http.NewRequest(http.MethodGet, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var recCodes []recoveryCode
	err = json.Unmarshal(rr.Body.Bytes(), &recCodes)
	assert.NoError(t, err)
	assert.Len(t, recCodes, 12)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestTwoFactorRequirements(t *testing.T) {
	u := getTestUser()
	u.Filters.TwoFactorAuthProtocols = []string{common.ProtocolHTTP, common.ProtocolFTP}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Two-factor authentication requirements not met, please configure two-factor authentication for the following protocols")

	req, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	req.RequestURI = webClientFilesPath
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Two-factor authentication requirements not met, please configure two-factor authentication for the following protocols")

	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	userTOTPConfig := dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolHTTP},
	}
	asJSON, err := json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the following protocols are required")

	userTOTPConfig.Protocols = []string{common.ProtocolHTTP, common.ProtocolFTP}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now get new tokens and check that the two factor requirements are now met
	passcode, err := generateTOTPPasscode(secret)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.Header.Set("X-SFTPGO-OTP", passcode)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	resp, err := httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	responseHolder := make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	assert.NoError(t, err)
	userToken := responseHolder["access_token"].(string)
	assert.NotEmpty(t, userToken)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userDirsPath), nil)
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginUserAPITOTP(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	userTOTPConfig := dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolHTTP},
	}
	asJSON, err := json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now require HTTP and SSH for TOTP
	user.Filters.TwoFactorAuthProtocols = []string{common.ProtocolHTTP, common.ProtocolSSH}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	// two factor auth cannot be disabled
	config := make(map[string]interface{})
	config["enabled"] = false
	asJSON, err = json.Marshal(config)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "two-factor authentication must be enabled")
	// all the required protocols must be enabled
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the following protocols are required")
	// setting all the required protocols should work
	userTOTPConfig.Protocols = []string{common.ProtocolHTTP, common.ProtocolSSH}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	resp, err := httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	passcode, err := generateTOTPPasscode(secret)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.Header.Set("X-SFTPGO-OTP", passcode)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	responseHolder := make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	assert.NoError(t, err)
	userToken := responseHolder["access_token"].(string)
	assert.NotEmpty(t, userToken)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.Header.Set("X-SFTPGO-OTP", passcode)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginAdminAPITOTP(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], admin.Username)
	assert.NoError(t, err)
	altToken, err := getJWTAPITokenFromTestServer(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)
	adminTOTPConfig := dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
	}
	asJSON, err := json.Marshal(adminTOTPConfig)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, adminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, tokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(altAdminUsername, altAdminPassword)
	resp, err := httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, tokenPath), nil)
	assert.NoError(t, err)
	req.Header.Set("X-SFTPGO-OTP", "passcode")
	req.SetBasicAuth(altAdminUsername, altAdminPassword)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	passcode, err := generateTOTPPasscode(secret)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, tokenPath), nil)
	assert.NoError(t, err)
	req.Header.Set("X-SFTPGO-OTP", passcode)
	req.SetBasicAuth(altAdminUsername, altAdminPassword)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	responseHolder := make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	assert.NoError(t, err)
	adminToken := responseHolder["access_token"].(string)
	assert.NotEmpty(t, adminToken)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, versionPath), nil)
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestHTTPStreamZipError(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	resp, err := httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	responseHolder := make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	assert.NoError(t, err)
	userToken := responseHolder["access_token"].(string)
	assert.NotEmpty(t, userToken)
	err = resp.Body.Close()
	assert.NoError(t, err)

	filesList := []string{"missing"}
	asJSON, err := json.Marshal(filesList)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, fmt.Sprintf("%v%v", httpBaseURL, userStreamZipPath), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", userToken))
	resp, err = httpclient.GetHTTPClient().Do(req)
	if !assert.Error(t, err) { // the connection will be closed
		err = resp.Body.Close()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
	err = dataprovider.UpdateAdmin(&admin, "", "")
	assert.NoError(t, err)
}

func TestPasswordValidations(t *testing.T) {
	if config.GetProviderConf().Driver == dataprovider.MemoryDataProviderName {
		t.Skip("this test is not supported with the memory provider")
	}
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	assert.NoError(t, err)
	providerConf.PasswordValidation.Admins.MinEntropy = 50
	providerConf.PasswordValidation.Users.MinEntropy = 70
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	a := getTestAdmin()
	a.Username = altAdminUsername
	a.Password = altAdminPassword

	_, resp, err := httpdtest.AddAdmin(a, http.StatusBadRequest)
	assert.NoError(t, err, string(resp))
	assert.Contains(t, string(resp), "insecure password")

	_, resp, err = httpdtest.AddUser(getTestUser(), http.StatusBadRequest)
	assert.NoError(t, err, string(resp))
	assert.Contains(t, string(resp), "insecure password")

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestAdminPasswordHashing(t *testing.T) {
	if config.GetProviderConf().Driver == dataprovider.MemoryDataProviderName {
		t.Skip("this test is not supported with the memory provider")
	}
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	assert.NoError(t, err)
	providerConf.PasswordHashing.Algo = dataprovider.HashingAlgoArgon2ID
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	currentAdmin, err := dataprovider.AdminExists(defaultTokenAuthUser)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(currentAdmin.Password, "$2a$"))

	a := getTestAdmin()
	a.Username = altAdminUsername
	a.Password = altAdminPassword

	admin, _, err := httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)

	newAdmin, err := dataprovider.AdminExists(altAdminUsername)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(newAdmin.Password, "$argon2id$"))

	token, _, err := httpdtest.GetToken(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)
	httpdtest.SetJWTToken(token)
	_, _, err = httpdtest.GetStatus(http.StatusOK)
	assert.NoError(t, err)

	httpdtest.SetJWTToken("")
	_, _, err = httpdtest.GetStatus(http.StatusOK)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestAdminInvalidCredentials(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, tokenPath), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultTokenAuthUser, defaultTokenAuthPass)
	resp, err := httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)
	// wrong password
	req.SetBasicAuth(defaultTokenAuthUser, "wrong pwd")
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	responseHolder := make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	assert.NoError(t, err)
	err = resp.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, dataprovider.ErrInvalidCredentials.Error(), responseHolder["error"].(string))
	// wrong username
	req.SetBasicAuth("wrong username", defaultTokenAuthPass)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	responseHolder = make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	assert.NoError(t, err)
	err = resp.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, dataprovider.ErrInvalidCredentials.Error(), responseHolder["error"].(string))
}

func TestAdminLastLogin(t *testing.T) {
	a := getTestAdmin()
	a.Username = altAdminUsername
	a.Password = altAdminPassword

	admin, _, err := httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), admin.LastLogin)

	_, _, err = httpdtest.GetToken(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)

	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Greater(t, admin.LastLogin, int64(0))

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
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

func TestUidGidLimits(t *testing.T) {
	u := getTestUser()
	u.UID = math.MaxInt32
	u.GID = math.MaxInt32
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, math.MaxInt32, user.GetUID())
	assert.Equal(t, math.MaxInt32, user.GetGID())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestAddUserNoCredentials(t *testing.T) {
	u := getTestUser()
	u.Password = ""
	u.PublicKeys = []string{}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	// this user cannot login with an empty password but it still can use an SSH cert
	_, err = getJWTAPITokenFromTestServer(defaultTokenAuthUser, "")
	assert.Error(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
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

func TestAddUserInvalidEmail(t *testing.T) {
	u := getTestUser()
	u.Email = "invalid_email"
	_, body, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Validation error: email")
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
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodTLSCertificateAndPwd}
	u.Filters.DeniedProtocols = dataprovider.ValidProtocols
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedProtocols = []string{common.ProtocolFTP}
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "relative",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/subdir",
			AllowedPatterns: []string{"*.zip"},
			DeniedPatterns:  []string{},
		},
		{
			Path:            "/subdir",
			AllowedPatterns: []string{"*.rar"},
			DeniedPatterns:  []string{"*.jpg"},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "relative",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []sdk.PatternsFilter{
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
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/subdir",
			AllowedPatterns: []string{"a\\"},
		},
	}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/subdir",
			AllowedPatterns: []string{"*.*"},
			DenyPolicy:      100,
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
	u.Filters.TLSUsername = ""
	u.Filters.WebClient = []string{"not a valid web client options"}
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidFsConfig(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = sdk.S3FilesystemProvider
	u.FsConfig.S3Config.Bucket = ""
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = os.MkdirAll(credentialsPath, 0700)
	assert.NoError(t, err)
	u.FsConfig.S3Config.Bucket = "testbucket"
	u.FsConfig.S3Config.Region = "eu-west-1"     //nolint:goconst
	u.FsConfig.S3Config.AccessKey = "access-key" //nolint:goconst
	u.FsConfig.S3Config.AccessSecret = kms.NewSecret(sdkkms.SecretStatusRedacted, "access-secret", "", "")
	u.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/path?a=b"
	u.FsConfig.S3Config.StorageClass = "Standard" //nolint:goconst
	u.FsConfig.S3Config.KeyPrefix = "/adir/subdir/"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.S3Config.AccessSecret.SetStatus(sdkkms.SecretStatusPlain)
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
	u.FsConfig.S3Config.UploadConcurrency = 0
	u.FsConfig.S3Config.DownloadPartSize = -1
	_, resp, err := httpdtest.AddUser(u, http.StatusBadRequest)
	if assert.NoError(t, err) {
		assert.Contains(t, string(resp), "download_part_size cannot be")
	}
	u.FsConfig.S3Config.DownloadPartSize = 5001
	_, resp, err = httpdtest.AddUser(u, http.StatusBadRequest)
	if assert.NoError(t, err) {
		assert.Contains(t, string(resp), "download_part_size cannot be")
	}
	u.FsConfig.S3Config.DownloadPartSize = 0
	u.FsConfig.S3Config.DownloadConcurrency = 100
	_, resp, err = httpdtest.AddUser(u, http.StatusBadRequest)
	if assert.NoError(t, err) {
		assert.Contains(t, string(resp), "invalid download concurrency")
	}
	u.FsConfig.S3Config.DownloadConcurrency = -1
	_, resp, err = httpdtest.AddUser(u, http.StatusBadRequest)
	if assert.NoError(t, err) {
		assert.Contains(t, string(resp), "invalid download concurrency")
	}
	u = getTestUser()
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = ""
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.Bucket = "abucket"
	u.FsConfig.GCSConfig.StorageClass = "Standard"
	u.FsConfig.GCSConfig.KeyPrefix = "/somedir/subdir/"
	u.FsConfig.GCSConfig.Credentials = kms.NewSecret(sdkkms.SecretStatusRedacted, "test", "", "") //nolint:goconst
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.Credentials.SetStatus(sdkkms.SecretStatusPlain)
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.KeyPrefix = "somedir/subdir/" //nolint:goconst
	u.FsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
	u.FsConfig.GCSConfig.AutomaticCredentials = 0
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.Credentials = kms.NewSecret(sdkkms.SecretStatusSecretBox, "invalid", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)

	u = getTestUser()
	u.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	u.FsConfig.AzBlobConfig.SASURL = kms.NewPlainSecret("http://foo\x7f.com/")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.SASURL = kms.NewSecret(sdkkms.SecretStatusRedacted, "key", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.SASURL = kms.NewEmptySecret()
	u.FsConfig.AzBlobConfig.AccountName = "name"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.Container = "container"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.AccountKey = kms.NewSecret(sdkkms.SecretStatusRedacted, "key", "", "")
	u.FsConfig.AzBlobConfig.KeyPrefix = "/amedir/subdir/"
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.AzBlobConfig.AccountKey.SetStatus(sdkkms.SecretStatusPlain)
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
	u.FsConfig.Provider = sdk.CryptedFilesystemProvider
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.CryptConfig.Passphrase = kms.NewSecret(sdkkms.SecretStatusRedacted, "akey", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u = getTestUser()
	u.FsConfig.Provider = sdk.SFTPFilesystemProvider
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.SFTPConfig.Password = kms.NewSecret(sdkkms.SecretStatusRedacted, "randompkey", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.SFTPConfig.Password = kms.NewEmptySecret()
	u.FsConfig.SFTPConfig.PrivateKey = kms.NewSecret(sdkkms.SecretStatusRedacted, "keyforpkey", "", "")
	_, _, err = httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret("pk")
	u.FsConfig.SFTPConfig.Endpoint = "127.1.1.1:22"
	u.FsConfig.SFTPConfig.Username = defaultUsername
	u.FsConfig.SFTPConfig.BufferSize = -1
	_, resp, err = httpdtest.AddUser(u, http.StatusBadRequest)
	if assert.NoError(t, err) {
		assert.Contains(t, string(resp), "invalid buffer_size")
	}
	u.FsConfig.SFTPConfig.BufferSize = 1000
	_, resp, err = httpdtest.AddUser(u, http.StatusBadRequest)
	if assert.NoError(t, err) {
		assert.Contains(t, string(resp), "invalid buffer_size")
	}
}

func TestUserRedactedPassword(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = sdk.S3FilesystemProvider
	u.FsConfig.S3Config.Bucket = "b"
	u.FsConfig.S3Config.Region = "eu-west-1"
	u.FsConfig.S3Config.AccessKey = "access-key"
	u.FsConfig.S3Config.RoleARN = "myRoleARN"
	u.FsConfig.S3Config.AccessSecret = kms.NewSecret(sdkkms.SecretStatusRedacted, "access-secret", "", "")
	u.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/path?k=m"
	u.FsConfig.S3Config.StorageClass = "Standard"
	u.FsConfig.S3Config.ACL = "bucket-owner-full-control"
	_, resp, err := httpdtest.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err, string(resp))
	assert.Contains(t, string(resp), "cannot save a user with a redacted secret")
	err = dataprovider.AddUser(&u, "", "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "cannot save a user with a redacted secret")
	}
	u.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("secret")
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	folderName := "folderName"
	vfolder := vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: filepath.Join(os.TempDir(), "crypted"),
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewSecret(sdkkms.SecretStatusRedacted, "crypted-secret", "", ""),
				},
			},
		},
		VirtualPath: "/avpath",
	}

	user.Password = defaultPassword
	user.VirtualFolders = append(user.VirtualFolders, vfolder)
	err = dataprovider.UpdateUser(&user, "", "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "cannot save a user with a redacted secret")
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserType(t *testing.T) {
	u := getTestUser()
	u.Filters.UserType = string(sdk.UserTypeLDAP)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, string(sdk.UserTypeLDAP), user.Filters.UserType)
	user.Filters.UserType = string(sdk.UserTypeOS)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, string(sdk.UserTypeOS), user.Filters.UserType)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestMetadataAPI(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, path.Join(metadataBasePath, "/checks"), nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var resp []interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp, 0)

	req, err = http.NewRequest(http.MethodPost, path.Join(metadataBasePath, user.Username, "/check"), nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)

	assert.Eventually(t, func() bool {
		req, err := http.NewRequest(http.MethodGet, path.Join(metadataBasePath, "/checks"), nil)
		assert.NoError(t, err)
		setBearerForReq(req, token)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
		var resp []interface{}
		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		assert.NoError(t, err)
		return len(resp) == 0
	}, 1000*time.Millisecond, 50*time.Millisecond)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, path.Join(metadataBasePath, user.Username, "/check"), nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestRetentionAPI(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	checks, _, err := httpdtest.GetRetentionChecks(http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, checks, 0)

	localFilePath := filepath.Join(user.HomeDir, "testdir", "testfile")
	err = os.MkdirAll(filepath.Dir(localFilePath), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(localFilePath, []byte("test data"), os.ModePerm)
	assert.NoError(t, err)

	folderRetention := []common.FolderRetention{
		{
			Path:            "/",
			Retention:       0,
			DeleteEmptyDirs: true,
		},
	}

	_, err = httpdtest.StartRetentionCheck(altAdminUsername, folderRetention, http.StatusNotFound)
	assert.NoError(t, err)

	resp, err := httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusBadRequest)
	assert.NoError(t, err)
	assert.Contains(t, string(resp), "Invalid retention check")

	folderRetention[0].Retention = 24
	_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
	assert.NoError(t, err)

	assert.Eventually(t, func() bool {
		return len(common.RetentionChecks.Get()) == 0
	}, 1000*time.Millisecond, 50*time.Millisecond)

	assert.FileExists(t, localFilePath)

	err = os.Chtimes(localFilePath, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
	assert.NoError(t, err)

	_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusAccepted)
	assert.NoError(t, err)

	assert.Eventually(t, func() bool {
		return len(common.RetentionChecks.Get()) == 0
	}, 1000*time.Millisecond, 50*time.Millisecond)

	assert.NoFileExists(t, localFilePath)
	assert.NoDirExists(t, filepath.Dir(localFilePath))

	check := common.RetentionCheck{
		Folders: folderRetention,
	}
	c := common.RetentionChecks.Add(check, &user)
	assert.NotNil(t, c)

	_, err = httpdtest.StartRetentionCheck(user.Username, folderRetention, http.StatusConflict)
	assert.NoError(t, err)

	c.Start()
	assert.Len(t, common.RetentionChecks.Get(), 0)

	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err = httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	token, err := getJWTAPITokenFromTestServer(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, retentionBasePath+"/"+user.Username+"/check",
		bytes.NewBuffer([]byte("invalid json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	asJSON, err := json.Marshal(folderRetention)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, retentionBasePath+"/"+user.Username+"/check?notifications=Email,",
		bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "to notify results via email")

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, retentionBasePath+"/"+user.Username+"/check?notifications=Email",
		bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
		VirtualPath: "/vdir",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
			Name:       folderName + "1",
		},
		VirtualPath: "/vdir", // invalid, already defined
	})
	_, _, err := httpdtest.AddUser(u, http.StatusBadRequest)
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
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
			Name:       folderName, // invalid, unique constraint (user.id, folder.id) violated
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
	assert.Equal(t, user.Password, userNoPwd.Password) // the password is hidden
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
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	u.Filters.Hooks.CheckPasswordDisabled = true
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
	user.Filters.TLSUsername = sdk.TLSUsernameNone
	user.Filters.Hooks.ExternalAuthDisabled = true
	user.Filters.Hooks.PreLoginDisabled = true
	user.Filters.Hooks.CheckPasswordDisabled = false
	user.Filters.DisableFsChecks = true
	user.Filters.FilePatterns = append(user.Filters.FilePatterns, sdk.PatternsFilter{
		Path:            "/subdir",
		AllowedPatterns: []string{"*.zip", "*.rar"},
		DeniedPatterns:  []string{"*.jpg", "*.png"},
		DenyPolicy:      sdk.DenyPolicyHide,
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

func TestUpdateUserTransferQuotaUsage(t *testing.T) {
	u := getTestUser()
	usedDownloadDataTransfer := int64(2 * 1024 * 1024)
	usedUploadDataTransfer := int64(1024 * 1024)
	u.UsedDownloadDataTransfer = usedDownloadDataTransfer
	u.UsedUploadDataTransfer = usedUploadDataTransfer
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), user.UsedUploadDataTransfer)
	assert.Equal(t, int64(0), user.UsedDownloadDataTransfer)
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "invalid_mode", http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedUploadDataTransfer, user.UsedUploadDataTransfer)
	assert.Equal(t, usedDownloadDataTransfer, user.UsedDownloadDataTransfer)
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "add", http.StatusBadRequest)
	assert.NoError(t, err, "user has no transfer quota restrictions add mode should fail")
	user.TotalDataTransfer = 100
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "add", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 2*usedUploadDataTransfer, user.UsedUploadDataTransfer)
	assert.Equal(t, 2*usedDownloadDataTransfer, user.UsedDownloadDataTransfer)
	u.UsedDownloadDataTransfer = -1
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "add", http.StatusBadRequest)
	assert.NoError(t, err)
	u.UsedDownloadDataTransfer = usedDownloadDataTransfer
	u.Username += "1"
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "", http.StatusNotFound)
	assert.NoError(t, err)
	u.Username = defaultUsername
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedUploadDataTransfer, user.UsedUploadDataTransfer)
	assert.Equal(t, usedDownloadDataTransfer, user.UsedDownloadDataTransfer)
	u.UsedDownloadDataTransfer = 0
	u.UsedUploadDataTransfer = 1
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "add", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedUploadDataTransfer+1, user.UsedUploadDataTransfer)
	assert.Equal(t, usedDownloadDataTransfer, user.UsedDownloadDataTransfer)
	u.UsedDownloadDataTransfer = 1
	u.UsedUploadDataTransfer = 0
	_, err = httpdtest.UpdateTransferQuotaUsage(u, "add", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedUploadDataTransfer+1, user.UsedUploadDataTransfer)
	assert.Equal(t, usedDownloadDataTransfer+1, user.UsedDownloadDataTransfer)

	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "users", u.Username, "transfer-usage"),
		bytes.NewBuffer([]byte(`not a json`)))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
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
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, user.UsedQuotaFiles)
	assert.Equal(t, int64(0), user.UsedQuotaSize)
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
			Name:            folderName1,
			MappedPath:      mappedPath1,
			UsedQuotaFiles:  2,
			UsedQuotaSize:   123,
			LastQuotaUpdate: 456,
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
	assert.Equal(t, int64(0), folder.LastQuotaUpdate)
	assert.Equal(t, 0, user1.VirtualFolders[0].UsedQuotaFiles)
	assert.Equal(t, int64(0), user1.VirtualFolders[0].UsedQuotaSize)
	assert.Equal(t, int64(0), user1.VirtualFolders[0].LastQuotaUpdate)

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
	user.FsConfig.Provider = sdk.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test"      //nolint:goconst
	user.FsConfig.S3Config.Region = "us-east-1" //nolint:goconst
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key"
	user.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("Server-Access-Secret")
	user.FsConfig.S3Config.RoleARN = "myRoleARN"
	user.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000"
	user.FsConfig.S3Config.UploadPartSize = 8
	user.FsConfig.S3Config.DownloadPartMaxTime = 60
	user.FsConfig.S3Config.UploadPartMaxTime = 40
	user.FsConfig.S3Config.ForcePathStyle = true
	user.FsConfig.S3Config.DownloadPartSize = 6
	folderName := "vfolderName"
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: filepath.Join(os.TempDir(), "folderName"),
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewPlainSecret("Crypted-Secret"),
				},
			},
		},
		VirtualPath: "/folderPath",
	})
	user, body, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(body))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, user.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Equal(t, 60, user.FsConfig.S3Config.DownloadPartMaxTime)
	assert.Equal(t, 40, user.FsConfig.S3Config.UploadPartMaxTime)
	if assert.Len(t, user.VirtualFolders, 1) {
		folder := user.VirtualFolders[0]
		assert.Equal(t, sdkkms.SecretStatusSecretBox, folder.FsConfig.CryptConfig.Passphrase.GetStatus())
		assert.NotEmpty(t, folder.FsConfig.CryptConfig.Passphrase.GetPayload())
		assert.Empty(t, folder.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
		assert.Empty(t, folder.FsConfig.CryptConfig.Passphrase.GetKey())
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	folder, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, folder.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, folder.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, folder.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, folder.FsConfig.CryptConfig.Passphrase.GetKey())
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	user.CreatedAt = 0
	user.VirtualFolders = nil
	secret := kms.NewSecret(sdkkms.SecretStatusSecretBox, "Server-Access-Secret", "", "")
	user.FsConfig.S3Config.AccessSecret = secret
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.S3Config.AccessSecret.SetStatus(sdkkms.SecretStatusPlain)
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	initialSecretPayload := user.FsConfig.S3Config.AccessSecret.GetPayload()
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, initialSecretPayload)
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetKey())
	user.FsConfig.Provider = sdk.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test-bucket"
	user.FsConfig.S3Config.Region = "us-east-1" //nolint:goconst
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key1"
	user.FsConfig.S3Config.Endpoint = "http://localhost:9000"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir" //nolint:goconst
	user.FsConfig.S3Config.UploadConcurrency = 5
	user.FsConfig.S3Config.DownloadConcurrency = 4
	user, bb, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.Equal(t, initialSecretPayload, user.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.Empty(t, user.FsConfig.S3Config.AccessSecret.GetKey())
	// test user without access key and access secret (shared config state)
	user.FsConfig.Provider = sdk.S3FilesystemProvider
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
	assert.Nil(t, user.FsConfig.S3Config.AccessSecret)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	user.CreatedAt = 0
	// shared credential test for add instead of update
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	assert.Nil(t, user.FsConfig.S3Config.AccessSecret)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserGCSConfig(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = false
	providerConf.CredentialsPath = credentialsPath
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = os.MkdirAll(credentialsPath, 0700)
	assert.NoError(t, err)
	user.FsConfig.Provider = sdk.GCSFilesystemProvider
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
	user.FsConfig.GCSConfig.Credentials = kms.NewSecret(sdkkms.SecretStatusSecretBox, "fake encrypted credentials", "", "")
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
	user.CreatedAt = 0
	user.FsConfig.GCSConfig.Credentials = kms.NewSecret(sdkkms.SecretStatusSecretBox, "fake credentials", "", "")
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.GCSConfig.Credentials.SetStatus(sdkkms.SecretStatusPlain)
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
	user.FsConfig.Provider = sdk.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test1"
	user.FsConfig.S3Config.Region = "us-east-1"
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key1"
	user.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("secret")
	user.FsConfig.S3Config.Endpoint = "http://localhost:9000"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir"
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	user.FsConfig.S3Config = vfs.S3FsConfig{}
	user.FsConfig.Provider = sdk.GCSFilesystemProvider
	user.FsConfig.GCSConfig.Bucket = "test1"
	user.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("fake credentials")
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestUserAzureBlobConfig(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.Container = "test"
	user.FsConfig.AzBlobConfig.AccountName = "Server-Account-Name"
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("Server-Account-Key")
	user.FsConfig.AzBlobConfig.Endpoint = "http://127.0.0.1:9000"
	user.FsConfig.AzBlobConfig.UploadPartSize = 8
	user.FsConfig.AzBlobConfig.DownloadPartSize = 6
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	initialPayload := user.FsConfig.AzBlobConfig.AccountKey.GetPayload()
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetKey())
	user.FsConfig.AzBlobConfig.AccountKey.SetStatus(sdkkms.SecretStatusSecretBox)
	user.FsConfig.AzBlobConfig.AccountKey.SetAdditionalData("data")
	user.FsConfig.AzBlobConfig.AccountKey.SetKey("fake key")
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.Equal(t, initialPayload, user.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetKey())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	user.CreatedAt = 0
	secret := kms.NewSecret(sdkkms.SecretStatusSecretBox, "Server-Account-Key", "", "")
	user.FsConfig.AzBlobConfig.AccountKey = secret
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("Server-Account-Key-Test")
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	initialPayload = user.FsConfig.AzBlobConfig.AccountKey.GetPayload()
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetKey())
	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.Container = "test-container"
	user.FsConfig.AzBlobConfig.Endpoint = "http://localhost:9001"
	user.FsConfig.AzBlobConfig.KeyPrefix = "somedir/subdir"
	user.FsConfig.AzBlobConfig.UploadConcurrency = 5
	user.FsConfig.AzBlobConfig.DownloadConcurrency = 4
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Equal(t, initialPayload, user.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.AccountKey.GetKey())
	// test user without access key and access secret (SAS)
	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.SASURL = kms.NewPlainSecret("https://myaccount.blob.core.windows.net/pictures/profile.jpg?sv=2012-02-12&st=2009-02-09&se=2009-02-10&sr=c&sp=r&si=YWJjZGVmZw%3d%3d&sig=dD80ihBh5jfNpymO5Hg1IdiJIEvHcJpCMiCMnN%2fRnbI%3d")
	user.FsConfig.AzBlobConfig.KeyPrefix = "somedir/subdir"
	user.FsConfig.AzBlobConfig.AccountName = ""
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewEmptySecret()
	user.FsConfig.AzBlobConfig.UploadPartSize = 6
	user.FsConfig.AzBlobConfig.UploadConcurrency = 4
	user.FsConfig.AzBlobConfig.DownloadPartSize = 3
	user.FsConfig.AzBlobConfig.DownloadConcurrency = 5
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Nil(t, user.FsConfig.AzBlobConfig.AccountKey)
	assert.NotNil(t, user.FsConfig.AzBlobConfig.SASURL)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	user.CreatedAt = 0
	// sas test for add instead of update
	user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{
		BaseAzBlobFsConfig: sdk.BaseAzBlobFsConfig{
			Container: user.FsConfig.AzBlobConfig.Container,
		},
		SASURL: kms.NewPlainSecret("http://127.0.0.1/fake/sass/url"),
	}
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	assert.Nil(t, user.FsConfig.AzBlobConfig.AccountKey)
	initialPayload = user.FsConfig.AzBlobConfig.SASURL.GetPayload()
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.SASURL.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.AzBlobConfig.SASURL.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.SASURL.GetKey())
	user.FsConfig.AzBlobConfig.SASURL.SetStatus(sdkkms.SecretStatusSecretBox)
	user.FsConfig.AzBlobConfig.SASURL.SetAdditionalData("data")
	user.FsConfig.AzBlobConfig.SASURL.SetKey("fake key")
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.AzBlobConfig.SASURL.GetStatus())
	assert.Equal(t, initialPayload, user.FsConfig.AzBlobConfig.SASURL.GetPayload())
	assert.Empty(t, user.FsConfig.AzBlobConfig.SASURL.GetAdditionalData())
	assert.Empty(t, user.FsConfig.AzBlobConfig.SASURL.GetKey())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserCryptFs(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("crypt passphrase")
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	initialPayload := user.FsConfig.CryptConfig.Passphrase.GetPayload()
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetKey())
	user.FsConfig.CryptConfig.Passphrase.SetStatus(sdkkms.SecretStatusSecretBox)
	user.FsConfig.CryptConfig.Passphrase.SetAdditionalData("data")
	user.FsConfig.CryptConfig.Passphrase.SetKey("fake pass key")
	user, bb, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.Equal(t, initialPayload, user.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetKey())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	user.CreatedAt = 0
	secret := kms.NewSecret(sdkkms.SecretStatusSecretBox, "invalid encrypted payload", "", "")
	user.FsConfig.CryptConfig.Passphrase = secret
	_, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.Error(t, err)
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("passphrase test")
	user, _, err = httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err)
	initialPayload = user.FsConfig.CryptConfig.Passphrase.GetPayload()
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, initialPayload)
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, user.FsConfig.CryptConfig.Passphrase.GetKey())
	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase.SetKey("pass")
	user, bb, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.CryptConfig.Passphrase.GetStatus())
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
	user.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user.FsConfig.SFTPConfig.Endpoint = "127.0.0.1" // missing port
	user.FsConfig.SFTPConfig.Username = "sftp_user"
	user.FsConfig.SFTPConfig.Password = kms.NewPlainSecret("sftp_pwd")
	user.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret(sftpPrivateKey)
	user.FsConfig.SFTPConfig.Fingerprints = []string{sftpPkeyFingerprint}
	user.FsConfig.SFTPConfig.BufferSize = 2
	_, resp, err := httpdtest.UpdateUser(user, http.StatusBadRequest, "")
	assert.NoError(t, err)
	assert.Contains(t, string(resp), "invalid endpoint")

	user.FsConfig.SFTPConfig.Endpoint = "127.0.0.1:2022"
	user.FsConfig.SFTPConfig.DisableCouncurrentReads = true
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, "/", user.FsConfig.SFTPConfig.Prefix)
	assert.True(t, user.FsConfig.SFTPConfig.DisableCouncurrentReads)
	assert.Equal(t, int64(2), user.FsConfig.SFTPConfig.BufferSize)
	initialPwdPayload := user.FsConfig.SFTPConfig.Password.GetPayload()
	initialPkeyPayload := user.FsConfig.SFTPConfig.PrivateKey.GetPayload()
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.Password.GetStatus())
	assert.NotEmpty(t, initialPwdPayload)
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetKey())
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, initialPkeyPayload)
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetKey())
	user.FsConfig.SFTPConfig.Password.SetStatus(sdkkms.SecretStatusSecretBox)
	user.FsConfig.SFTPConfig.Password.SetAdditionalData("adata")
	user.FsConfig.SFTPConfig.Password.SetKey("fake pwd key")
	user.FsConfig.SFTPConfig.PrivateKey.SetStatus(sdkkms.SecretStatusSecretBox)
	user.FsConfig.SFTPConfig.PrivateKey.SetAdditionalData("adata")
	user.FsConfig.SFTPConfig.PrivateKey.SetKey("fake key")
	user.FsConfig.SFTPConfig.DisableCouncurrentReads = false
	user, bb, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.Password.GetStatus())
	assert.Equal(t, initialPwdPayload, user.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.Password.GetKey())
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.Equal(t, initialPkeyPayload, user.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.False(t, user.FsConfig.SFTPConfig.DisableCouncurrentReads)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	user.CreatedAt = 0
	secret := kms.NewSecret(sdkkms.SecretStatusSecretBox, "invalid encrypted payload", "", "")
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
	assert.Nil(t, user.FsConfig.SFTPConfig.Password)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, initialPkeyPayload)
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Empty(t, user.FsConfig.SFTPConfig.PrivateKey.GetKey())
	user.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user.FsConfig.SFTPConfig.PrivateKey.SetKey("k")
	user, bb, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(bb))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.SFTPConfig.PrivateKey.GetStatus())
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
	u1.FsConfig.Provider = sdk.S3FilesystemProvider
	u1.FsConfig.S3Config.Bucket = "test"
	u1.FsConfig.S3Config.Region = "us-east-1"
	u1.FsConfig.S3Config.AccessKey = "S3-Access-Key"
	u1.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("S3-Access-Secret")
	user1, _, err := httpdtest.AddUser(u1, http.StatusCreated)
	assert.NoError(t, err)

	u2 := getTestUser()
	u2.Username = usernames[1]
	u2.FsConfig.Provider = sdk.GCSFilesystemProvider
	u2.FsConfig.GCSConfig.Bucket = "test"
	u2.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("fake credentials")
	u2.FsConfig.GCSConfig.ACL = "bucketOwnerRead"
	user2, _, err := httpdtest.AddUser(u2, http.StatusCreated)
	assert.NoError(t, err)

	u3 := getTestUser()
	u3.Username = usernames[2]
	u3.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	u3.FsConfig.AzBlobConfig.Container = "test"
	u3.FsConfig.AzBlobConfig.AccountName = "Server-Account-Name"
	u3.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("Server-Account-Key")
	user3, _, err := httpdtest.AddUser(u3, http.StatusCreated)
	assert.NoError(t, err)

	u4 := getTestUser()
	u4.Username = usernames[3]
	u4.FsConfig.Provider = sdk.CryptedFilesystemProvider
	u4.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("test passphrase")
	user4, _, err := httpdtest.AddUser(u4, http.StatusCreated)
	assert.NoError(t, err)

	u5 := getTestUser()
	u5.Username = usernames[4]
	u5.FsConfig.Provider = sdk.SFTPFilesystemProvider
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
	assert.Equal(t, sdkkms.SecretStatusPlain, user1.FsConfig.S3Config.AccessSecret.GetStatus())
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
	assert.Equal(t, sdkkms.SecretStatusPlain, user2.FsConfig.GCSConfig.Credentials.GetStatus())
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
	assert.Equal(t, sdkkms.SecretStatusPlain, user3.FsConfig.AzBlobConfig.AccountKey.GetStatus())
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
	assert.Equal(t, sdkkms.SecretStatusPlain, user4.FsConfig.CryptConfig.Passphrase.GetStatus())
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
	assert.Equal(t, sdkkms.SecretStatusPlain, user5.FsConfig.SFTPConfig.Password.GetStatus())
	assert.Equal(t, u5.FsConfig.SFTPConfig.Password.GetPayload(), user5.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, user5.FsConfig.SFTPConfig.Password.GetKey())
	assert.Empty(t, user5.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	err = user5.FsConfig.SFTPConfig.PrivateKey.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusPlain, user5.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.Equal(t, u5.FsConfig.SFTPConfig.PrivateKey.GetPayload(), user5.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Empty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.Empty(t, user5.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())

	// update the GCS user and check that the credentials are preserved
	user2.FsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
	user2.FsConfig.GCSConfig.ACL = "private"
	_, _, err = httpdtest.UpdateUser(user2, http.StatusOK, "")
	assert.NoError(t, err)

	user2, _, err = httpdtest.GetUserByUsername(user2.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Empty(t, user2.Password)
	assert.Empty(t, user2.FsConfig.GCSConfig.Credentials.GetKey())
	assert.Empty(t, user2.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.NotEmpty(t, user2.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user2.FsConfig.GCSConfig.Credentials.GetPayload())

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
	providerConf.BackupsPath = backupsPath
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
	require.Equal(t, sdkkms.SecretStatusSecretBox, s.GetStatus())
	require.NotEmpty(t, s.GetPayload())
	require.NotEmpty(t, s.GetKey())
	require.True(t, s.IsValid())
	err = s.Decrypt()
	require.NoError(t, err)
	require.Equal(t, sdkkms.SecretStatusPlain, s.GetStatus())
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

	for _, secretStatus := range []string{sdkkms.SecretStatusSecretBox} {
		kmsConfig := config.GetKMSConfig()
		assert.Empty(t, kmsConfig.Secrets.MasterKeyPath)
		if secretStatus == sdkkms.SecretStatusVaultTransit {
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
		if secretStatus == sdkkms.SecretStatusVaultTransit {
			// decrypt the local secret now that the provider is vault
			secretLocal := kms.NewEmptySecret()
			err = json.Unmarshal(localAsJSON, secretLocal)
			assert.NoError(t, err)
			assert.Equal(t, sdkkms.SecretStatusSecretBox, secretLocal.GetStatus())
			assert.Equal(t, 0, secretLocal.GetMode())
			err = secretLocal.Decrypt()
			assert.NoError(t, err)
			assert.Equal(t, testPayload, secretLocal.GetPayload())
			assert.Equal(t, sdkkms.SecretStatusPlain, secretLocal.GetStatus())
			err = secretLocal.Encrypt()
			assert.NoError(t, err)
			assert.Equal(t, sdkkms.SecretStatusSecretBox, secretLocal.GetStatus())
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
		if secretStatus == sdkkms.SecretStatusVaultTransit {
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
		if secretStatus == sdkkms.SecretStatusVaultTransit {
			// decrypt the local secret encryped without a master key now that
			// the provider is vault and a master key is set.
			// The provider will not change, the master key will be used
			secretLocal := kms.NewEmptySecret()
			err = json.Unmarshal(localAsJSON, secretLocal)
			assert.NoError(t, err)
			assert.Equal(t, sdkkms.SecretStatusSecretBox, secretLocal.GetStatus())
			assert.Equal(t, 0, secretLocal.GetMode())
			err = secretLocal.Decrypt()
			assert.NoError(t, err)
			assert.Equal(t, testPayload, secretLocal.GetPayload())
			assert.Equal(t, sdkkms.SecretStatusPlain, secretLocal.GetStatus())
			err = secretLocal.Encrypt()
			assert.NoError(t, err)
			assert.Equal(t, sdkkms.SecretStatusSecretBox, secretLocal.GetStatus())
			assert.Equal(t, 1, secretLocal.GetMode())
		}

		err = kmsConfig.Initialize()
		assert.NoError(t, err)
		err = os.Remove(masterKeyPath)
		assert.NoError(t, err)
		if secretStatus == sdkkms.SecretStatusVaultTransit {
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
	assert.EqualError(t, err, "mapped path mismatch")
	if assert.Len(t, user1.VirtualFolders, 1) {
		assert.Equal(t, mappedPath, user1.VirtualFolders[0].MappedPath)
		assert.Equal(t, u.VirtualFolders[0].VirtualPath, user1.VirtualFolders[0].VirtualPath)
		assert.Equal(t, u.VirtualFolders[0].QuotaFiles, user1.VirtualFolders[0].QuotaFiles)
		assert.Equal(t, u.VirtualFolders[0].QuotaSize, user1.VirtualFolders[0].QuotaSize)
	}
	user1.VirtualFolders = u.VirtualFolders
	user1, _, err = httpdtest.UpdateUser(user1, http.StatusOK, "")
	assert.EqualError(t, err, "mapped path mismatch")
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

func TestEmbeddedFoldersUpdate(t *testing.T) {
	u := getTestUser()
	mappedPath := filepath.Join(os.TempDir(), "mapped_path")
	name := filepath.Base(mappedPath)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:            name,
			MappedPath:      mappedPath,
			UsedQuotaFiles:  1000,
			UsedQuotaSize:   8192,
			LastQuotaUpdate: 123,
		},
		VirtualPath: "/vdir",
		QuotaSize:   4096,
		QuotaFiles:  1,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	folder, _, err := httpdtest.GetFolderByName(name, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath, folder.MappedPath)
	assert.Equal(t, 0, folder.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder.UsedQuotaSize)
	assert.Equal(t, int64(0), folder.LastQuotaUpdate)
	assert.Empty(t, folder.Description)
	assert.Equal(t, sdk.LocalFilesystemProvider, folder.FsConfig.Provider)
	assert.Len(t, folder.Users, 1)
	assert.Contains(t, folder.Users, user.Username)
	// update a field on the folder
	description := "updatedDesc"
	folder.MappedPath = mappedPath + "_update"
	folder.Description = description
	folder, _, err = httpdtest.UpdateFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath+"_update", folder.MappedPath)
	assert.Equal(t, 0, folder.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder.UsedQuotaSize)
	assert.Equal(t, int64(0), folder.LastQuotaUpdate)
	assert.Equal(t, description, folder.Description)
	assert.Equal(t, sdk.LocalFilesystemProvider, folder.FsConfig.Provider)
	// check that the user gets the changes
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	userFolder := user.VirtualFolders[0].BaseVirtualFolder
	assert.Equal(t, mappedPath+"_update", folder.MappedPath)
	assert.Equal(t, 0, userFolder.UsedQuotaFiles)
	assert.Equal(t, int64(0), userFolder.UsedQuotaSize)
	assert.Equal(t, int64(0), userFolder.LastQuotaUpdate)
	assert.Equal(t, description, userFolder.Description)
	assert.Equal(t, sdk.LocalFilesystemProvider, userFolder.FsConfig.Provider)
	// now update the folder embedding it inside the user
	user.VirtualFolders = []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:            name,
				MappedPath:      "",
				UsedQuotaFiles:  1000,
				UsedQuotaSize:   8192,
				LastQuotaUpdate: 123,
				FsConfig: vfs.Filesystem{
					Provider: sdk.S3FilesystemProvider,
					S3Config: vfs.S3FsConfig{
						BaseS3FsConfig: sdk.BaseS3FsConfig{
							Bucket:    "test",
							Region:    "us-east-1",
							AccessKey: "akey",
							Endpoint:  "http://127.0.1.1:9090",
						},
						AccessSecret: kms.NewPlainSecret("asecret"),
					},
				},
			},
			VirtualPath: "/vdir1",
			QuotaSize:   4096,
			QuotaFiles:  1,
		},
	}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	userFolder = user.VirtualFolders[0].BaseVirtualFolder
	assert.Equal(t, 0, userFolder.UsedQuotaFiles)
	assert.Equal(t, int64(0), userFolder.UsedQuotaSize)
	assert.Equal(t, int64(0), userFolder.LastQuotaUpdate)
	assert.Empty(t, userFolder.Description)
	assert.Equal(t, sdk.S3FilesystemProvider, userFolder.FsConfig.Provider)
	assert.Equal(t, "test", userFolder.FsConfig.S3Config.Bucket)
	assert.Equal(t, "us-east-1", userFolder.FsConfig.S3Config.Region)
	assert.Equal(t, "http://127.0.1.1:9090", userFolder.FsConfig.S3Config.Endpoint)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, userFolder.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, userFolder.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, userFolder.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, userFolder.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	// confirm the changes
	folder, _, err = httpdtest.GetFolderByName(name, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, folder.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder.UsedQuotaSize)
	assert.Equal(t, int64(0), folder.LastQuotaUpdate)
	assert.Empty(t, folder.Description)
	assert.Equal(t, sdk.S3FilesystemProvider, folder.FsConfig.Provider)
	assert.Equal(t, "test", folder.FsConfig.S3Config.Bucket)
	assert.Equal(t, "us-east-1", folder.FsConfig.S3Config.Region)
	assert.Equal(t, "http://127.0.1.1:9090", folder.FsConfig.S3Config.Endpoint)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, folder.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, folder.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, folder.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, folder.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	// now update folder usage limits and check that a folder update will not change them
	folder.UsedQuotaFiles = 100
	folder.UsedQuotaSize = 32768
	_, err = httpdtest.UpdateFolderQuotaUsage(folder, "reset", http.StatusOK)
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(name, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 100, folder.UsedQuotaFiles)
	assert.Equal(t, int64(32768), folder.UsedQuotaSize)
	assert.Greater(t, folder.LastQuotaUpdate, int64(0))
	assert.Equal(t, sdk.S3FilesystemProvider, folder.FsConfig.Provider)
	assert.Equal(t, "test", folder.FsConfig.S3Config.Bucket)
	assert.Equal(t, "us-east-1", folder.FsConfig.S3Config.Region)
	assert.Equal(t, "http://127.0.1.1:9090", folder.FsConfig.S3Config.Endpoint)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, folder.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, folder.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, folder.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, folder.FsConfig.S3Config.AccessSecret.GetAdditionalData())

	user.VirtualFolders[0].FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("updated secret")
	user, resp, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(resp))
	userFolder = user.VirtualFolders[0].BaseVirtualFolder
	assert.Equal(t, 100, userFolder.UsedQuotaFiles)
	assert.Equal(t, int64(32768), userFolder.UsedQuotaSize)
	assert.Greater(t, userFolder.LastQuotaUpdate, int64(0))
	assert.Empty(t, userFolder.Description)
	assert.Equal(t, sdk.S3FilesystemProvider, userFolder.FsConfig.Provider)
	assert.Equal(t, "test", userFolder.FsConfig.S3Config.Bucket)
	assert.Equal(t, "us-east-1", userFolder.FsConfig.S3Config.Region)
	assert.Equal(t, "http://127.0.1.1:9090", userFolder.FsConfig.S3Config.Endpoint)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, userFolder.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, userFolder.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, userFolder.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, userFolder.FsConfig.S3Config.AccessSecret.GetAdditionalData())

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
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
	c := common.NewBaseConnection("connID", common.ProtocolSFTP, "", "", user)
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
	c := common.NewBaseConnection("connID", common.ProtocolFTP, "", "", user)
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	common.Connections.Add(fakeConn)
	c1 := common.NewBaseConnection("connID1", common.ProtocolSFTP, "", "", user)
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

func TestNamingRules(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          3525,
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize("..")
	require.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.NamingRules = 7
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	u := getTestUser()
	u.Username = " uSeR@user.me "
	u.Email = dataprovider.ConvertName(u.Username)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, "user@user.me", user.Username)
	user.Username = u.Username
	user.AdditionalInfo = "info"
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(u.Username, http.StatusOK)
	assert.NoError(t, err)

	a := getTestAdmin()
	a.Username = "admiN@example.com "
	admin, _, err := httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, "admin@example.com", admin.Username)
	admin.Email = dataprovider.ConvertName(a.Username)
	admin.Username = a.Username
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	admin, _, err = httpdtest.GetAdminByUsername(a.Username, http.StatusOK)
	assert.NoError(t, err)

	f := vfs.BaseVirtualFolder{
		Name:       "文件夹AB",
		MappedPath: filepath.Clean(os.TempDir()),
	}
	folder, resp, err := httpdtest.AddFolder(f, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	assert.Equal(t, "文件夹ab", folder.Name)
	folder.Name = f.Name
	folder.Description = folder.Name
	folder, resp, err = httpdtest.UpdateFolder(folder, http.StatusOK)
	assert.NoError(t, err, string(resp))
	folder, resp, err = httpdtest.GetFolderByName(f.Name, http.StatusOK)
	assert.NoError(t, err, string(resp))
	_, err = httpdtest.RemoveFolder(f, http.StatusOK)
	assert.NoError(t, err)
	token, err := getJWTWebClientTokenFromTestServer(u.Username, defaultPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	adminAPIToken, err := getJWTAPITokenFromTestServer(a.Username, defaultTokenAuthPass)
	assert.NoError(t, err)
	assert.NotEmpty(t, adminAPIToken)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	if config.GetProviderConf().Driver == dataprovider.MemoryDataProviderName {
		return
	}

	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	token, err = getJWTWebClientTokenFromTestServer(user.Username, defaultPassword)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	req, err := http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "the following characters are allowed")
	// test user reset password
	form = make(url.Values)
	form.Set("username", user.Username)
	form.Set(csrfFormToken, csrfToken)
	lastResetCode = ""
	req, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)
	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("code", lastResetCode)
	form.Set("password", defaultPassword)
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unable to set the new password")

	adminAPIToken, err = getJWTAPITokenFromTestServer(admin.Username, defaultTokenAuthPass)
	assert.NoError(t, err)
	userAPIToken, err := getJWTAPIUserTokenFromTestServer(user.Username, defaultPassword)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userPath+"/"+user.Username+"/2fa/disable", nil)
	assert.NoError(t, err)
	setBearerForReq(req, adminAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the following characters are allowed")

	req, err = http.NewRequest(http.MethodPost, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, userAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the following characters are allowed")

	apiKeyAuthReq := make(map[string]bool)
	apiKeyAuthReq["allow_api_key_auth"] = true
	asJSON, err := json.Marshal(apiKeyAuthReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the following characters are allowed")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	token, err = getJWTWebTokenFromTestServer(admin.Username, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err = getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webAdminProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "the following characters are allowed")

	apiKeyAuthReq = make(map[string]bool)
	apiKeyAuthReq["allow_api_key_auth"] = true
	asJSON, err = json.Marshal(apiKeyAuthReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, adminProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, adminAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the following characters are allowed")

	req, err = http.NewRequest(http.MethodPut, adminPath+"/"+admin.Username+"/2fa/disable", nil)
	assert.NoError(t, err)
	setBearerForReq(req, adminAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the following characters are allowed")

	req, err = http.NewRequest(http.MethodPost, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, adminAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the following characters are allowed")
	// test admin reset password
	form = make(url.Values)
	form.Set("username", admin.Username)
	form.Set(csrfFormToken, csrfToken)
	lastResetCode = ""
	req, err = http.NewRequest(http.MethodPost, webAdminForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)
	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("code", lastResetCode)
	form.Set("password", defaultPassword)
	req, err = http.NewRequest(http.MethodPost, webAdminResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unable to set the new password")

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)
}

func TestSaveErrors(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.NamingRules = 1
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	recCode := "recovery code"
	recoveryCodes := []dataprovider.RecoveryCode{
		{
			Secret: kms.NewPlainSecret(recCode),
			Used:   false,
		},
	}

	u := getTestUser()
	u.Username = "user@example.com"
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = u.Password
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH, common.ProtocolHTTP},
	}
	user.Filters.RecoveryCodes = recoveryCodes
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, user.Filters.TOTPConfig.Enabled)
	assert.Len(t, user.Filters.RecoveryCodes, 1)

	a := getTestAdmin()
	a.Username = "admin@example.com"
	admin, _, err := httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)
	admin.Email = admin.Username
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	admin.Password = a.Password
	admin.Filters.TOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
	}
	admin.Filters.RecoveryCodes = recoveryCodes
	err = dataprovider.UpdateAdmin(&admin, "", "")
	assert.NoError(t, err)
	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, admin.Filters.TOTPConfig.Enabled)
	assert.Len(t, admin.Filters.RecoveryCodes, 1)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	if config.GetProviderConf().Driver == dataprovider.MemoryDataProviderName {
		return
	}

	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := getLoginForm(a.Username, a.Password, csrfToken)
	req, err := http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminTwoFactorPath, rr.Header().Get("Location"))
	cookie, err := getCookieFromResponse(rr)
	assert.NoError(t, err)

	form = make(url.Values)
	form.Set("recovery_code", recCode)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to set the recovery code as used")

	csrfToken, err = getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	form = getLoginForm(u.Username, u.Password, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientTwoFactorPath, rr.Header().Get("Location"))
	cookie, err = getCookieFromResponse(rr)
	assert.NoError(t, err)

	form = make(url.Values)
	form.Set("recovery_code", recCode)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to set the recovery code as used")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
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
		assert.EqualError(t, err, "home dir mismatch")
	}
	assert.Equal(t, filepath.Join(providerConf.UsersBaseDir, u.Username), user.HomeDir)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
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
	_, err = httpdtest.UpdateTransferQuotaUsage(user, "", http.StatusForbidden)
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
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestProviderErrors(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	userAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	userWebToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
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
	_, _, err = httpdtest.GetAPIKeys(1, 0, http.StatusInternalServerError)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, userSharesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, userAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	// password reset errors
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("username", "username")
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Error retrieving your account, please try again later")

	req, err = http.NewRequest(http.MethodGet, webClientSharesPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, userWebToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	req, err = http.NewRequest(http.MethodGet, webClientSharePath+"/shareID", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, userWebToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	req, err = http.NewRequest(http.MethodPost, webClientSharePath+"/shareID", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, userWebToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	_, _, err = httpdtest.UpdateUser(dataprovider.User{BaseUser: sdk.BaseUser{Username: "auser"}}, http.StatusInternalServerError, "")
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(dataprovider.User{BaseUser: sdk.BaseUser{Username: "auser"}}, http.StatusInternalServerError)
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
	user = getTestUser()
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
	backupData.Users = nil
	backupData.Folders = nil
	backupData.Admins = nil
	backupData.APIKeys = append(backupData.APIKeys, dataprovider.APIKey{
		Name:  "name",
		KeyID: util.GenerateUniqueID(),
		Key:   fmt.Sprintf("%v.%v", util.GenerateUniqueID(), util.GenerateUniqueID()),
		Scope: dataprovider.APIKeyScopeUser,
	})
	backupContent, err = json.Marshal(backupData)
	assert.NoError(t, err)
	err = os.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	backupData.APIKeys = nil
	backupData.Shares = append(backupData.Shares, dataprovider.Share{
		Name:     util.GenerateUniqueID(),
		ShareID:  util.GenerateUniqueID(),
		Scope:    dataprovider.ShareScopeRead,
		Paths:    []string{"/"},
		Username: defaultUsername,
	})
	backupContent, err = json.Marshal(backupData)
	assert.NoError(t, err)
	err = os.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
	_, _, err = httpdtest.Loaddata(backupFilePath, "", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, webUserPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, testServerToken)
	rr = executeRequest(req)
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
	providerConf.BackupsPath = backupsPath
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
		FsConfig: vfs.Filesystem{
			Provider: sdk.CryptedFilesystemProvider,
			CryptConfig: vfs.CryptFsConfig{
				Passphrase: kms.NewPlainSecret("asecret"),
			},
		},
	}
	_, _, err := httpdtest.AddFolder(folder, http.StatusBadRequest)
	assert.NoError(t, err)
	folder.MappedPath = filepath.Clean(os.TempDir())
	folder1, resp, err := httpdtest.AddFolder(folder, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	assert.Equal(t, folder.Name, folder1.Name)
	assert.Equal(t, folder.MappedPath, folder1.MappedPath)
	assert.Equal(t, 0, folder1.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder1.UsedQuotaSize)
	assert.Equal(t, int64(0), folder1.LastQuotaUpdate)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, folder1.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, folder1.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, folder1.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, folder1.FsConfig.CryptConfig.Passphrase.GetKey())
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
	assert.NoError(t, err, string(resp))
	assert.Equal(t, 1, folder2.UsedQuotaFiles)
	assert.Equal(t, int64(345), folder2.UsedQuotaSize)
	assert.Equal(t, int64(10), folder2.LastQuotaUpdate)
	assert.Len(t, folder2.Users, 0)
	folders, _, err := httpdtest.GetFolders(0, 0, http.StatusOK)
	assert.NoError(t, err)
	numResults := len(folders)
	assert.GreaterOrEqual(t, numResults, 2)
	found := false
	for _, f := range folders {
		if f.Name == folder1.Name {
			found = true
			assert.Equal(t, folder1.MappedPath, f.MappedPath)
			assert.Equal(t, sdkkms.SecretStatusSecretBox, f.FsConfig.CryptConfig.Passphrase.GetStatus())
			assert.NotEmpty(t, f.FsConfig.CryptConfig.Passphrase.GetPayload())
			assert.Empty(t, f.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
			assert.Empty(t, f.FsConfig.CryptConfig.Passphrase.GetKey())
			assert.Len(t, f.Users, 0)
		}
	}
	assert.True(t, found)
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
	assert.Equal(t, sdkkms.SecretStatusSecretBox, f.FsConfig.CryptConfig.Passphrase.GetStatus())
	assert.NotEmpty(t, f.FsConfig.CryptConfig.Passphrase.GetPayload())
	assert.Empty(t, f.FsConfig.CryptConfig.Passphrase.GetAdditionalData())
	assert.Empty(t, f.FsConfig.CryptConfig.Passphrase.GetKey())
	assert.Len(t, f.Users, 0)
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
	f, resp, err = httpdtest.UpdateFolder(folder1, http.StatusOK)
	assert.NoError(t, err, string(resp))
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
	providerConf.BackupsPath = backupsPath
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	_, rawResp, err := httpdtest.Dumpdata("", "", "", http.StatusBadRequest)
	assert.NoError(t, err, string(rawResp))
	_, _, err = httpdtest.Dumpdata(filepath.Join(backupsPath, "backup.json"), "", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, rawResp, err = httpdtest.Dumpdata("../backup.json", "", "", http.StatusBadRequest)
	assert.NoError(t, err, string(rawResp))
	_, rawResp, err = httpdtest.Dumpdata("backup.json", "", "0", http.StatusOK)
	assert.NoError(t, err, string(rawResp))
	response, _, err := httpdtest.Dumpdata("", "1", "0", http.StatusOK)
	assert.NoError(t, err)
	_, ok := response["admins"]
	assert.True(t, ok)
	_, ok = response["users"]
	assert.True(t, ok)
	_, ok = response["folders"]
	assert.True(t, ok)
	_, ok = response["api_keys"]
	assert.True(t, ok)
	_, ok = response["shares"]
	assert.True(t, ok)
	_, ok = response["version"]
	assert.True(t, ok)
	_, rawResp, err = httpdtest.Dumpdata("backup.json", "", "1", http.StatusOK)
	assert.NoError(t, err, string(rawResp))
	err = os.Remove(filepath.Join(backupsPath, "backup.json"))
	assert.NoError(t, err)
	if runtime.GOOS != osWindows {
		err = os.Chmod(backupsPath, 0001)
		assert.NoError(t, err)
		_, _, err = httpdtest.Dumpdata("bck.json", "", "", http.StatusForbidden)
		assert.NoError(t, err)
		// subdir cannot be created
		_, _, err = httpdtest.Dumpdata(filepath.Join("subdir", "bck.json"), "", "", http.StatusForbidden)
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
	providerConf.BackupsPath = backupsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestDefenderAPI(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	drivers := []string{common.DefenderDriverMemory}
	if isDbDefenderSupported() {
		drivers = append(drivers, common.DefenderDriverProvider)
	}

	for _, driver := range drivers {
		cfg := config.GetCommonConfig()
		cfg.DefenderConfig.Enabled = true
		cfg.DefenderConfig.Driver = driver
		cfg.DefenderConfig.Threshold = 3
		cfg.DefenderConfig.ScoreLimitExceeded = 2

		err := common.Initialize(cfg, 0)
		assert.NoError(t, err)

		ip := "::1"

		response, _, err := httpdtest.GetBanTime(ip, http.StatusOK)
		assert.NoError(t, err)
		banTime, ok := response["date_time"]
		assert.True(t, ok)
		assert.Nil(t, banTime)

		hosts, _, err := httpdtest.GetDefenderHosts(http.StatusOK)
		assert.NoError(t, err)
		assert.Len(t, hosts, 0)

		response, _, err = httpdtest.GetScore(ip, http.StatusOK)
		assert.NoError(t, err)
		score, ok := response["score"]
		assert.True(t, ok)
		assert.Equal(t, float64(0), score)

		err = httpdtest.UnbanIP(ip, http.StatusNotFound)
		assert.NoError(t, err)

		_, err = httpdtest.RemoveDefenderHostByIP(ip, http.StatusNotFound)
		assert.NoError(t, err)

		common.AddDefenderEvent(ip, common.HostEventNoLoginTried)
		response, _, err = httpdtest.GetScore(ip, http.StatusOK)
		assert.NoError(t, err)
		score, ok = response["score"]
		assert.True(t, ok)
		assert.Equal(t, float64(2), score)

		hosts, _, err = httpdtest.GetDefenderHosts(http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, hosts, 1) {
			host := hosts[0]
			assert.Empty(t, host.GetBanTime())
			assert.Equal(t, 2, host.Score)
			assert.Equal(t, ip, host.IP)
		}
		host, _, err := httpdtest.GetDefenderHostByIP(ip, http.StatusOK)
		assert.NoError(t, err)
		assert.Empty(t, host.GetBanTime())
		assert.Equal(t, 2, host.Score)

		common.AddDefenderEvent(ip, common.HostEventNoLoginTried)
		response, _, err = httpdtest.GetBanTime(ip, http.StatusOK)
		assert.NoError(t, err)
		banTime, ok = response["date_time"]
		assert.True(t, ok)
		assert.NotNil(t, banTime)
		hosts, _, err = httpdtest.GetDefenderHosts(http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, hosts, 1) {
			host := hosts[0]
			assert.NotEmpty(t, host.GetBanTime())
			assert.Equal(t, 0, host.Score)
			assert.Equal(t, ip, host.IP)
		}
		host, _, err = httpdtest.GetDefenderHostByIP(ip, http.StatusOK)
		assert.NoError(t, err)
		assert.NotEmpty(t, host.GetBanTime())
		assert.Equal(t, 0, host.Score)

		err = httpdtest.UnbanIP(ip, http.StatusOK)
		assert.NoError(t, err)

		err = httpdtest.UnbanIP(ip, http.StatusNotFound)
		assert.NoError(t, err)

		host, _, err = httpdtest.GetDefenderHostByIP(ip, http.StatusNotFound)
		assert.NoError(t, err)

		common.AddDefenderEvent(ip, common.HostEventNoLoginTried)
		common.AddDefenderEvent(ip, common.HostEventNoLoginTried)
		hosts, _, err = httpdtest.GetDefenderHosts(http.StatusOK)
		assert.NoError(t, err)
		assert.Len(t, hosts, 1)

		_, err = httpdtest.RemoveDefenderHostByIP(ip, http.StatusOK)
		assert.NoError(t, err)

		host, _, err = httpdtest.GetDefenderHostByIP(ip, http.StatusNotFound)
		assert.NoError(t, err)
		_, err = httpdtest.RemoveDefenderHostByIP(ip, http.StatusNotFound)
		assert.NoError(t, err)

		host, _, err = httpdtest.GetDefenderHostByIP("invalid_ip", http.StatusBadRequest)
		assert.NoError(t, err)
		_, err = httpdtest.RemoveDefenderHostByIP("invalid_ip", http.StatusBadRequest)
		assert.NoError(t, err)
		if driver == common.DefenderDriverProvider {
			err = dataprovider.CleanupDefender(util.GetTimeAsMsSinceEpoch(time.Now().Add(1 * time.Hour)))
			assert.NoError(t, err)
		}
	}

	err := common.Initialize(oldConfig, 0)
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
	if isDbDefenderSupported() {
		oldConfig := config.GetCommonConfig()

		cfg := config.GetCommonConfig()
		cfg.DefenderConfig.Enabled = true
		cfg.DefenderConfig.Driver = common.DefenderDriverProvider
		err := common.Initialize(cfg, 0)
		require.NoError(t, err)

		token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
		assert.NoError(t, err)

		err = dataprovider.Close()
		assert.NoError(t, err)

		ip := "127.1.1.2"

		req, err := http.NewRequest(http.MethodGet, defenderHosts, nil)
		assert.NoError(t, err)
		setBearerForReq(req, token)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusInternalServerError, rr)

		req, err = http.NewRequest(http.MethodGet, defenderBanTime+"?ip="+ip, nil)
		assert.NoError(t, err)
		setBearerForReq(req, token)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusInternalServerError, rr)

		req, err = http.NewRequest(http.MethodGet, defenderScore+"?ip="+ip, nil)
		assert.NoError(t, err)
		setBearerForReq(req, token)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusInternalServerError, rr)

		err = config.LoadConfig(configDir, "")
		assert.NoError(t, err)
		providerConf := config.GetProviderConf()
		providerConf.CredentialsPath = credentialsPath
		providerConf.BackupsPath = backupsPath
		err = os.RemoveAll(credentialsPath)
		assert.NoError(t, err)
		err = dataprovider.Initialize(providerConf, configDir, true)
		assert.NoError(t, err)

		err = common.Initialize(oldConfig, 0)
		require.NoError(t, err)
	}
}

func TestRestoreShares(t *testing.T) {
	// shares should be restored preserving the UsedTokens, CreatedAt, LastUseAt, UpdatedAt,
	// and ExpiresAt, so an expired share can be restored while we cannot create an already
	// expired share
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	share := dataprovider.Share{
		ShareID:     shortuuid.New(),
		Name:        "share name",
		Description: "share description",
		Scope:       dataprovider.ShareScopeRead,
		Paths:       []string{"/"},
		Username:    user.Username,
		CreatedAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(-144 * time.Hour)),
		UpdatedAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(-96 * time.Hour)),
		LastUseAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(-64 * time.Hour)),
		ExpiresAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(-48 * time.Hour)),
		MaxTokens:   10,
		UsedTokens:  8,
		AllowFrom:   []string{"127.0.0.0/8"},
	}
	backupData := dataprovider.BackupData{}
	backupData.Shares = append(backupData.Shares, share)
	backupContent, err := json.Marshal(backupData)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(backupContent, "0", "0", http.StatusOK)
	assert.NoError(t, err)
	shareGet, err := dataprovider.ShareExists(share.ShareID, user.Username)
	assert.NoError(t, err)
	assert.Equal(t, share, shareGet)

	share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-142 * time.Hour))
	share.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-92 * time.Hour))
	share.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-62 * time.Hour))
	share.UsedTokens = 6
	backupData.Shares = []dataprovider.Share{share}
	backupContent, err = json.Marshal(backupData)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(backupContent, "0", "0", http.StatusOK)
	assert.NoError(t, err)
	shareGet, err = dataprovider.ShareExists(share.ShareID, user.Username)
	assert.NoError(t, err)
	assert.Equal(t, share, shareGet)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
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
	backupData.APIKeys = append(backupData.APIKeys, dataprovider.APIKey{})
	backupData.Shares = append(backupData.Shares, dataprovider.Share{})
	backupContent, err := json.Marshal(backupData)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(nil, "0", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(backupContent, "a", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody([]byte("invalid content"), "0", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(backupContent, "0", "0", http.StatusInternalServerError)
	assert.NoError(t, err)

	keyID := util.GenerateUniqueID()
	backupData.APIKeys = []dataprovider.APIKey{
		{
			Name:  "test key",
			Scope: dataprovider.APIKeyScopeAdmin,
			KeyID: keyID,
			Key:   fmt.Sprintf("%v.%v", util.GenerateUniqueID(), util.GenerateUniqueID()),
		},
	}
	backupData.Shares = []dataprovider.Share{
		{
			ShareID:  keyID,
			Name:     keyID,
			Scope:    dataprovider.ShareScopeWrite,
			Paths:    []string{"/"},
			Username: user.Username,
		},
	}
	backupContent, err = json.Marshal(backupData)
	assert.NoError(t, err)
	_, _, err = httpdtest.LoaddataFromPostBody(backupContent, "0", "0", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = dataprovider.ShareExists(keyID, user.Username)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	apiKey, _, err := httpdtest.GetAPIKeyByID(keyID, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAPIKey(apiKey, http.StatusOK)
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
	apiKey := dataprovider.APIKey{
		Name:  util.GenerateUniqueID(),
		Scope: dataprovider.APIKeyScopeAdmin,
		KeyID: util.GenerateUniqueID(),
		Key:   fmt.Sprintf("%v.%v", util.GenerateUniqueID(), util.GenerateUniqueID()),
	}
	share := dataprovider.Share{
		ShareID:  util.GenerateUniqueID(),
		Name:     util.GenerateUniqueID(),
		Scope:    dataprovider.ShareScopeRead,
		Paths:    []string{"/"},
		Username: user.Username,
	}
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
	backupData.APIKeys = append(backupData.APIKeys, apiKey)
	backupData.Shares = append(backupData.Shares, share)
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
	if runtime.GOOS != osWindows {
		err = os.Chmod(backupFilePath, 0111)
		assert.NoError(t, err)
		_, _, err = httpdtest.Loaddata(backupFilePath, "1", "", http.StatusForbidden)
		assert.NoError(t, err)
		err = os.Chmod(backupFilePath, 0644)
		assert.NoError(t, err)
	}
	// add user, folder, admin, API key, share from backup
	_, _, err = httpdtest.Loaddata(backupFilePath, "1", "", http.StatusOK)
	assert.NoError(t, err)
	// update from backup
	_, _, err = httpdtest.Loaddata(backupFilePath, "2", "", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = dataprovider.ShareExists(share.ShareID, user.Username)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	apiKey, _, err = httpdtest.GetAPIKeyByID(apiKey.KeyID, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAPIKey(apiKey, http.StatusOK)
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
	apiKey := dataprovider.APIKey{
		Name:        util.GenerateUniqueID(),
		Scope:       dataprovider.APIKeyScopeAdmin,
		KeyID:       util.GenerateUniqueID(),
		Key:         fmt.Sprintf("%v.%v", util.GenerateUniqueID(), util.GenerateUniqueID()),
		Description: "desc",
	}
	share := dataprovider.Share{
		ShareID:  util.GenerateUniqueID(),
		Name:     util.GenerateUniqueID(),
		Scope:    dataprovider.ShareScopeRead,
		Paths:    []string{"/"},
		Username: user.Username,
	}
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
	backupData.APIKeys = append(backupData.APIKeys, apiKey)
	backupData.Shares = append(backupData.Shares, share)
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
	apiKey, _, err = httpdtest.GetAPIKeyByID(apiKey.KeyID, http.StatusOK)
	assert.NoError(t, err)
	oldAPIKeyDesc := apiKey.Description
	apiKey.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now())
	apiKey.Description = "new desc"
	apiKey, _, err = httpdtest.UpdateAPIKey(apiKey, http.StatusOK)
	assert.NoError(t, err)
	share.Description = "test desc"
	err = dataprovider.UpdateShare(&share, "", "")
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

	c := common.NewBaseConnection("connID", common.ProtocolFTP, "", "", user)
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

	apiKey, _, err = httpdtest.GetAPIKeyByID(apiKey.KeyID, http.StatusOK)
	assert.NoError(t, err)
	assert.NotEqual(t, int64(0), apiKey.ExpiresAt)
	assert.NotEqual(t, oldAPIKeyDesc, apiKey.Description)

	share, err = dataprovider.ShareExists(share.ShareID, user.Username)
	assert.NoError(t, err)
	assert.NotEmpty(t, share.Description)

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
	_, err = httpdtest.RemoveAPIKey(apiKey, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
}

func TestRateLimiter(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	cfg := config.GetCommonConfig()
	cfg.RateLimitersConfig = []common.RateLimiterConfig{
		{
			Average:   1,
			Period:    1000,
			Burst:     1,
			Type:      1,
			Protocols: []string{common.ProtocolHTTP},
		},
	}

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(httpBaseURL + healthzPath)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	resp, err = client.Get(httpBaseURL + healthzPath)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	assert.NotEmpty(t, resp.Header.Get("X-Retry-In"))
	err = resp.Body.Close()
	assert.NoError(t, err)

	resp, err = client.Get(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	assert.NotEmpty(t, resp.Header.Get("X-Retry-In"))
	err = resp.Body.Close()
	assert.NoError(t, err)

	resp, err = client.Get(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	assert.NotEmpty(t, resp.Header.Get("X-Retry-In"))
	err = resp.Body.Close()
	assert.NoError(t, err)

	err = common.Initialize(oldConfig, 0)
	assert.NoError(t, err)
}

func TestHTTPSConnection(t *testing.T) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://localhost:8443" + healthzPath)
	if assert.Error(t, err) {
		if !strings.Contains(err.Error(), "certificate is not valid") &&
			!strings.Contains(err.Error(), "certificate signed by unknown authority") &&
			!strings.Contains(err.Error(), "certificate is not standards compliant") {
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
	assert.True(t, util.IsStringInSlice(dataprovider.PermAny, updatedUser.Permissions["/"]))
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

func TestAdminTwoFactorLogin(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)
	// enable two factor authentication
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], admin.Username)
	assert.NoError(t, err)
	altToken, err := getJWTAPITokenFromTestServer(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)
	adminTOTPConfig := dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
	}
	asJSON, err := json.Marshal(adminTOTPConfig)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, adminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, admin.Filters.TOTPConfig.Enabled)

	req, err = http.NewRequest(http.MethodGet, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var recCodes []recoveryCode
	err = json.Unmarshal(rr.Body.Bytes(), &recCodes)
	assert.NoError(t, err)
	assert.Len(t, recCodes, 12)

	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, admin.Filters.RecoveryCodes, 12)
	for _, c := range admin.Filters.RecoveryCodes {
		assert.Empty(t, c.Secret.GetAdditionalData())
		assert.Empty(t, c.Secret.GetKey())
		assert.Equal(t, sdkkms.SecretStatusSecretBox, c.Secret.GetStatus())
		assert.NotEmpty(t, c.Secret.GetPayload())
	}

	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, webAdminTwoFactorPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, webAdminTwoFactorRecoveryPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := getLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminTwoFactorPath, rr.Header().Get("Location"))
	cookie, err := getCookieFromResponse(rr)
	assert.NoError(t, err)

	// without a cookie
	req, err = http.NewRequest(http.MethodGet, webAdminTwoFactorRecoveryPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, webAdminTwoFactorPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webAdminTwoFactorRecoveryPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	// any other page will be redirected to the two factor auth page
	req, err = http.NewRequest(http.MethodGet, webUsersPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webAdminTwoFactorPath, rr.Header().Get("Location"))
	// a partial token cannot be used for user pages
	req, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))

	passcode, err := generateTOTPPasscode(secret)
	assert.NoError(t, err)
	form = make(url.Values)
	form.Set("passcode", passcode)
	// no csrf
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("passcode", "invalid_passcode")
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid authentication code")

	form.Set("passcode", "")
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	form.Set("passcode", passcode)
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webUsersPath, rr.Header().Get("Location"))
	// the same cookie cannot be reused
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	// get a new cookie and login using a recovery code
	form = getLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminTwoFactorPath, rr.Header().Get("Location"))
	cookie, err = getCookieFromResponse(rr)
	assert.NoError(t, err)

	form = make(url.Values)
	recoveryCode := recCodes[0].Code
	form.Set("recovery_code", recoveryCode)
	// no csrf
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("recovery_code", "")
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	form.Set("recovery_code", recoveryCode)
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webUsersPath, rr.Header().Get("Location"))
	authenticatedCookie, err := getCookieFromResponse(rr)
	assert.NoError(t, err)
	//render MFA page
	req, err = http.NewRequest(http.MethodGet, webAdminMFAPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, authenticatedCookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// check that the recovery code was marked as used
	req, err = http.NewRequest(http.MethodGet, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	recCodes = nil
	err = json.Unmarshal(rr.Body.Bytes(), &recCodes)
	assert.NoError(t, err)
	assert.Len(t, recCodes, 12)
	found := false
	for _, rc := range recCodes {
		if rc.Code == recoveryCode {
			found = true
			assert.True(t, rc.Used)
		} else {
			assert.False(t, rc.Used)
		}
	}
	assert.True(t, found)
	// the same recovery code cannot be reused
	form = getLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminTwoFactorPath, rr.Header().Get("Location"))
	cookie, err = getCookieFromResponse(rr)
	assert.NoError(t, err)
	form = make(url.Values)
	form.Set("recovery_code", recoveryCode)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "This recovery code was already used")

	form.Set("recovery_code", "invalid_recovery_code")
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid recovery code")

	form = getLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminTwoFactorPath, rr.Header().Get("Location"))
	cookie, err = getCookieFromResponse(rr)
	assert.NoError(t, err)

	// disable TOTP
	req, err = http.NewRequest(http.MethodPut, adminPath+"/"+altAdminUsername+"/2fa/disable", nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form = make(url.Values)
	form.Set("recovery_code", recoveryCode)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Two factory authentication is not enabled")

	form.Set("passcode", passcode)
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Two factory authentication is not enabled")

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	req, err = http.NewRequest(http.MethodGet, webAdminMFAPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, authenticatedCookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
}

func TestAdminTOTP(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	// TOTPConfig will be ignored on add
	admin.Filters.TOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: "config",
		Secret:     kms.NewEmptySecret(),
	}
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, adminPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.False(t, admin.Filters.TOTPConfig.Enabled)
	assert.Len(t, admin.Filters.RecoveryCodes, 0)

	altToken, err := getJWTAPITokenFromTestServer(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, adminTOTPConfigsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var configs []mfa.TOTPConfig
	err = json.Unmarshal(rr.Body.Bytes(), &configs)
	assert.NoError(t, err, rr.Body.String())
	assert.Len(t, configs, len(mfa.GetAvailableTOTPConfigs()))
	totpConfig := configs[0]
	totpReq := generateTOTPRequest{
		ConfigName: totpConfig.Name,
	}
	asJSON, err = json.Marshal(totpReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, adminTOTPGeneratePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var totpGenResp generateTOTPResponse
	err = json.Unmarshal(rr.Body.Bytes(), &totpGenResp)
	assert.NoError(t, err)
	assert.NotEmpty(t, totpGenResp.Secret)
	assert.NotEmpty(t, totpGenResp.QRCode)

	passcode, err := generateTOTPPasscode(totpGenResp.Secret)
	assert.NoError(t, err)
	validateReq := validateTOTPRequest{
		ConfigName: totpGenResp.ConfigName,
		Passcode:   passcode,
		Secret:     totpGenResp.Secret,
	}
	asJSON, err = json.Marshal(validateReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, adminTOTPValidatePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// the same passcode cannot be reused
	req, err = http.NewRequest(http.MethodPost, adminTOTPValidatePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "this passcode was already used")

	adminTOTPConfig := dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: totpGenResp.ConfigName,
		Secret:     kms.NewPlainSecret(totpGenResp.Secret),
	}
	asJSON, err = json.Marshal(adminTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, adminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, admin.Filters.TOTPConfig.Enabled)
	assert.Equal(t, totpGenResp.ConfigName, admin.Filters.TOTPConfig.ConfigName)
	assert.Empty(t, admin.Filters.TOTPConfig.Secret.GetKey())
	assert.Empty(t, admin.Filters.TOTPConfig.Secret.GetAdditionalData())
	assert.NotEmpty(t, admin.Filters.TOTPConfig.Secret.GetPayload())
	assert.Equal(t, sdkkms.SecretStatusSecretBox, admin.Filters.TOTPConfig.Secret.GetStatus())
	admin.Filters.TOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled:    false,
		ConfigName: util.GenerateUniqueID(),
		Secret:     kms.NewEmptySecret(),
	}
	admin.Filters.RecoveryCodes = []dataprovider.RecoveryCode{
		{
			Secret: kms.NewEmptySecret(),
		},
	}
	admin, resp, err := httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err, string(resp))
	assert.True(t, admin.Filters.TOTPConfig.Enabled)
	assert.Len(t, admin.Filters.RecoveryCodes, 12)
	// if we use token we should get no recovery codes
	req, err = http.NewRequest(http.MethodGet, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var recCodes []recoveryCode
	err = json.Unmarshal(rr.Body.Bytes(), &recCodes)
	assert.NoError(t, err)
	assert.Len(t, recCodes, 0)
	// now the same but with altToken
	req, err = http.NewRequest(http.MethodGet, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	recCodes = nil
	err = json.Unmarshal(rr.Body.Bytes(), &recCodes)
	assert.NoError(t, err)
	assert.Len(t, recCodes, 12)
	// regenerate recovery codes
	req, err = http.NewRequest(http.MethodPost, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// check that recovery codes are different
	req, err = http.NewRequest(http.MethodGet, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var newRecCodes []recoveryCode
	err = json.Unmarshal(rr.Body.Bytes(), &newRecCodes)
	assert.NoError(t, err)
	assert.Len(t, newRecCodes, 12)
	assert.NotEqual(t, recCodes, newRecCodes)
	// disable 2FA, the update admin API should not work
	admin.Filters.TOTPConfig.Enabled = false
	admin.Filters.RecoveryCodes = nil
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, altAdminUsername, admin.Username)
	assert.True(t, admin.Filters.TOTPConfig.Enabled)
	assert.Len(t, admin.Filters.RecoveryCodes, 12)
	// use the dedicated API
	req, err = http.NewRequest(http.MethodPut, adminPath+"/"+altAdminUsername+"/2fa/disable", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.False(t, admin.Filters.TOTPConfig.Enabled)
	assert.Len(t, admin.Filters.RecoveryCodes, 0)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(adminPath, altAdminUsername), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodPut, adminPath+"/"+altAdminUsername+"/2fa/disable", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, admin2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, adminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestChangeAdminPwdInvalidJsonMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPut, adminPwdPath, bytes.NewBuffer([]byte("{")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestMFAPermission(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webClientMFAPath, nil)
	assert.NoError(t, err)
	req.RequestURI = webClientMFAPath
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user.Filters.WebClient = []string{sdk.WebClientMFADisabled}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	webToken, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientMFAPath, nil)
	assert.NoError(t, err)
	req.RequestURI = webClientMFAPath
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebUserTwoFactorLogin(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	// enable two factor authentication
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	adminToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	userTOTPConfig := dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolHTTP},
	}
	asJSON, err := json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var recCodes []recoveryCode
	err = json.Unmarshal(rr.Body.Bytes(), &recCodes)
	assert.NoError(t, err)
	assert.Len(t, recCodes, 12)

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user.Filters.RecoveryCodes, 12)
	for _, c := range user.Filters.RecoveryCodes {
		assert.Empty(t, c.Secret.GetAdditionalData())
		assert.Empty(t, c.Secret.GetKey())
		assert.Equal(t, sdkkms.SecretStatusSecretBox, c.Secret.GetStatus())
		assert.NotEmpty(t, c.Secret.GetPayload())
	}

	req, err = http.NewRequest(http.MethodGet, webClientTwoFactorPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, webClientTwoFactorRecoveryPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	form := getLoginForm(defaultUsername, defaultPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientTwoFactorPath, rr.Header().Get("Location"))
	cookie, err := getCookieFromResponse(rr)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientTwoFactorPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	// without a cookie
	req, err = http.NewRequest(http.MethodGet, webClientTwoFactorPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, webClientTwoFactorRecoveryPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// any other page will be redirected to the two factor auth page
	req, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientTwoFactorPath, rr.Header().Get("Location"))
	// a partial token cannot be used for admin pages
	req, err = http.NewRequest(http.MethodGet, webUsersPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))

	passcode, err := generateTOTPPasscode(secret)
	assert.NoError(t, err)
	form = make(url.Values)
	form.Set("passcode", passcode)

	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("passcode", "invalid_user_passcode")
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid authentication code")

	form.Set("passcode", "")
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	form.Set("passcode", passcode)
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientFilesPath, rr.Header().Get("Location"))
	// the same cookie cannot be reused
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	// get a new cookie and login using a recovery code
	form = getLoginForm(defaultUsername, defaultPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientTwoFactorPath, rr.Header().Get("Location"))
	cookie, err = getCookieFromResponse(rr)
	assert.NoError(t, err)

	form = make(url.Values)
	recoveryCode := recCodes[0].Code
	form.Set("recovery_code", recoveryCode)
	// no csrf
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("recovery_code", "")
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	form.Set("recovery_code", recoveryCode)
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientFilesPath, rr.Header().Get("Location"))
	authenticatedCookie, err := getCookieFromResponse(rr)
	assert.NoError(t, err)
	//render MFA page
	req, err = http.NewRequest(http.MethodGet, webClientMFAPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, authenticatedCookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	// check that the recovery code was marked as used
	req, err = http.NewRequest(http.MethodGet, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	recCodes = nil
	err = json.Unmarshal(rr.Body.Bytes(), &recCodes)
	assert.NoError(t, err)
	assert.Len(t, recCodes, 12)
	found := false
	for _, rc := range recCodes {
		if rc.Code == recoveryCode {
			found = true
			assert.True(t, rc.Used)
		} else {
			assert.False(t, rc.Used)
		}
	}
	assert.True(t, found)
	// the same recovery code cannot be reused
	form = getLoginForm(defaultUsername, defaultPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientTwoFactorPath, rr.Header().Get("Location"))
	cookie, err = getCookieFromResponse(rr)
	assert.NoError(t, err)
	form = make(url.Values)
	form.Set("recovery_code", recoveryCode)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "This recovery code was already used")

	form.Set("recovery_code", "invalid_user_recovery_code")
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid recovery code")

	form = getLoginForm(defaultUsername, defaultPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientTwoFactorPath, rr.Header().Get("Location"))
	cookie, err = getCookieFromResponse(rr)
	assert.NoError(t, err)

	// disable TOTP
	req, err = http.NewRequest(http.MethodPut, userPath+"/"+user.Username+"/2fa/disable", nil)
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form = make(url.Values)
	form.Set("recovery_code", recoveryCode)
	form.Set("passcode", passcode)
	form.Set(csrfFormToken, csrfToken)

	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Two factory authentication is not enabled")

	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Two factory authentication is not enabled")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	req, err = http.NewRequest(http.MethodGet, webClientMFAPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, authenticatedCookie)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
}

func TestSearchEvents(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, fsEventsPath+"?limit=10&order=ASC&fs_provider=0", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	events := make([]map[string]interface{}, 0)
	err = json.Unmarshal(rr.Body.Bytes(), &events)
	assert.NoError(t, err)
	if assert.Len(t, events, 1) {
		ev := events[0]
		for _, field := range []string{"id", "timestamp", "action", "username", "fs_path", "status", "protocol",
			"ip", "session_id", "fs_provider", "bucket", "endpoint", "open_flags", "instance_id"} {
			_, ok := ev[field]
			assert.True(t, ok, field)
		}
	}

	// the test eventsearcher plugin returns error if start_timestamp < 0
	req, err = http.NewRequest(http.MethodGet, fsEventsPath+"?start_timestamp=-1&end_timestamp=123456&statuses=1,2", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	req, err = http.NewRequest(http.MethodGet, fsEventsPath+"?limit=a", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, providerEventsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	events = make([]map[string]interface{}, 0)
	err = json.Unmarshal(rr.Body.Bytes(), &events)
	assert.NoError(t, err)
	if assert.Len(t, events, 1) {
		ev := events[0]
		for _, field := range []string{"id", "timestamp", "action", "username", "object_type", "object_name",
			"object_data", "instance_id"} {
			_, ok := ev[field]
			assert.True(t, ok, field)
		}
	}

	// the test eventsearcher plugin returns error if start_timestamp < 0
	req, err = http.NewRequest(http.MethodGet, providerEventsPath+"?start_timestamp=-1", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	req, err = http.NewRequest(http.MethodGet, providerEventsPath+"?limit=2000", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, fsEventsPath+"?start_timestamp=a", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, fsEventsPath+"?end_timestamp=a", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, fsEventsPath+"?order=ASSC", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, fsEventsPath+"?statuses=a,b", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, fsEventsPath+"?fs_provider=a", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestMFAErrors(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	assert.False(t, user.Filters.TOTPConfig.Enabled)
	userToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	adminToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)

	// invalid config name
	totpReq := generateTOTPRequest{
		ConfigName: "invalid config name",
	}
	asJSON, err := json.Marshal(totpReq)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userTOTPGeneratePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	// invalid JSON
	invalidJSON := []byte("not a JSON")
	req, err = http.NewRequest(http.MethodPost, userTOTPGeneratePath, bytes.NewBuffer(invalidJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(invalidJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodPost, adminTOTPSavePath, bytes.NewBuffer(invalidJSON))
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodPost, adminTOTPValidatePath, bytes.NewBuffer(invalidJSON))
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	// invalid TOTP config name
	userTOTPConfig := dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: "missing name",
		Secret:     kms.NewPlainSecret(xid.New().String()),
		Protocols:  []string{common.ProtocolSSH},
	}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "totp: config name")
	// invalid TOTP secret
	userTOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: mfa.GetAvailableTOTPConfigNames()[0],
		Secret:     nil,
		Protocols:  []string{common.ProtocolSSH},
	}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "totp: secret is mandatory")
	// no protocol
	userTOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: mfa.GetAvailableTOTPConfigNames()[0],
		Secret:     kms.NewPlainSecret(xid.New().String()),
		Protocols:  nil,
	}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "totp: specify at least one protocol")
	// invalid protocol
	userTOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: mfa.GetAvailableTOTPConfigNames()[0],
		Secret:     kms.NewPlainSecret(xid.New().String()),
		Protocols:  []string{common.ProtocolWebDAV},
	}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "totp: invalid protocol")

	adminTOTPConfig := dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: "",
		Secret:     kms.NewPlainSecret("secret"),
	}
	asJSON, err = json.Marshal(adminTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, adminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "totp: config name is mandatory")

	adminTOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: mfa.GetAvailableTOTPConfigNames()[0],
		Secret:     nil,
	}
	asJSON, err = json.Marshal(adminTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, adminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "totp: secret is mandatory")

	// invalid TOTP secret status
	userTOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: mfa.GetAvailableTOTPConfigNames()[0],
		Secret:     kms.NewSecret(sdkkms.SecretStatusRedacted, "", "", ""),
		Protocols:  []string{common.ProtocolSSH},
	}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	// previous secret will be preserved and we have no secret saved
	assert.Contains(t, rr.Body.String(), "totp: secret is mandatory")

	req, err = http.NewRequest(http.MethodPost, adminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "totp: secret is mandatory")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestMFAInvalidSecret(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	userToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: mfa.GetAvailableTOTPConfigNames()[0],
		Secret:     kms.NewSecret(sdkkms.SecretStatusSecretBox, "payload", "key", user.Username),
		Protocols:  []string{common.ProtocolSSH, common.ProtocolHTTP},
	}
	user.Filters.RecoveryCodes = append(user.Filters.RecoveryCodes, dataprovider.RecoveryCode{
		Used:   false,
		Secret: kms.NewSecret(sdkkms.SecretStatusSecretBox, "payload", "key", user.Username),
	})
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, userToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	assert.Contains(t, rr.Body.String(), "Unable to decrypt recovery codes")

	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	form := getLoginForm(defaultUsername, defaultPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientTwoFactorPath, rr.Header().Get("Location"))
	cookie, err := getCookieFromResponse(rr)
	assert.NoError(t, err)
	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("passcode", "123456")
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("recovery_code", "RC-123456")
	req, err = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, userTokenPath), nil)
	assert.NoError(t, err)
	req.Header.Set("X-SFTPGO-OTP", "authcode")
	req.SetBasicAuth(defaultUsername, defaultPassword)
	resp, err := httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err = httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	admin.Password = altAdminPassword
	admin.Filters.TOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: mfa.GetAvailableTOTPConfigNames()[0],
		Secret:     kms.NewSecret(sdkkms.SecretStatusSecretBox, "payload", "key", user.Username),
	}
	admin.Filters.RecoveryCodes = append(user.Filters.RecoveryCodes, dataprovider.RecoveryCode{
		Used:   false,
		Secret: kms.NewSecret(sdkkms.SecretStatusSecretBox, "payload", "key", user.Username),
	})
	err = dataprovider.UpdateAdmin(&admin, "", "")
	assert.NoError(t, err)

	csrfToken, err = getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form = getLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminTwoFactorPath, rr.Header().Get("Location"))
	cookie, err = getCookieFromResponse(rr)
	assert.NoError(t, err)
	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("passcode", "123456")
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("recovery_code", "RC-123456")
	req, err = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v%v", httpBaseURL, tokenPath), nil)
	assert.NoError(t, err)
	req.Header.Set("X-SFTPGO-OTP", "auth-code")
	req.SetBasicAuth(altAdminUsername, altAdminPassword)
	resp, err = httpclient.GetHTTPClient().Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestWebUserTOTP(t *testing.T) {
	u := getTestUser()
	// TOTPConfig will be ignored on add
	u.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: "",
		Secret:     kms.NewEmptySecret(),
		Protocols:  []string{common.ProtocolSSH},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.False(t, user.Filters.TOTPConfig.Enabled)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, userTOTPConfigsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var configs []mfa.TOTPConfig
	err = json.Unmarshal(rr.Body.Bytes(), &configs)
	assert.NoError(t, err, rr.Body.String())
	assert.Len(t, configs, len(mfa.GetAvailableTOTPConfigs()))
	totpConfig := configs[0]
	totpReq := generateTOTPRequest{
		ConfigName: totpConfig.Name,
	}
	asJSON, err := json.Marshal(totpReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPGeneratePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var totpGenResp generateTOTPResponse
	err = json.Unmarshal(rr.Body.Bytes(), &totpGenResp)
	assert.NoError(t, err)
	assert.NotEmpty(t, totpGenResp.Secret)
	assert.NotEmpty(t, totpGenResp.QRCode)

	passcode, err := generateTOTPPasscode(totpGenResp.Secret)
	assert.NoError(t, err)
	validateReq := validateTOTPRequest{
		ConfigName: totpGenResp.ConfigName,
		Passcode:   passcode,
		Secret:     totpGenResp.Secret,
	}
	asJSON, err = json.Marshal(validateReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPValidatePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// the same passcode cannot be reused
	req, err = http.NewRequest(http.MethodPost, userTOTPValidatePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "this passcode was already used")

	userTOTPConfig := dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: totpGenResp.ConfigName,
		Secret:     kms.NewPlainSecret(totpGenResp.Secret),
		Protocols:  []string{common.ProtocolSSH},
	}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	totpCfg := user.Filters.TOTPConfig
	assert.True(t, totpCfg.Enabled)
	secretPayload := totpCfg.Secret.GetPayload()
	assert.Equal(t, totpGenResp.ConfigName, totpCfg.ConfigName)
	assert.Empty(t, totpCfg.Secret.GetKey())
	assert.Empty(t, totpCfg.Secret.GetAdditionalData())
	assert.NotEmpty(t, secretPayload)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, totpCfg.Secret.GetStatus())
	assert.Len(t, totpCfg.Protocols, 1)
	assert.Contains(t, totpCfg.Protocols, common.ProtocolSSH)
	// update protocols only
	userTOTPConfig = dataprovider.UserTOTPConfig{
		Protocols: []string{common.ProtocolSSH, common.ProtocolFTP},
		Secret:    kms.NewEmptySecret(),
	}
	asJSON, err = json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	// update the user, TOTP should not be affected
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled: false,
		Secret:  kms.NewEmptySecret(),
	}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, user.Filters.TOTPConfig.Enabled)
	assert.Equal(t, totpCfg.ConfigName, user.Filters.TOTPConfig.ConfigName)
	assert.Empty(t, user.Filters.TOTPConfig.Secret.GetKey())
	assert.Empty(t, user.Filters.TOTPConfig.Secret.GetAdditionalData())
	assert.Equal(t, secretPayload, user.Filters.TOTPConfig.Secret.GetPayload())
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.Filters.TOTPConfig.Secret.GetStatus())
	assert.Len(t, user.Filters.TOTPConfig.Protocols, 2)
	assert.Contains(t, user.Filters.TOTPConfig.Protocols, common.ProtocolSSH)
	assert.Contains(t, user.Filters.TOTPConfig.Protocols, common.ProtocolFTP)

	req, err = http.NewRequest(http.MethodGet, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var recCodes []recoveryCode
	err = json.Unmarshal(rr.Body.Bytes(), &recCodes)
	assert.NoError(t, err)
	assert.Len(t, recCodes, 12)
	// regenerate recovery codes
	req, err = http.NewRequest(http.MethodPost, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// check that recovery codes are different
	req, err = http.NewRequest(http.MethodGet, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var newRecCodes []recoveryCode
	err = json.Unmarshal(rr.Body.Bytes(), &newRecCodes)
	assert.NoError(t, err)
	assert.Len(t, newRecCodes, 12)
	assert.NotEqual(t, recCodes, newRecCodes)
	// disable 2FA, the update user API should not work
	adminToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user.Filters.TOTPConfig.Enabled = false
	user.Filters.RecoveryCodes = nil
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Equal(t, defaultUsername, user.Username)
	assert.True(t, user.Filters.TOTPConfig.Enabled)
	assert.Len(t, user.Filters.RecoveryCodes, 12)
	// use the dedicated API
	req, err = http.NewRequest(http.MethodPut, userPath+"/"+defaultUsername+"/2fa/disable", nil)
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.False(t, user.Filters.TOTPConfig.Enabled)
	assert.Len(t, user.Filters.RecoveryCodes, 0)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodPut, userPath+"/"+defaultUsername+"/2fa/disable", nil)
	assert.NoError(t, err)
	setBearerForReq(req, adminToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, user2FARecoveryCodesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, userTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestWebAPIChangeUserProfileMock(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	assert.False(t, user.Filters.AllowAPIKeyAuth)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	// invalid json
	req, err := http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer([]byte("{")))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	email := "userapi@example.com"
	description := "user API description"
	profileReq := make(map[string]interface{})
	profileReq["allow_api_key_auth"] = true
	profileReq["email"] = email
	profileReq["description"] = description
	profileReq["public_keys"] = []string{testPubKey, testPubKey1}
	asJSON, err := json.Marshal(profileReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	profileReq = make(map[string]interface{})
	req, err = http.NewRequest(http.MethodGet, userProfilePath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = json.Unmarshal(rr.Body.Bytes(), &profileReq)
	assert.NoError(t, err)
	assert.Equal(t, email, profileReq["email"].(string))
	assert.Equal(t, description, profileReq["description"].(string))
	assert.True(t, profileReq["allow_api_key_auth"].(bool))
	assert.Len(t, profileReq["public_keys"].([]interface{}), 2)
	// set an invalid email
	profileReq = make(map[string]interface{})
	profileReq["email"] = "notavalidemail"
	asJSON, err = json.Marshal(profileReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: email")
	// set an invalid public key
	profileReq = make(map[string]interface{})
	profileReq["public_keys"] = []string{"not a public key"}
	asJSON, err = json.Marshal(profileReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: could not parse key")

	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled, sdk.WebClientPubKeyChangeDisabled}
	user.Email = email
	user.Description = description
	user.Filters.AllowAPIKeyAuth = true
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	token, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	profileReq = make(map[string]interface{})
	profileReq["allow_api_key_auth"] = false
	profileReq["email"] = email
	profileReq["description"] = description + "_mod"
	profileReq["public_keys"] = []string{testPubKey}
	asJSON, err = json.Marshal(profileReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Profile updated")
	// check that api key auth and public keys were not changed
	profileReq = make(map[string]interface{})
	req, err = http.NewRequest(http.MethodGet, userProfilePath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = json.Unmarshal(rr.Body.Bytes(), &profileReq)
	assert.NoError(t, err)
	assert.Equal(t, email, profileReq["email"].(string))
	assert.Equal(t, description+"_mod", profileReq["description"].(string))
	assert.True(t, profileReq["allow_api_key_auth"].(bool))
	assert.Len(t, profileReq["public_keys"].([]interface{}), 2)

	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled, sdk.WebClientInfoChangeDisabled}
	user.Description = description + "_mod"
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	token, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	profileReq = make(map[string]interface{})
	profileReq["allow_api_key_auth"] = false
	profileReq["email"] = "newemail@apiuser.com"
	profileReq["description"] = description
	profileReq["public_keys"] = []string{testPubKey}
	asJSON, err = json.Marshal(profileReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	profileReq = make(map[string]interface{})
	req, err = http.NewRequest(http.MethodGet, userProfilePath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = json.Unmarshal(rr.Body.Bytes(), &profileReq)
	assert.NoError(t, err)
	assert.Equal(t, email, profileReq["email"].(string))
	assert.Equal(t, description+"_mod", profileReq["description"].(string))
	assert.True(t, profileReq["allow_api_key_auth"].(bool))
	assert.Len(t, profileReq["public_keys"].([]interface{}), 1)
	// finally disable all profile permissions
	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled, sdk.WebClientInfoChangeDisabled,
		sdk.WebClientPubKeyChangeDisabled}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "You are not allowed to change anything")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, userProfilePath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPut, userProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestWebAPIChangeUserPwdMock(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	// invalid json
	req, err := http.NewRequest(http.MethodPut, userPwdPath, bytes.NewBuffer([]byte("{")))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	pwd := make(map[string]string)
	pwd["current_password"] = defaultPassword
	pwd["new_password"] = defaultPassword
	asJSON, err := json.Marshal(pwd)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userPwdPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the new password must be different from the current one")

	pwd["new_password"] = altAdminPassword
	asJSON, err = json.Marshal(pwd)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userPwdPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)
	token, err = getJWTAPIUserTokenFromTestServer(defaultUsername, altAdminPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// remove the change password permission
	user.Filters.WebClient = []string{sdk.WebClientPasswordChangeDisabled}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Len(t, user.Filters.WebClient, 1)
	assert.Contains(t, user.Filters.WebClient, sdk.WebClientPasswordChangeDisabled)

	token, err = getJWTAPIUserTokenFromTestServer(defaultUsername, altAdminPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	pwd["current_password"] = altAdminPassword
	pwd["new_password"] = defaultPassword
	asJSON, err = json.Marshal(pwd)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userPwdPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginInvalidPasswordMock(t *testing.T) {
	_, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass+"1")
	assert.Error(t, err)
	// now a login with no credentials
	req, _ := http.NewRequest(http.MethodGet, "/api/v2/token", nil)
	rr := executeRequest(req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestWebAPIChangeAdminProfileMock(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)
	assert.False(t, admin.Filters.AllowAPIKeyAuth)

	token, err := getJWTAPITokenFromTestServer(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)
	// invalid json
	req, err := http.NewRequest(http.MethodPut, adminProfilePath, bytes.NewBuffer([]byte("{")))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	email := "adminapi@example.com"
	description := "admin API description"
	profileReq := make(map[string]interface{})
	profileReq["allow_api_key_auth"] = true
	profileReq["email"] = email
	profileReq["description"] = description
	asJSON, err := json.Marshal(profileReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, adminProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Profile updated")

	profileReq = make(map[string]interface{})
	req, err = http.NewRequest(http.MethodGet, adminProfilePath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = json.Unmarshal(rr.Body.Bytes(), &profileReq)
	assert.NoError(t, err)
	assert.Equal(t, email, profileReq["email"].(string))
	assert.Equal(t, description, profileReq["description"].(string))
	assert.True(t, profileReq["allow_api_key_auth"].(bool))
	// set an invalid email
	profileReq["email"] = "admin_invalid_email"
	asJSON, err = json.Marshal(profileReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, adminProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: email")

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, adminProfilePath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPut, adminProfilePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
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
	_, err = getJWTAPITokenFromTestServer(altAdminUsername, defaultTokenAuthPass)
	assert.Error(t, err)
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Permissions = []string{dataprovider.PermAdminManageAdmins}
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, adminPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	_, err = getJWTAPITokenFromTestServer(altAdminUsername, defaultTokenAuthPass)
	assert.NoError(t, err)

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
	admin.Password = "" // it must remain unchanged
	admin.Permissions = []string{dataprovider.PermAdminManageAdmins, dataprovider.PermAdminCloseConnections}
	asJSON, err = json.Marshal(admin)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(adminPath, altAdminUsername), bytes.NewBuffer(asJSON))
	setBearerForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = getJWTAPITokenFromTestServer(altAdminUsername, defaultTokenAuthPass)
	assert.NoError(t, err)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(adminPath, altAdminUsername), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestAdminLastLoginWithAPIKey(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Filters.AllowAPIKeyAuth = true
	admin, resp, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	assert.Equal(t, int64(0), admin.LastLogin)

	apiKey := dataprovider.APIKey{
		Name:      "admin API key",
		Scope:     dataprovider.APIKeyScopeAdmin,
		Admin:     altAdminUsername,
		LastUseAt: 123,
	}

	apiKey, resp, err = httpdtest.AddAPIKey(apiKey, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	assert.Equal(t, int64(0), apiKey.LastUseAt)

	req, err := http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, admin.Username)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Greater(t, admin.LastLogin, int64(0))

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserLastLoginWithAPIKey(t *testing.T) {
	user := getTestUser()
	user.Filters.AllowAPIKeyAuth = true
	user, resp, err := httpdtest.AddUser(user, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	assert.Equal(t, int64(0), user.LastLogin)

	apiKey := dataprovider.APIKey{
		Name:  "user API key",
		Scope: dataprovider.APIKeyScopeUser,
		User:  user.Username,
	}

	apiKey, resp, err = httpdtest.AddAPIKey(apiKey, http.StatusCreated)
	assert.NoError(t, err, string(resp))

	req, err := http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Greater(t, user.LastLogin, int64(0))

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestAdminHandlingWithAPIKeys(t *testing.T) {
	sysAdmin, _, err := httpdtest.GetAdminByUsername(defaultTokenAuthUser, http.StatusOK)
	assert.NoError(t, err)
	sysAdmin.Filters.AllowAPIKeyAuth = true
	sysAdmin, _, err = httpdtest.UpdateAdmin(sysAdmin, http.StatusOK)
	assert.NoError(t, err)

	apiKey := dataprovider.APIKey{
		Name:  "test admin API key",
		Scope: dataprovider.APIKeyScopeAdmin,
		Admin: defaultTokenAuthUser,
	}

	apiKey, resp, err := httpdtest.AddAPIKey(apiKey, http.StatusCreated)
	assert.NoError(t, err, string(resp))

	admin := getTestAdmin()
	admin.Username = altAdminUsername
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, adminPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	_, err = getJWTAPITokenFromTestServer(altAdminUsername, defaultTokenAuthPass)
	assert.NoError(t, err)

	admin.Filters.AllowAPIKeyAuth = true
	asJSON, err = json.Marshal(admin)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, path.Join(adminPath, altAdminUsername), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(adminPath, altAdminUsername), nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var adminGet dataprovider.Admin
	err = json.Unmarshal(rr.Body.Bytes(), &adminGet)
	assert.NoError(t, err)
	assert.True(t, adminGet.Filters.AllowAPIKeyAuth)

	req, err = http.NewRequest(http.MethodPut, path.Join(adminPath, defaultTokenAuthUser), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "updating the admin impersonated with an API key is not allowed")
	// changing the password for the impersonated admin is not allowed
	pwd := make(map[string]string)
	pwd["current_password"] = defaultTokenAuthPass
	pwd["new_password"] = altAdminPassword
	asJSON, err = json.Marshal(pwd)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, adminPwdPath, bytes.NewBuffer(asJSON))
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "API key authentication is not allowed")

	req, err = http.NewRequest(http.MethodDelete, path.Join(adminPath, defaultTokenAuthUser), nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "you cannot delete yourself")

	req, err = http.NewRequest(http.MethodDelete, path.Join(adminPath, altAdminUsername), nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = httpdtest.RemoveAPIKey(apiKey, http.StatusOK)
	assert.NoError(t, err)

	dbAdmin, err := dataprovider.AdminExists(defaultTokenAuthUser)
	assert.NoError(t, err)
	dbAdmin.Filters.AllowAPIKeyAuth = false
	err = dataprovider.UpdateAdmin(&dbAdmin, "", "")
	assert.NoError(t, err)
	sysAdmin, _, err = httpdtest.GetAdminByUsername(defaultTokenAuthUser, http.StatusOK)
	assert.NoError(t, err)
	assert.False(t, sysAdmin.Filters.AllowAPIKeyAuth)
}

func TestUserHandlingWithAPIKey(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Filters.AllowAPIKeyAuth = true
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	apiKey := dataprovider.APIKey{
		Name:  "test admin API key",
		Scope: dataprovider.APIKeyScopeAdmin,
		Admin: admin.Username,
	}

	apiKey, _, err = httpdtest.AddAPIKey(apiKey, http.StatusCreated)
	assert.NoError(t, err)

	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, err := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	user.Filters.DisableFsChecks = true
	user.Description = "desc"
	userAsJSON = getUserAsJSON(t, user)
	req, err = http.NewRequest(http.MethodPut, path.Join(userPath, user.Username), bytes.NewBuffer(userAsJSON))
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updatedUser dataprovider.User
	err = json.Unmarshal(rr.Body.Bytes(), &updatedUser)
	assert.NoError(t, err)
	assert.True(t, updatedUser.Filters.DisableFsChecks)
	assert.Equal(t, user.Description, updatedUser.Description)

	req, err = http.NewRequest(http.MethodDelete, path.Join(userPath, user.Username), nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetAPIKeyByID(apiKey.KeyID, http.StatusNotFound)
	assert.NoError(t, err)
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
				assert.True(t, util.IsStringInSlice(v, perms))
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
	u.QuotaFiles = 100
	userAsJSON := getUserAsJSON(t, u)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "users", u.Username, "usage"), bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodPut, updateUsedQuotaCompatPath, bytes.NewBuffer(userAsJSON))
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
	// now update only quota size
	u.UsedQuotaFiles = 0
	userAsJSON = getUserAsJSON(t, u)
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "users", u.Username, "usage")+"?mode=add", bytes.NewBuffer(userAsJSON))
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
	assert.Equal(t, usedQuotaSize*2, user.UsedQuotaSize)
	// only quota files
	u.UsedQuotaFiles = usedQuotaFiles
	u.UsedQuotaSize = 0
	userAsJSON = getUserAsJSON(t, u)
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "users", u.Username, "usage")+"?mode=add", bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles*2, user.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize*2, user.UsedQuotaSize)
	req, _ = http.NewRequest(http.MethodPut, updateUsedQuotaCompatPath, bytes.NewBuffer([]byte("string")))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "users", u.Username, "usage"), bytes.NewBuffer([]byte("string")))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.True(t, common.QuotaScans.AddUserQuotaScan(user.Username))
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "users", u.Username, "usage"), bytes.NewBuffer(userAsJSON))
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
		assert.True(t, util.IsStringInSlice(dataprovider.PermListItems, val))
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
	user.CreatedAt = 0
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
	req, err := http.NewRequest(http.MethodGet, quotaScanPath, nil)
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
	common.QuotaScans.AddUserQuotaScan(user.Username)
	req, _ = http.NewRequest(http.MethodPost, path.Join(quotasBasePath, "users", user.Username, "scan"), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr)
	assert.True(t, common.QuotaScans.RemoveUserQuotaScan(user.Username))

	req, _ = http.NewRequest(http.MethodPost, path.Join(quotasBasePath, "users", user.Username, "scan"), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)

	waitForUsersQuotaScan(t, token)

	_, err = os.Stat(user.HomeDir)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(user.HomeDir, os.ModePerm)
		assert.NoError(t, err)
	}
	req, _ = http.NewRequest(http.MethodPost, path.Join(quotasBasePath, "users", user.Username, "scan"), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)

	waitForUsersQuotaScan(t, token)

	req, _ = http.NewRequest(http.MethodPost, path.Join(quotasBasePath, "users", user.Username, "scan"), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)

	waitForUsersQuotaScan(t, token)

	asJSON, err := json.Marshal(user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, quotaScanCompatPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)

	waitForUsersQuotaScan(t, token)

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
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "folders", folder.Name, "usage"), bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodPut, updateFolderUsedQuotaCompatPath, bytes.NewBuffer(folderAsJSON))
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
	// now update only quota size
	f.UsedQuotaFiles = 0
	folderAsJSON, err = json.Marshal(f)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "folders", folder.Name, "usage")+"?mode=add",
		bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	folderGet = vfs.BaseVirtualFolder{}
	req, _ = http.NewRequest(http.MethodGet, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &folderGet)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, folderGet.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize*2, folderGet.UsedQuotaSize)
	// now update only quota files
	f.UsedQuotaSize = 0
	f.UsedQuotaFiles = 1
	folderAsJSON, err = json.Marshal(f)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "folders", folder.Name, "usage")+"?mode=add",
		bytes.NewBuffer(folderAsJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	folderGet = vfs.BaseVirtualFolder{}
	req, _ = http.NewRequest(http.MethodGet, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &folderGet)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles*2, folderGet.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize*2, folderGet.UsedQuotaSize)
	req, _ = http.NewRequest(http.MethodPut, updateFolderUsedQuotaCompatPath, bytes.NewBuffer([]byte("string")))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "folders", folder.Name, "usage"),
		bytes.NewBuffer([]byte("not a json")))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	assert.True(t, common.QuotaScans.AddVFolderQuotaScan(folderName))
	req, _ = http.NewRequest(http.MethodPut, path.Join(quotasBasePath, "folders", folder.Name, "usage"),
		bytes.NewBuffer(folderAsJSON))
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
	req, _ = http.NewRequest(http.MethodPost, path.Join(quotasBasePath, "folders", folder.Name, "scan"), nil)
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
	req, _ = http.NewRequest(http.MethodPost, path.Join(quotasBasePath, "folders", folder.Name, "scan"), nil)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)
	waitForFoldersQuotaScanPath(t, token)

	asJSON, err := json.Marshal(folder)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, quotaScanVFolderCompatPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusAccepted, rr)
	waitForFoldersQuotaScanPath(t, token)

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

	req, _ := http.NewRequest(http.MethodPost, path.Join(quotasBasePath, "users", user.Username, "scan"), nil)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestStartQuotaScanBadUserMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, quotaScanCompatPath, bytes.NewBuffer([]byte("invalid json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestStartQuotaScanBadFolderMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, quotaScanVFolderCompatPath, bytes.NewBuffer([]byte("invalid json")))
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
	req, _ := http.NewRequest(http.MethodPost, path.Join(quotasBasePath, "folders", folder.Name, "scan"), nil)
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
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	req, _ = http.NewRequest(http.MethodGet, webBasePath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	req, _ = http.NewRequest(http.MethodGet, webBasePathAdmin, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))
	req, _ = http.NewRequest(http.MethodGet, webBasePathClient, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
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

	urlString = httpBaseURL + webBasePathClient + "/a"
	req, err = http.NewRequest(http.MethodGet, urlString, nil)
	assert.NoError(t, err)
	resp, err = httpclient.GetHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, urlString, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, "invalid client token")
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

func TestDefenderAPIInvalidIDMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, path.Join(defenderHosts, "abc"), nil) // not hex id
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "invalid host id")
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

func TestWebAPILoginMock(t *testing.T) {
	_, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername+"1", defaultPassword)
	assert.Error(t, err)
	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword+"1")
	assert.Error(t, err)
	apiToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	// a web token is not valid for API usage
	req, err := http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "Your token audience is not valid")

	req, err = http.NewRequest(http.MethodGet, userDirsPath+"/?path=%2F", nil)
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// API token is not valid for web usage
	req, _ = http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	setJWTCookieForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))

	req, _ = http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebClientLoginMock(t *testing.T) {
	_, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	// a web token is not valid for API or WebAdmin usage
	req, _ := http.NewRequest(http.MethodGet, serverStatusPath, nil)
	setBearerForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "Your token audience is not valid")
	req, _ = http.NewRequest(http.MethodGet, webStatusPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))
	// bearer should not work
	req, _ = http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	setBearerForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	// now try to render client pages
	req, _ = http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now logout
	req, _ = http.NewRequest(http.MethodGet, webClientLogoutPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	req, _ = http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))

	// get a new token and use it after removing the user
	webToken, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	apiUserToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	req, _ = http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	setJWTCookieForReq(req, webToken)
	req.RemoteAddr = defaultRemoteAddr
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	req, _ = http.NewRequest(http.MethodGet, webClientDirsPath, nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	req, _ = http.NewRequest(http.MethodGet, webClientDownloadZipPath, nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	req, _ = http.NewRequest(http.MethodGet, userDirsPath, nil)
	setBearerForReq(req, apiUserToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	req, _ = http.NewRequest(http.MethodGet, userFilesPath, nil)
	setBearerForReq(req, apiUserToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	req, _ = http.NewRequest(http.MethodPost, userStreamZipPath, bytes.NewBuffer([]byte(`{}`)))
	setBearerForReq(req, apiUserToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	req, _ = http.NewRequest(http.MethodGet, userPublicKeysPath, nil)
	setBearerForReq(req, apiUserToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	req, _ = http.NewRequest(http.MethodPut, userPublicKeysPath, bytes.NewBuffer([]byte(`{}`)))
	setBearerForReq(req, apiUserToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("public_keys", testPubKey)
	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
}

func TestWebClientLoginErrorsMock(t *testing.T) {
	form := getLoginForm("", "", "")
	req, _ := http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid credentials")

	form = getLoginForm(defaultUsername, defaultPassword, "")
	req, _ = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")
}

func TestWebClientMaxConnections(t *testing.T) {
	oldValue := common.Config.MaxTotalConnections
	common.Config.MaxTotalConnections = 1

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	// now add a fake connection
	fs := vfs.NewOsFs("id", os.TempDir(), "")
	connection := &httpd.Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolHTTP, "", "", user),
	}
	common.Connections.Add(connection)

	_, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "connection not allowed from your ip")

	common.Connections.Remove(connection.GetID())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 0)

	common.Config.MaxTotalConnections = oldValue
}

func TestTokenInvalidIPAddress(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	req.RequestURI = webClientFilesPath
	setJWTCookieForReq(req, webToken)
	req.RemoteAddr = "1.1.1.2"
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)

	apiToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, userDirsPath+"/?path=%2F", nil)
	assert.NoError(t, err)
	req.RemoteAddr = "2.2.2.2"
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "Your token is not valid")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDefender(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	cfg := config.GetCommonConfig()
	cfg.DefenderConfig.Enabled = true
	cfg.DefenderConfig.Threshold = 3
	cfg.DefenderConfig.ScoreLimitExceeded = 2

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	remoteAddr := "172.16.5.6:9876"

	webAdminToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServerWithAddr(defaultUsername, defaultPassword, remoteAddr)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.RequestURI = webClientFilesPath
	setJWTCookieForReq(req, webToken)
	req.RemoteAddr = remoteAddr
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	for i := 0; i < 3; i++ {
		_, err = getJWTWebClientTokenFromTestServerWithAddr(defaultUsername, "wrong pwd", remoteAddr)
		assert.Error(t, err)
	}

	_, err = getJWTWebClientTokenFromTestServerWithAddr(defaultUsername, defaultPassword, remoteAddr)
	assert.Error(t, err)
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.RequestURI = webClientFilesPath
	setJWTCookieForReq(req, webToken)
	req.RemoteAddr = remoteAddr
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "your IP address is banned")

	req, _ = http.NewRequest(http.MethodGet, webUsersPath, nil)
	req.RequestURI = webUsersPath
	setJWTCookieForReq(req, webAdminToken)
	req.RemoteAddr = remoteAddr
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "your IP address is banned")

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.Header.Set("X-Real-IP", "127.0.0.1:2345")
	setJWTCookieForReq(req, webToken)
	req.RemoteAddr = remoteAddr
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "your IP address is banned")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = common.Initialize(oldConfig, 0)
	assert.NoError(t, err)
}

func TestPostConnectHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	common.Config.PostConnectHook = postConnectPath

	u := getTestUser()
	u.Filters.AllowAPIKeyAuth = true
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	apiKey, _, err := httpdtest.AddAPIKey(dataprovider.APIKey{
		Name:  "name",
		Scope: dataprovider.APIKeyScopeUser,
		User:  user.Username,
	}, http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(postConnectPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)

	_, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	err = os.WriteFile(postConnectPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)

	_, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)

	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)

	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.PostConnectHook = ""
}

func TestMaxSessions(t *testing.T) {
	u := getTestUser()
	u.MaxSessions = 1
	u.Email = "user@session.com"
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	_, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	// now add a fake connection
	fs := vfs.NewOsFs("id", os.TempDir(), "")
	connection := &httpd.Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolHTTP, "", "", user),
	}
	common.Connections.Add(connection)
	_, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)
	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)
	// test reset password
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          3525,
		TemplatesPath: "templates",
	}
	err = smtpCfg.Initialize("..")
	assert.NoError(t, err)

	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	lastResetCode = ""
	req, err := http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)
	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("password", defaultPassword)
	form.Set("code", lastResetCode)
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Password reset successfully but unable to login")

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)

	common.Connections.Remove(connection.GetID())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Len(t, common.Connections.GetStats(), 0)
}

func TestSFTPLoopError(t *testing.T) {
	user1 := getTestUser()
	user2 := getTestUser()
	user1.Username += "1"
	user1.Email = "user1@test.com"
	user2.Username += "2"
	user1.FsConfig = vfs.Filesystem{
		Provider: sdk.SFTPFilesystemProvider,
		SFTPConfig: vfs.SFTPFsConfig{
			BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
				Endpoint: sftpServerAddr,
				Username: user2.Username,
			},
			Password: kms.NewPlainSecret(defaultPassword),
		},
	}

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

	// test reset password
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          3525,
		TemplatesPath: "templates",
	}
	err = smtpCfg.Initialize("..")
	assert.NoError(t, err)

	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user1.Username)
	lastResetCode = ""
	req, err := http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)
	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("password", defaultPassword)
	form.Set("code", lastResetCode)
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Password reset successfully but unable to login")

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)

	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user2.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginInvalidFs(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = false
	providerConf.CredentialsPath = credentialsPath
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	u := getTestUser()
	u.Filters.AllowAPIKeyAuth = true
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("invalid JSON for credentials")
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	apiKey, _, err := httpdtest.AddAPIKey(dataprovider.APIKey{
		Name:  "testk",
		Scope: dataprovider.APIKeyScopeUser,
		User:  u.Username,
	}, http.StatusCreated)
	assert.NoError(t, err)

	credentialsFile := filepath.Join(credentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	// now remove the credentials file so the filesystem creation will fail
	err = os.Remove(credentialsFile)
	assert.NoError(t, err)

	_, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)

	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)

	req, err := http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestWebClientChangePwd(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webChangeClientPwdPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form := make(url.Values)
	form.Set("current_password", defaultPassword)
	form.Set("new_password1", defaultPassword)
	form.Set("new_password2", defaultPassword)
	// no csrf token
	req, err = http.NewRequest(http.MethodPost, webChangeClientPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webChangeClientPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "the new password must be different from the current one")

	form.Set("current_password", defaultPassword+"2")
	form.Set("new_password1", defaultPassword+"1")
	form.Set("new_password2", defaultPassword+"1")
	req, _ = http.NewRequest(http.MethodPost, webChangeClientPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "current password does not match")

	form.Set("current_password", defaultPassword)
	form.Set("new_password1", defaultPassword+"1")
	form.Set("new_password2", defaultPassword+"1")
	req, _ = http.NewRequest(http.MethodPost, webChangeClientPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))

	_, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)
	_, err = getJWTWebClientTokenFromTestServer(defaultUsername+"1", defaultPassword+"1")
	assert.Error(t, err)
	_, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword+"1")
	assert.NoError(t, err)

	// remove the change password permission
	user.Filters.WebClient = []string{sdk.WebClientPasswordChangeDisabled}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	assert.Len(t, user.Filters.WebClient, 1)
	assert.Contains(t, user.Filters.WebClient, sdk.WebClientPasswordChangeDisabled)

	webToken, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword+"1")
	assert.NoError(t, err)
	form.Set("current_password", defaultPassword+"1")
	form.Set("new_password1", defaultPassword)
	form.Set("new_password2", defaultPassword)
	req, _ = http.NewRequest(http.MethodPost, webChangeClientPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebAPIPublicKeys(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	apiToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, userPublicKeysPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var keys []string
	err = json.Unmarshal(rr.Body.Bytes(), &keys)
	assert.NoError(t, err)
	assert.Len(t, keys, 0)

	keys = []string{testPubKey, testPubKey1}
	asJSON, err := json.Marshal(keys)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userPublicKeysPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, userPublicKeysPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	keys = nil
	err = json.Unmarshal(rr.Body.Bytes(), &keys)
	assert.NoError(t, err)
	assert.Len(t, keys, 2)

	req, err = http.NewRequest(http.MethodPut, userPublicKeysPath, bytes.NewBuffer([]byte(`invalid json`)))
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	keys = []string{`not a public key`}
	asJSON, err = json.Marshal(keys)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userPublicKeysPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "could not parse key")

	user.Filters.WebClient = append(user.Filters.WebClient, sdk.WebClientPubKeyChangeDisabled)
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	apiToken, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, userPublicKeysPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPreDownloadHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	oldExecuteOn := common.Config.Actions.ExecuteOn
	oldHook := common.Config.Actions.Hook

	common.Config.Actions.ExecuteOn = []string{common.OperationPreDownload}
	common.Config.Actions.Hook = preActionPath

	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(preActionPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)

	testFileName := "testfile"
	testFileContents := []byte("file contents")
	err = os.MkdirAll(filepath.Join(user.GetHomeDir()), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), testFileName), testFileContents, os.ModePerm)
	assert.NoError(t, err)

	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, testFileContents, rr.Body.Bytes())

	req, err = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, testFileContents, rr.Body.Bytes())

	err = os.WriteFile(preActionPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "permission denied")

	req, err = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "permission denied")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.Actions.ExecuteOn = oldExecuteOn
	common.Config.Actions.Hook = oldHook
}

func TestPreUploadHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	oldExecuteOn := common.Config.Actions.ExecuteOn
	oldHook := common.Config.Actions.Hook

	common.Config.Actions.ExecuteOn = []string{common.OperationPreUpload}
	common.Config.Actions.Hook = preActionPath

	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(preActionPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)

	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filenames", "filepre")
	assert.NoError(t, err)
	_, err = part.Write([]byte("file content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=filepre",
		bytes.NewBuffer([]byte("single upload content")))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	err = os.WriteFile(preActionPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=filepre",
		bytes.NewBuffer([]byte("single upload content")))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.Actions.ExecuteOn = oldExecuteOn
	common.Config.Actions.Hook = oldHook
}

func TestShareUsage(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	testFileName := "testfile.dat"
	testFileSize := int64(65536)
	testFilePath := filepath.Join(user.GetHomeDir(), testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	share := dataprovider.Share{
		Name:      "test share",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{"/"},
		Password:  defaultPassword,
		MaxTokens: 2,
		ExpiresAt: util.GetTimeAsMsSinceEpoch(time.Now().Add(1 * time.Second)),
	}
	asJSON, err := json.Marshal(share)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	req, err = http.NewRequest(http.MethodGet, sharesPath+"/unknownid", nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, sharesPath+"/"+objectID, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	req.SetBasicAuth(defaultUsername, "wrong password")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	time.Sleep(2 * time.Second)

	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID, nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	share.ExpiresAt = 0
	jsonReq := make(map[string]interface{})
	jsonReq["name"] = share.Name
	jsonReq["scope"] = share.Scope
	jsonReq["paths"] = share.Paths
	jsonReq["password"] = share.Password
	jsonReq["max_tokens"] = share.MaxTokens
	jsonReq["expires_at"] = share.ExpiresAt
	asJSON, err = json.Marshal(jsonReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userSharesPath+"/"+objectID, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID, nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, sharesPath+"/"+objectID, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid share scope")

	share.MaxTokens = 3
	share.Scope = dataprovider.ShareScopeWrite
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userSharesPath+"/"+objectID, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part1, err := writer.CreateFormFile("filenames", "file1.txt")
	assert.NoError(t, err)
	_, err = part1.Write([]byte("file1 content"))
	assert.NoError(t, err)
	part2, err := writer.CreateFormFile("filenames", "file2.txt")
	assert.NoError(t, err)
	_, err = part2.Write([]byte("file2 content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())

	req, err = http.NewRequest(http.MethodPost, sharesPath+"/"+objectID, reader)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Unable to parse multipart form")

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	// set the proper content type
	req, err = http.NewRequest(http.MethodPost, sharesPath+"/"+objectID, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Allowed usage exceeded")

	share.MaxTokens = 6
	share.Scope = dataprovider.ShareScopeWrite
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, userSharesPath+"/"+objectID, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, sharesPath+"/"+objectID, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webClientPubSharesPath+"/"+objectID, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	share, err = dataprovider.ShareExists(objectID, user.Username)
	assert.NoError(t, err)
	assert.Equal(t, 6, share.UsedTokens)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, sharesPath+"/"+objectID, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	share.MaxTokens = 0
	err = dataprovider.UpdateShare(&share, user.Username, "")
	assert.NoError(t, err)

	user.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, sharesPath+"/"+objectID, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "permission denied")

	body = new(bytes.Buffer)
	writer = multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filename", "file1.txt")
	assert.NoError(t, err)
	_, err = part.Write([]byte("file content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader = bytes.NewReader(body.Bytes())

	req, err = http.NewRequest(http.MethodPost, sharesPath+"/"+objectID, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "No files uploaded!")

	share.Scope = dataprovider.ShareScopeRead
	share.Paths = []string{"/missing"}
	err = dataprovider.UpdateShare(&share, user.Username, "")
	assert.NoError(t, err)

	defer func() {
		rcv := recover()
		assert.Equal(t, http.ErrAbortHandler, rcv)

		share, err = dataprovider.ShareExists(objectID, user.Username)
		assert.NoError(t, err)
		assert.Equal(t, 6, share.UsedTokens)

		_, err = httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}()

	req, err = http.NewRequest(http.MethodGet, sharesPath+"/"+objectID, nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	executeRequest(req)
}

func TestShareUploadSingle(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	share := dataprovider.Share{
		Name:      "test share",
		Scope:     dataprovider.ShareScopeWrite,
		Paths:     []string{"/"},
		Password:  defaultPassword,
		MaxTokens: 0,
	}
	asJSON, err := json.Marshal(share)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	content := []byte("shared file content")
	modTime := time.Now().Add(-12 * time.Hour)
	req, err = http.NewRequest(http.MethodPost, path.Join(sharesPath, objectID, "file.txt"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	req.Header.Set("X-SFTPGO-MTIME", strconv.FormatInt(util.GetTimeAsMsSinceEpoch(modTime), 10))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	info, err := os.Stat(filepath.Join(user.GetHomeDir(), "file.txt"))
	if assert.NoError(t, err) {
		assert.InDelta(t, util.GetTimeAsMsSinceEpoch(modTime), util.GetTimeAsMsSinceEpoch(info.ModTime()), float64(1000))
	}
	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "upload"), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodPost, path.Join(webClientPubSharesPath, objectID, "file.txt"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	info, err = os.Stat(filepath.Join(user.GetHomeDir(), "file.txt"))
	if assert.NoError(t, err) {
		assert.InDelta(t, util.GetTimeAsMsSinceEpoch(time.Now()), util.GetTimeAsMsSinceEpoch(info.ModTime()), float64(3000))
	}
	// we don't allow to create the file in subdirectories
	req, err = http.NewRequest(http.MethodPost, path.Join(sharesPath, objectID, "%2Fdir%2Ffile1.txt"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodPost, path.Join(sharesPath, objectID, "dir", "file.dat"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, path.Join(sharesPath, objectID, "%2F"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	err = os.MkdirAll(filepath.Join(user.GetHomeDir(), "dir"), os.ModePerm)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(sharesPath, objectID, "dir"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "operation unsupported")

	share, err = dataprovider.ShareExists(objectID, user.Username)
	assert.NoError(t, err)
	assert.Equal(t, 2, share.UsedTokens)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, path.Join(sharesPath, objectID, "file1.txt"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestShareUncompressed(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	testFileName := "testfile.dat"
	testFileSize := int64(65536)
	testFilePath := filepath.Join(user.GetHomeDir(), testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	share := dataprovider.Share{
		Name:      "test share",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{"/"},
		Password:  defaultPassword,
		MaxTokens: 0,
	}
	asJSON, err := json.Marshal(share)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID, nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "application/zip", rr.Header().Get("Content-Type"))

	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID+"?compress=false", nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "application/zip", rr.Header().Get("Content-Type"))

	share = dataprovider.Share{
		Name:      "test share1",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{testFileName},
		Password:  defaultPassword,
		MaxTokens: 0,
	}
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID = rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID, nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "application/zip", rr.Header().Get("Content-Type"))

	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID+"?compress=false", nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "application/octet-stream", rr.Header().Get("Content-Type"))

	share, err = dataprovider.ShareExists(objectID, user.Username)
	assert.NoError(t, err)
	assert.Equal(t, 2, share.UsedTokens)

	user.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermUpload}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID+"?compress=false", nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	share, err = dataprovider.ShareExists(objectID, user.Username)
	assert.NoError(t, err)
	assert.Equal(t, 2, share.UsedTokens)

	user.Permissions["/"] = []string{dataprovider.PermAny}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID+"?compress=false", nil)
	assert.NoError(t, err)
	req.SetBasicAuth(defaultUsername, defaultPassword)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDownloadFromShareError(t *testing.T) {
	u := getTestUser()
	u.DownloadDataTransfer = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user.UsedDownloadDataTransfer = 1024*1024 - 32768
	_, err = httpdtest.UpdateTransferQuotaUsage(user, "add", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(1024*1024-32768), user.UsedDownloadDataTransfer)
	testFileName := "test_share_file.dat"
	testFileSize := int64(524288)
	testFilePath := filepath.Join(user.GetHomeDir(), testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	share := dataprovider.Share{
		Name:      "test share root browse",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{"/"},
		MaxTokens: 2,
	}
	asJSON, err := json.Marshal(share)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	defer func() {
		rcv := recover()
		assert.Equal(t, http.ErrAbortHandler, rcv)

		share, err = dataprovider.ShareExists(objectID, user.Username)
		assert.NoError(t, err)
		assert.Equal(t, 0, share.UsedTokens)

		_, err = httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}()

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path="+testFileName), nil)
	assert.NoError(t, err)
	executeRequest(req)
}

func TestBrowseShares(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	testFileName := "testsharefile.dat"
	testFileNameLink := "testsharefile.link"
	shareDir := "share"
	subDir := "sub"
	testFileSize := int64(65536)
	testFilePath := filepath.Join(user.GetHomeDir(), shareDir, testFileName)
	testLinkPath := filepath.Join(user.GetHomeDir(), shareDir, testFileNameLink)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = createTestFile(filepath.Join(user.GetHomeDir(), shareDir, subDir, testFileName), testFileSize)
	assert.NoError(t, err)
	err = os.Symlink(testFilePath, testLinkPath)
	assert.NoError(t, err)

	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	share := dataprovider.Share{
		Name:      "test share browse",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{shareDir},
		MaxTokens: 0,
	}
	asJSON, err := json.Marshal(share)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "upload"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid share scope")

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "files?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Please set the path to a valid file")

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "dirs?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents := make([]map[string]interface{}, 0)
	err = json.Unmarshal(rr.Body.Bytes(), &contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 2)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = make([]map[string]interface{}, 0)
	err = json.Unmarshal(rr.Body.Bytes(), &contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 2)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs?path=%2F"+subDir), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = make([]map[string]interface{}, 0)
	err = json.Unmarshal(rr.Body.Bytes(), &contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 1)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path=%2F.."), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Invalid share path")

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "dirs?path=%2F.."), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs?path=%2F.."), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "files?path=%2F..%2F"+testFileName), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path="+testFileName), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contentDisposition := rr.Header().Get("Content-Disposition")
	assert.NotEmpty(t, contentDisposition)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "files?path="+testFileName), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contentDisposition = rr.Header().Get("Content-Disposition")
	assert.NotEmpty(t, contentDisposition)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path="+subDir+"%2F"+testFileName), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contentDisposition = rr.Header().Get("Content-Disposition")
	assert.NotEmpty(t, contentDisposition)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path=missing"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "file does not exist")

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "files?path=missing"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "dirs?path=missing"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs?path=missing"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path="+testFileNameLink), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "non regular files are not supported for shares")

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "files?path="+testFileNameLink), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "non regular files are not supported for shares")

	// share a symlink
	share = dataprovider.Share{
		Name:      "test share browse",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{path.Join(shareDir, testFileNameLink)},
		MaxTokens: 0,
	}
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID = rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)
	// uncompressed download should not work
	req, err = http.NewRequest(http.MethodGet, webClientPubSharesPath+"/"+objectID+"?compress=false", nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "application/zip", rr.Header().Get("Content-Type"))
	// this share is not browsable, it does not contains a directory
	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "files?path="+testFileName), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "dirs?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "The shared object is not a directory and so it is not browsable")

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "The shared object is not a directory and so it is not browsable")

	// now test a missing shareID
	objectID = "123456"
	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "files?path="+testFileName), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "dirs?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	// share a missing base path
	share = dataprovider.Share{
		Name:      "test share",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{path.Join(shareDir, "missingdir")},
		MaxTokens: 0,
	}
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID = rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	assert.Contains(t, rr.Body.String(), "unable to check the share directory")
	// share multiple paths
	share = dataprovider.Share{
		Name:      "test share",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{shareDir, "/anotherdir"},
		MaxTokens: 0,
	}
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID = rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)
	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "A share with multiple paths is not browsable")
	// share the root path
	share = dataprovider.Share{
		Name:      "test share root",
		Scope:     dataprovider.ShareScopeRead,
		Paths:     []string{"/"},
		MaxTokens: 0,
	}
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID = rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	req, err = http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, objectID, "browse?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = make([]map[string]interface{}, 0)
	err = json.Unmarshal(rr.Body.Bytes(), &contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 1)
	// if we require two-factor auth for HTTP protocol the share should not work anymore
	user.Filters.TwoFactorAuthProtocols = []string{common.ProtocolSSH}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	user.Filters.TwoFactorAuthProtocols = []string{common.ProtocolSSH, common.ProtocolHTTP}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, path.Join(sharesPath, objectID, "dirs?path=%2F"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "two-factor authentication requirements not met")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUserAPIShareErrors(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	share := dataprovider.Share{
		Scope: 1000,
	}
	asJSON, err := json.Marshal(share)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "invalid scope")
	// invalid json
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer([]byte("{")))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	share.Scope = dataprovider.ShareScopeWrite
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "at least a shared path is required")

	share.Paths = []string{"path1", "../path1", "/path2"}
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the write share scope requires exactly one path")

	share.Paths = []string{"", ""}
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "at least a shared path is required")

	share.Paths = []string{"path1", "../path1", "/path1"}
	share.Password = redactedSecret
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "cannot save a share with a redacted password")

	share.Password = "newpass"
	share.AllowFrom = []string{"not valid"}
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "could not parse allow from entry")

	share.AllowFrom = []string{"127.0.0.1/8"}
	share.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-12 * time.Hour))
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "expiration must be in the future")

	share.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(12 * time.Hour))
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	location := rr.Header().Get("Location")

	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "name is mandatory")
	// invalid json
	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer([]byte("}")))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, userSharesPath+"?limit=a", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUserAPIShares(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	u := getTestUser()
	u.Username = altAdminUsername
	user1, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	token1, err := getJWTAPIUserTokenFromTestServer(user1.Username, defaultPassword)
	assert.NoError(t, err)

	// the share username will be set from the claims
	share := dataprovider.Share{
		Name:        "share1",
		Description: "description1",
		Scope:       dataprovider.ShareScopeRead,
		Paths:       []string{"/"},
		CreatedAt:   1,
		UpdatedAt:   2,
		LastUseAt:   3,
		ExpiresAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(2 * time.Hour)),
		Password:    defaultPassword,
		MaxTokens:   10,
		UsedTokens:  2,
		AllowFrom:   []string{"192.168.1.0/24"},
	}
	asJSON, err := json.Marshal(share)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	location := rr.Header().Get("Location")
	assert.NotEmpty(t, location)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)
	assert.Equal(t, fmt.Sprintf("%v/%v", userSharesPath, objectID), location)

	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var shareGet dataprovider.Share
	err = json.Unmarshal(rr.Body.Bytes(), &shareGet)
	assert.NoError(t, err)
	assert.Equal(t, objectID, shareGet.ShareID)
	assert.Equal(t, share.Name, shareGet.Name)
	assert.Equal(t, share.Description, shareGet.Description)
	assert.Equal(t, share.Scope, shareGet.Scope)
	assert.Equal(t, share.Paths, shareGet.Paths)
	assert.Equal(t, int64(0), shareGet.LastUseAt)
	assert.Greater(t, shareGet.CreatedAt, share.CreatedAt)
	assert.Greater(t, shareGet.UpdatedAt, share.UpdatedAt)
	assert.Equal(t, share.ExpiresAt, shareGet.ExpiresAt)
	assert.Equal(t, share.MaxTokens, shareGet.MaxTokens)
	assert.Equal(t, 0, shareGet.UsedTokens)
	assert.Equal(t, share.Paths, shareGet.Paths)
	assert.Equal(t, redactedSecret, shareGet.Password)

	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token1)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	s, err := dataprovider.ShareExists(objectID, defaultUsername)
	assert.NoError(t, err)
	match, err := s.CheckCredentials(defaultUsername, defaultPassword)
	assert.True(t, match)
	assert.NoError(t, err)
	match, err = s.CheckCredentials(defaultUsername, defaultPassword+"mod")
	assert.False(t, match)
	assert.Error(t, err)
	match, err = s.CheckCredentials(altAdminUsername, defaultPassword)
	assert.False(t, match)
	assert.Error(t, err)

	shareGet.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(3 * time.Hour))
	asJSON, err = json.Marshal(shareGet)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	s, err = dataprovider.ShareExists(objectID, defaultUsername)
	assert.NoError(t, err)
	match, err = s.CheckCredentials(defaultUsername, defaultPassword)
	assert.True(t, match)
	assert.NoError(t, err)
	match, err = s.CheckCredentials(defaultUsername, defaultPassword+"mod")
	assert.False(t, match)
	assert.Error(t, err)

	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var shareGetNew dataprovider.Share
	err = json.Unmarshal(rr.Body.Bytes(), &shareGetNew)
	assert.NoError(t, err)
	assert.NotEqual(t, shareGet.UpdatedAt, shareGetNew.UpdatedAt)
	shareGet.UpdatedAt = shareGetNew.UpdatedAt
	assert.Equal(t, shareGet, shareGetNew)

	req, err = http.NewRequest(http.MethodGet, userSharesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var shares []dataprovider.Share
	err = json.Unmarshal(rr.Body.Bytes(), &shares)
	assert.NoError(t, err)
	if assert.Len(t, shares, 1) {
		assert.Equal(t, shareGetNew, shares[0])
	}

	err = dataprovider.UpdateShareLastUse(&shareGetNew, 2)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	shareGetNew = dataprovider.Share{}
	err = json.Unmarshal(rr.Body.Bytes(), &shareGetNew)
	assert.NoError(t, err)
	assert.Equal(t, 2, shareGetNew.UsedTokens, "share: %v", shareGetNew)
	assert.Greater(t, shareGetNew.LastUseAt, int64(0), "share: %v", shareGetNew)

	req, err = http.NewRequest(http.MethodGet, userSharesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token1)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	shares = nil
	err = json.Unmarshal(rr.Body.Bytes(), &shares)
	assert.NoError(t, err)
	assert.Len(t, shares, 0)

	// set an empty password
	shareGet.Password = ""
	asJSON, err = json.Marshal(shareGet)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	shareGetNew = dataprovider.Share{}
	err = json.Unmarshal(rr.Body.Bytes(), &shareGetNew)
	assert.NoError(t, err)
	assert.Empty(t, shareGetNew.Password)

	req, err = http.NewRequest(http.MethodDelete, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	share.Name = ""
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	location = rr.Header().Get("Location")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	// the share should be deleted with the associated user
	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodDelete, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
}

func TestUsersAPISharesNoPasswordDisabled(t *testing.T) {
	u := getTestUser()
	u.Filters.WebClient = []string{sdk.WebClientShareNoPasswordDisabled}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	share := dataprovider.Share{
		Name:  "s",
		Scope: dataprovider.ShareScopeRead,
		Paths: []string{"/"},
	}
	asJSON, err := json.Marshal(share)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "You are not authorized to share files/folders without a password")

	share.Password = defaultPassword
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	location := rr.Header().Get("Location")
	assert.NotEmpty(t, location)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)
	assert.Equal(t, fmt.Sprintf("%v/%v", userSharesPath, objectID), location)

	share.Password = ""
	asJSON, err = json.Marshal(share)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "You are not authorized to share files/folders without a password")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUserAPIKey(t *testing.T) {
	u := getTestUser()
	u.Filters.AllowAPIKeyAuth = true
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	apiKey := dataprovider.APIKey{
		Name:  "testkey",
		User:  user.Username + "1",
		Scope: dataprovider.APIKeyScopeUser,
	}
	_, _, err = httpdtest.AddAPIKey(apiKey, http.StatusBadRequest)
	assert.NoError(t, err)
	apiKey.User = user.Username
	apiKey, _, err = httpdtest.AddAPIKey(apiKey, http.StatusCreated)
	assert.NoError(t, err)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filenames", "filenametest")
	assert.NoError(t, err)
	_, err = part.Write([]byte("test file content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setAPIKeyForReq(req, apiKey.Key, "")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var dirEntries []map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &dirEntries)
	assert.NoError(t, err)
	assert.Len(t, dirEntries, 1)

	user.Status = 0
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	user.Status = 1
	user.Filters.DeniedProtocols = []string{common.ProtocolHTTP}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	user.Filters.DeniedProtocols = []string{common.ProtocolFTP}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	apiKeyNew := dataprovider.APIKey{
		Name:  apiKey.Name,
		Scope: dataprovider.APIKeyScopeUser,
	}

	apiKeyNew, _, err = httpdtest.AddAPIKey(apiKeyNew, http.StatusCreated)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKeyNew.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	// now associate a user
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKeyNew.Key, user.Username)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now with a missing user
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKeyNew.Key, user.Username+"1")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	// empty user and key not associated to any user
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKeyNew.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	apiKeyNew.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-24 * time.Hour))
	_, _, err = httpdtest.UpdateAPIKey(apiKeyNew, http.StatusOK)
	assert.NoError(t, err)
	// expired API key
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKeyNew.Key, user.Username)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	_, err = httpdtest.RemoveAPIKey(apiKeyNew, http.StatusOK)
	assert.NoError(t, err)
}

func TestWebClientViewPDF(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webClientViewPDFPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, webClientViewPDFPath+"?path=test.pdf", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebEditFile(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	testFile1 := "testfile1.txt"
	testFile2 := "testfile2"
	file1Size := int64(65536)
	file2Size := int64(1048576 * 2)
	err = createTestFile(filepath.Join(user.GetHomeDir(), testFile1), file1Size)
	assert.NoError(t, err)
	err = createTestFile(filepath.Join(user.GetHomeDir(), testFile2), file2Size)
	assert.NoError(t, err)

	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webClientEditFilePath+"?path="+testFile1, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webClientEditFilePath+"?path="+testFile2, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "exceeds the maximum allowed size")

	req, err = http.NewRequest(http.MethodGet, webClientEditFilePath+"?path=missing", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Unable to stat file")

	req, err = http.NewRequest(http.MethodGet, webClientEditFilePath+"?path=%2F", nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "does not point to a file")

	user.Filters.DeniedProtocols = []string{common.ProtocolHTTP}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientEditFilePath+"?path="+testFile1, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	user.Filters.DeniedProtocols = []string{common.ProtocolFTP}
	user.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:           "/",
			DeniedPatterns: []string{"*.txt"},
		},
	}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientEditFilePath+"?path="+testFile1, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Unable to get a reader")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientEditFilePath+"?path="+testFile1, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestWebGetFiles(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	testFileName := "testfile"
	testDir := "testdir"
	testFileContents := []byte("file contents")
	err = os.MkdirAll(filepath.Join(user.GetHomeDir(), testDir), os.ModePerm)
	assert.NoError(t, err)
	extensions := []string{"", ".doc", ".ppt", ".xls", ".pdf", ".mkv", ".png", ".go", ".zip", ".txt"}
	for _, ext := range extensions {
		err = os.WriteFile(filepath.Join(user.GetHomeDir(), testFileName+ext), testFileContents, os.ModePerm)
		assert.NoError(t, err)
	}
	err = os.Symlink(filepath.Join(user.GetHomeDir(), testFileName+".doc"), filepath.Join(user.GetHomeDir(), testDir, testFileName+".link"))
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testDir, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientDirsPath+"?path="+testDir, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var dirContents []map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &dirContents)
	assert.NoError(t, err)
	assert.Len(t, dirContents, 1)

	req, _ = http.NewRequest(http.MethodGet, userDirsPath+"?path="+testDir, nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var dirEntries []map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &dirEntries)
	assert.NoError(t, err)
	assert.Len(t, dirEntries, 1)

	req, _ = http.NewRequest(http.MethodGet, webClientDownloadZipPath+"?path="+url.QueryEscape("/")+"&files="+
		url.QueryEscape(fmt.Sprintf(`["%v","%v","%v"]`, testFileName, testDir, testFileName+extensions[2])), nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	filesList := []string{testFileName, testDir, testFileName + extensions[2]}
	asJSON, err := json.Marshal(filesList)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, userStreamZipPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, userStreamZipPath, bytes.NewBuffer([]byte(`file`)))
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientDownloadZipPath+"?path="+url.QueryEscape("/")+"&files="+
		url.QueryEscape(fmt.Sprintf(`["%v"]`, testDir)), nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientDownloadZipPath+"?path="+url.QueryEscape("/")+"&files=notalist", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	assert.Contains(t, rr.Body.String(), "Unable to get files list")

	req, _ = http.NewRequest(http.MethodGet, webClientDirsPath+"?path=/", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	dirContents = nil
	err = json.Unmarshal(rr.Body.Bytes(), &dirContents)
	assert.NoError(t, err)
	assert.Len(t, dirContents, len(extensions)+1)

	req, _ = http.NewRequest(http.MethodGet, userDirsPath+"?path=/", nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	dirEntries = nil
	err = json.Unmarshal(rr.Body.Bytes(), &dirEntries)
	assert.NoError(t, err)
	assert.Len(t, dirEntries, len(extensions)+1)

	req, _ = http.NewRequest(http.MethodGet, webClientDirsPath+"?path=/missing", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to get directory contents")

	req, _ = http.NewRequest(http.MethodGet, userDirsPath+"?path=missing", nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to get directory contents")

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, testFileContents, rr.Body.Bytes())

	req, _ = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, testFileContents, rr.Body.Bytes())

	req, _ = http.NewRequest(http.MethodGet, userFilesPath+"?path=", nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Please set the path to a valid file")

	req, _ = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testDir, nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "is a directory")

	req, _ = http.NewRequest(http.MethodGet, userFilesPath+"?path=notafile", nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to stat the requested file")

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=2-")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusPartialContent, rr)
	assert.Equal(t, testFileContents[2:], rr.Body.Bytes())

	req, _ = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=2-")
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusPartialContent, rr)
	assert.Equal(t, testFileContents[2:], rr.Body.Bytes())

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=-2")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusPartialContent, rr)
	assert.Equal(t, testFileContents[11:], rr.Body.Bytes())

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=-2,")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestedRangeNotSatisfiable, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=1a-")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestedRangeNotSatisfiable, rr)

	req, _ = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=2b-")
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestedRangeNotSatisfiable, rr)

	req, _ = http.NewRequest(http.MethodHead, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=2-")
	req.Header.Set("If-Range", time.Now().UTC().Add(120*time.Second).Format(http.TimeFormat))
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusPartialContent, rr)

	req, _ = http.NewRequest(http.MethodHead, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=2-")
	req.Header.Set("If-Range", time.Now().UTC().Add(-120*time.Second).Format(http.TimeFormat))
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodHead, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("If-Modified-Since", time.Now().UTC().Add(-120*time.Second).Format(http.TimeFormat))
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodHead, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("If-Modified-Since", time.Now().UTC().Add(120*time.Second).Format(http.TimeFormat))
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotModified, rr)

	req, _ = http.NewRequest(http.MethodHead, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("If-Unmodified-Since", time.Now().UTC().Add(-120*time.Second).Format(http.TimeFormat))
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusPreconditionFailed, rr)

	req, _ = http.NewRequest(http.MethodHead, userFilesPath+"?path="+testFileName, nil)
	req.Header.Set("If-Unmodified-Since", time.Now().UTC().Add(-120*time.Second).Format(http.TimeFormat))
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusPreconditionFailed, rr)

	req, _ = http.NewRequest(http.MethodHead, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("If-Unmodified-Since", time.Now().UTC().Add(120*time.Second).Format(http.TimeFormat))
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user.Filters.DeniedProtocols = []string{common.ProtocolHTTP}
	_, resp, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(resp))

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientDirsPath+"?path=/", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, _ = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, _ = http.NewRequest(http.MethodGet, userDirsPath+"?path="+testDir, nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	filesList = []string{testDir}
	asJSON, err = json.Marshal(filesList)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, userStreamZipPath, bytes.NewBuffer(asJSON))
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	user.Filters.DeniedProtocols = []string{common.ProtocolFTP}
	user.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	_, resp, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err, string(resp))

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientDownloadZipPath, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, _ = http.NewRequest(http.MethodGet, userDirsPath+"?path="+testDir, nil)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebDirsAPI(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	testDir := "testdir"

	req, err := http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var contents []map[string]interface{}
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 0)

	// rename a missing folder
	req, err = http.NewRequest(http.MethodPatch, userDirsPath+"?path="+testDir+"&target="+testDir+"new", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	// delete a missing folder
	req, err = http.NewRequest(http.MethodDelete, userDirsPath+"?path="+testDir, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	// create a dir
	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path="+testDir, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	// check the dir was created
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = nil
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	if assert.Len(t, contents, 1) {
		assert.Equal(t, testDir, contents[0]["name"])
	}
	// rename a dir with the same source and target name
	req, err = http.NewRequest(http.MethodPatch, userDirsPath+"?path="+testDir+"&target="+testDir, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "operation unsupported")
	req, err = http.NewRequest(http.MethodPatch, userDirsPath+"?path="+testDir+"&target=%2F"+testDir+"%2F", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "operation unsupported")
	// create a dir with missing parents
	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path="+url.QueryEscape(path.Join("/sub/dir", testDir)), nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	// setting the mkdir_parents param will work
	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?mkdir_parents=true&path="+url.QueryEscape(path.Join("/sub/dir", testDir)), nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	// rename the dir
	req, err = http.NewRequest(http.MethodPatch, userDirsPath+"?path="+testDir+"&target="+testDir+"new", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// delete the dir
	req, err = http.NewRequest(http.MethodDelete, userDirsPath+"?path="+testDir+"new", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// the root dir cannot be created
	req, err = http.NewRequest(http.MethodPost, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)

	user.Permissions["/"] = []string{dataprovider.PermListItems}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	// the user has no more the permission to create the directory
	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path="+testDir, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	// the user is deleted, any API call should fail
	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path="+testDir, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPatch, userDirsPath+"?path="+testDir+"&target="+testDir+"new", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodDelete, userDirsPath+"?path="+testDir+"new", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestWebUploadSingleFile(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	content := []byte("test content")

	req, err := http.NewRequest(http.MethodPost, userUploadFilePath, bytes.NewBuffer(content))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "please set a file path")

	modTime := time.Now().Add(-24 * time.Hour)
	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=file.txt", bytes.NewBuffer(content))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	req.Header.Set("X-SFTPGO-MTIME", strconv.FormatInt(util.GetTimeAsMsSinceEpoch(modTime), 10))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	info, err := os.Stat(filepath.Join(user.GetHomeDir(), "file.txt"))
	if assert.NoError(t, err) {
		assert.InDelta(t, util.GetTimeAsMsSinceEpoch(modTime), util.GetTimeAsMsSinceEpoch(info.ModTime()), float64(1000))
	}
	// invalid modification time will be ignored
	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=file.txt", bytes.NewBuffer(content))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	req.Header.Set("X-SFTPGO-MTIME", "123abc")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	info, err = os.Stat(filepath.Join(user.GetHomeDir(), "file.txt"))
	if assert.NoError(t, err) {
		assert.InDelta(t, util.GetTimeAsMsSinceEpoch(time.Now()), util.GetTimeAsMsSinceEpoch(info.ModTime()), float64(3000))
	}
	// upload to a missing dir will fail without the mkdir_parents param
	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path="+url.QueryEscape("/subdir/file.txt"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?mkdir_parents=true&path="+url.QueryEscape("/subdir/file.txt"), bytes.NewBuffer(content))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	metadataReq := make(map[string]int64)
	metadataReq["modification_time"] = util.GetTimeAsMsSinceEpoch(modTime)
	asJSON, err := json.Marshal(metadataReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPatch, userFilesDirsMetadataPath+"?path=file.txt", bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	info, err = os.Stat(filepath.Join(user.GetHomeDir(), "file.txt"))
	if assert.NoError(t, err) {
		assert.InDelta(t, util.GetTimeAsMsSinceEpoch(modTime), util.GetTimeAsMsSinceEpoch(info.ModTime()), float64(1000))
	}
	// missing file
	req, err = http.NewRequest(http.MethodPatch, userFilesDirsMetadataPath+"?path=file2.txt", bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to set metadata for path")
	// invalid JSON
	req, err = http.NewRequest(http.MethodPatch, userFilesDirsMetadataPath+"?path=file.txt", bytes.NewBuffer(content))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	// missing mandatory parameter
	req, err = http.NewRequest(http.MethodPatch, userFilesDirsMetadataPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "please set a modification_time and a path")

	metadataReq = make(map[string]int64)
	asJSON, err = json.Marshal(metadataReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPatch, userFilesDirsMetadataPath+"?path=file.txt", bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "please set a modification_time and a path")

	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=%2Fdir%2Ffile.txt", bytes.NewBuffer(content))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to write file")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=file.txt", bytes.NewBuffer(content))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")

	metadataReq["modification_time"] = util.GetTimeAsMsSinceEpoch(modTime)
	asJSON, err = json.Marshal(metadataReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPatch, userFilesDirsMetadataPath+"?path=file.txt", bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to retrieve your user")
}

func TestWebFilesAPI(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part1, err := writer.CreateFormFile("filenames", "file1.txt")
	assert.NoError(t, err)
	_, err = part1.Write([]byte("file1 content"))
	assert.NoError(t, err)
	part2, err := writer.CreateFormFile("filenames", "file2.txt")
	assert.NoError(t, err)
	_, err = part2.Write([]byte("file2 content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())

	req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Unable to parse multipart form")
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	// set the proper content type
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	// check we have 2 files
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var contents []map[string]interface{}
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 2)
	// overwrite the existing files
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = nil
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 2)
	// now create a dir and upload to that dir
	testDir := "tdir"
	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path="+testDir, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?path="+testDir, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	// upload to a missing subdir will fail without the mkdir_parents param
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?path="+url.QueryEscape("/sub/"+testDir), reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?mkdir_parents=true&path="+url.QueryEscape("/sub/"+testDir), reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = nil
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 4)
	req, err = http.NewRequest(http.MethodGet, userDirsPath+"?path="+testDir, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = nil
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 2)
	// rename a file
	req, err = http.NewRequest(http.MethodPatch, userFilesPath+"?path=file1.txt&target=%2Ftdir%2Ffile3.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// rename a missing file
	req, err = http.NewRequest(http.MethodPatch, userFilesPath+"?path=file1.txt&target=%2Ftdir%2Ffile3.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	// rename a file with target name equal to source name
	req, err = http.NewRequest(http.MethodPatch, userFilesPath+"?path=file1.txt&target=file1.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "operation unsupported")
	// delete a file
	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=file2.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// delete a missing file
	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=file2.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	// delete a directory
	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=tdir", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	// make a symlink outside the home dir and then try to delete it
	extPath := filepath.Join(os.TempDir(), "file")
	err = os.WriteFile(extPath, []byte("contents"), os.ModePerm)
	assert.NoError(t, err)
	err = os.Symlink(extPath, filepath.Join(user.GetHomeDir(), "file"))
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=file", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	err = os.Remove(extPath)
	assert.NoError(t, err)
	// remove delete and overwrite permissions
	user.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?path=tdir", reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=%2Ftdir%2Ffile1.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	// the user is deleted, any API call should fail
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPatch, userFilesPath+"?path=file1.txt&target=%2Ftdir%2Ffile3.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=file2.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestStartDirectory(t *testing.T) {
	u := getTestUser()
	u.Filters.StartDirectory = "/start/dir"
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	filename := "file1.txt"
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part1, err := writer.CreateFormFile("filenames", filename)
	assert.NoError(t, err)
	_, err = part1.Write([]byte("test content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())
	req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	// check we have 2 files in the defined start dir
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var contents []map[string]interface{}
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	if assert.Len(t, contents, 1) {
		assert.Equal(t, filename, contents[0]["name"].(string))
	}
	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=file2.txt",
		bytes.NewBuffer([]byte("single upload content")))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path=testdir", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, err = http.NewRequest(http.MethodPatch, userDirsPath+"?path=testdir&target=testdir1", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path=%2Ftestdirroot", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, err = http.NewRequest(http.MethodGet, userDirsPath+"?path="+url.QueryEscape(u.Filters.StartDirectory), nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = nil
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 3)

	req, err = http.NewRequest(http.MethodGet, userFilesPath+"?path="+filename, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, userFilesPath+"?path=%2F"+filename, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPatch, userFilesPath+"?path="+filename+"&target="+filename+"_rename", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodDelete, userDirsPath+"?path=testdir1", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = nil
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 2)

	req, err = http.NewRequest(http.MethodGet, webClientDirsPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = nil
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 2)

	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path="+filename+"_rename", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, userDirsPath+"?path="+url.QueryEscape(u.Filters.StartDirectory), nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	contents = nil
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 1)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebFilesTransferQuotaLimits(t *testing.T) {
	u := getTestUser()
	u.UploadDataTransfer = 1
	u.DownloadDataTransfer = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	testFileName := "file.data"
	testFileSize := 550000
	testFileContents := make([]byte, testFileSize)
	n, err := io.ReadFull(rand.Reader, testFileContents)
	assert.NoError(t, err)
	assert.Equal(t, testFileSize, n)
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filenames", testFileName)
	assert.NoError(t, err)
	_, err = part.Write(testFileContents)
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())
	req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	req, err = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, testFileContents, rr.Body.Bytes())
	// error while download is active
	downloadFunc := func() {
		defer func() {
			rcv := recover()
			assert.Equal(t, http.ErrAbortHandler, rcv)
		}()

		req, err = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
		assert.NoError(t, err)
		setBearerForReq(req, webAPIToken)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
	}
	downloadFunc()
	// error before starting the download
	req, err = http.NewRequest(http.MethodGet, userFilesPath+"?path="+testFileName, nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	// error while upload is active
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestEntityTooLarge, rr)
	// error before starting the upload
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestEntityTooLarge, rr)
	// now test upload/download to/from shares
	share1 := dataprovider.Share{
		Name:  "share1",
		Scope: dataprovider.ShareScopeRead,
		Paths: []string{"/"},
	}
	asJSON, err := json.Marshal(share1)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	req, err = http.NewRequest(http.MethodGet, sharesPath+"/"+objectID, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	share2 := dataprovider.Share{
		Name:  "share2",
		Scope: dataprovider.ShareScopeWrite,
		Paths: []string{"/"},
	}
	asJSON, err = json.Marshal(share2)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userSharesPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	objectID = rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, sharesPath+"/"+objectID, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestEntityTooLarge, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebUploadErrors(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 65535
	subDir1 := "sub1"
	subDir2 := "sub2"
	u.Permissions[path.Join("/", subDir1)] = []string{dataprovider.PermListItems}
	u.Permissions[path.Join("/", subDir2)] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermDelete}
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/sub2",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{"*.zip"},
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filenames", "file.zip")
	assert.NoError(t, err)
	_, err = part.Write([]byte("file content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	// zip file are not allowed within sub2
	req, err := http.NewRequest(http.MethodPost, userFilesPath+"?path=sub2", reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	// we have no upload permissions within sub1
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?path=sub1", reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	// we cannot create dirs in sub2
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?mkdir_parents=true&path="+url.QueryEscape("/sub2/dir"), reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to check/create missing parent dir")
	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?mkdir_parents=true&path="+url.QueryEscape("/sub2/dir/test"), nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Error checking parent directories")
	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?mkdir_parents=true&path="+url.QueryEscape("/sub2/dir1/file.txt"), bytes.NewBuffer([]byte("")))
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Error checking parent directories")
	// create a dir and try to overwrite it with a file
	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path=file.zip", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "operation unsupported")
	// try to upload to a missing parent directory
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?path=missingdir", reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodDelete, userDirsPath+"?path=file.zip", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// upload will work now
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	// overwrite the file
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	vfs.SetTempPath(filepath.Join(os.TempDir(), "missingpath"))

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	if runtime.GOOS != osWindows {
		req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=file.zip", nil)
		assert.NoError(t, err)
		setBearerForReq(req, webAPIToken)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)

		vfs.SetTempPath(filepath.Clean(os.TempDir()))
		err = os.Chmod(user.GetHomeDir(), 0555)
		assert.NoError(t, err)

		_, err = reader.Seek(0, io.SeekStart)
		assert.NoError(t, err)
		req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
		assert.NoError(t, err)
		req.Header.Add("Content-Type", writer.FormDataContentType())
		setBearerForReq(req, webAPIToken)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusForbidden, rr)
		assert.Contains(t, rr.Body.String(), "Error closing file")

		req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=file.zip", bytes.NewBuffer(nil))
		assert.NoError(t, err)
		setBearerForReq(req, webAPIToken)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusForbidden, rr)
		assert.Contains(t, rr.Body.String(), "Error closing file")

		err = os.Chmod(user.GetHomeDir(), os.ModePerm)
		assert.NoError(t, err)
	}

	vfs.SetTempPath("")

	// upload a multipart form with no files
	body = new(bytes.Buffer)
	writer = multipart.NewWriter(body)
	err = writer.Close()
	assert.NoError(t, err)
	reader = bytes.NewReader(body.Bytes())
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?path=sub2", reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "No files uploaded!")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebAPIVFolder(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 65535
	vdir := "/vdir"
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	folderName := filepath.Base(mappedPath)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdir,
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	webAPIToken, err := getJWTAPIUserTokenFromTestServer(user.Username, defaultPassword)
	assert.NoError(t, err)

	fileContents := []byte("test contents")

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filenames", "file.txt")
	assert.NoError(t, err)
	_, err = part.Write(fileContents)
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())

	req, err := http.NewRequest(http.MethodPost, userFilesPath+"?path=vdir", reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(fileContents)), user.UsedQuotaSize)

	folder, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(fileContents)), folder.UsedQuotaSize)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath+"?path=vdir", reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(fileContents)), user.UsedQuotaSize)

	folder, _, err = httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(fileContents)), folder.UsedQuotaSize)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestWebAPIWritePermission(t *testing.T) {
	u := getTestUser()
	u.Filters.WebClient = append(u.Filters.WebClient, sdk.WebClientWriteDisabled)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filenames", "file.txt")
	assert.NoError(t, err)
	_, err = part.Write([]byte(""))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())

	req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodPatch, userFilesPath+"?path=a&target=b", nil)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=a", nil)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodGet, userFilesPath+"?path=a.txt", nil)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodPost, userDirsPath+"?path=dir", nil)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodPatch, userDirsPath+"?path=dir&target=dir1", nil)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodDelete, userDirsPath+"?path=dir", nil)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebAPICryptFs(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 65535
	u.FsConfig.Provider = sdk.CryptedFilesystemProvider
	u.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret(defaultPassword)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filenames", "file.txt")
	assert.NoError(t, err)
	_, err = part.Write([]byte("content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())

	req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebUploadSFTP(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.QuotaFiles = 100
	u.FsConfig.SFTPConfig.BufferSize = 2
	u.HomeDir = filepath.Join(os.TempDir(), u.Username)
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	webAPIToken, err := getJWTAPIUserTokenFromTestServer(sftpUser.Username, defaultPassword)
	assert.NoError(t, err)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("filenames", "file.txt")
	assert.NoError(t, err)
	_, err = part.Write([]byte("test file content"))
	assert.NoError(t, err)
	err = writer.Close()
	assert.NoError(t, err)
	reader := bytes.NewReader(body.Bytes())

	req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)

	expectedQuotaSize := int64(17)
	expectedQuotaFiles := 1
	user, _, err := httpdtest.GetUserByUsername(sftpUser.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)

	user.QuotaSize = 10
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	// we are now overquota on overwrite
	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestEntityTooLarge, rr)
	assert.Contains(t, rr.Body.String(), "denying write due to space limit")
	assert.Contains(t, rr.Body.String(), "Unable to write file")

	// delete the file
	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=file.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user, _, err = httpdtest.GetUserByUsername(sftpUser.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, user.UsedQuotaFiles)
	assert.Equal(t, int64(0), user.UsedQuotaSize)

	req, err = http.NewRequest(http.MethodPost, userUploadFilePath+"?path=file.txt",
		bytes.NewBuffer([]byte("test upload single file content")))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestEntityTooLarge, rr)
	assert.Contains(t, rr.Body.String(), "denying write due to space limit")
	assert.Contains(t, rr.Body.String(), "Error saving file")

	// delete the file
	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=file.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = reader.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userFilesPath, reader)
	assert.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusRequestEntityTooLarge, rr)
	assert.Contains(t, rr.Body.String(), "denying write due to space limit")
	assert.Contains(t, rr.Body.String(), "Error saving file")

	// delete the file
	req, err = http.NewRequest(http.MethodDelete, userFilesPath+"?path=file.txt", nil)
	assert.NoError(t, err)
	setBearerForReq(req, webAPIToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user, _, err = httpdtest.GetUserByUsername(sftpUser.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, user.UsedQuotaFiles)
	assert.Equal(t, int64(0), user.UsedQuotaSize)

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(sftpUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebUploadMultipartFormReadError(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, userFilesPath, nil)
	assert.NoError(t, err)

	mpartForm := &multipart.Form{
		File: make(map[string][]*multipart.FileHeader),
	}
	mpartForm.File["filenames"] = append(mpartForm.File["filenames"], &multipart.FileHeader{Filename: "missing"})
	req.MultipartForm = mpartForm
	req.Header.Add("Content-Type", "multipart/form-data")
	setBearerForReq(req, webAPIToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
	assert.Contains(t, rr.Body.String(), "Unable to read uploaded file")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestCompressionErrorMock(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	defer func() {
		rcv := recover()
		assert.Equal(t, http.ErrAbortHandler, rcv)
		_, err := httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}()

	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, webClientDownloadZipPath+"?path="+url.QueryEscape("/")+"&files="+
		url.QueryEscape(`["missing"]`), nil)
	setJWTCookieForReq(req, webToken)
	executeRequest(req)
}

func TestGetFilesSFTPBackend(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	u := getTestSFTPUser()
	u.FsConfig.SFTPConfig.BufferSize = 2
	u.Permissions["/adir"] = nil
	u.Permissions["/adir1"] = []string{dataprovider.PermListItems}
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:           "/adir2",
			DeniedPatterns: []string{"*.txt"},
		},
	}
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	testFileName := "testsftpfile"
	testDir := "testsftpdir"
	testFileContents := []byte("sftp file contents")
	err = os.MkdirAll(filepath.Join(user.GetHomeDir(), testDir, "sub"), os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(filepath.Join(user.GetHomeDir(), "adir1"), os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(filepath.Join(user.GetHomeDir(), "adir2"), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), testFileName), testFileContents, os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "adir1", "afile"), testFileContents, os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "adir2", "afile.txt"), testFileContents, os.ModePerm)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(sftpUser.Username, defaultPassword)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+path.Join(testDir, "sub"), nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+path.Join(testDir, "missing"), nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "card-body text-form-error")
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path=adir/sub", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "card-body text-form-error")

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path=adir1/afile", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "card-body text-form-error")

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path=adir2/afile.txt", nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "card-body text-form-error")

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, testFileContents, rr.Body.Bytes())

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
	req.Header.Set("Range", "bytes=2-")
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusPartialContent, rr)
	assert.Equal(t, testFileContents[2:], rr.Body.Bytes())

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(sftpUser.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestClientUserClose(t *testing.T) {
	u := getTestUser()
	u.UploadBandwidth = 32
	u.DownloadBandwidth = 32
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFileName := "file.dat"
	testFileSize := int64(524288)
	testFilePath := filepath.Join(user.GetHomeDir(), testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	uploadContent := make([]byte, testFileSize)
	_, err = rand.Read(uploadContent)
	assert.NoError(t, err)
	webToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	webAPIToken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			rcv := recover()
			assert.Equal(t, http.ErrAbortHandler, rcv)
		}()
		req, _ := http.NewRequest(http.MethodGet, webClientFilesPath+"?path="+testFileName, nil)
		setJWTCookieForReq(req, webToken)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := http.NewRequest(http.MethodGet, webClientEditFilePath+"?path="+testFileName, nil)
		setJWTCookieForReq(req, webToken)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusInternalServerError, rr)
		assert.Contains(t, rr.Body.String(), "Unable to read the file")
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("filenames", "upload.dat")
		assert.NoError(t, err)
		n, err := part.Write(uploadContent)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, int64(n))
		err = writer.Close()
		assert.NoError(t, err)
		reader := bytes.NewReader(body.Bytes())
		req, err := http.NewRequest(http.MethodPost, userFilesPath, reader)
		assert.NoError(t, err)
		req.Header.Add("Content-Type", writer.FormDataContentType())
		setBearerForReq(req, webAPIToken)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusBadRequest, rr)
		assert.Contains(t, rr.Body.String(), "transfer aborted")
	}()
	// wait for the transfers
	assert.Eventually(t, func() bool {
		stats := common.Connections.GetStats()
		if len(stats) == 3 {
			if len(stats[0].Transfers) > 0 && len(stats[1].Transfers) > 0 {
				return true
			}
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)

	for _, stat := range common.Connections.GetStats() {
		// close all the active transfers
		common.Connections.Close(stat.ConnectionID)
	}
	wg.Wait()
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 },
		1*time.Second, 100*time.Millisecond)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWebAdminSetupMock(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, webAdminSetupPath, nil)
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))
	// now delete all the admins
	admins, err := dataprovider.GetAdmins(100, 0, dataprovider.OrderASC)
	assert.NoError(t, err)
	for _, admin := range admins {
		err = dataprovider.DeleteAdmin(admin.Username, "", "")
		assert.NoError(t, err)
	}
	// close the provider and initializes it without creating the default admin
	os.Setenv("SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", "0")
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	// now the setup page must be rendered
	req, err = http.NewRequest(http.MethodGet, webAdminSetupPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// check redirects to the setup page
	req, err = http.NewRequest(http.MethodGet, "/", nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))
	req, err = http.NewRequest(http.MethodGet, webBasePath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))
	req, err = http.NewRequest(http.MethodGet, webBasePathAdmin, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))
	req, err = http.NewRequest(http.MethodGet, webLoginPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))
	req, err = http.NewRequest(http.MethodGet, webClientLoginPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))

	csrfToken, err := getCSRFToken(httpBaseURL + webAdminSetupPath)
	assert.NoError(t, err)
	form := make(url.Values)
	req, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Please set a username")
	form.Set("username", defaultTokenAuthUser)
	req, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Please set a password")
	form.Set("password", defaultTokenAuthPass)
	req, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Passwords mismatch")
	form.Set("confirm_password", defaultTokenAuthPass)
	// test a parse form error
	req, err = http.NewRequest(http.MethodPost, webAdminSetupPath+"?param=p%C3%AO%GH", bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test a dataprovider error
	err = dataprovider.Close()
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// finally initialize the provider and create the default admin
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webUsersPath, rr.Header().Get("Location"))
	// if we resubmit the form we get a bad request, an admin already exists
	req, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "an admin user already exists")
	os.Setenv("SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", "1")
}

func TestWhitelist(t *testing.T) {
	configCopy := common.Config

	common.Config.MaxTotalConnections = 1
	wlFile := filepath.Join(os.TempDir(), "wl.json")
	common.Config.WhiteListFile = wlFile
	wl := common.HostListFile{
		IPAddresses:  []string{"172.120.1.1", "172.120.1.2"},
		CIDRNetworks: []string{"192.8.7.0/22"},
	}
	data, err := json.Marshal(wl)
	assert.NoError(t, err)
	err = os.WriteFile(wlFile, data, 0664)
	assert.NoError(t, err)
	defer os.Remove(wlFile)

	err = common.Initialize(common.Config, 0)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, webLoginPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "connection not allowed from your ip")

	req.RemoteAddr = "172.120.1.1"
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req.RemoteAddr = "172.120.1.3"
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "connection not allowed from your ip")

	req.RemoteAddr = "192.8.7.1"
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	wl.IPAddresses = append(wl.IPAddresses, "172.120.1.3")
	data, err = json.Marshal(wl)
	assert.NoError(t, err)
	err = os.WriteFile(wlFile, data, 0664)
	assert.NoError(t, err)
	err = common.Reload()
	assert.NoError(t, err)

	req.RemoteAddr = "172.120.1.3"
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	common.Config = configCopy
	err = common.Initialize(common.Config, 0)
	assert.NoError(t, err)
}

func TestWebAdminLoginMock(t *testing.T) {
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
	req.RemoteAddr = defaultRemoteAddr
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

	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	// now try using wrong credentials
	form := getLoginForm(defaultTokenAuthUser, "wrong pwd", csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
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

	rAddr := "127.1.1.1:1234"
	csrfToken, err = getCSRFTokenMock(webLoginPath, rAddr)
	assert.NoError(t, err)
	form = getLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = rAddr
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "login from IP 127.1.1.1 not allowed")

	rAddr = "10.9.9.9:1234"
	csrfToken, err = getCSRFTokenMock(webLoginPath, rAddr)
	assert.NoError(t, err)
	form = getLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = rAddr
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)

	rAddr = "127.0.1.1:4567"
	csrfToken, err = getCSRFTokenMock(webLoginPath, rAddr)
	assert.NoError(t, err)
	form = getLoginForm(altAdminUsername, altAdminPassword, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = rAddr
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "login from IP 127.0.1.1 not allowed")

	// invalid csrf token
	form = getLoginForm(altAdminUsername, altAdminPassword, "invalid csrf")
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.9.9.8:1234"
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	req, _ = http.NewRequest(http.MethodGet, webLoginPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = httpdtest.RemoveAdmin(a, http.StatusOK)
	assert.NoError(t, err)
}

func TestAdminNoToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, webAdminProfilePath, nil)
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

func TestWebUserShare(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	token, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	userAPItoken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	share := dataprovider.Share{
		Name:        "test share",
		Description: "test share desc",
		Scope:       dataprovider.ShareScopeRead,
		Paths:       []string{"/"},
		ExpiresAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour)),
		MaxTokens:   100,
		AllowFrom:   []string{"127.0.0.0/8", "172.16.0.0/16"},
		Password:    defaultPassword,
	}
	form := make(url.Values)
	form.Set("name", share.Name)
	form.Set("scope", strconv.Itoa(int(share.Scope)))
	form.Set("paths", "/")
	form.Set("max_tokens", strconv.Itoa(share.MaxTokens))
	form.Set("allowed_ip", strings.Join(share.AllowFrom, ","))
	form.Set("description", share.Description)
	form.Set("password", share.Password)
	form.Set("expiration_date", "123")
	// invalid expiration date
	req, err := http.NewRequest(http.MethodPost, webClientSharePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "cannot parse")
	form.Set("expiration_date", util.GetTimeFromMsecSinceEpoch(share.ExpiresAt).UTC().Format("2006-01-02 15:04:05"))
	form.Set("scope", "")
	// invalid scope
	req, err = http.NewRequest(http.MethodPost, webClientSharePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid syntax")
	form.Set("scope", strconv.Itoa(int(share.Scope)))
	// invalid max tokens
	form.Set("max_tokens", "t")
	req, err = http.NewRequest(http.MethodPost, webClientSharePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid syntax")
	form.Set("max_tokens", strconv.Itoa(share.MaxTokens))
	// no csrf token
	req, err = http.NewRequest(http.MethodPost, webClientSharePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("scope", "100")
	req, err = http.NewRequest(http.MethodPost, webClientSharePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: invalid scope")

	form.Set("scope", strconv.Itoa(int(share.Scope)))
	req, err = http.NewRequest(http.MethodPost, webClientSharePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	req, err = http.NewRequest(http.MethodGet, userSharesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, userAPItoken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var shares []dataprovider.Share
	err = json.Unmarshal(rr.Body.Bytes(), &shares)
	assert.NoError(t, err)
	if assert.Len(t, shares, 1) {
		s := shares[0]
		assert.Equal(t, share.Name, s.Name)
		assert.Equal(t, share.Description, s.Description)
		assert.Equal(t, share.Scope, s.Scope)
		assert.Equal(t, share.Paths, s.Paths)
		assert.InDelta(t, share.ExpiresAt, s.ExpiresAt, 999)
		assert.Equal(t, share.MaxTokens, s.MaxTokens)
		assert.Equal(t, share.AllowFrom, s.AllowFrom)
		assert.Equal(t, redactedSecret, s.Password)
		share.ShareID = s.ShareID
	}
	form.Set("password", redactedSecret)
	form.Set("expiration_date", "123")
	req, err = http.NewRequest(http.MethodPost, webClientSharePath+"/unknowid", bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPost, webClientSharePath+"/"+share.ShareID, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "cannot parse")

	form.Set("expiration_date", "")
	form.Set(csrfFormToken, "")
	req, err = http.NewRequest(http.MethodPost, webClientSharePath+"/"+share.ShareID, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("allowed_ip", "1.1.1")
	req, err = http.NewRequest(http.MethodPost, webClientSharePath+"/"+share.ShareID, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: could not parse allow from entry")

	form.Set("allowed_ip", "")
	req, err = http.NewRequest(http.MethodPost, webClientSharePath+"/"+share.ShareID, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	req, err = http.NewRequest(http.MethodGet, userSharesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, userAPItoken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	shares = nil
	err = json.Unmarshal(rr.Body.Bytes(), &shares)
	assert.NoError(t, err)
	if assert.Len(t, shares, 1) {
		s := shares[0]
		assert.Equal(t, share.Name, s.Name)
		assert.Equal(t, share.Description, s.Description)
		assert.Equal(t, share.Scope, s.Scope)
		assert.Equal(t, share.Paths, s.Paths)
		assert.Equal(t, int64(0), s.ExpiresAt)
		assert.Equal(t, share.MaxTokens, s.MaxTokens)
		assert.Empty(t, s.AllowFrom)
	}
	// check the password
	s, err := dataprovider.ShareExists(share.ShareID, user.Username)
	assert.NoError(t, err)
	match, err := s.CheckCredentials(user.Username, defaultPassword)
	assert.NoError(t, err)
	assert.True(t, match)

	req, err = http.NewRequest(http.MethodGet, webClientSharePath+"?path=%2F&files=a", nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Invalid share list")

	req, err = http.NewRequest(http.MethodGet, webClientSharePath+"?path=%2F&files=%5B\"adir\"%5D", nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webClientSharePath+"/unknown", nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, webClientSharePath+"/"+share.ShareID, nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webClientSharesPath+"?qlimit=a", nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webClientSharesPath+"?qlimit=1", nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestWebUserShareNoPasswordDisabled(t *testing.T) {
	u := getTestUser()
	u.Filters.WebClient = []string{sdk.WebClientShareNoPasswordDisabled}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	token, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	userAPItoken, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	share := dataprovider.Share{
		Name:  "s",
		Scope: dataprovider.ShareScopeRead,
		Paths: []string{"/"},
	}
	form := make(url.Values)
	form.Set("name", share.Name)
	form.Set("scope", strconv.Itoa(int(share.Scope)))
	form.Set("paths", "/")
	form.Set("max_tokens", "0")
	form.Set(csrfFormToken, csrfToken)
	req, err := http.NewRequest(http.MethodPost, webClientSharePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "You are not authorized to share files/folders without a password")

	form.Set("password", defaultPassword)
	req, err = http.NewRequest(http.MethodPost, webClientSharePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	req, err = http.NewRequest(http.MethodGet, userSharesPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, userAPItoken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var shares []dataprovider.Share
	err = json.Unmarshal(rr.Body.Bytes(), &shares)
	assert.NoError(t, err)
	if assert.Len(t, shares, 1) {
		s := shares[0]
		assert.Equal(t, share.Name, s.Name)
		assert.Equal(t, share.Scope, s.Scope)
		assert.Equal(t, share.Paths, s.Paths)
		share.ShareID = s.ShareID
	}
	assert.NotEmpty(t, share.ShareID)
	form.Set("password", "")
	req, err = http.NewRequest(http.MethodPost, webClientSharePath+"/"+share.ShareID, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "You are not authorized to share files/folders without a password")

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestWebUserProfile(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	assert.NoError(t, err)
	token, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	email := "user@user.com"
	description := "User"

	form := make(url.Values)
	form.Set("allow_api_key_auth", "1")
	form.Set("email", email)
	form.Set("description", description)
	form.Set("public_keys", testPubKey)
	form.Add("public_keys", testPubKey1)
	// no csrf token
	req, err := http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Your profile has been successfully updated")

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, user.Filters.AllowAPIKeyAuth)
	assert.Len(t, user.PublicKeys, 2)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, description, user.Description)

	// set an invalid email
	form.Set("email", "not an email")
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: email")
	// invalid public key
	form.Set("email", email)
	form.Set("public_keys", "invalid")
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: could not parse key")
	// now remove permissions
	form.Set("public_keys", testPubKey)
	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	token, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)

	form.Set("allow_api_key_auth", "0")
	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Your profile has been successfully updated")
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, user.Filters.AllowAPIKeyAuth)
	assert.Len(t, user.PublicKeys, 1)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, description, user.Description)

	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled, sdk.WebClientPubKeyChangeDisabled}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	token, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	form.Set("public_keys", testPubKey)
	form.Add("public_keys", testPubKey1)
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Your profile has been successfully updated")
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, user.Filters.AllowAPIKeyAuth)
	assert.Len(t, user.PublicKeys, 1)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, description, user.Description)

	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled, sdk.WebClientInfoChangeDisabled}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	token, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	form.Set("email", "newemail@user.com")
	form.Set("description", "new description")
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Your profile has been successfully updated")
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, user.Filters.AllowAPIKeyAuth)
	assert.Len(t, user.PublicKeys, 2)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, description, user.Description)
	// finally disable all profile permissions
	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled, sdk.WebClientInfoChangeDisabled,
		sdk.WebClientPubKeyChangeDisabled}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	token, err = getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
}

func TestWebAdminProfile(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)
	token, err := getJWTWebTokenFromTestServer(admin.Username, altAdminPassword)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, webAdminProfilePath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form := make(url.Values)
	form.Set("allow_api_key_auth", "1")
	form.Set("email", "admin@example.com")
	form.Set("description", "admin desc")
	// no csrf token
	req, err = http.NewRequest(http.MethodPost, webAdminProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webAdminProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Your profile has been successfully updated")

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, admin.Filters.AllowAPIKeyAuth)
	assert.Equal(t, "admin@example.com", admin.Email)
	assert.Equal(t, "admin desc", admin.Description)

	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webAdminProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Your profile has been successfully updated")

	admin, _, err = httpdtest.GetAdminByUsername(admin.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.False(t, admin.Filters.AllowAPIKeyAuth)
	assert.Empty(t, admin.Email)
	assert.Empty(t, admin.Description)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webAdminProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
}

func TestWebAdminPwdChange(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	token, err := getJWTWebTokenFromTestServer(admin.Username, altAdminPassword)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, webChangeAdminPwdPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form := make(url.Values)
	form.Set("current_password", altAdminPassword)
	form.Set("new_password1", altAdminPassword)
	form.Set("new_password2", altAdminPassword)
	// no csrf token
	req, _ = http.NewRequest(http.MethodPost, webChangeAdminPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	req, _ = http.NewRequest(http.MethodPost, webChangeAdminPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "the new password must be different from the current one")

	form.Set("new_password1", altAdminPassword+"1")
	form.Set("new_password2", altAdminPassword+"1")
	req, _ = http.NewRequest(http.MethodPost, webChangeAdminPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webLoginPath, rr.Header().Get("Location"))

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestAPIKeysManagement(t *testing.T) {
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err := httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiKey := dataprovider.APIKey{
		Name:  "test key",
		Scope: dataprovider.APIKeyScopeAdmin,
	}
	asJSON, err := json.Marshal(apiKey)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, apiKeysPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	location := rr.Header().Get("Location")
	assert.NotEmpty(t, location)
	objectID := rr.Header().Get("X-Object-ID")
	assert.NotEmpty(t, objectID)
	assert.Equal(t, fmt.Sprintf("%v/%v", apiKeysPath, objectID), location)
	apiKey.KeyID = objectID
	response := make(map[string]string)
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	key := response["key"]
	assert.NotEmpty(t, key)
	assert.True(t, strings.HasPrefix(key, apiKey.KeyID+"."))

	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var keyGet dataprovider.APIKey
	err = json.Unmarshal(rr.Body.Bytes(), &keyGet)
	assert.NoError(t, err)
	assert.Empty(t, keyGet.Key)
	assert.Equal(t, apiKey.KeyID, keyGet.KeyID)
	assert.Equal(t, apiKey.Scope, keyGet.Scope)
	assert.Equal(t, apiKey.Name, keyGet.Name)
	assert.Equal(t, int64(0), keyGet.ExpiresAt)
	assert.Equal(t, int64(0), keyGet.LastUseAt)
	assert.Greater(t, keyGet.CreatedAt, int64(0))
	assert.Greater(t, keyGet.UpdatedAt, int64(0))
	assert.Empty(t, keyGet.Description)
	assert.Empty(t, keyGet.User)
	assert.Empty(t, keyGet.Admin)

	// API key is not enabled for the admin user so this request should fail
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, admin.Username)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "the admin associated with the provided api key cannot be authenticated")

	admin.Filters.AllowAPIKeyAuth = true
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, admin.Username)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, admin.Username+"1")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	// now associate the key directly to the admin
	apiKey.Admin = admin.Username
	apiKey.Description = "test description"
	asJSON, err = json.Marshal(apiKey)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, apiKeysPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var keys []dataprovider.APIKey
	err = json.Unmarshal(rr.Body.Bytes(), &keys)
	assert.NoError(t, err)
	if assert.GreaterOrEqual(t, len(keys), 1) {
		found := false
		for _, k := range keys {
			if k.KeyID == apiKey.KeyID {
				found = true
				assert.Empty(t, k.Key)
				assert.Equal(t, apiKey.Scope, k.Scope)
				assert.Equal(t, apiKey.Name, k.Name)
				assert.Equal(t, int64(0), k.ExpiresAt)
				assert.Greater(t, k.LastUseAt, int64(0))
				assert.Equal(t, k.CreatedAt, keyGet.CreatedAt)
				assert.Greater(t, k.UpdatedAt, keyGet.UpdatedAt)
				assert.Equal(t, apiKey.Description, k.Description)
				assert.Empty(t, k.User)
				assert.Equal(t, admin.Username, k.Admin)
			}
		}
		assert.True(t, found)
	}
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// invalid API keys
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key+"invalid", "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)
	assert.Contains(t, rr.Body.String(), "the provided api key cannot be authenticated")
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, "invalid", "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	// using an API key we cannot modify/get API keys
	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)

	admin.Filters.AllowList = []string{"172.16.18.0/24"}
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	req, err = http.NewRequest(http.MethodDelete, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "the provided api key is not valid")

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestAPIKeySearch(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiKey := dataprovider.APIKey{
		Scope: dataprovider.APIKeyScopeAdmin,
	}
	for i := 1; i < 5; i++ {
		apiKey.Name = fmt.Sprintf("testapikey%v", i)
		asJSON, err := json.Marshal(apiKey)
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, apiKeysPath, bytes.NewBuffer(asJSON))
		assert.NoError(t, err)
		setBearerForReq(req, token)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusCreated, rr)
	}

	req, err := http.NewRequest(http.MethodGet, apiKeysPath+"?limit=1&order=ASC", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var keys []dataprovider.APIKey
	err = json.Unmarshal(rr.Body.Bytes(), &keys)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	firstKey := keys[0]

	req, err = http.NewRequest(http.MethodGet, apiKeysPath+"?limit=1&order=DESC", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	keys = nil
	err = json.Unmarshal(rr.Body.Bytes(), &keys)
	assert.NoError(t, err)
	if assert.Len(t, keys, 1) {
		assert.NotEqual(t, firstKey.KeyID, keys[0].KeyID)
	}

	req, err = http.NewRequest(http.MethodGet, apiKeysPath+"?limit=1&offset=100", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	keys = nil
	err = json.Unmarshal(rr.Body.Bytes(), &keys)
	assert.NoError(t, err)
	assert.Len(t, keys, 0)

	req, err = http.NewRequest(http.MethodGet, apiKeysPath+"?limit=a", nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%v/%v", apiKeysPath, "missingid"), nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, apiKeysPath, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	keys = nil
	err = json.Unmarshal(rr.Body.Bytes(), &keys)
	assert.NoError(t, err)
	counter := 0
	for _, k := range keys {
		if strings.HasPrefix(k.Name, "testapikey") {
			req, err = http.NewRequest(http.MethodDelete, fmt.Sprintf("%v/%v", apiKeysPath, k.KeyID), nil)
			assert.NoError(t, err)
			setBearerForReq(req, token)
			rr = executeRequest(req)
			checkResponseCode(t, http.StatusOK, rr)
			counter++
		}
	}
	assert.Equal(t, 4, counter)
}

func TestAPIKeyErrors(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiKey := dataprovider.APIKey{
		Name:  "testkey",
		Scope: dataprovider.APIKeyScopeUser,
	}
	asJSON, err := json.Marshal(apiKey)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, apiKeysPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	location := rr.Header().Get("Location")
	assert.NotEmpty(t, location)

	// invalid API scope
	apiKey.Scope = 1000
	asJSON, err = json.Marshal(apiKey)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, apiKeysPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	// invalid JSON
	req, err = http.NewRequest(http.MethodPost, apiKeysPath, bytes.NewBuffer([]byte(`invalid JSON`)))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer([]byte(`invalid JSON`)))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	req, err = http.NewRequest(http.MethodDelete, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodDelete, location, nil)
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodPut, location, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)
}

func TestAPIKeyOnDeleteCascade(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	admin, _, err = httpdtest.AddAdmin(admin, http.StatusCreated)
	assert.NoError(t, err)

	apiKey := dataprovider.APIKey{
		Name:  "user api key",
		Scope: dataprovider.APIKeyScopeUser,
		User:  user.Username,
	}

	apiKey, _, err = httpdtest.AddAPIKey(apiKey, http.StatusCreated)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	user.Filters.AllowAPIKeyAuth = true
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	assert.NoError(t, err)
	setAPIKeyForReq(req, apiKey.Key, "")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var contents []map[string]interface{}
	err = json.NewDecoder(rr.Body).Decode(&contents)
	assert.NoError(t, err)
	assert.Len(t, contents, 0)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	_, _, err = httpdtest.GetAPIKeyByID(apiKey.KeyID, http.StatusNotFound)
	assert.NoError(t, err)

	apiKey.User = ""
	apiKey.Admin = admin.Username
	apiKey.Scope = dataprovider.APIKeyScopeAdmin

	apiKey, _, err = httpdtest.AddAPIKey(apiKey, http.StatusCreated)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	_, _, err = httpdtest.GetAPIKeyByID(apiKey.KeyID, http.StatusNotFound)
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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
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

func TestRenderDefenderPageMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, webDefenderPath, nil)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "View and manage blocklist")
}

func TestWebAdminBasicMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	admin := getTestAdmin()
	admin.Username = altAdminUsername
	admin.Password = altAdminPassword
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("username", admin.Username)
	form.Set("password", "")
	form.Set("status", "1")
	form.Set("permissions", "*")
	form.Set("description", admin.Description)
	req, _ := http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("status", "a")
	req, _ = http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("status", "1")
	req, _ = http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("password", admin.Password)
	req, _ = http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	// add TOTP config
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], altAdminUsername)
	assert.NoError(t, err)
	altToken, err := getJWTWebTokenFromTestServer(altAdminUsername, altAdminPassword)
	assert.NoError(t, err)
	adminTOTPConfig := dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
	}
	asJSON, err := json.Marshal(adminTOTPConfig)
	assert.NoError(t, err)
	// no CSRF token
	req, err = http.NewRequest(http.MethodPost, webAdminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, altToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid token")

	req, err = http.NewRequest(http.MethodPost, webAdminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setJWTCookieForReq(req, altToken)
	setCSRFHeaderForReq(req, csrfToken)
	req.RemoteAddr = defaultRemoteAddr
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, admin.Filters.TOTPConfig.Enabled)
	secretPayload := admin.Filters.TOTPConfig.Secret.GetPayload()
	assert.NotEmpty(t, secretPayload)

	adminTOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewEmptySecret(),
	}
	asJSON, err = json.Marshal(adminTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webAdminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, altToken)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, admin.Filters.TOTPConfig.Enabled)
	assert.Equal(t, secretPayload, admin.Filters.TOTPConfig.Secret.GetPayload())

	adminTOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     nil,
	}
	asJSON, err = json.Marshal(adminTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webAdminTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, altToken)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webAdminsPath+"?qlimit=a", nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	req, _ = http.NewRequest(http.MethodGet, webAdminsPath+"?qlimit=1", nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, webAdminPath, nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("password", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	form.Set(csrfFormToken, "invalid csrf")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	form.Set("email", "not-an-email")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("email", "")
	form.Set("status", "b")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("email", "admin@example.com")
	form.Set("status", "0")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername), bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	admin, _, err = httpdtest.GetAdminByUsername(altAdminUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, admin.Filters.TOTPConfig.Enabled)
	assert.Equal(t, "admin@example.com", admin.Email)
	assert.Equal(t, 0, admin.Status)

	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, altAdminUsername+"1"), bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, _ = http.NewRequest(http.MethodGet, path.Join(webAdminPath, altAdminUsername), nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, _ = http.NewRequest(http.MethodGet, path.Join(webAdminPath, altAdminUsername+"1"), nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webAdminPath, altAdminUsername), nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusNotFound)
	assert.NoError(t, err)

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webAdminPath, defaultTokenAuthUser), nil)
	req.RemoteAddr = defaultRemoteAddr
	setJWTCookieForReq(req, token)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "you cannot delete yourself")

	req, _ = http.NewRequest(http.MethodDelete, path.Join(webAdminPath, defaultTokenAuthUser), nil)
	req.RemoteAddr = defaultRemoteAddr
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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("username", admin.Username)
	form.Set("password", admin.Password)
	form.Set("status", "0")
	form.Set("permissions", dataprovider.PermAdminAddUsers)
	form.Set("permissions", dataprovider.PermAdminCloseConnections)
	form.Set(csrfFormToken, csrfToken)
	req, _ := http.NewRequest(http.MethodPost, path.Join(webAdminPath, defaultTokenAuthUser), bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "You cannot remove these permissions to yourself")

	form.Set("permissions", dataprovider.PermAdminAny)
	req, _ = http.NewRequest(http.MethodPost, path.Join(webAdminPath, defaultTokenAuthUser), bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)

	form := make(url.Values)
	form.Set("mode", "a")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webRestorePath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

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

	apiKey := dataprovider.APIKey{
		Name:  "key name",
		KeyID: util.GenerateUniqueID(),
		Key:   fmt.Sprintf("%v.%v", util.GenerateUniqueID(), util.GenerateUniqueID()),
		Scope: dataprovider.APIKeyScopeAdmin,
	}
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupData.Admins = append(backupData.Admins, admin)
	backupData.APIKeys = append(backupData.APIKeys, apiKey)
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

	_, _, err = httpdtest.GetAPIKeyByID(apiKey.KeyID, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveAPIKey(apiKey, http.StatusOK)
	assert.NoError(t, err)

	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
}

func TestWebUserAddMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	user := getTestUser()
	user.UploadBandwidth = 32
	user.DownloadBandwidth = 64
	user.UploadDataTransfer = 1000
	user.DownloadDataTransfer = 2000
	user.UID = 1000
	user.AdditionalInfo = "info"
	user.Description = "user dsc"
	user.Email = "test@test.com"
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
	form.Set("email", user.Email)
	form.Set("home_dir", user.HomeDir)
	form.Set("password", user.Password)
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "")
	form.Set("permissions", "*")
	form.Set("sub_perm_path0", "/subdir")
	form.Set("sub_perm_permissions0", "list")
	form.Add("sub_perm_permissions0", "download")
	form.Set("vfolder_path", " /vdir")
	form.Set("vfolder_name", folderName)
	form.Set("vfolder_quota_size", "1024")
	form.Set("vfolder_quota_files", "2")
	form.Set("pattern_path0", "/dir2")
	form.Set("patterns0", "*.jpg,*.png")
	form.Set("pattern_type0", "allowed")
	form.Set("pattern_policy0", "1")
	form.Set("pattern_path1", "/dir1")
	form.Set("patterns1", "*.png")
	form.Set("pattern_type1", "allowed")
	form.Set("pattern_path2", "/dir1")
	form.Set("patterns2", "*.zip")
	form.Set("pattern_type2", "denied")
	form.Set("pattern_path3", "/dir3")
	form.Set("patterns3", "*.rar")
	form.Set("pattern_type3", "denied")
	form.Set("pattern_path4", "/dir2")
	form.Set("patterns4", "*.mkv")
	form.Set("pattern_type4", "denied")
	form.Set("additional_info", user.AdditionalInfo)
	form.Set("description", user.Description)
	form.Add("hooks", "external_auth_disabled")
	form.Set("disable_fs_checks", "checked")
	form.Set("total_data_transfer", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("start_directory", "start/dir")
	b, contentType, _ := getMultipartFormData(form, "", "")
	// test invalid url escape
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"?a=%2", &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("public_keys", testPubKey)
	form.Add("public_keys", testPubKey1)
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
	form.Set("upload_data_transfer", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid upload data transfer
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("upload_data_transfer", strconv.FormatInt(user.UploadDataTransfer, 10))
	form.Set("download_data_transfer", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid download data transfer
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("download_data_transfer", strconv.FormatInt(user.DownloadDataTransfer, 10))
	form.Set("total_data_transfer", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid total data transfer
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("total_data_transfer", strconv.FormatInt(user.TotalDataTransfer, 10))
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
	form.Set("tls_username", string(sdk.TLSUsernameNone))
	// invalid upload_bandwidth_source0
	form.Set("bandwidth_limit_sources0", "192.168.1.0/24, 192.168.2.0/25")
	form.Set("upload_bandwidth_source0", "a")
	form.Set("download_bandwidth_source0", "0")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid upload_bandwidth_source")
	// invalid download_bandwidth_source0
	form.Set("upload_bandwidth_source0", "256")
	form.Set("download_bandwidth_source0", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid download_bandwidth_source")
	form.Set("download_bandwidth_source0", "512")
	form.Set("download_bandwidth_source1", "1024")
	form.Set("bandwidth_limit_sources1", "1.1.1")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "Validation error: could not parse bandwidth limit source")
	form.Set("bandwidth_limit_sources1", "127.0.0.1/32")
	form.Set("upload_bandwidth_source1", "-1")
	form.Set("data_transfer_limit_sources0", "127.0.1.1")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "could not parse data transfer limit source")
	form.Set("data_transfer_limit_sources0", "127.0.1.1/32")
	form.Set("upload_data_transfer_source0", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid upload_data_transfer_source")
	form.Set("upload_data_transfer_source0", "0")
	form.Set("download_data_transfer_source0", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid download_data_transfer_source")
	form.Set("download_data_transfer_source0", "0")
	form.Set("total_data_transfer_source0", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid total_data_transfer_source")
	form.Set("total_data_transfer_source0", "0")
	form.Set("data_transfer_limit_sources10", "192.168.5.0/24, 10.8.0.0/16")
	form.Set("download_data_transfer_source10", "100")
	form.Set("upload_data_transfer_source10", "120")
	form.Set("data_transfer_limit_sources12", "192.168.3.0/24, 10.8.2.0/24,::1/64")
	form.Set("download_data_transfer_source12", "100")
	form.Set("upload_data_transfer_source12", "120")
	form.Set("total_data_transfer_source12", "200")
	// invalid external auth cache size
	form.Set("external_auth_cache_time", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	form.Set("external_auth_cache_time", "0")
	form.Set(csrfFormToken, "invalid form token")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

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
	assert.Equal(t, user.UploadDataTransfer, newUser.UploadDataTransfer)
	assert.Equal(t, user.DownloadDataTransfer, newUser.DownloadDataTransfer)
	assert.Equal(t, user.TotalDataTransfer, newUser.TotalDataTransfer)
	assert.Equal(t, int64(1000), newUser.Filters.MaxUploadFileSize)
	assert.Equal(t, user.AdditionalInfo, newUser.AdditionalInfo)
	assert.Equal(t, user.Description, newUser.Description)
	assert.True(t, newUser.Filters.Hooks.ExternalAuthDisabled)
	assert.False(t, newUser.Filters.Hooks.PreLoginDisabled)
	assert.False(t, newUser.Filters.Hooks.CheckPasswordDisabled)
	assert.True(t, newUser.Filters.DisableFsChecks)
	assert.False(t, newUser.Filters.AllowAPIKeyAuth)
	assert.Equal(t, user.Email, newUser.Email)
	assert.Equal(t, "/start/dir", newUser.Filters.StartDirectory)
	assert.True(t, util.IsStringInSlice(testPubKey, newUser.PublicKeys))
	if val, ok := newUser.Permissions["/subdir"]; ok {
		assert.True(t, util.IsStringInSlice(dataprovider.PermListItems, val))
		assert.True(t, util.IsStringInSlice(dataprovider.PermDownload, val))
	} else {
		assert.Fail(t, "user permissions must contain /somedir", "actual: %v", newUser.Permissions)
	}
	assert.Len(t, newUser.PublicKeys, 2)
	assert.Len(t, newUser.VirtualFolders, 1)
	for _, v := range newUser.VirtualFolders {
		assert.Equal(t, v.VirtualPath, "/vdir")
		assert.Equal(t, v.Name, folderName)
		assert.Equal(t, v.MappedPath, mappedDir)
		assert.Equal(t, v.QuotaFiles, 2)
		assert.Equal(t, v.QuotaSize, int64(1024))
	}
	assert.Len(t, newUser.Filters.FilePatterns, 3)
	for _, filter := range newUser.Filters.FilePatterns {
		switch filter.Path {
		case "/dir1":
			assert.Len(t, filter.DeniedPatterns, 1)
			assert.Len(t, filter.AllowedPatterns, 1)
			assert.True(t, util.IsStringInSlice("*.png", filter.AllowedPatterns))
			assert.True(t, util.IsStringInSlice("*.zip", filter.DeniedPatterns))
			assert.Equal(t, sdk.DenyPolicyDefault, filter.DenyPolicy)
		case "/dir2":
			assert.Len(t, filter.DeniedPatterns, 1)
			assert.Len(t, filter.AllowedPatterns, 2)
			assert.True(t, util.IsStringInSlice("*.jpg", filter.AllowedPatterns))
			assert.True(t, util.IsStringInSlice("*.png", filter.AllowedPatterns))
			assert.True(t, util.IsStringInSlice("*.mkv", filter.DeniedPatterns))
			assert.Equal(t, sdk.DenyPolicyHide, filter.DenyPolicy)
		case "/dir3":
			assert.Len(t, filter.DeniedPatterns, 1)
			assert.Len(t, filter.AllowedPatterns, 0)
			assert.True(t, util.IsStringInSlice("*.rar", filter.DeniedPatterns))
			assert.Equal(t, sdk.DenyPolicyDefault, filter.DenyPolicy)
		}
	}
	if assert.Len(t, newUser.Filters.BandwidthLimits, 2) {
		for _, bwLimit := range newUser.Filters.BandwidthLimits {
			if len(bwLimit.Sources) == 2 {
				assert.Equal(t, "192.168.1.0/24", bwLimit.Sources[0])
				assert.Equal(t, "192.168.2.0/25", bwLimit.Sources[1])
				assert.Equal(t, int64(256), bwLimit.UploadBandwidth)
				assert.Equal(t, int64(512), bwLimit.DownloadBandwidth)
			} else {
				assert.Equal(t, []string{"127.0.0.1/32"}, bwLimit.Sources)
				assert.Equal(t, int64(0), bwLimit.UploadBandwidth)
				assert.Equal(t, int64(1024), bwLimit.DownloadBandwidth)
			}
		}
	}
	if assert.Len(t, newUser.Filters.DataTransferLimits, 3) {
		for _, dtLimit := range newUser.Filters.DataTransferLimits {
			switch len(dtLimit.Sources) {
			case 3:
				assert.Equal(t, "192.168.3.0/24", dtLimit.Sources[0])
				assert.Equal(t, "10.8.2.0/24", dtLimit.Sources[1])
				assert.Equal(t, "::1/64", dtLimit.Sources[2])
				assert.Equal(t, int64(0), dtLimit.UploadDataTransfer)
				assert.Equal(t, int64(0), dtLimit.DownloadDataTransfer)
				assert.Equal(t, int64(200), dtLimit.TotalDataTransfer)
			case 2:
				assert.Equal(t, "192.168.5.0/24", dtLimit.Sources[0])
				assert.Equal(t, "10.8.0.0/16", dtLimit.Sources[1])
				assert.Equal(t, int64(120), dtLimit.UploadDataTransfer)
				assert.Equal(t, int64(100), dtLimit.DownloadDataTransfer)
				assert.Equal(t, int64(0), dtLimit.TotalDataTransfer)
			case 1:
				assert.Equal(t, "127.0.1.1/32", dtLimit.Sources[0])
				assert.Equal(t, int64(0), dtLimit.UploadDataTransfer)
				assert.Equal(t, int64(0), dtLimit.DownloadDataTransfer)
				assert.Equal(t, int64(0), dtLimit.TotalDataTransfer)
			}
		}
	}

	assert.Equal(t, sdk.TLSUsernameNone, newUser.Filters.TLSUsername)
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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	user := getTestUser()
	user.Filters.BandwidthLimits = []sdk.BandwidthLimit{
		{
			Sources:           []string{"10.8.0.0/16", "192.168.1.0/25"},
			UploadBandwidth:   256,
			DownloadBandwidth: 512,
		},
	}
	user.TotalDataTransfer = 4000
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	// add TOTP config
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	userToken, err := getJWTWebClientTokenFromTestServer(defaultUsername, defaultPassword)
	assert.NoError(t, err)
	userTOTPConfig := dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH, common.ProtocolFTP},
	}
	asJSON, err := json.Marshal(userTOTPConfig)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webClientTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setJWTCookieForReq(req, userToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Invalid token")

	req, err = http.NewRequest(http.MethodPost, webClientTOTPSavePath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	setJWTCookieForReq(req, userToken)
	setCSRFHeaderForReq(req, csrfToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, user.Filters.TOTPConfig.Enabled)
	assert.Equal(t, int64(4000), user.TotalDataTransfer)
	if assert.Len(t, user.Filters.BandwidthLimits, 1) {
		if assert.Len(t, user.Filters.BandwidthLimits[0].Sources, 2) {
			assert.Equal(t, "10.8.0.0/16", user.Filters.BandwidthLimits[0].Sources[0])
			assert.Equal(t, "192.168.1.0/25", user.Filters.BandwidthLimits[0].Sources[1])
		}
		assert.Equal(t, int64(256), user.Filters.BandwidthLimits[0].UploadBandwidth)
		assert.Equal(t, int64(512), user.Filters.BandwidthLimits[0].DownloadBandwidth)
	}

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
	user.Filters.AllowAPIKeyAuth = true
	user.AdditionalInfo = "new additional info"
	user.Email = "user@example.com"
	form := make(url.Values)
	form.Set("username", user.Username)
	form.Set("email", user.Email)
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
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("permissions", "*")
	form.Set("sub_perm_path0", "/otherdir")
	form.Set("sub_perm_permissions0", "list")
	form.Add("sub_perm_permissions0", "upload")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", " 192.168.1.3/32, 192.168.2.0/24 ")
	form.Set("denied_ip", " 10.0.0.2/32 ")
	form.Set("pattern_path0", "/dir1")
	form.Set("patterns0", "*.zip")
	form.Set("pattern_type0", "denied")
	form.Set("denied_login_methods", dataprovider.SSHLoginMethodKeyboardInteractive)
	form.Set("denied_protocols", common.ProtocolFTP)
	form.Set("max_upload_file_size", "100")
	form.Set("disconnect", "1")
	form.Set("additional_info", user.AdditionalInfo)
	form.Set("description", user.Description)
	form.Set("tls_username", string(sdk.TLSUsernameCN))
	form.Set("allow_api_key_auth", "1")
	form.Set("external_auth_cache_time", "120")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

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
	assert.True(t, dbUser.Filters.TOTPConfig.Enabled)

	req, _ = http.NewRequest(http.MethodGet, path.Join(userPath, user.Username), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	var updateUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updateUser)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, updateUser.Email)
	assert.Equal(t, user.HomeDir, updateUser.HomeDir)
	assert.Equal(t, user.MaxSessions, updateUser.MaxSessions)
	assert.Equal(t, user.QuotaFiles, updateUser.QuotaFiles)
	assert.Equal(t, user.QuotaSize, updateUser.QuotaSize)
	assert.Equal(t, user.UID, updateUser.UID)
	assert.Equal(t, user.GID, updateUser.GID)
	assert.Equal(t, user.AdditionalInfo, updateUser.AdditionalInfo)
	assert.Equal(t, user.Description, updateUser.Description)
	assert.Equal(t, int64(100), updateUser.Filters.MaxUploadFileSize)
	assert.Equal(t, sdk.TLSUsernameCN, updateUser.Filters.TLSUsername)
	assert.True(t, updateUser.Filters.AllowAPIKeyAuth)
	assert.True(t, updateUser.Filters.TOTPConfig.Enabled)
	assert.Equal(t, int64(0), updateUser.TotalDataTransfer)
	assert.Equal(t, int64(0), updateUser.DownloadDataTransfer)
	assert.Equal(t, int64(0), updateUser.UploadDataTransfer)
	assert.Equal(t, int64(0), updateUser.Filters.ExternalAuthCacheTime)
	if val, ok := updateUser.Permissions["/otherdir"]; ok {
		assert.True(t, util.IsStringInSlice(dataprovider.PermListItems, val))
		assert.True(t, util.IsStringInSlice(dataprovider.PermUpload, val))
	} else {
		assert.Fail(t, "user permissions must contains /otherdir", "actual: %v", updateUser.Permissions)
	}
	assert.True(t, util.IsStringInSlice("192.168.1.3/32", updateUser.Filters.AllowedIP))
	assert.True(t, util.IsStringInSlice("10.0.0.2/32", updateUser.Filters.DeniedIP))
	assert.True(t, util.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, updateUser.Filters.DeniedLoginMethods))
	assert.True(t, util.IsStringInSlice(common.ProtocolFTP, updateUser.Filters.DeniedProtocols))
	assert.True(t, util.IsStringInSlice("*.zip", updateUser.Filters.FilePatterns[0].DeniedPatterns))
	assert.Len(t, updateUser.Filters.BandwidthLimits, 0)
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

func TestUserTemplateWithFoldersMock(t *testing.T) {
	folder := vfs.BaseVirtualFolder{
		Name:        "vfolder",
		MappedPath:  filepath.Join(os.TempDir(), "mapped"),
		Description: "vfolder desc with spéciàl ch@rs",
	}

	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
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
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("permissions", "*")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("fs_provider", "0")
	form.Set("max_upload_file_size", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("description", "desc %username% %password%")
	form.Set("vfolder_path", "/vdir%username%")
	form.Set("vfolder_name", folder.Name)
	form.Set("vfolder_quota_size", "-1")
	form.Set("vfolder_quota_files", "-1")
	form.Add("tpl_username", "auser1")
	form.Add("tpl_password", "password1")
	form.Add("tpl_public_keys", " ")
	form.Add("tpl_username", "auser2")
	form.Add("tpl_password", "password2")
	form.Add("tpl_public_keys", testPubKey)
	form.Add("tpl_username", "auser1")
	form.Add("tpl_password", "password")
	form.Add("tpl_public_keys", "")
	form.Set("form_action", "export_from_template")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ := http.NewRequest(http.MethodPost, path.Join(webTemplateUser), &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	require.Contains(t, rr.Body.String(), "unable to verify form token")

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

func TestUserSaveFromTemplateMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	user1 := "u1"
	user2 := "u2"
	form := make(url.Values)
	form.Set("username", "")
	form.Set("home_dir", filepath.Join(os.TempDir(), "%username%"))
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("uid", "0")
	form.Set("gid", "0")
	form.Set("max_sessions", "0")
	form.Set("quota_size", "0")
	form.Set("quota_files", "0")
	form.Set("permissions", "*")
	form.Set("status", "1")
	form.Set("expiration_date", "")
	form.Set("fs_provider", "0")
	form.Set("max_upload_file_size", "0")
	form.Set("external_auth_cache_time", "0")
	form.Add("tpl_username", user1)
	form.Add("tpl_password", "password1")
	form.Add("tpl_public_keys", " ")
	form.Add("tpl_username", user2)
	form.Add("tpl_public_keys", testPubKey)
	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ := http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	u1, _, err := httpdtest.GetUserByUsername(user1, http.StatusOK)
	assert.NoError(t, err)
	u2, _, err := httpdtest.GetUserByUsername(user2, http.StatusOK)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(u1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(u2, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)

	b, contentType, _ = getMultipartFormData(form, "", "")
	req, err = http.NewRequest(http.MethodPost, webTemplateUser, &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	assert.Contains(t, rr.Body.String(), "Cannot save the defined users")

	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestUserTemplateMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	user := getTestUser()
	user.FsConfig.Provider = sdk.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test"
	user.FsConfig.S3Config.Region = "eu-central-1"
	user.FsConfig.S3Config.AccessKey = "%username%"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir/"
	user.FsConfig.S3Config.UploadPartSize = 5
	user.FsConfig.S3Config.UploadConcurrency = 4
	user.FsConfig.S3Config.DownloadPartSize = 6
	user.FsConfig.S3Config.DownloadConcurrency = 3
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
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
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("permissions", "*")
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
	form.Add("hooks", "external_auth_disabled")
	form.Add("hooks", "check_password_disabled")
	form.Set("disable_fs_checks", "checked")
	form.Set("s3_download_part_max_time", "0")
	form.Set("s3_upload_part_max_time", "0")
	// test invalid s3_upload_part_size
	form.Set("s3_upload_part_size", "a")
	form.Set("form_action", "export_from_template")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ := http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	form.Set("s3_upload_part_size", strconv.FormatInt(user.FsConfig.S3Config.UploadPartSize, 10))
	form.Set("s3_upload_concurrency", strconv.Itoa(user.FsConfig.S3Config.UploadConcurrency))
	form.Set("s3_download_part_size", strconv.FormatInt(user.FsConfig.S3Config.DownloadPartSize, 10))
	form.Set("s3_download_concurrency", strconv.Itoa(user.FsConfig.S3Config.DownloadConcurrency))

	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	form.Set("tpl_username", "user1")
	form.Set("tpl_password", "password1")
	form.Set("tpl_public_keys", "invalid-pkey")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	require.Contains(t, rr.Body.String(), "Error validating user")

	form.Set("tpl_username", " ")
	form.Set("tpl_password", "pwd")
	form.Set("tpl_public_keys", testPubKey)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateUser, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	require.Contains(t, rr.Body.String(), "No valid users defined, unable to complete the requested action")

	form.Set("tpl_username", "user1")
	form.Set("tpl_password", "password1")
	form.Set("tpl_public_keys", " ")
	form.Add("tpl_username", "user2")
	form.Add("tpl_password", "password2")
	form.Add("tpl_public_keys", testPubKey)
	form.Add("tpl_username", "")
	form.Add("tpl_password", "password3")
	form.Add("tpl_public_keys", testPubKey)
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
	require.Equal(t, sdk.S3FilesystemProvider, user1.FsConfig.Provider)
	require.Equal(t, "user2", user2.Username)
	require.Equal(t, sdk.S3FilesystemProvider, user2.FsConfig.Provider)
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
	require.True(t, user1.Filters.Hooks.ExternalAuthDisabled)
	require.True(t, user1.Filters.Hooks.CheckPasswordDisabled)
	require.False(t, user1.Filters.Hooks.PreLoginDisabled)
	require.True(t, user2.Filters.Hooks.ExternalAuthDisabled)
	require.True(t, user2.Filters.Hooks.CheckPasswordDisabled)
	require.False(t, user2.Filters.Hooks.PreLoginDisabled)
	require.True(t, user1.Filters.DisableFsChecks)
	require.True(t, user2.Filters.DisableFsChecks)
}

func TestUserPlaceholders(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	u := getTestUser()
	u.HomeDir = filepath.Join(os.TempDir(), "%username%_%password%")
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", u.Username)
	form.Set("home_dir", u.HomeDir)
	form.Set("password", u.Password)
	form.Set("status", strconv.Itoa(u.Status))
	form.Set("expiration_date", "")
	form.Set("permissions", "*")
	form.Set("public_keys", testPubKey)
	form.Add("public_keys", testPubKey1)
	form.Set("uid", "0")
	form.Set("gid", "0")
	form.Set("max_sessions", "0")
	form.Set("quota_size", "0")
	form.Set("quota_files", "0")
	form.Set("upload_bandwidth", "0")
	form.Set("download_bandwidth", "0")
	form.Set("total_data_transfer", "0")
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("max_upload_file_size", "0")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ := http.NewRequest(http.MethodPost, webUserPath, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(os.TempDir(), fmt.Sprintf("%v_%v", defaultUsername, defaultPassword)), user.HomeDir)

	dbUser, err := dataprovider.UserExists(defaultUsername)
	assert.NoError(t, err)
	assert.True(t, dbUser.IsPasswordHashed())
	hashedPwd := dbUser.Password

	form.Set("password", redactedSecret)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, err = http.NewRequest(http.MethodPost, path.Join(webUserPath, defaultUsername), &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(os.TempDir(), defaultUsername+"_%password%"), user.HomeDir)
	// check that the password was unchanged
	dbUser, err = dataprovider.UserExists(defaultUsername)
	assert.NoError(t, err)
	assert.True(t, dbUser.IsPasswordHashed())
	assert.Equal(t, hashedPwd, dbUser.Password)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestFolderPlaceholders(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	folderName := "folderName"
	form := make(url.Values)
	form.Set("name", folderName)
	form.Set("mapped_path", filepath.Join(os.TempDir(), "%name%"))
	form.Set("description", "desc folder %name%")
	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, err := http.NewRequest(http.MethodPost, webFolderPath, &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	folderGet, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(os.TempDir(), folderName), folderGet.MappedPath)
	assert.Equal(t, fmt.Sprintf("desc folder %v", folderName), folderGet.Description)

	form.Set("mapped_path", filepath.Join(os.TempDir(), "%name%_%name%"))
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	folderGet, _, err = httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(os.TempDir(), fmt.Sprintf("%v_%v", folderName, folderName)), folderGet.MappedPath)
	assert.Equal(t, fmt.Sprintf("desc folder %v", folderName), folderGet.Description)

	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
}

func TestFolderSaveFromTemplateMock(t *testing.T) {
	folder1 := "f1"
	folder2 := "f2"
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("name", "name")
	form.Set("mapped_path", filepath.Join(os.TempDir(), "%name%"))
	form.Set("description", "desc folder %name%")
	form.Add("tpl_foldername", folder1)
	form.Add("tpl_foldername", folder2)
	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, err := http.NewRequest(http.MethodPost, webTemplateFolder, &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	_, _, err = httpdtest.GetFolderByName(folder1, http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetFolderByName(folder2, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folder1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folder2}, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)

	b, contentType, _ = getMultipartFormData(form, "", "")
	req, err = http.NewRequest(http.MethodPost, webTemplateFolder, &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr)
	assert.Contains(t, rr.Body.String(), "Cannot save the defined folders")

	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.BackupsPath = backupsPath
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestFolderTemplateMock(t *testing.T) {
	folderName := "vfolder-template"
	mappedPath := filepath.Join(os.TempDir(), "%name%mapped%name%path")
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form := make(url.Values)
	form.Set("name", folderName)
	form.Set("mapped_path", mappedPath)
	form.Set("description", "desc folder %name%")
	form.Add("tpl_foldername", "folder1")
	form.Add("tpl_foldername", "folder2")
	form.Add("tpl_foldername", "folder3")
	form.Add("tpl_foldername", "folder1 ")
	form.Add("tpl_foldername", " ")
	form.Set("form_action", "export_from_template")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ := http.NewRequest(http.MethodPost, webTemplateFolder, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder+"?param=p%C3%AO%GG", &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Error parsing folders fields")

	folder1 := "folder1"
	folder2 := "folder2"
	folder3 := "folder3"
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder, &b)
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
	require.Equal(t, folder1, dump.Folders[0].Name)
	require.Equal(t, "desc folder folder1", dump.Folders[0].Description)
	require.True(t, strings.HasSuffix(dump.Folders[0].MappedPath, "folder1mappedfolder1path"))
	require.Equal(t, folder2, dump.Folders[1].Name)
	require.Equal(t, "desc folder folder2", dump.Folders[1].Description)
	require.True(t, strings.HasSuffix(dump.Folders[1].MappedPath, "folder2mappedfolder2path"))
	require.Equal(t, folder3, dump.Folders[2].Name)
	require.Equal(t, "desc folder folder3", dump.Folders[2].Description)
	require.True(t, strings.HasSuffix(dump.Folders[2].MappedPath, "folder3mappedfolder3path"))

	form.Set("fs_provider", "1")
	form.Set("s3_bucket", "bucket")
	form.Set("s3_region", "us-east-1")
	form.Set("s3_access_key", "%name%")
	form.Set("s3_access_secret", "pwd%name%")
	form.Set("s3_key_prefix", "base/%name%")

	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Error parsing folders fields")

	form.Set("s3_upload_part_size", "5")
	form.Set("s3_upload_concurrency", "4")
	form.Set("s3_download_part_max_time", "0")
	form.Set("s3_upload_part_max_time", "0")
	form.Set("s3_download_part_size", "6")
	form.Set("s3_download_concurrency", "2")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	dump = dataprovider.BackupData{}
	err = json.Unmarshal(rr.Body.Bytes(), &dump)
	require.NoError(t, err)
	require.Len(t, dump.Users, 0)
	require.Len(t, dump.Admins, 0)
	require.Len(t, dump.Folders, 3)
	require.Equal(t, folder1, dump.Folders[0].Name)
	require.Equal(t, folder1, dump.Folders[0].FsConfig.S3Config.AccessKey)
	err = dump.Folders[0].FsConfig.S3Config.AccessSecret.Decrypt()
	require.NoError(t, err)
	require.Equal(t, "pwd"+folder1, dump.Folders[0].FsConfig.S3Config.AccessSecret.GetPayload())
	require.Equal(t, "base/"+folder1+"/", dump.Folders[0].FsConfig.S3Config.KeyPrefix)
	require.Equal(t, folder2, dump.Folders[1].Name)
	require.Equal(t, folder2, dump.Folders[1].FsConfig.S3Config.AccessKey)
	err = dump.Folders[1].FsConfig.S3Config.AccessSecret.Decrypt()
	require.NoError(t, err)
	require.Equal(t, "pwd"+folder2, dump.Folders[1].FsConfig.S3Config.AccessSecret.GetPayload())
	require.Equal(t, "base/"+folder2+"/", dump.Folders[1].FsConfig.S3Config.KeyPrefix)
	require.Equal(t, folder3, dump.Folders[2].Name)
	require.Equal(t, folder3, dump.Folders[2].FsConfig.S3Config.AccessKey)
	err = dump.Folders[2].FsConfig.S3Config.AccessSecret.Decrypt()
	require.NoError(t, err)
	require.Equal(t, "pwd"+folder3, dump.Folders[2].FsConfig.S3Config.AccessSecret.GetPayload())
	require.Equal(t, "base/"+folder3+"/", dump.Folders[2].FsConfig.S3Config.KeyPrefix)

	form.Set("tpl_foldername", " ")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder, &b)
	setJWTCookieForReq(req, token)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "No valid folders defined")

	form.Set("tpl_foldername", "name")
	form.Set("mapped_path", "relative-path")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webTemplateFolder, &b)
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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = sdk.S3FilesystemProvider
	user.FsConfig.S3Config.Bucket = "test"
	user.FsConfig.S3Config.Region = "eu-west-1"
	user.FsConfig.S3Config.AccessKey = "access-key"
	user.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("access-secret")
	user.FsConfig.S3Config.RoleARN = "arn:aws:iam::123456789012:user/Development/product_1234/*"
	user.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/path?a=b"
	user.FsConfig.S3Config.StorageClass = "Standard"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir/"
	user.FsConfig.S3Config.UploadPartSize = 5
	user.FsConfig.S3Config.UploadConcurrency = 4
	user.FsConfig.S3Config.DownloadPartMaxTime = 60
	user.FsConfig.S3Config.UploadPartMaxTime = 120
	user.FsConfig.S3Config.DownloadPartSize = 6
	user.FsConfig.S3Config.DownloadConcurrency = 3
	user.FsConfig.S3Config.ForcePathStyle = true
	user.FsConfig.S3Config.ACL = "public-read"
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
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("permissions", "*")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "1")
	form.Set("s3_bucket", user.FsConfig.S3Config.Bucket)
	form.Set("s3_region", user.FsConfig.S3Config.Region)
	form.Set("s3_access_key", user.FsConfig.S3Config.AccessKey)
	form.Set("s3_access_secret", user.FsConfig.S3Config.AccessSecret.GetPayload())
	form.Set("s3_role_arn", user.FsConfig.S3Config.RoleARN)
	form.Set("s3_storage_class", user.FsConfig.S3Config.StorageClass)
	form.Set("s3_acl", user.FsConfig.S3Config.ACL)
	form.Set("s3_endpoint", user.FsConfig.S3Config.Endpoint)
	form.Set("s3_key_prefix", user.FsConfig.S3Config.KeyPrefix)
	form.Set("pattern_path0", "/dir1")
	form.Set("patterns0", "*.jpg,*.png")
	form.Set("pattern_type0", "allowed")
	form.Set("pattern_policy0", "0")
	form.Set("pattern_path1", "/dir2")
	form.Set("patterns1", "*.zip")
	form.Set("pattern_type1", "denied")
	form.Set("pattern_policy1", "1")
	form.Set("max_upload_file_size", "0")
	form.Set("s3_force_path_style", "checked")
	form.Set("description", user.Description)
	form.Add("hooks", "pre_login_disabled")
	form.Add("allow_api_key_auth", "1")
	// test invalid s3_upload_part_size
	form.Set("s3_upload_part_size", "a")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test invalid s3_upload_concurrency
	form.Set("s3_upload_part_size", strconv.FormatInt(user.FsConfig.S3Config.UploadPartSize, 10))
	form.Set("s3_upload_concurrency", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test invalid s3_download_part_size
	form.Set("s3_upload_concurrency", strconv.Itoa(user.FsConfig.S3Config.UploadConcurrency))
	form.Set("s3_download_part_size", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test invalid s3_download_concurrency
	form.Set("s3_download_part_size", strconv.FormatInt(user.FsConfig.S3Config.DownloadPartSize, 10))
	form.Set("s3_download_concurrency", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test invalid s3_download_part_max_time
	form.Set("s3_download_concurrency", strconv.Itoa(user.FsConfig.S3Config.DownloadConcurrency))
	form.Set("s3_download_part_max_time", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test invalid s3_upload_part_max_time
	form.Set("s3_download_part_max_time", strconv.Itoa(user.FsConfig.S3Config.DownloadPartMaxTime))
	form.Set("s3_upload_part_max_time", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now add the user
	form.Set("s3_upload_part_max_time", strconv.Itoa(user.FsConfig.S3Config.UploadPartMaxTime))
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
	assert.Equal(t, updateUser.FsConfig.S3Config.RoleARN, user.FsConfig.S3Config.RoleARN)
	assert.Equal(t, updateUser.FsConfig.S3Config.StorageClass, user.FsConfig.S3Config.StorageClass)
	assert.Equal(t, updateUser.FsConfig.S3Config.ACL, user.FsConfig.S3Config.ACL)
	assert.Equal(t, updateUser.FsConfig.S3Config.Endpoint, user.FsConfig.S3Config.Endpoint)
	assert.Equal(t, updateUser.FsConfig.S3Config.KeyPrefix, user.FsConfig.S3Config.KeyPrefix)
	assert.Equal(t, updateUser.FsConfig.S3Config.UploadPartSize, user.FsConfig.S3Config.UploadPartSize)
	assert.Equal(t, updateUser.FsConfig.S3Config.UploadConcurrency, user.FsConfig.S3Config.UploadConcurrency)
	assert.Equal(t, updateUser.FsConfig.S3Config.DownloadPartMaxTime, user.FsConfig.S3Config.DownloadPartMaxTime)
	assert.Equal(t, updateUser.FsConfig.S3Config.UploadPartMaxTime, user.FsConfig.S3Config.UploadPartMaxTime)
	assert.Equal(t, updateUser.FsConfig.S3Config.DownloadPartSize, user.FsConfig.S3Config.DownloadPartSize)
	assert.Equal(t, updateUser.FsConfig.S3Config.DownloadConcurrency, user.FsConfig.S3Config.DownloadConcurrency)
	assert.True(t, updateUser.FsConfig.S3Config.ForcePathStyle)
	if assert.Equal(t, 2, len(updateUser.Filters.FilePatterns)) {
		for _, filter := range updateUser.Filters.FilePatterns {
			switch filter.Path {
			case "/dir1":
				assert.Equal(t, sdk.DenyPolicyDefault, filter.DenyPolicy)
			case "/dir2":
				assert.Equal(t, sdk.DenyPolicyHide, filter.DenyPolicy)
			}
		}
	}
	assert.Equal(t, sdkkms.SecretStatusSecretBox, updateUser.FsConfig.S3Config.AccessSecret.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Empty(t, updateUser.FsConfig.S3Config.AccessSecret.GetKey())
	assert.Empty(t, updateUser.FsConfig.S3Config.AccessSecret.GetAdditionalData())
	assert.Equal(t, user.Description, updateUser.Description)
	assert.True(t, updateUser.Filters.Hooks.PreLoginDisabled)
	assert.False(t, updateUser.Filters.Hooks.ExternalAuthDisabled)
	assert.False(t, updateUser.Filters.Hooks.CheckPasswordDisabled)
	assert.False(t, updateUser.Filters.DisableFsChecks)
	assert.True(t, updateUser.Filters.AllowAPIKeyAuth)
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
	assert.Equal(t, sdkkms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.S3Config.AccessSecret.GetStatus())
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
	assert.Nil(t, userGet.FsConfig.S3Config.AccessSecret)

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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
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
	user.FsConfig.Provider = sdk.GCSFilesystemProvider
	user.FsConfig.GCSConfig.Bucket = "test"
	user.FsConfig.GCSConfig.KeyPrefix = "somedir/subdir/"
	user.FsConfig.GCSConfig.StorageClass = "standard"
	user.FsConfig.GCSConfig.ACL = "publicReadWrite"
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
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("permissions", "*")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "2")
	form.Set("gcs_bucket", user.FsConfig.GCSConfig.Bucket)
	form.Set("gcs_storage_class", user.FsConfig.GCSConfig.StorageClass)
	form.Set("gcs_acl", user.FsConfig.GCSConfig.ACL)
	form.Set("gcs_key_prefix", user.FsConfig.GCSConfig.KeyPrefix)
	form.Set("pattern_path0", "/dir1")
	form.Set("patterns0", "*.jpg,*.png")
	form.Set("pattern_type0", "allowed")
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
	assert.Equal(t, user.FsConfig.GCSConfig.ACL, updateUser.FsConfig.GCSConfig.ACL)
	assert.Equal(t, user.FsConfig.GCSConfig.KeyPrefix, updateUser.FsConfig.GCSConfig.KeyPrefix)
	if assert.Len(t, updateUser.Filters.FilePatterns, 1) {
		assert.Equal(t, "/dir1", updateUser.Filters.FilePatterns[0].Path)
		assert.Len(t, updateUser.Filters.FilePatterns[0].AllowedPatterns, 2)
		assert.Contains(t, updateUser.Filters.FilePatterns[0].AllowedPatterns, "*.png")
		assert.Contains(t, updateUser.Filters.FilePatterns[0].AllowedPatterns, "*.jpg")
	}
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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.Container = "container"
	user.FsConfig.AzBlobConfig.AccountName = "aname"
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("access-skey")
	user.FsConfig.AzBlobConfig.Endpoint = "http://127.0.0.1:9000/path?b=c"
	user.FsConfig.AzBlobConfig.KeyPrefix = "somedir/subdir/"
	user.FsConfig.AzBlobConfig.UploadPartSize = 5
	user.FsConfig.AzBlobConfig.UploadConcurrency = 4
	user.FsConfig.AzBlobConfig.DownloadPartSize = 3
	user.FsConfig.AzBlobConfig.DownloadConcurrency = 6
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
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("permissions", "*")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "3")
	form.Set("az_container", user.FsConfig.AzBlobConfig.Container)
	form.Set("az_account_name", user.FsConfig.AzBlobConfig.AccountName)
	form.Set("az_account_key", user.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	form.Set("az_endpoint", user.FsConfig.AzBlobConfig.Endpoint)
	form.Set("az_key_prefix", user.FsConfig.AzBlobConfig.KeyPrefix)
	form.Set("az_use_emulator", "checked")
	form.Set("pattern_path0", "/dir1")
	form.Set("patterns0", "*.jpg,*.png")
	form.Set("pattern_type0", "allowed")
	form.Set("pattern_path1", "/dir2")
	form.Set("patterns1", "*.zip")
	form.Set("pattern_type1", "denied")
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
	// test invalid az_download_part_size
	form.Set("az_upload_concurrency", strconv.Itoa(user.FsConfig.AzBlobConfig.UploadConcurrency))
	form.Set("az_download_part_size", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// test invalid az_download_concurrency
	form.Set("az_download_part_size", strconv.FormatInt(user.FsConfig.AzBlobConfig.DownloadPartSize, 10))
	form.Set("az_download_concurrency", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, path.Join(webUserPath, user.Username), &b)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// now add the user
	form.Set("az_download_concurrency", strconv.Itoa(user.FsConfig.AzBlobConfig.DownloadConcurrency))
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
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.KeyPrefix, user.FsConfig.AzBlobConfig.KeyPrefix)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.UploadPartSize, user.FsConfig.AzBlobConfig.UploadPartSize)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.UploadConcurrency, user.FsConfig.AzBlobConfig.UploadConcurrency)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.DownloadPartSize, user.FsConfig.AzBlobConfig.DownloadPartSize)
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.DownloadConcurrency, user.FsConfig.AzBlobConfig.DownloadConcurrency)
	assert.Equal(t, 2, len(updateUser.Filters.FilePatterns))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, updateUser.FsConfig.AzBlobConfig.AccountKey.GetStatus())
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
	assert.Equal(t, sdkkms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.AzBlobConfig.AccountKey.GetStatus())
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.AccountKey.GetPayload(), lastUpdatedUser.FsConfig.AzBlobConfig.AccountKey.GetPayload())
	assert.Empty(t, lastUpdatedUser.FsConfig.AzBlobConfig.AccountKey.GetKey())
	assert.Empty(t, lastUpdatedUser.FsConfig.AzBlobConfig.AccountKey.GetAdditionalData())
	// test SAS url
	user.FsConfig.AzBlobConfig.SASURL = kms.NewPlainSecret("sasurl")
	form.Set("az_account_name", "")
	form.Set("az_account_key", "")
	form.Set("az_container", "")
	form.Set("az_sas_url", user.FsConfig.AzBlobConfig.SASURL.GetPayload())
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
	assert.Equal(t, sdkkms.SecretStatusSecretBox, updateUser.FsConfig.AzBlobConfig.SASURL.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.AzBlobConfig.SASURL.GetPayload())
	assert.Empty(t, updateUser.FsConfig.AzBlobConfig.SASURL.GetKey())
	assert.Empty(t, updateUser.FsConfig.AzBlobConfig.SASURL.GetAdditionalData())
	// now check that a redacted sas url is not saved
	form.Set("az_sas_url", redactedSecret)
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
	lastUpdatedUser = dataprovider.User{}
	err = render.DecodeJSON(rr.Body, &lastUpdatedUser)
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.AzBlobConfig.SASURL.GetStatus())
	assert.Equal(t, updateUser.FsConfig.AzBlobConfig.SASURL.GetPayload(), lastUpdatedUser.FsConfig.AzBlobConfig.SASURL.GetPayload())
	assert.Empty(t, lastUpdatedUser.FsConfig.AzBlobConfig.SASURL.GetKey())
	assert.Empty(t, lastUpdatedUser.FsConfig.AzBlobConfig.SASURL.GetAdditionalData())

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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
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
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("permissions", "*")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "4")
	form.Set("crypt_passphrase", "")
	form.Set("pattern_path0", "/dir1")
	form.Set("patterns0", "*.jpg,*.png")
	form.Set("pattern_type0", "allowed")
	form.Set("pattern_path1", "/dir2")
	form.Set("patterns1", "*.zip")
	form.Set("pattern_type1", "denied")
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
	assert.Equal(t, 2, len(updateUser.Filters.FilePatterns))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, updateUser.FsConfig.CryptConfig.Passphrase.GetStatus())
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
	assert.Equal(t, sdkkms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.CryptConfig.Passphrase.GetStatus())
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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	setBearerForReq(req, apiToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user.FsConfig.SFTPConfig.Endpoint = "127.0.0.1:22"
	user.FsConfig.SFTPConfig.Username = "sftpuser"
	user.FsConfig.SFTPConfig.Password = kms.NewPlainSecret("pwd")
	user.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret(sftpPrivateKey)
	user.FsConfig.SFTPConfig.Fingerprints = []string{sftpPkeyFingerprint}
	user.FsConfig.SFTPConfig.Prefix = "/home/sftpuser"
	user.FsConfig.SFTPConfig.DisableCouncurrentReads = true
	user.FsConfig.SFTPConfig.BufferSize = 5
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
	form.Set("upload_data_transfer", "0")
	form.Set("download_data_transfer", "0")
	form.Set("total_data_transfer", "0")
	form.Set("external_auth_cache_time", "0")
	form.Set("permissions", "*")
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "2020-01-01 00:00:00")
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "")
	form.Set("fs_provider", "5")
	form.Set("crypt_passphrase", "")
	form.Set("pattern_path0", "/dir1")
	form.Set("patterns0", "*.jpg,*.png")
	form.Set("pattern_type0", "allowed")
	form.Set("pattern_path1", "/dir2")
	form.Set("patterns1", "*.zip")
	form.Set("pattern_type1", "denied")
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
	form.Set("sftp_buffer_size", strconv.FormatInt(user.FsConfig.SFTPConfig.BufferSize, 10))
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
	assert.Equal(t, 2, len(updateUser.Filters.FilePatterns))
	assert.Equal(t, sdkkms.SecretStatusSecretBox, updateUser.FsConfig.SFTPConfig.Password.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, updateUser.FsConfig.SFTPConfig.Password.GetKey())
	assert.Empty(t, updateUser.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.Equal(t, sdkkms.SecretStatusSecretBox, updateUser.FsConfig.SFTPConfig.PrivateKey.GetStatus())
	assert.NotEmpty(t, updateUser.FsConfig.SFTPConfig.PrivateKey.GetPayload())
	assert.Empty(t, updateUser.FsConfig.SFTPConfig.PrivateKey.GetKey())
	assert.Empty(t, updateUser.FsConfig.SFTPConfig.PrivateKey.GetAdditionalData())
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.Prefix, user.FsConfig.SFTPConfig.Prefix)
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.Username, user.FsConfig.SFTPConfig.Username)
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.Endpoint, user.FsConfig.SFTPConfig.Endpoint)
	assert.True(t, updateUser.FsConfig.SFTPConfig.DisableCouncurrentReads)
	assert.Len(t, updateUser.FsConfig.SFTPConfig.Fingerprints, 1)
	assert.Equal(t, user.FsConfig.SFTPConfig.BufferSize, updateUser.FsConfig.SFTPConfig.BufferSize)
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
	assert.Equal(t, sdkkms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.SFTPConfig.Password.GetStatus())
	assert.Equal(t, updateUser.FsConfig.SFTPConfig.Password.GetPayload(), lastUpdatedUser.FsConfig.SFTPConfig.Password.GetPayload())
	assert.Empty(t, lastUpdatedUser.FsConfig.SFTPConfig.Password.GetKey())
	assert.Empty(t, lastUpdatedUser.FsConfig.SFTPConfig.Password.GetAdditionalData())
	assert.Equal(t, sdkkms.SecretStatusSecretBox, lastUpdatedUser.FsConfig.SFTPConfig.PrivateKey.GetStatus())
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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	mappedPath := filepath.Clean(os.TempDir())
	folderName := filepath.Base(mappedPath)
	folderDesc := "a simple desc"
	form := make(url.Values)
	form.Set("mapped_path", mappedPath)
	form.Set("name", folderName)
	form.Set("description", folderDesc)
	b, contentType, err := getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, webFolderPath, &b)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	setJWTCookieForReq(req, webToken)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webFolderPath, &b)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	setJWTCookieForReq(req, webToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)
	// adding the same folder will fail since the name must be unique
	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webFolderPath, &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
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

func TestS3WebFolderMock(t *testing.T) {
	webToken, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	apiToken, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	mappedPath := filepath.Clean(os.TempDir())
	folderName := filepath.Base(mappedPath)
	folderDesc := "a simple desc"
	S3Bucket := "test"
	S3Region := "eu-west-1"
	S3AccessKey := "access-key"
	S3AccessSecret := kms.NewPlainSecret("folder-access-secret")
	S3SessionToken := "fake session token"
	S3RoleARN := "arn:aws:iam::123456789012:user/Development/product_1234/*"
	S3Endpoint := "http://127.0.0.1:9000/path?b=c"
	S3StorageClass := "Standard"
	S3ACL := "public-read-write"
	S3KeyPrefix := "somedir/subdir/"
	S3UploadPartSize := 5
	S3UploadConcurrency := 4
	S3MaxPartDownloadTime := 120
	S3MaxPartUploadTime := 60
	S3DownloadPartSize := 6
	S3DownloadConcurrency := 3
	form := make(url.Values)
	form.Set("mapped_path", mappedPath)
	form.Set("name", folderName)
	form.Set("description", folderDesc)
	form.Set("fs_provider", "1")
	form.Set("s3_bucket", S3Bucket)
	form.Set("s3_region", S3Region)
	form.Set("s3_access_key", S3AccessKey)
	form.Set("s3_access_secret", S3AccessSecret.GetPayload())
	form.Set("s3_session_token", S3SessionToken)
	form.Set("s3_role_arn", S3RoleARN)
	form.Set("s3_storage_class", S3StorageClass)
	form.Set("s3_acl", S3ACL)
	form.Set("s3_endpoint", S3Endpoint)
	form.Set("s3_key_prefix", S3KeyPrefix)
	form.Set("s3_upload_part_size", strconv.Itoa(S3UploadPartSize))
	form.Set("s3_download_part_max_time", strconv.Itoa(S3MaxPartDownloadTime))
	form.Set("s3_download_part_size", strconv.Itoa(S3DownloadPartSize))
	form.Set("s3_download_concurrency", strconv.Itoa(S3DownloadConcurrency))
	form.Set("s3_upload_part_max_time", strconv.Itoa(S3MaxPartUploadTime))
	form.Set("s3_upload_concurrency", "a")
	form.Set(csrfFormToken, csrfToken)
	b, contentType, err := getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, webFolderPath, &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("s3_upload_concurrency", strconv.Itoa(S3UploadConcurrency))
	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, webFolderPath, &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

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
	assert.Equal(t, sdk.S3FilesystemProvider, folder.FsConfig.Provider)
	assert.Equal(t, S3Bucket, folder.FsConfig.S3Config.Bucket)
	assert.Equal(t, S3Region, folder.FsConfig.S3Config.Region)
	assert.Equal(t, S3AccessKey, folder.FsConfig.S3Config.AccessKey)
	assert.NotEmpty(t, folder.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Equal(t, S3Endpoint, folder.FsConfig.S3Config.Endpoint)
	assert.Equal(t, S3StorageClass, folder.FsConfig.S3Config.StorageClass)
	assert.Equal(t, S3ACL, folder.FsConfig.S3Config.ACL)
	assert.Equal(t, S3KeyPrefix, folder.FsConfig.S3Config.KeyPrefix)
	assert.Equal(t, S3UploadConcurrency, folder.FsConfig.S3Config.UploadConcurrency)
	assert.Equal(t, int64(S3UploadPartSize), folder.FsConfig.S3Config.UploadPartSize)
	assert.Equal(t, S3MaxPartDownloadTime, folder.FsConfig.S3Config.DownloadPartMaxTime)
	assert.Equal(t, S3MaxPartUploadTime, folder.FsConfig.S3Config.UploadPartMaxTime)
	assert.Equal(t, S3DownloadConcurrency, folder.FsConfig.S3Config.DownloadConcurrency)
	assert.Equal(t, int64(S3DownloadPartSize), folder.FsConfig.S3Config.DownloadPartSize)
	assert.False(t, folder.FsConfig.S3Config.ForcePathStyle)
	// update
	S3UploadConcurrency = 10
	form.Set("s3_upload_concurrency", "b")
	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form.Set("s3_upload_concurrency", strconv.Itoa(S3UploadConcurrency))
	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr)

	folder = vfs.BaseVirtualFolder{}
	req, _ = http.NewRequest(http.MethodGet, path.Join(folderPath, folderName), nil)
	setBearerForReq(req, apiToken)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	err = render.DecodeJSON(rr.Body, &folder)
	assert.NoError(t, err)
	assert.Equal(t, mappedPath, folder.MappedPath)
	assert.Equal(t, folderName, folder.Name)
	assert.Equal(t, folderDesc, folder.Description)
	assert.Equal(t, sdk.S3FilesystemProvider, folder.FsConfig.Provider)
	assert.Equal(t, S3Bucket, folder.FsConfig.S3Config.Bucket)
	assert.Equal(t, S3Region, folder.FsConfig.S3Config.Region)
	assert.Equal(t, S3AccessKey, folder.FsConfig.S3Config.AccessKey)
	assert.Equal(t, S3RoleARN, folder.FsConfig.S3Config.RoleARN)
	assert.NotEmpty(t, folder.FsConfig.S3Config.AccessSecret.GetPayload())
	assert.Equal(t, S3Endpoint, folder.FsConfig.S3Config.Endpoint)
	assert.Equal(t, S3StorageClass, folder.FsConfig.S3Config.StorageClass)
	assert.Equal(t, S3KeyPrefix, folder.FsConfig.S3Config.KeyPrefix)
	assert.Equal(t, S3UploadConcurrency, folder.FsConfig.S3Config.UploadConcurrency)
	assert.Equal(t, int64(S3UploadPartSize), folder.FsConfig.S3Config.UploadPartSize)

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
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
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
	b, contentType, err := getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "unable to verify form token")

	form.Set(csrfFormToken, csrfToken)
	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
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
	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName)+"??a=a%B3%A2%G3", &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName+"1"), &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	form.Set("mapped_path", "arelative/path")
	b, contentType, err = getMultipartFormData(form, "", "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(webFolderPath, folderName), &b)
	assert.NoError(t, err)
	setJWTCookieForReq(req, webToken)
	req.Header.Set("Content-Type", contentType)
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

func TestAdminForgotPassword(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          3525,
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize("..")
	require.NoError(t, err)

	a := getTestAdmin()
	a.Username = altAdminUsername
	a.Password = altAdminPassword
	admin, _, err := httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webAdminForgotPwdPath, nil)
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webAdminResetPwdPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webLoginPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)

	form := make(url.Values)
	form.Set("username", "")
	// no csrf token
	req, err = http.NewRequest(http.MethodPost, webAdminForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	// empty username
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webAdminForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Username is mandatory")

	lastResetCode = ""
	form.Set("username", altAdminUsername)
	req, err = http.NewRequest(http.MethodPost, webAdminForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)

	form = make(url.Values)
	req, err = http.NewRequest(http.MethodPost, webAdminResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	// no password
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webAdminResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Please set a password")
	// no code
	form.Set("password", defaultPassword)
	req, err = http.NewRequest(http.MethodPost, webAdminResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Please set a confirmation code")
	// ok
	form.Set("code", lastResetCode)
	req, err = http.NewRequest(http.MethodPost, webAdminResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)

	form.Set("username", altAdminUsername)
	req, err = http.NewRequest(http.MethodPost, webAdminForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)

	// not working smtp server
	smtpCfg = smtp.Config{
		Host:          "127.0.0.1",
		Port:          3526,
		TemplatesPath: "templates",
	}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)

	form = make(url.Values)
	form.Set("username", altAdminUsername)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webAdminForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unable to send confirmation code via email")

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)

	form.Set("username", altAdminUsername)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webAdminForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unable to render password reset template")

	req, err = http.NewRequest(http.MethodGet, webAdminForgotPwdPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, webAdminResetPwdPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserForgotPassword(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          3525,
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize("..")
	require.NoError(t, err)

	u := getTestUser()
	u.Email = "user@test.com"
	u.Filters.WebClient = []string{sdk.WebClientPasswordResetDisabled}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webClientForgotPwdPath, nil)
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webClientResetPwdPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, webClientLoginPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	form := make(url.Values)
	form.Set("username", "")
	// no csrf token
	req, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	// empty username
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	assert.NoError(t, err)
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Username is mandatory")
	// user cannot reset the password
	form.Set("username", user.Username)
	req, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "You are not allowed to reset your password")
	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	lastResetCode = ""
	req, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)
	// no csrf token
	form = make(url.Values)
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	// no password
	form.Set(csrfFormToken, csrfToken)
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Please set a password")
	// no code
	form.Set("password", altAdminPassword)
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Please set a confirmation code")
	// ok
	form.Set("code", lastResetCode)
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)

	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", user.Username)
	lastResetCode = ""
	req, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientForgotPwdPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	req, err = http.NewRequest(http.MethodGet, webClientResetPwdPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	// user does not exist anymore
	form = make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("code", lastResetCode)
	form.Set("password", "pwd")
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unable to associate the confirmation code with an existing user")
}

func TestAPIForgotPassword(t *testing.T) {
	smtpCfg := smtp.Config{
		Host:          "127.0.0.1",
		Port:          3525,
		TemplatesPath: "templates",
	}
	err := smtpCfg.Initialize("..")
	require.NoError(t, err)

	a := getTestAdmin()
	a.Username = altAdminUsername
	a.Password = altAdminPassword
	a.Email = ""
	admin, _, err := httpdtest.AddAdmin(a, http.StatusCreated)
	assert.NoError(t, err)
	// no email, forgot pwd will not work
	lastResetCode = ""
	req, err := http.NewRequest(http.MethodPost, path.Join(adminPath, altAdminUsername, "/forgot-password"), nil)
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Your account does not have an email address")

	admin.Email = "admin@test.com"
	admin, _, err = httpdtest.UpdateAdmin(admin, http.StatusOK)
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, altAdminUsername, "/forgot-password"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)

	// invalid JSON
	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, altAdminUsername, "/reset-password"), bytes.NewBuffer([]byte(`{`)))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)

	resetReq := make(map[string]string)
	resetReq["code"] = lastResetCode
	resetReq["password"] = defaultPassword
	asJSON, err := json.Marshal(resetReq)
	assert.NoError(t, err)

	// a user cannot use an admin code
	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, defaultUsername, "/reset-password"), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Invalid confirmation code")

	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, altAdminUsername, "/reset-password"), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	// the same code cannot be reused
	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, altAdminUsername, "/reset-password"), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Confirmation code not found")

	admin, err = dataprovider.AdminExists(altAdminUsername)
	assert.NoError(t, err)

	match, err := admin.CheckPassword(defaultPassword)
	assert.NoError(t, err)
	assert.True(t, match)
	lastResetCode = ""
	// now the same for a user
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, defaultUsername, "/forgot-password"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Your account does not have an email address")

	user.Email = "user@test.com"
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, defaultUsername, "/forgot-password"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)

	// invalid JSON
	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, defaultUsername, "/reset-password"), bytes.NewBuffer([]byte(`{`)))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	// remove the reset password permission
	user.Filters.WebClient = []string{sdk.WebClientPasswordResetDisabled}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	resetReq["code"] = lastResetCode
	resetReq["password"] = altAdminPassword
	asJSON, err = json.Marshal(resetReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, defaultUsername, "/reset-password"), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "You are not allowed to reset your password")

	user.Filters.WebClient = []string{sdk.WebClientSharesDisabled}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, defaultUsername, "/reset-password"), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	// the same code cannot be reused
	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, defaultUsername, "/reset-password"), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Confirmation code not found")

	user, err = dataprovider.UserExists(defaultUsername)
	assert.NoError(t, err)
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(altAdminPassword))
	assert.NoError(t, err)

	lastResetCode = ""
	// a request for a missing admin/user will be silently ignored
	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, "missing-admin", "/forgot-password"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Empty(t, lastResetCode)

	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, "missing-user", "/forgot-password"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Empty(t, lastResetCode)

	lastResetCode = ""
	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, altAdminUsername, "/forgot-password"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
	assert.GreaterOrEqual(t, len(lastResetCode), 20)

	smtpCfg = smtp.Config{}
	err = smtpCfg.Initialize("..")
	require.NoError(t, err)

	// without an smtp configuration reset password is not available
	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, altAdminUsername, "/forgot-password"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "No SMTP configuration")

	req, err = http.NewRequest(http.MethodPost, path.Join(userPath, defaultUsername, "/forgot-password"), nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "No SMTP configuration")

	_, err = httpdtest.RemoveAdmin(admin, http.StatusOK)
	assert.NoError(t, err)
	// the admin does not exist anymore
	resetReq["code"] = lastResetCode
	resetReq["password"] = altAdminPassword
	asJSON, err = json.Marshal(resetReq)
	assert.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, altAdminUsername, "/reset-password"), bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
	assert.Contains(t, rr.Body.String(), "Unable to associate the confirmation code with an existing admin")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestProviderClosedMock(t *testing.T) {
	token, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
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
	providerConf.BackupsPath = backupsPath
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

	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
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
	req, err := http.NewRequest(http.MethodGet, "/static/favicon.ico", nil)
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, "/openapi/openapi.yaml", nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, "/static", nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusMovedPermanently, rr)
	location := rr.Header().Get("Location")
	assert.Equal(t, "/static/", location)
	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)

	req, err = http.NewRequest(http.MethodGet, "/openapi", nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusMovedPermanently, rr)
	location = rr.Header().Get("Location")
	assert.Equal(t, "/openapi/", location)
	req, err = http.NewRequest(http.MethodGet, location, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr)
}

func TestSecondFactorRequirements(t *testing.T) {
	user := getTestUser()
	user.Filters.TwoFactorAuthProtocols = []string{common.ProtocolHTTP, common.ProtocolSSH}
	assert.True(t, user.MustSetSecondFactor())
	assert.False(t, user.MustSetSecondFactorForProtocol(common.ProtocolFTP))
	assert.True(t, user.MustSetSecondFactorForProtocol(common.ProtocolHTTP))
	assert.True(t, user.MustSetSecondFactorForProtocol(common.ProtocolSSH))

	user.Filters.TOTPConfig.Enabled = true
	assert.True(t, user.MustSetSecondFactor())
	assert.False(t, user.MustSetSecondFactorForProtocol(common.ProtocolFTP))
	assert.True(t, user.MustSetSecondFactorForProtocol(common.ProtocolHTTP))
	assert.True(t, user.MustSetSecondFactorForProtocol(common.ProtocolSSH))

	user.Filters.TOTPConfig.Protocols = []string{common.ProtocolHTTP}
	assert.True(t, user.MustSetSecondFactor())
	assert.False(t, user.MustSetSecondFactorForProtocol(common.ProtocolFTP))
	assert.False(t, user.MustSetSecondFactorForProtocol(common.ProtocolHTTP))
	assert.True(t, user.MustSetSecondFactorForProtocol(common.ProtocolSSH))

	user.Filters.TOTPConfig.Protocols = []string{common.ProtocolHTTP, common.ProtocolSSH}
	assert.False(t, user.MustSetSecondFactor())
	assert.False(t, user.MustSetSecondFactorForProtocol(common.ProtocolFTP))
	assert.False(t, user.MustSetSecondFactorForProtocol(common.ProtocolHTTP))
	assert.False(t, user.MustSetSecondFactorForProtocol(common.ProtocolSSH))
}

func startOIDCMockServer() {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "OK\n")
		})
		http.HandleFunc("/auth/realms/sftpgo/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"issuer":"http://127.0.0.1:11111/auth/realms/sftpgo","authorization_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/auth","token_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/token","introspection_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/token/introspect","userinfo_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/userinfo","end_session_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/logout","frontchannel_logout_session_supported":true,"frontchannel_logout_supported":true,"jwks_uri":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/certs","check_session_iframe":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"request_object_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"response_modes_supported":["query","fragment","form_post","query.jwt","fragment.jwt","form_post.jwt","jwt"],"registration_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"introspection_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"authorization_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported":true,"scopes_supported":["openid","phone","email","web-origins","offline_access","microprofile-jwt","profile","address","roles"],"request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens":true,"revocation_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/revoke","revocation_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"device_authorization_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/auth/device","backchannel_token_delivery_modes_supported":["poll","ping"],"backchannel_authentication_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/ext/ciba/auth","backchannel_authentication_request_signing_alg_values_supported":["PS384","ES384","RS384","ES256","RS256","ES512","PS256","PS512","RS512"],"require_pushed_authorization_requests":false,"pushed_authorization_request_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/ext/par/request","mtls_endpoint_aliases":{"token_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/token","revocation_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/revoke","introspection_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/token/introspect","device_authorization_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/auth/device","registration_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/clients-registrations/openid-connect","userinfo_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/userinfo","pushed_authorization_request_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/ext/par/request","backchannel_authentication_endpoint":"http://127.0.0.1:11111/auth/realms/sftpgo/protocol/openid-connect/ext/ciba/auth"}}`)
		})
		http.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Not found\n")
		})
		if err := http.ListenAndServe(oidcMockAddr, nil); err != nil {
			logger.ErrorToConsole("could not start HTTP notification server: %v", err)
			os.Exit(1)
		}
	}()
	waitTCPListening(oidcMockAddr)
}

func waitForUsersQuotaScan(t *testing.T, token string) {
	for {
		var scans []common.ActiveQuotaScan
		req, _ := http.NewRequest(http.MethodGet, quotaScanPath, nil)
		setBearerForReq(req, token)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
		err := render.DecodeJSON(rr.Body, &scans)

		if !assert.NoError(t, err, "Error getting active scans") {
			break
		}
		if len(scans) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitForFoldersQuotaScanPath(t *testing.T, token string) {
	var scans []common.ActiveVirtualFolderQuotaScan
	for {
		req, _ := http.NewRequest(http.MethodGet, quotaScanVFolderPath, nil)
		setBearerForReq(req, token)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr)
		err := render.DecodeJSON(rr.Body, &scans)
		if !assert.NoError(t, err, "Error getting active folders scans") {
			break
		}
		if len(scans) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
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

func startSMTPServer() {
	go func() {
		if err := smtpd.ListenAndServe(smtpServerAddr, func(remoteAddr net.Addr, from string, to []string, data []byte) error {
			re := regexp.MustCompile(`code is ".*?"`)
			code := strings.TrimPrefix(string(re.Find(data)), "code is ")
			lastResetCode = strings.ReplaceAll(code, "\"", "")
			return nil
		}, "SFTPGo test", "localhost"); err != nil {
			logger.ErrorToConsole("could not start SMTP server: %v", err)
			os.Exit(1)
		}
	}()
	waitTCPListening(smtpServerAddr)
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
		BaseUser: sdk.BaseUser{
			Username:    defaultUsername,
			Password:    defaultPassword,
			HomeDir:     filepath.Join(homeBasePath, defaultUsername),
			Status:      1,
			Description: "test user",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = defaultPerms
	return user
}

func getTestSFTPUser() dataprovider.User {
	u := getTestUser()
	u.Username = u.Username + "_sftp"
	u.FsConfig.Provider = sdk.SFTPFilesystemProvider
	u.FsConfig.SFTPConfig.Endpoint = sftpServerAddr
	u.FsConfig.SFTPConfig.Username = defaultUsername
	u.FsConfig.SFTPConfig.Password = kms.NewPlainSecret(defaultPassword)
	return u
}

func getUserAsJSON(t *testing.T, user dataprovider.User) []byte {
	json, err := json.Marshal(user)
	assert.NoError(t, err)
	return json
}

func getCSRFTokenMock(loginURLPath, remoteAddr string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, loginURLPath, nil)
	if err != nil {
		return "", err
	}
	req.RemoteAddr = remoteAddr
	rr := executeRequest(req)
	return getCSRFTokenFromBody(bytes.NewBuffer(rr.Body.Bytes()))
}

func getCSRFToken(url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpclient.GetHTTPClient().Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	return getCSRFTokenFromBody(resp.Body)
}

func getCSRFTokenFromBody(body io.Reader) (string, error) {
	doc, err := html.Parse(body)
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

func getLoginForm(username, password, csrfToken string) url.Values {
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

func setAPIKeyForReq(req *http.Request, apiKey, username string) {
	if username != "" {
		apiKey += "." + username
	}
	req.Header.Set("X-SFTPGO-API-KEY", apiKey)
}

func setJWTCookieForReq(req *http.Request, jwtToken string) {
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", jwtToken))
}

func getJWTAPITokenFromTestServer(username, password string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, tokenPath, nil)
	req.SetBasicAuth(username, password)
	rr := executeRequest(req)
	if rr.Code != http.StatusOK {
		return "", fmt.Errorf("unexpected  status code %v", rr.Code)
	}
	responseHolder := make(map[string]interface{})
	err := render.DecodeJSON(rr.Body, &responseHolder)
	if err != nil {
		return "", err
	}
	return responseHolder["access_token"].(string), nil
}

func getJWTAPIUserTokenFromTestServer(username, password string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, userTokenPath, nil)
	req.SetBasicAuth(username, password)
	rr := executeRequest(req)
	if rr.Code != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %v", rr.Code)
	}
	responseHolder := make(map[string]interface{})
	err := render.DecodeJSON(rr.Body, &responseHolder)
	if err != nil {
		return "", err
	}
	return responseHolder["access_token"].(string), nil
}

func getJWTWebToken(username, password string) (string, error) {
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	if err != nil {
		return "", err
	}
	form := getLoginForm(username, password, csrfToken)
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

func getCookieFromResponse(rr *httptest.ResponseRecorder) (string, error) {
	cookie := strings.Split(rr.Header().Get("Set-Cookie"), ";")
	if strings.HasPrefix(cookie[0], "jwt=") {
		return cookie[0][4:], nil
	}
	return "", errors.New("no cookie found")
}

func getJWTWebClientTokenFromTestServerWithAddr(username, password, remoteAddr string) (string, error) {
	csrfToken, err := getCSRFTokenMock(webClientLoginPath, remoteAddr)
	if err != nil {
		return "", err
	}
	form := getLoginForm(username, password, csrfToken)
	req, _ := http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	if rr.Code != http.StatusFound {
		return "", fmt.Errorf("unexpected  status code %v", rr)
	}
	return getCookieFromResponse(rr)
}

func getJWTWebClientTokenFromTestServer(username, password string) (string, error) {
	csrfToken, err := getCSRFToken(httpBaseURL + webClientLoginPath)
	if err != nil {
		return "", err
	}
	form := getLoginForm(username, password, csrfToken)
	req, _ := http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	if rr.Code != http.StatusFound {
		return "", fmt.Errorf("unexpected  status code %v", rr)
	}
	return getCookieFromResponse(rr)
}

func getJWTWebTokenFromTestServer(username, password string) (string, error) {
	csrfToken, err := getCSRFToken(httpBaseURL + webLoginPath)
	if err != nil {
		return "", err
	}
	form := getLoginForm(username, password, csrfToken)
	req, _ := http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = defaultRemoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	if rr.Code != http.StatusFound {
		return "", fmt.Errorf("unexpected  status code %v", rr)
	}
	return getCookieFromResponse(rr)
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

func getExitCodeScriptContent(exitCode int) []byte {
	content := []byte("#!/bin/sh\n\n")
	content = append(content, []byte(fmt.Sprintf("exit %v", exitCode))...)
	return content
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

func generateTOTPPasscode(secret string) (string, error) {
	return totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
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
