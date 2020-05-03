package httpd_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	defaultUsername       = "test_user"
	defaultPassword       = "test_password"
	testPubKey            = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	logSender             = "APITesting"
	userPath              = "/api/v1/user"
	activeConnectionsPath = "/api/v1/connection"
	quotaScanPath         = "/api/v1/quota_scan"
	versionPath           = "/api/v1/version"
	providerStatusPath    = "/api/v1/providerstatus"
	dumpDataPath          = "/api/v1/dumpdata"
	loadDataPath          = "/api/v1/loaddata"
	metricsPath           = "/metrics"
	pprofPath             = "/debug/pprof/"
	webBasePath           = "/web"
	webUsersPath          = "/web/users"
	webUserPath           = "/web/user"
	webConnectionsPath    = "/web/connections"
	configDir             = ".."
	httpsCert             = `-----BEGIN CERTIFICATE-----
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
)

var (
	defaultPerms       = []string{dataprovider.PermAny}
	homeBasePath       string
	backupsPath        string
	credentialsPath    string
	testServer         *httptest.Server
	providerDriverName string
)

func TestMain(m *testing.M) {
	homeBasePath = os.TempDir()
	logfilePath := filepath.Join(configDir, "sftpgo_api_test.log")
	logger.InitLogger(logfilePath, 5, 1, 28, false, zerolog.DebugLevel)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	credentialsPath = filepath.Join(os.TempDir(), "test_credentials")
	providerConf.CredentialsPath = credentialsPath
	providerDriverName = providerConf.Driver
	os.RemoveAll(credentialsPath)

	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		logger.Warn(logSender, "", "error initializing data provider: %v", err)
		os.Exit(1)
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Initialize(configDir)

	dataProvider := dataprovider.GetProvider()
	httpdConf := config.GetHTTPDConfig()

	httpdConf.BindPort = 8081
	httpd.SetBaseURLAndCredentials("http://127.0.0.1:8081", "", "")
	backupsPath = filepath.Join(os.TempDir(), "test_backups")
	httpdConf.BackupsPath = backupsPath
	os.MkdirAll(backupsPath, 0777)

	sftpd.SetDataProvider(dataProvider)
	httpd.SetDataProvider(dataProvider)

	go func() {
		if err := httpdConf.Initialize(configDir, true); err != nil {
			logger.Error(logSender, "", "could not start HTTP server: %v", err)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))
	// now start an https server
	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	ioutil.WriteFile(certPath, []byte(httpsCert), 0666)
	ioutil.WriteFile(keyPath, []byte(httpsKey), 0666)
	httpdConf.BindPort = 8443
	httpdConf.CertificateFile = certPath
	httpdConf.CertificateKeyFile = keyPath

	go func() {
		if err := httpdConf.Initialize(configDir, true); err != nil {
			logger.Error(logSender, "", "could not start HTTPS server: %v", err)
		}
	}()
	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))
	httpd.ReloadTLSCertificate()

	testServer = httptest.NewServer(httpd.GetHTTPRouter())
	defer testServer.Close()

	exitCode := m.Run()
	os.Remove(logfilePath)
	os.RemoveAll(backupsPath)
	os.RemoveAll(credentialsPath)
	os.Remove(certPath)
	os.Remove(keyPath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	httpdConf := config.GetHTTPDConfig()
	httpdConf.BackupsPath = "test_backups"
	httpdConf.AuthUserFile = "invalid file"
	err = httpdConf.Initialize(configDir, true)
	assert.Error(t, err)
	httpdConf.BackupsPath = backupsPath
	httpdConf.AuthUserFile = ""
	httpdConf.CertificateFile = "invalid file"
	httpdConf.CertificateKeyFile = "invalid file"
	err = httpdConf.Initialize(configDir, true)
	assert.Error(t, err)
	httpdConf.CertificateFile = ""
	httpdConf.CertificateKeyFile = ""
	httpdConf.TemplatesPath = "."
	err = httpdConf.Initialize(configDir, true)
	assert.Error(t, err)
	err = httpd.ReloadTLSCertificate()
	assert.NoError(t, err, "reloading TLS Certificate must return nil error if no certificate is configured")
}

func TestBasicUserHandling(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	user.MaxSessions = 10
	user.QuotaSize = 4096
	user.QuotaFiles = 2
	user.UploadBandwidth = 128
	user.DownloadBandwidth = 64
	user.ExpirationDate = utils.GetTimeAsMsSinceEpoch(time.Now())
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserStatus(t *testing.T) {
	u := getTestUser()
	u.Status = 3
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Status = 0
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	user.Status = 2
	_, _, err = httpd.UpdateUser(user, http.StatusBadRequest)
	assert.NoError(t, err)
	user.Status = 1
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestAddUserNoCredentials(t *testing.T) {
	u := getTestUser()
	u.Password = ""
	u.PublicKeys = []string{}
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserNoUsername(t *testing.T) {
	u := getTestUser()
	u.Username = ""
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserNoHomeDir(t *testing.T) {
	u := getTestUser()
	u.HomeDir = ""
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidHomeDir(t *testing.T) {
	u := getTestUser()
	u.HomeDir = "relative_path"
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserNoPerms(t *testing.T) {
	u := getTestUser()
	u.Permissions = make(map[string][]string)
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Permissions["/"] = []string{}
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidPerms(t *testing.T) {
	u := getTestUser()
	u.Permissions["/"] = []string{"invalidPerm"}
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	// permissions for root dir are mandatory
	u.Permissions["/"] = []string{}
	u.Permissions["/somedir"] = []string{dataprovider.PermAny}
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir/.."] = []string{dataprovider.PermAny}
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidFilters(t *testing.T) {
	u := getTestUser()
	u.Filters.AllowedIP = []string{"192.168.1.0/24", "192.168.2.0"}
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.AllowedIP = []string{}
	u.Filters.DeniedIP = []string{"192.168.3.0/16", "invalid"}
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedIP = []string{}
	u.Filters.DeniedLoginMethods = []string{"invalid"}
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedLoginMethods = dataprovider.ValidSSHLoginMethods
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.DeniedLoginMethods = []string{}
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "relative",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{},
		},
	}
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/",
			AllowedExtensions: []string{},
			DeniedExtensions:  []string{},
		},
	}
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
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
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidFsConfig(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = 1
	u.FsConfig.S3Config.Bucket = ""
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = os.MkdirAll(credentialsPath, 0700)
	assert.NoError(t, err)
	u.FsConfig.S3Config.Bucket = "test"
	u.FsConfig.S3Config.Region = "eu-west-1"
	u.FsConfig.S3Config.AccessKey = "access-key"
	u.FsConfig.S3Config.AccessSecret = "access-secret"
	u.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/path?a=b"
	u.FsConfig.S3Config.StorageClass = "Standard"
	u.FsConfig.S3Config.KeyPrefix = "/somedir/subdir/"
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.S3Config.KeyPrefix = ""
	u.FsConfig.S3Config.UploadPartSize = 3
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.S3Config.UploadPartSize = 0
	u.FsConfig.S3Config.UploadConcurrency = -1
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u = getTestUser()
	u.FsConfig.Provider = 2
	u.FsConfig.GCSConfig.Bucket = ""
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.StorageClass = "Standard"
	u.FsConfig.GCSConfig.KeyPrefix = "/somedir/subdir/"
	u.FsConfig.GCSConfig.Credentials = base64.StdEncoding.EncodeToString([]byte("test"))
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.KeyPrefix = "somedir/subdir/"
	u.FsConfig.GCSConfig.Credentials = ""
	u.FsConfig.GCSConfig.AutomaticCredentials = 0
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.Credentials = "no base64 encoded"
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestAddUserInvalidVirtualFolders(t *testing.T) {
	u := getTestUser()
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "vdir",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir"),
	})
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir"),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  filepath.Join(u.GetHomeDir(), "mapped_dir"),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  u.GetHomeDir(),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  filepath.Join(u.GetHomeDir(), ".."),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir"),
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir1"),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir"),
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir2",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir"),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir", "subdir"),
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir2",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir"),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir"),
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir2",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir", "subdir"),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1/subdir",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir1"),
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1/../vdir1",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir2"),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1/",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir1"),
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1/subdir",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir2"),
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestUserPublicKey(t *testing.T) {
	u := getTestUser()
	invalidPubKey := "invalid"
	validPubKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	u.PublicKeys = []string{invalidPubKey}
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.PublicKeys = []string{validPubKey}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	user.PublicKeys = []string{validPubKey, invalidPubKey}
	_, _, err = httpd.UpdateUser(user, http.StatusBadRequest)
	assert.NoError(t, err)
	user.PublicKeys = []string{validPubKey, validPubKey, validPubKey}
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUser(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
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
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPassword}
	user.Filters.FileExtensions = append(user.Filters.FileExtensions, dataprovider.ExtensionsFilter{
		Path:              "/subdir",
		AllowedExtensions: []string{".zip", ".rar"},
		DeniedExtensions:  []string{".jpg", ".png"},
	})
	user.UploadBandwidth = 1024
	user.DownloadBandwidth = 512
	user.VirtualFolders = nil
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1",
		MappedPath:  filepath.Join(os.TempDir(), "mapped_dir1"),
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		VirtualPath:      "/vdir12/subdir",
		MappedPath:       filepath.Join(os.TempDir(), "mapped_dir2"),
		ExcludeFromQuota: true,
	})
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Permissions["/subdir"] = []string{}
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	if len(user.Permissions["/subdir"]) > 0 {
		t.Errorf("unexpected subdir permissions, must be empty")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserS3Config(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	user.FsConfig.Provider = 1
	user.FsConfig.S3Config.Bucket = "test"
	user.FsConfig.S3Config.Region = "us-east-1"
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key"
	user.FsConfig.S3Config.AccessSecret = "Server-Access-Secret"
	user.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000"
	user.FsConfig.S3Config.UploadPartSize = 8
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	secret, _ := utils.EncryptData("Server-Access-Secret")
	user.FsConfig.S3Config.AccessSecret = secret
	user, _, err = httpd.AddUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.FsConfig.Provider = 1
	user.FsConfig.S3Config.Bucket = "test1"
	user.FsConfig.S3Config.Region = "us-east-1"
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key1"
	user.FsConfig.S3Config.Endpoint = "http://localhost:9000"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir"
	user.FsConfig.S3Config.UploadConcurrency = 5
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.FsConfig.Provider = 0
	user.FsConfig.S3Config.Bucket = ""
	user.FsConfig.S3Config.Region = ""
	user.FsConfig.S3Config.AccessKey = ""
	user.FsConfig.S3Config.AccessSecret = ""
	user.FsConfig.S3Config.Endpoint = ""
	user.FsConfig.S3Config.KeyPrefix = ""
	user.FsConfig.S3Config.UploadPartSize = 0
	user.FsConfig.S3Config.UploadConcurrency = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	// test user without access key and access secret (shared config state)
	user.FsConfig.Provider = 1
	user.FsConfig.S3Config.Bucket = "test1"
	user.FsConfig.S3Config.Region = "us-east-1"
	user.FsConfig.S3Config.AccessKey = ""
	user.FsConfig.S3Config.AccessSecret = ""
	user.FsConfig.S3Config.Endpoint = ""
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir"
	user.FsConfig.S3Config.UploadPartSize = 6
	user.FsConfig.S3Config.UploadConcurrency = 4
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserGCSConfig(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = os.MkdirAll(credentialsPath, 0700)
	assert.NoError(t, err)
	user.FsConfig.Provider = 2
	user.FsConfig.GCSConfig.Bucket = "test"
	user.FsConfig.GCSConfig.Credentials = base64.StdEncoding.EncodeToString([]byte("fake credentials"))
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.ID = 0
	// the user will be added since the credentials file is found
	user, _, err = httpd.AddUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = os.MkdirAll(credentialsPath, 0700)
	assert.NoError(t, err)
	user.FsConfig.GCSConfig.Credentials = ""
	user.FsConfig.GCSConfig.AutomaticCredentials = 1
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.FsConfig.Provider = 1
	user.FsConfig.S3Config.Bucket = "test1"
	user.FsConfig.S3Config.Region = "us-east-1"
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key1"
	user.FsConfig.S3Config.AccessSecret = "secret"
	user.FsConfig.S3Config.Endpoint = "http://localhost:9000"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir"
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.FsConfig.Provider = 2
	user.FsConfig.GCSConfig.Bucket = "test1"
	user.FsConfig.GCSConfig.Credentials = base64.StdEncoding.EncodeToString([]byte("fake credentials"))
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUserNoCredentials(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	user.Password = ""
	user.PublicKeys = []string{}
	// password and public key will be omitted from json serialization if empty and so they will remain unchanged
	// and no validation error will be raised
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUserEmptyHomeDir(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	user.HomeDir = ""
	_, _, err = httpd.UpdateUser(user, http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateUserInvalidHomeDir(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	user.HomeDir = "relative_path"
	_, _, err = httpd.UpdateUser(user, http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateNonExistentUser(t *testing.T) {
	_, _, err := httpd.UpdateUser(getTestUser(), http.StatusNotFound)
	assert.NoError(t, err)
}

func TestGetNonExistentUser(t *testing.T) {
	_, _, err := httpd.GetUserByID(0, http.StatusNotFound)
	assert.NoError(t, err)
}

func TestDeleteNonExistentUser(t *testing.T) {
	_, err := httpd.RemoveUser(getTestUser(), http.StatusNotFound)
	assert.NoError(t, err)
}

func TestAddDuplicateUser(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpd.AddUser(getTestUser(), http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.AddUser(getTestUser(), http.StatusOK)
	assert.Error(t, err, "adding a duplicate user must fail")
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestGetUsers(t *testing.T) {
	user1, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	u := getTestUser()
	u.Username = defaultUsername + "1"
	user2, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	users, _, err := httpd.GetUsers(0, 0, "", http.StatusOK)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(users), 2)
	users, _, err = httpd.GetUsers(1, 0, "", http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	users, _, err = httpd.GetUsers(1, 1, "", http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	_, _, err = httpd.GetUsers(1, 1, "", http.StatusInternalServerError)
	assert.Error(t, err)
	_, err = httpd.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
}

func TestGetQuotaScans(t *testing.T) {
	_, _, err := httpd.GetQuotaScans(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpd.GetQuotaScans(http.StatusInternalServerError)
	assert.Error(t, err, "quota scan request must succeed, we requested to check a wrong status code")
}

func TestStartQuotaScan(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.StartQuotaScan(user, http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestGetVersion(t *testing.T) {
	_, _, err := httpd.GetVersion(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpd.GetVersion(http.StatusInternalServerError)
	assert.Error(t, err, "get version request must succeed, we requested to check a wrong status code")
}

func TestGetProviderStatus(t *testing.T) {
	_, _, err := httpd.GetProviderStatus(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpd.GetProviderStatus(http.StatusBadRequest)
	assert.Error(t, err, "get provider status request must succeed, we requested to check a wrong status code")
}

func TestGetConnections(t *testing.T) {
	_, _, err := httpd.GetConnections(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpd.GetConnections(http.StatusInternalServerError)
	assert.Error(t, err, "get sftp connections request must succeed, we requested to check a wrong status code")
}

func TestCloseActiveConnection(t *testing.T) {
	_, err := httpd.CloseConnection("non_existent_id", http.StatusNotFound)
	assert.NoError(t, err)
}

func TestUserBaseDir(t *testing.T) {
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.UsersBaseDir = homeBasePath
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	u := getTestUser()
	u.HomeDir = ""
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(providerConf.UsersBaseDir, u.Username), user.HomeDir)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	dataProvider = dataprovider.GetProvider()
	err = dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
}

func TestProviderErrors(t *testing.T) {
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	_, _, err = httpd.GetUserByID(0, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.GetUsers(1, 0, defaultUsername, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.UpdateUser(dataprovider.User{}, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(dataprovider.User{}, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.GetProviderStatus(http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.Dumpdata("backup.json", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	user := getTestUser()
	user.ID = 1
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupContent, _ := json.Marshal(backupData)
	backupFilePath := filepath.Join(backupsPath, "backup.json")
	ioutil.WriteFile(backupFilePath, backupContent, 0666)
	_, _, err = httpd.Loaddata(backupFilePath, "", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
}

func TestDumpdata(t *testing.T) {
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	_, _, err = httpd.Dumpdata("", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpd.Dumpdata(filepath.Join(backupsPath, "backup.json"), "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpd.Dumpdata("../backup.json", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpd.Dumpdata("backup.json", "0", http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpd.Dumpdata("backup.json", "1", http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(filepath.Join(backupsPath, "backup.json"))
	assert.NoError(t, err)
	if runtime.GOOS != "windows" {
		err = os.Chmod(backupsPath, 0001)
		assert.NoError(t, err)
		_, _, err = httpd.Dumpdata("bck.json", "", http.StatusInternalServerError)
		assert.NoError(t, err)
		// subdir cannot be created
		_, _, err = httpd.Dumpdata(filepath.Join("subdir", "bck.json"), "", http.StatusInternalServerError)
		assert.NoError(t, err)
		err = os.Chmod(backupsPath, 0755)
		assert.NoError(t, err)
	}
	dataProvider = dataprovider.GetProvider()
	err = dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
}

func TestLoaddata(t *testing.T) {
	user := getTestUser()
	user.ID = 1
	user.Username = "test_user_restore"
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupContent, _ := json.Marshal(backupData)
	backupFilePath := filepath.Join(backupsPath, "backup.json")
	err := ioutil.WriteFile(backupFilePath, backupContent, 0666)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata(backupFilePath, "a", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata(backupFilePath, "", "a", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata("backup.json", "1", "", http.StatusBadRequest)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata(backupFilePath+"a", "1", "", http.StatusBadRequest)
	assert.NoError(t, err)
	if runtime.GOOS != "windows" {
		err = os.Chmod(backupFilePath, 0111)
		assert.NoError(t, err)
		_, _, err = httpd.Loaddata(backupFilePath, "1", "", http.StatusInternalServerError)
		assert.NoError(t, err)
		err = os.Chmod(backupFilePath, 0644)
		assert.NoError(t, err)
	}
	// add user from backup
	_, _, err = httpd.Loaddata(backupFilePath, "1", "", http.StatusOK)
	assert.NoError(t, err)
	// update user from backup
	_, _, err = httpd.Loaddata(backupFilePath, "2", "", http.StatusOK)
	assert.NoError(t, err)
	users, _, err := httpd.GetUsers(1, 0, user.Username, http.StatusOK)
	assert.NoError(t, err)
	if assert.Equal(t, 1, len(users)) {
		user = users[0]
		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
	}
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
	err = createTestFile(backupFilePath, 10485761)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata(backupFilePath, "1", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
	err = createTestFile(backupFilePath, 65535)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata(backupFilePath, "1", "0", http.StatusBadRequest)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
}

func TestLoaddataMode(t *testing.T) {
	user := getTestUser()
	user.ID = 1
	user.Username = "test_user_restore"
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupContent, _ := json.Marshal(backupData)
	backupFilePath := filepath.Join(backupsPath, "backup.json")
	err := ioutil.WriteFile(backupFilePath, backupContent, 0666)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata(backupFilePath, "0", "0", http.StatusOK)
	assert.NoError(t, err)
	users, _, err := httpd.GetUsers(1, 0, user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	user = users[0]
	oldUploadBandwidth := user.UploadBandwidth
	user.UploadBandwidth = oldUploadBandwidth + 128
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata(backupFilePath, "0", "1", http.StatusOK)
	assert.NoError(t, err)
	users, _, err = httpd.GetUsers(1, 0, user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	user = users[0]
	assert.NotEqual(t, oldUploadBandwidth, user.UploadBandwidth)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(backupFilePath)
	assert.NoError(t, err)
}

func TestHTTPSConnection(t *testing.T) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	_, err := client.Get("https://localhost:8443" + metricsPath)
	assert.Error(t, err)
	if !strings.Contains(err.Error(), "certificate is not valid") &&
		!strings.Contains(err.Error(), "certificate signed by unknown authority") {
		assert.Fail(t, err.Error())
	}
}

// test using mock http server

func TestBasicUserHandlingMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, err := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr.Code)
	user.MaxSessions = 10
	user.UploadBandwidth = 128
	user.Permissions["/"] = []string{dataprovider.PermAny, dataprovider.PermDelete, dataprovider.PermDownload}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)

	req, _ = http.NewRequest(http.MethodGet, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)

	var updatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updatedUser)
	assert.NoError(t, err)
	assert.Equal(t, user.MaxSessions, updatedUser.MaxSessions)
	assert.Equal(t, user.UploadBandwidth, updatedUser.UploadBandwidth)
	assert.Equal(t, 1, len(updatedUser.Permissions["/"]))
	assert.True(t, utils.IsStringInSlice(dataprovider.PermAny, updatedUser.Permissions["/"]))
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestGetUserByIdInvalidParamsMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, userPath+"/0", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"/a", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestAddUserNoUsernameMock(t *testing.T) {
	user := getTestUser()
	user.Username = ""
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestAddUserInvalidHomeDirMock(t *testing.T) {
	user := getTestUser()
	user.HomeDir = "relative_path"
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestAddUserInvalidPermsMock(t *testing.T) {
	user := getTestUser()
	user.Permissions["/"] = []string{}
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestAddUserInvalidJsonMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer([]byte("invalid json")))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestUpdateUserMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	// permissions should not change if empty or nil
	permissions := user.Permissions
	user.Permissions = make(map[string][]string)
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
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
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestUserPermissionsMock(t *testing.T) {
	user := getTestUser()
	user.Permissions = make(map[string][]string)
	user.Permissions["/somedir"] = []string{dataprovider.PermAny}
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Permissions[".."] = []string{dataprovider.PermAny}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.Permissions["/somedir"] = []string{"invalid"}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	delete(user.Permissions, "/somedir")
	user.Permissions["/somedir/.."] = []string{dataprovider.PermAny}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	delete(user.Permissions, "/somedir/..")
	user.Permissions["not_abs_path"] = []string{dataprovider.PermAny}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	delete(user.Permissions, "not_abs_path")
	user.Permissions["/somedir/../otherdir/"] = []string{dataprovider.PermListItems}
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	var updatedUser dataprovider.User
	err = render.DecodeJSON(rr.Body, &updatedUser)
	assert.NoError(t, err)
	if val, ok := updatedUser.Permissions["/otherdir"]; ok {
		assert.True(t, utils.IsStringInSlice(dataprovider.PermListItems, val))
		assert.Equal(t, 1, len(val))
	} else {
		assert.Fail(t, "expected dir not found in permissions")
	}
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestUpdateUserInvalidJsonMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer([]byte("Invalid json")))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestUpdateUserInvalidParamsMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.HomeDir = ""
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	userID := user.ID
	user.ID = 0
	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/"+strconv.FormatInt(userID, 10), bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	user.ID = userID
	req, _ = http.NewRequest(http.MethodPut, userPath+"/0", bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
	req, _ = http.NewRequest(http.MethodPut, userPath+"/a", bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestGetUsersMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=510&offset=0&order=ASC&username="+defaultUsername, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	var users []dataprovider.User
	err = render.DecodeJSON(rr.Body, &users)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=a&offset=0&order=ASC", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=a&order=ASC", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=0&order=ASCa", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)

	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestDeleteUserInvalidParamsMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodDelete, userPath+"/0", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/a", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestGetQuotaScansMock(t *testing.T) {
	req, err := http.NewRequest("GET", quotaScanPath, nil)
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestStartQuotaScanMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	_, err = os.Stat(user.HomeDir)
	if err == nil {
		err = os.Remove(user.HomeDir)
		assert.NoError(t, err)
	}
	// simulate a duplicate quota scan
	userAsJSON = getUserAsJSON(t, user)
	sftpd.AddQuotaScan(user.Username)
	req, _ = http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr.Code)
	sftpd.RemoveQuotaScan(user.Username)

	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr.Code)

	req, _ = http.NewRequest(http.MethodGet, quotaScanPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	var scans []sftpd.ActiveQuotaScan
	err = render.DecodeJSON(rr.Body, &scans)
	assert.NoError(t, err)
	for len(scans) > 0 {
		req, _ = http.NewRequest(http.MethodGet, quotaScanPath, nil)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr.Code)
		err = render.DecodeJSON(rr.Body, &scans)
		if err != nil {
			assert.Fail(t, err.Error(), "Error get active scans")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, err = os.Stat(user.HomeDir)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(user.HomeDir, 0777)
		assert.NoError(t, err)
	}
	req, _ = http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr.Code)

	req, _ = http.NewRequest(http.MethodGet, quotaScanPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &scans)
	assert.NoError(t, err)
	for len(scans) > 0 {
		req, _ = http.NewRequest(http.MethodGet, quotaScanPath, nil)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr.Code)
		err = render.DecodeJSON(rr.Body, &scans)
		if err != nil {
			assert.Fail(t, err.Error(), "Error get active scans")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestStartQuotaScanBadUserMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
}

func TestStartQuotaScanNonExistentUserMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer([]byte("invalid json")))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestGetVersionMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, versionPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestGetConnectionsMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, activeConnectionsPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestDeleteActiveConnectionMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodDelete, activeConnectionsPath+"/connectionID", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
}

func TestNotFoundMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/non/existing/path", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
}

func TestMethodNotAllowedMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, activeConnectionsPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestMetricsMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, metricsPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestPProfEndPointMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, pprofPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestGetWebRootMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusMovedPermanently, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webBasePath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusMovedPermanently, rr.Code)
}

func TestBasicWebUsersMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user1 := getTestUser()
	user1.Username += "1"
	user1AsJSON := getUserAsJSON(t, user1)
	req, _ = http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(user1AsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &user1)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, webUsersPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUsersPath+"?qlimit=a", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUsersPath+"?qlimit=1", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUserPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUserPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUserPath+"/0", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUserPath+"/a", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	form := make(url.Values)
	form.Set("username", user.Username)
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/0", &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/a", &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user1.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestWebUserAddMock(t *testing.T) {
	user := getTestUser()
	user.UploadBandwidth = 32
	user.DownloadBandwidth = 64
	user.UID = 1000
	mappedDir := filepath.Join(os.TempDir(), "mapped")
	form := make(url.Values)
	form.Set("username", user.Username)
	form.Set("home_dir", user.HomeDir)
	form.Set("password", user.Password)
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "")
	form.Set("permissions", "*")
	form.Set("sub_dirs_permissions", " /subdir::list ,download ")
	form.Set("virtual_folders", fmt.Sprintf(" /vdir:: %v ::1", mappedDir))
	form.Set("allowed_extensions", "/dir1::.jpg,.png")
	form.Set("denied_extensions", "/dir1::.zip")
	b, contentType, _ := getMultipartFormData(form, "", "")
	// test invalid url escape
	req, _ := http.NewRequest(http.MethodPost, webUserPath+"?a=%2", &b)
	req.Header.Set("Content-Type", contentType)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("public_keys", testPubKey)
	form.Set("uid", strconv.FormatInt(int64(user.UID), 10))
	form.Set("gid", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid gid
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("gid", "0")
	form.Set("max_sessions", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid max sessions
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("max_sessions", "0")
	form.Set("quota_size", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid quota size
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("quota_size", "0")
	form.Set("quota_files", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid quota files
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("quota_files", "0")
	form.Set("upload_bandwidth", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid upload bandwidth
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("upload_bandwidth", strconv.FormatInt(user.UploadBandwidth, 10))
	form.Set("download_bandwidth", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid download bandwidth
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("download_bandwidth", strconv.FormatInt(user.DownloadBandwidth, 10))
	form.Set("status", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid status
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("status", strconv.Itoa(user.Status))
	form.Set("expiration_date", "123")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid expiration date
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("expiration_date", "")
	form.Set("allowed_ip", "invalid,ip")
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid allowed_ip
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("allowed_ip", "")
	form.Set("denied_ip", "192.168.1.2") // it should be 192.168.1.2/32
	b, contentType, _ = getMultipartFormData(form, "", "")
	// test invalid denied_ip
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	form.Set("denied_ip", "")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr.Code)
	// the user already exists, was created with the above request
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath, &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=0&order=ASC&username="+user.Username, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	var users []dataprovider.User
	render.DecodeJSON(rr.Body, &users)
	assert.Equal(t, 1, len(users))
	newUser := users[0]
	assert.Equal(t, user.UID, newUser.UID)
	assert.Equal(t, user.UploadBandwidth, newUser.UploadBandwidth)
	assert.Equal(t, user.DownloadBandwidth, newUser.DownloadBandwidth)
	assert.True(t, utils.IsStringInSlice(testPubKey, newUser.PublicKeys))
	if val, ok := newUser.Permissions["/subdir"]; ok {
		assert.True(t, utils.IsStringInSlice(dataprovider.PermListItems, val))
		assert.True(t, utils.IsStringInSlice(dataprovider.PermDownload, val))
	} else {
		assert.Fail(t, "user permissions must contain /somedir", "actual: %v", newUser.Permissions)
	}
	vfolderFound := false
	for _, v := range newUser.VirtualFolders {
		if v.VirtualPath == "/vdir" && v.MappedPath == mappedDir && v.ExcludeFromQuota == true {
			vfolderFound = true
		}
	}
	assert.True(t, vfolderFound)
	extFilters := newUser.Filters.FileExtensions[0]
	assert.True(t, utils.IsStringInSlice(".zip", extFilters.DeniedExtensions))
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(newUser.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestWebUserUpdateMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.MaxSessions = 1
	user.QuotaFiles = 2
	user.QuotaSize = 3
	user.GID = 1000
	form := make(url.Values)
	form.Set("username", user.Username)
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
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=0&order=ASC&username="+user.Username, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	var users []dataprovider.User
	render.DecodeJSON(rr.Body, &users)
	assert.Equal(t, 1, len(users))
	updateUser := users[0]
	assert.Equal(t, user.HomeDir, updateUser.HomeDir)
	assert.Equal(t, user.MaxSessions, updateUser.MaxSessions)
	assert.Equal(t, user.QuotaFiles, updateUser.QuotaFiles)
	assert.Equal(t, user.QuotaSize, updateUser.QuotaSize)
	assert.Equal(t, user.UID, updateUser.UID)
	assert.Equal(t, user.GID, updateUser.GID)

	if val, ok := updateUser.Permissions["/otherdir"]; ok {
		if !utils.IsStringInSlice(dataprovider.PermListItems, val) || !utils.IsStringInSlice(dataprovider.PermUpload, val) {
			t.Error("permssions for /otherdir does not match")
		}
	} else {
		assert.Fail(t, "user permissions must contains /otherdir", "actual: %v", updateUser.Permissions)
	}
	assert.True(t, utils.IsStringInSlice("192.168.1.3/32", updateUser.Filters.AllowedIP))
	assert.True(t, utils.IsStringInSlice("10.0.0.2/32", updateUser.Filters.DeniedIP))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, updateUser.Filters.DeniedLoginMethods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, updateUser.Filters.DeniedLoginMethods))
	assert.True(t, utils.IsStringInSlice(".zip", updateUser.Filters.FileExtensions[0].DeniedExtensions))
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestWebUserS3Mock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	user.FsConfig.Provider = 1
	user.FsConfig.S3Config.Bucket = "test"
	user.FsConfig.S3Config.Region = "eu-west-1"
	user.FsConfig.S3Config.AccessKey = "access-key"
	user.FsConfig.S3Config.AccessSecret = "access-secret"
	user.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/path?a=b"
	user.FsConfig.S3Config.StorageClass = "Standard"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir/"
	user.FsConfig.S3Config.UploadPartSize = 5
	user.FsConfig.S3Config.UploadConcurrency = 4
	form := make(url.Values)
	form.Set("username", user.Username)
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
	form.Set("s3_access_secret", user.FsConfig.S3Config.AccessSecret)
	form.Set("s3_storage_class", user.FsConfig.S3Config.StorageClass)
	form.Set("s3_endpoint", user.FsConfig.S3Config.Endpoint)
	form.Set("s3_key_prefix", user.FsConfig.S3Config.KeyPrefix)
	form.Set("allowed_extensions", "/dir1::.jpg,.png")
	form.Set("denied_extensions", "/dir2::.zip")
	// test invalid s3_upload_part_size
	form.Set("s3_upload_part_size", "a")
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	// test invalid s3_concurrency
	form.Set("s3_upload_part_size", strconv.FormatInt(user.FsConfig.S3Config.UploadPartSize, 10))
	form.Set("s3_upload_concurrency", "a")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	// now add the user
	form.Set("s3_upload_concurrency", strconv.Itoa(user.FsConfig.S3Config.UploadConcurrency))
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=0&order=ASC&username="+user.Username, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	var users []dataprovider.User
	err = render.DecodeJSON(rr.Body, &users)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	updateUser := users[0]
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
	if !strings.HasPrefix(updateUser.FsConfig.S3Config.AccessSecret, "$aes$") {
		t.Error("s3 access secret is not encrypted")
	}
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestWebUserGCSMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, err := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	credentialsFilePath := filepath.Join(os.TempDir(), "gcs.json")
	err = createTestFile(credentialsFilePath, 0)
	assert.NoError(t, err)
	user.FsConfig.Provider = 2
	user.FsConfig.GCSConfig.Bucket = "test"
	user.FsConfig.GCSConfig.KeyPrefix = "somedir/subdir/"
	user.FsConfig.GCSConfig.StorageClass = "standard"
	form := make(url.Values)
	form.Set("username", user.Username)
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
	b, contentType, _ := getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	b, contentType, _ = getMultipartFormData(form, "gcs_credential_file", credentialsFilePath)
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = createTestFile(credentialsFilePath, 4096)
	assert.NoError(t, err)
	b, contentType, _ = getMultipartFormData(form, "gcs_credential_file", credentialsFilePath)
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=0&order=ASC&username="+user.Username, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	var users []dataprovider.User
	render.DecodeJSON(rr.Body, &users)
	assert.Equal(t, 1, len(users))
	updateUser := users[0]
	assert.Equal(t, int64(1577836800000), updateUser.ExpirationDate)
	assert.Equal(t, user.FsConfig.Provider, updateUser.FsConfig.Provider)
	assert.Equal(t, user.FsConfig.GCSConfig.Bucket, updateUser.FsConfig.GCSConfig.Bucket)
	assert.Equal(t, user.FsConfig.GCSConfig.StorageClass, updateUser.FsConfig.GCSConfig.StorageClass)
	assert.Equal(t, user.FsConfig.GCSConfig.KeyPrefix, updateUser.FsConfig.GCSConfig.KeyPrefix)
	assert.Equal(t, "/dir1", updateUser.Filters.FileExtensions[0].Path)
	form.Set("gcs_auto_credentials", "on")
	b, contentType, _ = getMultipartFormData(form, "", "")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/"+strconv.FormatInt(user.ID, 10), &b)
	req.Header.Set("Content-Type", contentType)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"?limit=1&offset=0&order=ASC&username="+user.Username, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &users)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	updateUser = users[0]
	assert.Equal(t, 1, updateUser.FsConfig.GCSConfig.AutomaticCredentials)
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = os.Remove(credentialsFilePath)
	assert.NoError(t, err)
}

func TestProviderClosedMock(t *testing.T) {
	dataProvider := dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	req, _ := http.NewRequest(http.MethodGet, webUsersPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUserPath+"/0", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr.Code)
	form := make(url.Values)
	form.Set("username", "test")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/0", strings.NewReader(form.Encode()))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr.Code)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	os.RemoveAll(credentialsPath)
	err := dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
}

func TestGetWebConnectionsMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, webConnectionsPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestStaticFilesMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/static/favicon.ico", nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
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
		defer conn.Close()
		break
	}
}

func getTestUser() dataprovider.User {
	user := dataprovider.User{
		Username: defaultUsername,
		Password: defaultPassword,
		HomeDir:  filepath.Join(homeBasePath, defaultUsername),
		Status:   1,
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

func executeRequest(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	return rr
}

func checkResponseCode(t *testing.T, expected, actual int) {
	assert.Equal(t, expected, actual)
}

func createTestFile(path string, size int64) error {
	baseDir := filepath.Dir(path)
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		os.MkdirAll(baseDir, 0777)
	}
	content := make([]byte, size)
	if size > 0 {
		_, err := rand.Read(content)
		if err != nil {
			return err
		}
	}
	return ioutil.WriteFile(path, content, 0666)
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
		if _, err = io.Copy(fw, f); err != nil {
			return b, "", err
		}
	}
	err := w.Close()
	return b, w.FormDataContentType(), err
}
