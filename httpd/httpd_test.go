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

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	defaultUsername           = "test_user"
	defaultPassword           = "test_password"
	testPubKey                = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	userPath                  = "/api/v1/user"
	folderPath                = "/api/v1/folder"
	activeConnectionsPath     = "/api/v1/connection"
	quotaScanPath             = "/api/v1/quota_scan"
	quotaScanVFolderPath      = "/api/v1/folder_quota_scan"
	updateUsedQuotaPath       = "/api/v1/quota_update"
	updateFolderUsedQuotaPath = "/api/v1/folder_quota_update"
	versionPath               = "/api/v1/version"
	metricsPath               = "/metrics"
	pprofPath                 = "/debug/pprof/"
	webBasePath               = "/web"
	webUsersPath              = "/web/users"
	webUserPath               = "/web/user"
	webFoldersPath            = "/web/folders"
	webFolderPath             = "/web/folder"
	webConnectionsPath        = "/web/connections"
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

	common.Initialize(config.GetCommonConfig())

	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		logger.WarnToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Initialize(configDir)

	httpdConf := config.GetHTTPDConfig()

	httpdConf.BindPort = 8081
	httpd.SetBaseURLAndCredentials("http://127.0.0.1:8081", "", "")
	backupsPath = filepath.Join(os.TempDir(), "test_backups")
	httpdConf.BackupsPath = backupsPath
	err = os.MkdirAll(backupsPath, os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error creating backups path: %v", err)
		os.Exit(1)
	}

	go func() {
		if err := httpdConf.Initialize(configDir, true); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))
	// now start an https server
	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	err = ioutil.WriteFile(certPath, []byte(httpsCert), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing HTTPS certificate: %v", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(keyPath, []byte(httpsKey), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing HTTPS private key: %v", err)
		os.Exit(1)
	}
	httpdConf.BindPort = 8443
	httpdConf.CertificateFile = certPath
	httpdConf.CertificateKeyFile = keyPath

	go func() {
		if err := httpdConf.Initialize(configDir, true); err != nil {
			logger.ErrorToConsole("could not start HTTPS server: %v", err)
			os.Exit(1)
		}
	}()
	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))
	httpd.ReloadTLSCertificate() //nolint:errcheck

	testServer = httptest.NewServer(httpd.GetHTTPRouter())
	defer testServer.Close() //nolint:errcheck

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
	httpdConf.BackupsPath = "test_backups"
	httpdConf.AuthUserFile = invalidFile
	err = httpdConf.Initialize(configDir, true)
	assert.Error(t, err)
	httpdConf.BackupsPath = backupsPath
	httpdConf.AuthUserFile = ""
	httpdConf.CertificateFile = invalidFile
	httpdConf.CertificateKeyFile = invalidFile
	err = httpdConf.Initialize(configDir, true)
	assert.Error(t, err)
	httpdConf.CertificateFile = ""
	httpdConf.CertificateKeyFile = ""
	httpdConf.TemplatesPath = "."
	err = httpdConf.Initialize(configDir, true)
	assert.Error(t, err)
	err = httpd.ReloadTLSCertificate()
	assert.NoError(t, err, "reloading TLS Certificate must return nil error if no certificate is configured")
	httpdConf = config.GetHTTPDConfig()
	httpdConf.BackupsPath = ".."
	err = httpdConf.Initialize(configDir, true)
	assert.Error(t, err)
	httpdConf.BackupsPath = backupsPath
	httpdConf.CertificateFile = invalidFile
	httpdConf.CertificateKeyFile = invalidFile
	httpdConf.StaticFilesPath = ""
	httpdConf.TemplatesPath = ""
	err = httpdConf.Initialize(configDir, true)
	assert.Error(t, err)
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
	u.HomeDir = "relative_path" //nolint:goconst
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
	u.FsConfig.S3Config.Bucket = "testbucket"
	u.FsConfig.S3Config.Region = "eu-west-1"
	u.FsConfig.S3Config.AccessKey = "access-key"
	u.FsConfig.S3Config.AccessSecret = "access-secret"
	u.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/path?a=b"
	u.FsConfig.S3Config.StorageClass = "Standard" //nolint:goconst
	u.FsConfig.S3Config.KeyPrefix = "/adir/subdir/"
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
	u.FsConfig.GCSConfig.Bucket = "abucket"
	u.FsConfig.GCSConfig.StorageClass = "Standard"
	u.FsConfig.GCSConfig.KeyPrefix = "/somedir/subdir/"
	u.FsConfig.GCSConfig.Credentials = base64.StdEncoding.EncodeToString([]byte("test"))
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.FsConfig.GCSConfig.KeyPrefix = "somedir/subdir/" //nolint:goconst
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
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "vdir",
	})
	_, _, err := httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "/",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(u.GetHomeDir(), "mapped_dir"),
		},
		VirtualPath: "/vdir",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: u.GetHomeDir(),
		},
		VirtualPath: "/vdir",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(u.GetHomeDir(), ".."),
		},
		VirtualPath: "/vdir",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "/vdir",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
		},
		VirtualPath: "/vdir",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "/vdir1",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "/vdir2",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir", "subdir"),
		},
		VirtualPath: "/vdir1",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "/vdir2",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir"),
		},
		VirtualPath: "/vdir1",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir", "subdir"),
		},
		VirtualPath: "/vdir2",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
		},
		VirtualPath: "/vdir1/subdir",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir2"),
		},
		VirtualPath: "/vdir1/../vdir1",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
		},
		VirtualPath: "/vdir1/",
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir2"),
		},
		VirtualPath: "/vdir1/subdir",
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
		},
		VirtualPath: "/vdir1/",
		QuotaSize:   -1,
		QuotaFiles:  1,
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
		},
		VirtualPath: "/vdir1/",
		QuotaSize:   1,
		QuotaFiles:  -1,
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
		},
		VirtualPath: "/vdir1/",
		QuotaSize:   -2,
		QuotaFiles:  0,
	})
	_, _, err = httpd.AddUser(u, http.StatusBadRequest)
	assert.NoError(t, err)
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped_dir1"),
		},
		VirtualPath: "/vdir1/",
		QuotaSize:   0,
		QuotaFiles:  -2,
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
	u := getTestUser()
	u.UsedQuotaFiles = 1
	u.UsedQuotaSize = 2
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPassword}
	user.Filters.FileExtensions = append(user.Filters.FileExtensions, dataprovider.ExtensionsFilter{
		Path:              "/subdir",
		AllowedExtensions: []string{".zip", ".rar"},
		DeniedExtensions:  []string{".jpg", ".png"},
	})
	user.UploadBandwidth = 1024
	user.DownloadBandwidth = 512
	user.VirtualFolders = nil
	mappedPath1 := filepath.Join(os.TempDir(), "mapped_dir1")
	mappedPath2 := filepath.Join(os.TempDir(), "mapped_dir2")
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1",
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: "/vdir12/subdir",
		QuotaSize:   123,
		QuotaFiles:  2,
	})
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	user.Permissions["/subdir"] = []string{}
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folder, 1) {
		f := folder[0]
		assert.Len(t, f.Users, 1)
		assert.Contains(t, f.Users, user.Username)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	// removing the user must remove folder mapping
	folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folder, 1) {
		f := folder[0]
		assert.Len(t, f.Users, 0)
		_, err = httpd.RemoveFolder(f, http.StatusOK)
		assert.NoError(t, err)
	}
	folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folder, 1) {
		f := folder[0]
		assert.Len(t, f.Users, 0)
		_, err = httpd.RemoveFolder(f, http.StatusOK)
		assert.NoError(t, err)
	}
}

func TestUpdateUserQuotaUsage(t *testing.T) {
	u := getTestUser()
	usedQuotaFiles := 1
	usedQuotaSize := int64(65535)
	u.UsedQuotaFiles = usedQuotaFiles
	u.UsedQuotaSize = usedQuotaSize
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.UpdateQuotaUsage(u, "invalid_mode", http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpd.UpdateQuotaUsage(u, "", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize, user.UsedQuotaSize)
	_, err = httpd.UpdateQuotaUsage(u, "add", http.StatusBadRequest)
	assert.NoError(t, err, "user has no quota restrictions add mode should fail")
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize, user.UsedQuotaSize)
	user.QuotaFiles = 100
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.UpdateQuotaUsage(u, "add", http.StatusOK)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 2*usedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, 2*usedQuotaSize, user.UsedQuotaSize)
	u.UsedQuotaFiles = -1
	_, err = httpd.UpdateQuotaUsage(u, "", http.StatusBadRequest)
	assert.NoError(t, err)
	u.UsedQuotaFiles = usedQuotaFiles
	u.Username = u.Username + "1"
	_, err = httpd.UpdateQuotaUsage(u, "", http.StatusNotFound)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserFolderMapping(t *testing.T) {
	mappedPath1 := filepath.Join(os.TempDir(), "mapped_dir1")
	mappedPath2 := filepath.Join(os.TempDir(), "mapped_dir2")
	u1 := getTestUser()
	u1.VirtualFolders = append(u1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath:     mappedPath1,
			UsedQuotaFiles: 2,
			UsedQuotaSize:  123,
		},
		VirtualPath: "/vdir",
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	user1, _, err := httpd.AddUser(u1, http.StatusOK)
	assert.NoError(t, err)
	// virtual folder must be auto created
	folders, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Len(t, folder.Users, 1)
		assert.Contains(t, folder.Users, user1.Username)
		assert.Equal(t, 0, folder.UsedQuotaFiles)
		assert.Equal(t, int64(0), folder.UsedQuotaSize)
	}
	u2 := getTestUser()
	u2.Username = defaultUsername + "2"
	u2.VirtualFolders = append(u2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1",
		QuotaSize:   0,
		QuotaFiles:  0,
	})
	u2.VirtualFolders = append(u2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: "/vdir2",
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	user2, _, err := httpd.AddUser(u2, http.StatusOK)
	assert.NoError(t, err)
	folders, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Len(t, folder.Users, 1)
		assert.Contains(t, folder.Users, user2.Username)
	}
	folders, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Len(t, folder.Users, 2)
		assert.Contains(t, folder.Users, user1.Username)
		assert.Contains(t, folder.Users, user2.Username)
	}
	// now update user2 removing mappedPath1
	user2.VirtualFolders = nil
	user2.VirtualFolders = append(user2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath:     mappedPath2,
			UsedQuotaFiles: 2,
			UsedQuotaSize:  123,
		},
		VirtualPath: "/vdir",
		QuotaSize:   0,
		QuotaFiles:  0,
	})
	user2, _, err = httpd.UpdateUser(user2, http.StatusOK)
	assert.NoError(t, err)
	folders, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Len(t, folder.Users, 1)
		assert.Contains(t, folder.Users, user2.Username)
		assert.Equal(t, 0, folder.UsedQuotaFiles)
		assert.Equal(t, int64(0), folder.UsedQuotaSize)
	}
	folders, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Len(t, folder.Users, 1)
		assert.Contains(t, folder.Users, user1.Username)
	}
	// add mappedPath1 again to user2
	user2.VirtualFolders = append(user2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: "/vdir1",
	})
	user2, _, err = httpd.UpdateUser(user2, http.StatusOK)
	assert.NoError(t, err)
	folders, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Len(t, folder.Users, 1)
		assert.Contains(t, folder.Users, user2.Username)
	}
	// removing virtual folders should clear relations on both side
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
	assert.NoError(t, err)
	user2, _, err = httpd.GetUserByID(user2.ID, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, user2.VirtualFolders, 1) {
		folder := user2.VirtualFolders[0]
		assert.Equal(t, mappedPath1, folder.MappedPath)
	}
	user1, _, err = httpd.GetUserByID(user1.ID, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, user2.VirtualFolders, 1) {
		folder := user2.VirtualFolders[0]
		assert.Equal(t, mappedPath1, folder.MappedPath)
	}

	folders, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Len(t, folder.Users, 2)
	}
	// removing a user should clear virtual folder mapping
	_, err = httpd.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	folders, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Len(t, folder.Users, 1)
		assert.Contains(t, folder.Users, user2.Username)
	}
	// removing a folder should clear mapping on the user side too
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	user2, _, err = httpd.GetUserByID(user2.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user2.VirtualFolders, 0)
	_, err = httpd.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserS3Config(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	user.FsConfig.Provider = 1
	user.FsConfig.S3Config.Bucket = "test"      //nolint:goconst
	user.FsConfig.S3Config.Region = "us-east-1" //nolint:goconst
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
	user.FsConfig.S3Config.Bucket = "test-bucket"
	user.FsConfig.S3Config.Region = "us-east-1" //nolint:goconst
	user.FsConfig.S3Config.AccessKey = "Server-Access-Key1"
	user.FsConfig.S3Config.Endpoint = "http://localhost:9000"
	user.FsConfig.S3Config.KeyPrefix = "somedir/subdir" //nolint:goconst
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
	user.FsConfig.S3Config.Bucket = "testbucket"
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
	assert.Error(t, err)
	_, _, err = httpd.GetFoldersQuotaScans(http.StatusOK)
	assert.NoError(t, err)
	_, _, err = httpd.GetFoldersQuotaScans(http.StatusInternalServerError)
	assert.Error(t, err)
}

func TestStartQuotaScan(t *testing.T) {
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.StartQuotaScan(user, http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	folder := vfs.BaseVirtualFolder{
		MappedPath: filepath.Join(os.TempDir(), "folder"),
	}
	_, _, err = httpd.AddFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.StartFolderQuotaScan(folder, http.StatusCreated)
	assert.NoError(t, err)
	for {
		quotaScan, _, err := httpd.GetFoldersQuotaScans(http.StatusOK)
		if !assert.NoError(t, err, "Error getting active scans") {
			break
		}
		if len(quotaScan) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, err = httpd.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
}

func TestUpdateFolderQuotaUsage(t *testing.T) {
	f := vfs.BaseVirtualFolder{
		MappedPath: filepath.Join(os.TempDir(), "folder"),
	}
	usedQuotaFiles := 1
	usedQuotaSize := int64(65535)
	f.UsedQuotaFiles = usedQuotaFiles
	f.UsedQuotaSize = usedQuotaSize
	folder, _, err := httpd.AddFolder(f, http.StatusOK)
	if assert.NoError(t, err) {
		assert.Equal(t, usedQuotaFiles, folder.UsedQuotaFiles)
		assert.Equal(t, usedQuotaSize, folder.UsedQuotaSize)
	}
	_, err = httpd.UpdateFolderQuotaUsage(folder, "invalid mode", http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpd.UpdateFolderQuotaUsage(f, "reset", http.StatusOK)
	assert.NoError(t, err)
	folders, _, err := httpd.GetFolders(0, 0, f.MappedPath, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder = folders[0]
		assert.Equal(t, usedQuotaFiles, folder.UsedQuotaFiles)
		assert.Equal(t, usedQuotaSize, folder.UsedQuotaSize)
	}
	_, err = httpd.UpdateFolderQuotaUsage(f, "add", http.StatusOK)
	assert.NoError(t, err)
	folders, _, err = httpd.GetFolders(0, 0, f.MappedPath, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder = folders[0]
		assert.Equal(t, 2*usedQuotaFiles, folder.UsedQuotaFiles)
		assert.Equal(t, 2*usedQuotaSize, folder.UsedQuotaSize)
	}
	f.UsedQuotaSize = -1
	_, err = httpd.UpdateFolderQuotaUsage(f, "", http.StatusBadRequest)
	assert.NoError(t, err)
	f.UsedQuotaSize = usedQuotaSize
	f.MappedPath = f.MappedPath + "1"
	_, err = httpd.UpdateFolderQuotaUsage(f, "", http.StatusNotFound)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(folder, http.StatusOK)
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
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.UsersBaseDir = homeBasePath
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	u := getTestUser()
	u.HomeDir = ""
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if assert.Error(t, err) {
		assert.EqualError(t, err, "HomeDir mismatch")
	}
	assert.Equal(t, filepath.Join(providerConf.UsersBaseDir, u.Username), user.HomeDir)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
}

func TestQuotaTrackingDisabled(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.TrackQuota = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	// user quota scan must fail
	user, _, err := httpd.AddUser(getTestUser(), http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.StartQuotaScan(user, http.StatusForbidden)
	assert.NoError(t, err)
	_, err = httpd.UpdateQuotaUsage(user, "", http.StatusForbidden)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	// folder quota scan must fail
	folder := vfs.BaseVirtualFolder{
		MappedPath: filepath.Clean(os.TempDir()),
	}
	folder, _, err = httpd.AddFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.StartFolderQuotaScan(folder, http.StatusForbidden)
	assert.NoError(t, err)
	_, err = httpd.UpdateFolderQuotaUsage(folder, "", http.StatusForbidden)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
}

func TestProviderErrors(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	_, _, err = httpd.GetUserByID(0, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.GetUsers(1, 0, defaultUsername, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.UpdateUser(dataprovider.User{}, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(dataprovider.User{}, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: "apath"}, http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.GetProviderStatus(http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.Dumpdata("backup.json", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	_, _, err = httpd.GetFolders(0, 0, "", http.StatusInternalServerError)
	assert.NoError(t, err)
	user := getTestUser()
	user.ID = 1
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupContent, err := json.Marshal(backupData)
	assert.NoError(t, err)
	backupFilePath := filepath.Join(backupsPath, "backup.json")
	err = ioutil.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
	_, _, err = httpd.Loaddata(backupFilePath, "", "", http.StatusInternalServerError)
	assert.NoError(t, err)
	backupData.Folders = append(backupData.Folders, vfs.BaseVirtualFolder{MappedPath: os.TempDir()})
	backupContent, err = json.Marshal(backupData)
	assert.NoError(t, err)
	err = ioutil.WriteFile(backupFilePath, backupContent, os.ModePerm)
	assert.NoError(t, err)
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
}

func TestFolders(t *testing.T) {
	folder := vfs.BaseVirtualFolder{
		MappedPath: "relative path",
	}
	_, _, err := httpd.AddFolder(folder, http.StatusBadRequest)
	assert.NoError(t, err)
	folder.MappedPath = filepath.Clean(os.TempDir())
	folder1, _, err := httpd.AddFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, folder.MappedPath, folder1.MappedPath)
	assert.Equal(t, 0, folder1.UsedQuotaFiles)
	assert.Equal(t, int64(0), folder1.UsedQuotaSize)
	assert.Equal(t, int64(0), folder1.LastQuotaUpdate)
	// adding a duplicate folder must fail
	_, _, err = httpd.AddFolder(folder, http.StatusOK)
	assert.Error(t, err)
	folder.MappedPath = filepath.Join(os.TempDir(), "vfolder")
	folder.UsedQuotaFiles = 1
	folder.UsedQuotaSize = 345
	folder.LastQuotaUpdate = 10
	folder2, _, err := httpd.AddFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, folder2.UsedQuotaFiles)
	assert.Equal(t, int64(345), folder2.UsedQuotaSize)
	assert.Equal(t, int64(10), folder2.LastQuotaUpdate)
	folders, _, err := httpd.GetFolders(0, 0, "", http.StatusOK)
	assert.NoError(t, err)
	numResults := len(folders)
	assert.GreaterOrEqual(t, numResults, 2)
	folders, _, err = httpd.GetFolders(0, 1, "", http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folders, numResults-1)
	folders, _, err = httpd.GetFolders(1, 0, "", http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, folders, 1)
	folders, _, err = httpd.GetFolders(0, 0, folder1.MappedPath, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		f := folders[0]
		assert.Equal(t, folder1.MappedPath, f.MappedPath)
	}
	folders, _, err = httpd.GetFolders(0, 0, folder2.MappedPath, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		f := folders[0]
		assert.Equal(t, folder2.MappedPath, f.MappedPath)
	}
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{}, http.StatusBadRequest)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{
		MappedPath: "invalid",
	}, http.StatusNotFound)
	assert.NoError(t, err)

	_, err = httpd.RemoveFolder(folder1, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(folder2, http.StatusOK)
	assert.NoError(t, err)
}

func TestDumpdata(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
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
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
}

func TestLoaddata(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "restored_folder")
	user := getTestUser()
	user.ID = 1
	user.Username = "test_user_restore"
	backupData := dataprovider.BackupData{}
	backupData.Users = append(backupData.Users, user)
	backupData.Folders = []vfs.BaseVirtualFolder{
		{
			MappedPath:      mappedPath,
			UsedQuotaSize:   123,
			UsedQuotaFiles:  456,
			LastQuotaUpdate: 789,
			Users:           []string{"user"},
		},
		{
			MappedPath: mappedPath,
		},
	}
	backupContent, err := json.Marshal(backupData)
	assert.NoError(t, err)
	backupFilePath := filepath.Join(backupsPath, "backup.json")
	err = ioutil.WriteFile(backupFilePath, backupContent, os.ModePerm)
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
	// add user and folder from backup
	_, _, err = httpd.Loaddata(backupFilePath, "1", "", http.StatusOK)
	assert.NoError(t, err)
	// update user from backup
	_, _, err = httpd.Loaddata(backupFilePath, "2", "", http.StatusOK)
	assert.NoError(t, err)
	users, _, err := httpd.GetUsers(1, 0, user.Username, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, users, 1) {
		user = users[0]
		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
	}
	folders, _, err := httpd.GetFolders(1, 0, mappedPath, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Equal(t, mappedPath, folder.MappedPath)
		assert.Equal(t, int64(123), folder.UsedQuotaSize)
		assert.Equal(t, 456, folder.UsedQuotaFiles)
		assert.Equal(t, int64(789), folder.LastQuotaUpdate)
		assert.Len(t, folder.Users, 0)
		_, err = httpd.RemoveFolder(folder, http.StatusOK)
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
	err := ioutil.WriteFile(backupFilePath, backupContent, os.ModePerm)
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
	resp, err := client.Get("https://localhost:8443" + metricsPath)
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

func TestAddFolderInvalidJsonMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer([]byte("invalid json")))
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

func TestUpdateUserQuotaUsageMock(t *testing.T) {
	var user dataprovider.User
	u := getTestUser()
	usedQuotaFiles := 1
	usedQuotaSize := int64(65535)
	u.UsedQuotaFiles = usedQuotaFiles
	u.UsedQuotaSize = usedQuotaSize
	userAsJSON := getUserAsJSON(t, u)
	req, _ := http.NewRequest(http.MethodPost, userPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err := render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, updateUsedQuotaPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &user)
	assert.NoError(t, err)
	assert.Equal(t, usedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, usedQuotaSize, user.UsedQuotaSize)
	req, _ = http.NewRequest(http.MethodPut, updateUsedQuotaPath, bytes.NewBuffer([]byte("string")))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	assert.True(t, common.QuotaScans.AddUserQuotaScan(user.Username))
	req, _ = http.NewRequest(http.MethodPut, updateUsedQuotaPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr.Code)
	assert.True(t, common.QuotaScans.RemoveUserQuotaScan(user.Username))
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
	common.QuotaScans.AddUserQuotaScan(user.Username)
	req, _ = http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr.Code)
	assert.True(t, common.QuotaScans.RemoveUserQuotaScan(user.Username))

	userAsJSON = getUserAsJSON(t, user)
	req, _ = http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr.Code)

	for {
		var scans []common.ActiveQuotaScan
		req, _ = http.NewRequest(http.MethodGet, quotaScanPath, nil)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr.Code)
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
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr.Code)

	for {
		var scans []common.ActiveQuotaScan
		req, _ = http.NewRequest(http.MethodGet, quotaScanPath, nil)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr.Code)
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

	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUpdateFolderQuotaUsageMock(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "vfolder")
	f := vfs.BaseVirtualFolder{
		MappedPath: mappedPath,
	}
	usedQuotaFiles := 1
	usedQuotaSize := int64(65535)
	f.UsedQuotaFiles = usedQuotaFiles
	f.UsedQuotaSize = usedQuotaSize
	var folder vfs.BaseVirtualFolder
	folderAsJSON, err := json.Marshal(f)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &folder)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, updateFolderUsedQuotaPath, bytes.NewBuffer(folderAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)

	var folders []vfs.BaseVirtualFolder
	url, err := url.Parse(folderPath)
	assert.NoError(t, err)
	q := url.Query()
	q.Add("folder_path", mappedPath)
	url.RawQuery = q.Encode()
	req, _ = http.NewRequest(http.MethodGet, url.String(), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &folders)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder = folders[0]
		assert.Equal(t, usedQuotaFiles, folder.UsedQuotaFiles)
		assert.Equal(t, usedQuotaSize, folder.UsedQuotaSize)
	}

	req, _ = http.NewRequest(http.MethodPut, updateFolderUsedQuotaPath, bytes.NewBuffer([]byte("string")))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)

	assert.True(t, common.QuotaScans.AddVFolderQuotaScan(mappedPath))
	req, _ = http.NewRequest(http.MethodPut, updateFolderUsedQuotaPath, bytes.NewBuffer(folderAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr.Code)
	assert.True(t, common.QuotaScans.RemoveVFolderQuotaScan(mappedPath))

	url, err = url.Parse(folderPath)
	assert.NoError(t, err)
	q = url.Query()
	q.Add("folder_path", mappedPath)
	url.RawQuery = q.Encode()
	req, _ = http.NewRequest(http.MethodDelete, url.String(), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestStartFolderQuotaScanMock(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "vfolder")
	folder := vfs.BaseVirtualFolder{
		MappedPath: mappedPath,
	}
	folderAsJSON, err := json.Marshal(folder)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	_, err = os.Stat(mappedPath)
	if err == nil {
		err = os.Remove(mappedPath)
		assert.NoError(t, err)
	}
	// simulate a duplicate quota scan
	common.QuotaScans.AddVFolderQuotaScan(mappedPath)
	req, _ = http.NewRequest(http.MethodPost, quotaScanVFolderPath, bytes.NewBuffer(folderAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusConflict, rr.Code)
	assert.True(t, common.QuotaScans.RemoveVFolderQuotaScan(mappedPath))
	// and now a real quota scan
	_, err = os.Stat(mappedPath)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(mappedPath, os.ModePerm)
		assert.NoError(t, err)
	}
	req, _ = http.NewRequest(http.MethodPost, quotaScanVFolderPath, bytes.NewBuffer(folderAsJSON))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusCreated, rr.Code)
	var scans []common.ActiveVirtualFolderQuotaScan
	for {
		req, _ = http.NewRequest(http.MethodGet, quotaScanVFolderPath, nil)
		rr = executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr.Code)
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
	url, err := url.Parse(folderPath)
	assert.NoError(t, err)
	q := url.Query()
	q.Add("folder_path", mappedPath)
	url.RawQuery = q.Encode()
	req, _ = http.NewRequest(http.MethodDelete, url.String(), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = os.RemoveAll(folderPath)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestStartQuotaScanNonExistentUserMock(t *testing.T) {
	user := getTestUser()
	userAsJSON := getUserAsJSON(t, user)
	req, _ := http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer(userAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
}

func TestStartQuotaScanBadUserMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, quotaScanPath, bytes.NewBuffer([]byte("invalid json")))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestStartQuotaScanBadFolderMock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, quotaScanVFolderPath, bytes.NewBuffer([]byte("invalid json")))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
}

func TestStartQuotaScanNonExistentFolderMock(t *testing.T) {
	folder := vfs.BaseVirtualFolder{
		MappedPath: os.TempDir(),
	}
	folderAsJSON, err := json.Marshal(folder)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, quotaScanVFolderPath, bytes.NewBuffer(folderAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusNotFound, rr.Code)
}

func TestGetFoldersMock(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "vfolder")
	folder := vfs.BaseVirtualFolder{
		MappedPath: mappedPath,
	}
	folderAsJSON, err := json.Marshal(folder)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &folder)
	assert.NoError(t, err)

	var folders []vfs.BaseVirtualFolder
	url, err := url.Parse(folderPath + "?limit=510&offset=0&order=DESC")
	assert.NoError(t, err)
	q := url.Query()
	q.Add("folder_path", mappedPath)
	url.RawQuery = q.Encode()
	req, _ = http.NewRequest(http.MethodGet, url.String(), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &folders)
	assert.NoError(t, err)
	assert.Len(t, folders, 1)
	req, _ = http.NewRequest(http.MethodGet, folderPath+"?limit=a&offset=0&order=ASC", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, folderPath+"?limit=1&offset=a&order=ASC", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, folderPath+"?limit=1&offset=0&order=ASCa", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr.Code)

	url, err = url.Parse(folderPath)
	assert.NoError(t, err)
	q = url.Query()
	q.Add("folder_path", mappedPath)
	url.RawQuery = q.Encode()
	req, _ = http.NewRequest(http.MethodDelete, url.String(), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
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
	form.Set("virtual_folders", fmt.Sprintf(" /vdir:: %v :: 2 :: 1024", mappedDir))
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
	err := render.DecodeJSON(rr.Body, &users)
	assert.NoError(t, err)
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
	assert.Len(t, newUser.VirtualFolders, 1)
	for _, v := range newUser.VirtualFolders {
		assert.Equal(t, v.VirtualPath, "/vdir")
		assert.Equal(t, v.MappedPath, mappedDir)
		assert.Equal(t, v.QuotaFiles, 2)
		assert.Equal(t, v.QuotaSize, int64(1024))
	}
	extFilters := newUser.Filters.FileExtensions[0]
	assert.True(t, utils.IsStringInSlice(".zip", extFilters.DeniedExtensions))
	req, _ = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(newUser.ID, 10), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	url, err := url.Parse(folderPath)
	assert.NoError(t, err)
	q := url.Query()
	q.Add("folder_path", mappedDir)
	url.RawQuery = q.Encode()
	req, _ = http.NewRequest(http.MethodDelete, url.String(), nil)
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
	err = render.DecodeJSON(rr.Body, &users)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	updateUser := users[0]
	assert.Equal(t, user.HomeDir, updateUser.HomeDir)
	assert.Equal(t, user.MaxSessions, updateUser.MaxSessions)
	assert.Equal(t, user.QuotaFiles, updateUser.QuotaFiles)
	assert.Equal(t, user.QuotaSize, updateUser.QuotaSize)
	assert.Equal(t, user.UID, updateUser.UID)
	assert.Equal(t, user.GID, updateUser.GID)

	if val, ok := updateUser.Permissions["/otherdir"]; ok {
		assert.True(t, utils.IsStringInSlice(dataprovider.PermListItems, val))
		assert.True(t, utils.IsStringInSlice(dataprovider.PermUpload, val))
	} else {
		assert.Fail(t, "user permissions must contains /otherdir", "actual: %v", updateUser.Permissions)
	}
	assert.True(t, utils.IsStringInSlice("192.168.1.3/32", updateUser.Filters.AllowedIP))
	assert.True(t, utils.IsStringInSlice("10.0.0.2/32", updateUser.Filters.DeniedIP))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, updateUser.Filters.DeniedLoginMethods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, updateUser.Filters.DeniedLoginMethods))
	assert.True(t, utils.IsStringInSlice(".zip", updateUser.Filters.FileExtensions[0].DeniedExtensions))
	req, err = http.NewRequest(http.MethodDelete, userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	assert.NoError(t, err)
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
	err = render.DecodeJSON(rr.Body, &users)
	assert.NoError(t, err)
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

func TestAddWebFoldersMock(t *testing.T) {
	mappedPath := filepath.Clean(os.TempDir())
	form := make(url.Values)
	form.Set("mapped_path", mappedPath)
	req, err := http.NewRequest(http.MethodPost, webFolderPath, strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusSeeOther, rr.Code)
	// adding the same folder will fail since the path must be unique
	req, err = http.NewRequest(http.MethodPost, webFolderPath, strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	// invalid form
	req, err = http.NewRequest(http.MethodPost, webFolderPath, strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain; boundary=")
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)

	// now render the add folder page
	req, err = http.NewRequest(http.MethodGet, webFolderPath, nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)

	var folders []vfs.BaseVirtualFolder
	url, err := url.Parse(folderPath)
	assert.NoError(t, err)
	q := url.Query()
	q.Add("folder_path", mappedPath)
	url.RawQuery = q.Encode()
	req, _ = http.NewRequest(http.MethodGet, url.String(), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	err = render.DecodeJSON(rr.Body, &folders)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder := folders[0]
		assert.Equal(t, mappedPath, folder.MappedPath)
	}
	// cleanup
	url, err = url.Parse(folderPath)
	assert.NoError(t, err)
	q = url.Query()
	q.Add("folder_path", mappedPath)
	url.RawQuery = q.Encode()
	req, _ = http.NewRequest(http.MethodDelete, url.String(), nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
}

func TestWebFoldersMock(t *testing.T) {
	mappedPath1 := filepath.Join(os.TempDir(), "vfolder1")
	mappedPath2 := filepath.Join(os.TempDir(), "vfolder2")
	folders := []vfs.BaseVirtualFolder{
		{
			MappedPath: mappedPath1,
		},
		{
			MappedPath: mappedPath2,
		},
	}
	for _, folder := range folders {
		folderAsJSON, err := json.Marshal(folder)
		assert.NoError(t, err)
		req, _ := http.NewRequest(http.MethodPost, folderPath, bytes.NewBuffer(folderAsJSON))
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr.Code)
	}

	req, err := http.NewRequest(http.MethodGet, webFoldersPath, nil)
	assert.NoError(t, err)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, err = http.NewRequest(http.MethodGet, webFoldersPath+"?qlimit=a", nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)
	req, err = http.NewRequest(http.MethodGet, webFoldersPath+"?qlimit=1", nil)
	assert.NoError(t, err)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusOK, rr.Code)

	for _, folder := range folders {
		url, err := url.Parse(folderPath)
		assert.NoError(t, err)
		q := url.Query()
		q.Add("folder_path", folder.MappedPath)
		url.RawQuery = q.Encode()
		req, _ := http.NewRequest(http.MethodDelete, url.String(), nil)
		rr := executeRequest(req)
		checkResponseCode(t, http.StatusOK, rr.Code)
	}
}

func TestProviderClosedMock(t *testing.T) {
	dataprovider.Close()
	req, _ := http.NewRequest(http.MethodGet, webFoldersPath, nil)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUsersPath, nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr.Code)
	req, _ = http.NewRequest(http.MethodGet, webUserPath+"/0", nil)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr.Code)
	form := make(url.Values)
	form.Set("username", "test")
	req, _ = http.NewRequest(http.MethodPost, webUserPath+"/0", strings.NewReader(form.Encode()))
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusInternalServerError, rr.Code)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = credentialsPath
	err = os.RemoveAll(credentialsPath)
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
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
		conn.Close()
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
	return ioutil.WriteFile(path, content, os.ModePerm)
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
