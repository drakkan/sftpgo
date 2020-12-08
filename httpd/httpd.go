// Package httpd implements REST API and Web interface for SFTPGo.
// REST API allows to manage users and quota and to get real time reports for the active connections
// with possibility of forcibly closing a connection.
// The OpenAPI 3 schema for the exposed API can be found inside the source tree:
// https://github.com/drakkan/sftpgo/tree/master/api/schema/openapi.yaml
// A basic Web interface to manage users and connections is provided too
package httpd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/go-chi/chi"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/ftpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/webdavd"
)

const (
	logSender                 = "httpd"
	apiPrefix                 = "/api/v1"
	activeConnectionsPath     = "/api/v1/connection"
	quotaScanPath             = "/api/v1/quota_scan"
	quotaScanVFolderPath      = "/api/v1/folder_quota_scan"
	userPath                  = "/api/v1/user"
	versionPath               = "/api/v1/version"
	folderPath                = "/api/v1/folder"
	serverStatusPath          = "/api/v1/status"
	dumpDataPath              = "/api/v1/dumpdata"
	loadDataPath              = "/api/v1/loaddata"
	updateUsedQuotaPath       = "/api/v1/quota_update"
	updateFolderUsedQuotaPath = "/api/v1/folder_quota_update"
	metricsPath               = "/metrics"
	pprofBasePath             = "/debug"
	webBasePath               = "/web"
	webUsersPath              = "/web/users"
	webUserPath               = "/web/user"
	webConnectionsPath        = "/web/connections"
	webFoldersPath            = "/web/folders"
	webFolderPath             = "/web/folder"
	webStatusPath             = "/web/status"
	webStaticFilesPath        = "/static"
	// MaxRestoreSize defines the max size for the loaddata input file
	MaxRestoreSize = 10485760 // 10 MB
	maxRequestSize = 1048576  // 1MB
)

var (
	router      *chi.Mux
	backupsPath string
	httpAuth    httpAuthProvider
	certMgr     *common.CertManager
)

// ServicesStatus keep the state of the running services
type ServicesStatus struct {
	SSH          sftpd.ServiceStatus         `json:"ssh"`
	FTP          ftpd.ServiceStatus          `json:"ftp"`
	WebDAV       webdavd.ServiceStatus       `json:"webdav"`
	DataProvider dataprovider.ProviderStatus `json:"data_provider"`
}

// Conf httpd daemon configuration
type Conf struct {
	// The port used for serving HTTP requests. 0 disable the HTTP server. Default: 8080
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces. Default: "127.0.0.1"
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
	TemplatesPath string `json:"templates_path" mapstructure:"templates_path"`
	// Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir.
	// If both TemplatesPath and StaticFilesPath are empty the built-in web interface will be disabled
	StaticFilesPath string `json:"static_files_path" mapstructure:"static_files_path"`
	// Path to the backup directory. This can be an absolute path or a path relative to the config dir
	BackupsPath string `json:"backups_path" mapstructure:"backups_path"`
	// Path to a file used to store usernames and password for basic authentication.
	// This can be an absolute path or a path relative to the config dir.
	// We support HTTP basic authentication and the file format must conform to the one generated using the Apache
	// htpasswd tool. The supported password formats are bcrypt ($2y$ prefix) and md5 crypt ($apr1$ prefix).
	// If empty HTTP authentication is disabled
	AuthUserFile string `json:"auth_user_file" mapstructure:"auth_user_file"`
	// If files containing a certificate and matching private key for the server are provided the server will expect
	// HTTPS connections.
	// Certificate and key files can be reloaded on demand sending a "SIGHUP" signal on Unix based systems and a
	// "paramchange" request to the running service on Windows.
	CertificateFile    string `json:"certificate_file" mapstructure:"certificate_file"`
	CertificateKeyFile string `json:"certificate_key_file" mapstructure:"certificate_key_file"`
}

type apiResponse struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message"`
}

// Initialize configures and starts the HTTP server
func (c Conf) Initialize(configDir string, enableProfiler bool) error {
	var err error
	logger.Debug(logSender, "", "initializing HTTP server with config %+v", c)
	backupsPath = getConfigPath(c.BackupsPath, configDir)
	staticFilesPath := getConfigPath(c.StaticFilesPath, configDir)
	templatesPath := getConfigPath(c.TemplatesPath, configDir)
	enableWebAdmin := len(staticFilesPath) > 0 || len(templatesPath) > 0
	if len(backupsPath) == 0 {
		return fmt.Errorf("Required directory is invalid, backup path %#v", backupsPath)
	}
	if enableWebAdmin && (len(staticFilesPath) == 0 || len(templatesPath) == 0) {
		return fmt.Errorf("Required directory is invalid, static file path: %#v template path: %#v",
			staticFilesPath, templatesPath)
	}
	authUserFile := getConfigPath(c.AuthUserFile, configDir)
	httpAuth, err = newBasicAuthProvider(authUserFile)
	if err != nil {
		return err
	}
	certificateFile := getConfigPath(c.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(c.CertificateKeyFile, configDir)
	if enableWebAdmin {
		loadTemplates(templatesPath)
	} else {
		logger.Info(logSender, "", "built-in web interface disabled, please set templates_path and static_files_path to enable it")
	}
	initializeRouter(staticFilesPath, enableProfiler, enableWebAdmin)
	httpServer := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort),
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64KB
	}
	if len(certificateFile) > 0 && len(certificateKeyFile) > 0 {
		certMgr, err = common.NewCertManager(certificateFile, certificateKeyFile, logSender)
		if err != nil {
			return err
		}
		config := &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(),
			MinVersion:     tls.VersionTLS12,
		}
		httpServer.TLSConfig = config
		return httpServer.ListenAndServeTLS("", "")
	}
	return httpServer.ListenAndServe()
}

// ReloadTLSCertificate reloads the TLS certificate and key from the configured paths
func ReloadTLSCertificate() error {
	if certMgr != nil {
		return certMgr.LoadCertificate(logSender)
	}
	return nil
}

func getConfigPath(name, configDir string) string {
	if !utils.IsFileInputValid(name) {
		return ""
	}
	if len(name) > 0 && !filepath.IsAbs(name) {
		return filepath.Join(configDir, name)
	}
	return name
}

func getServicesStatus() ServicesStatus {
	status := ServicesStatus{
		SSH:          sftpd.GetStatus(),
		FTP:          ftpd.GetStatus(),
		WebDAV:       webdavd.GetStatus(),
		DataProvider: dataprovider.GetProviderStatus(),
	}
	return status
}
