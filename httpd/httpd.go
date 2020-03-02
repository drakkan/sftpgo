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

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/go-chi/chi"
)

const (
	logSender             = "httpd"
	apiPrefix             = "/api/v1"
	activeConnectionsPath = "/api/v1/connection"
	quotaScanPath         = "/api/v1/quota_scan"
	userPath              = "/api/v1/user"
	versionPath           = "/api/v1/version"
	providerStatusPath    = "/api/v1/providerstatus"
	dumpDataPath          = "/api/v1/dumpdata"
	loadDataPath          = "/api/v1/loaddata"
	metricsPath           = "/metrics"
	webBasePath           = "/web"
	webUsersPath          = "/web/users"
	webUserPath           = "/web/user"
	webConnectionsPath    = "/web/connections"
	webStaticFilesPath    = "/static"
	maxRestoreSize        = 10485760 // 10 MB
	maxRequestSize        = 1048576  // 1MB
)

var (
	router       *chi.Mux
	dataProvider dataprovider.Provider
	backupsPath  string
	httpAuth     httpAuthProvider
	certMgr      *certManager
)

// Conf httpd daemon configuration
type Conf struct {
	// The port used for serving HTTP requests. 0 disable the HTTP server. Default: 8080
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces. Default: "127.0.0.1"
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
	TemplatesPath string `json:"templates_path" mapstructure:"templates_path"`
	// Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir
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
	Error      string `json:"error"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"status"`
}

// SetDataProvider sets the data provider to use to fetch the data about users
func SetDataProvider(provider dataprovider.Provider) {
	dataProvider = provider
}

// Initialize the HTTP server
func (c Conf) Initialize(configDir string) error {
	var err error
	logger.Debug(logSender, "", "initializing HTTP server with config %+v", c)
	backupsPath = getConfigPath(c.BackupsPath, configDir)
	staticFilesPath := getConfigPath(c.StaticFilesPath, configDir)
	templatesPath := getConfigPath(c.TemplatesPath, configDir)
	authUserFile := getConfigPath(c.AuthUserFile, configDir)
	httpAuth, err = newBasicAuthProvider(authUserFile)
	if err != nil {
		return err
	}
	certificateFile := getConfigPath(c.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(c.CertificateKeyFile, configDir)
	loadTemplates(templatesPath)
	initializeRouter(staticFilesPath)
	httpServer := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort),
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64KB
	}
	if len(certificateFile) > 0 && len(certificateKeyFile) > 0 {
		certMgr, err = newCertManager(certificateFile, certificateKeyFile)
		if err != nil {
			return err
		}
		config := &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(),
		}
		httpServer.TLSConfig = config
		return httpServer.ListenAndServeTLS("", "")
	}
	return httpServer.ListenAndServe()
}

// ReloadTLSCertificate reloads the TLS certificate and key from the configured paths
func ReloadTLSCertificate() {
	if certMgr != nil {
		certMgr.loadCertificate()
	}
}

func getConfigPath(name, configDir string) string {
	if len(name) > 0 && !filepath.IsAbs(name) && name != "." {
		return filepath.Join(configDir, name)
	}
	return name
}
