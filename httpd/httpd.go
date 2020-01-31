// Package httpd implements REST API and Web interface for SFTPGo.
// REST API allows to manage users and quota and to get real time reports for the active connections
// with possibility of forcibly closing a connection.
// The OpenAPI 3 schema for the exposed API can be found inside the source tree:
// https://github.com/drakkan/sftpgo/tree/master/api/schema/openapi.yaml
// A basic Web interface to manage users and connections is provided too
package httpd

import (
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
}

// BackupData defines the structure for the backup/restore files
type BackupData struct {
	Users []dataprovider.User `json:"users"`
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
	logger.Debug(logSender, "", "initializing HTTP server with config %+v", c)
	backupsPath = c.BackupsPath
	if !filepath.IsAbs(backupsPath) {
		backupsPath = filepath.Join(configDir, backupsPath)
	}
	staticFilesPath := c.StaticFilesPath
	if !filepath.IsAbs(staticFilesPath) {
		staticFilesPath = filepath.Join(configDir, staticFilesPath)
	}
	templatesPath := c.TemplatesPath
	if !filepath.IsAbs(templatesPath) {
		templatesPath = filepath.Join(configDir, templatesPath)
	}
	loadTemplates(templatesPath)
	initializeRouter(staticFilesPath)
	httpServer := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort),
		Handler:        router,
		ReadTimeout:    300 * time.Second,
		WriteTimeout:   300 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64KB
	}
	return httpServer.ListenAndServe()
}
