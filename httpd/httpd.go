// Package httpd implements REST API and Web interface for SFTPGo.
// The OpenAPI 3 schema for the exposed API can be found inside the source tree:
// https://github.com/drakkan/sftpgo/blob/main/httpd/schema/openapi.yaml
// A basic Web interface to manage users and connections is provided too
package httpd

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"

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
	tokenPath                 = "/api/v2/token"
	logoutPath                = "/api/v2/logout"
	activeConnectionsPath     = "/api/v2/connections"
	quotaScanPath             = "/api/v2/quota-scans"
	quotaScanVFolderPath      = "/api/v2/folder-quota-scans"
	userPath                  = "/api/v2/users"
	versionPath               = "/api/v2/version"
	folderPath                = "/api/v2/folders"
	serverStatusPath          = "/api/v2/status"
	dumpDataPath              = "/api/v2/dumpdata"
	loadDataPath              = "/api/v2/loaddata"
	updateUsedQuotaPath       = "/api/v2/quota-update"
	updateFolderUsedQuotaPath = "/api/v2/folder-quota-update"
	defenderBanTime           = "/api/v2/defender/bantime"
	defenderUnban             = "/api/v2/defender/unban"
	defenderScore             = "/api/v2/defender/score"
	adminPath                 = "/api/v2/admins"
	adminPwdPath              = "/api/v2/changepwd/admin"
	healthzPath               = "/healthz"
	webBasePath               = "/web"
	webLoginPath              = "/web/login"
	webLogoutPath             = "/web/logout"
	webUsersPath              = "/web/users"
	webUserPath               = "/web/user"
	webConnectionsPath        = "/web/connections"
	webFoldersPath            = "/web/folders"
	webFolderPath             = "/web/folder"
	webStatusPath             = "/web/status"
	webAdminsPath             = "/web/admins"
	webAdminPath              = "/web/admin"
	webMaintenancePath        = "/web/maintenance"
	webBackupPath             = "/web/backup"
	webRestorePath            = "/web/restore"
	webScanVFolderPath        = "/web/folder-quota-scans"
	webQuotaScanPath          = "/web/quota-scans"
	webChangeAdminPwdPath     = "/web/changepwd/admin"
	webTemplateUser           = "/web/template/user"
	webTemplateFolder         = "/web/template/folder"
	webStaticFilesPath        = "/static"
	// MaxRestoreSize defines the max size for the loaddata input file
	MaxRestoreSize = 10485760 // 10 MB
	maxRequestSize = 1048576  // 1MB
	osWindows      = "windows"
)

var (
	backupsPath            string
	certMgr                *common.CertManager
	jwtTokensCleanupTicker *time.Ticker
	jwtTokensCleanupDone   chan bool
	invalidatedJWTTokens   sync.Map
	csrfTokenAuth          *jwtauth.JWTAuth
)

// Binding defines the configuration for a network listener
type Binding struct {
	// The address to listen on. A blank value means listen on all available network interfaces.
	Address string `json:"address" mapstructure:"address"`
	// The port used for serving requests
	Port int `json:"port" mapstructure:"port"`
	// Enable the built-in admin interface.
	// You have to define TemplatesPath and StaticFilesPath for this to work
	EnableWebAdmin bool `json:"enable_web_admin" mapstructure:"enable_web_admin"`
	// you also need to provide a certificate for enabling HTTPS
	EnableHTTPS bool `json:"enable_https" mapstructure:"enable_https"`
	// set to 1 to require client certificate authentication in addition to basic auth.
	// You need to define at least a certificate authority for this to work
	ClientAuthType int `json:"client_auth_type" mapstructure:"client_auth_type"`
	// TLSCipherSuites is a list of supported cipher suites for TLS version 1.2.
	// If CipherSuites is nil/empty, a default list of secure cipher suites
	// is used, with a preference order based on hardware performance.
	// Note that TLS 1.3 ciphersuites are not configurable.
	// The supported ciphersuites names are defined here:
	//
	// https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go#L52
	//
	// any invalid name will be silently ignored.
	// The order matters, the ciphers listed first will be the preferred ones.
	TLSCipherSuites []string `json:"tls_cipher_suites" mapstructure:"tls_cipher_suites"`
}

// GetAddress returns the binding address
func (b *Binding) GetAddress() string {
	return fmt.Sprintf("%s:%d", b.Address, b.Port)
}

// IsValid returns true if the binding is valid
func (b *Binding) IsValid() bool {
	if b.Port > 0 {
		return true
	}
	if filepath.IsAbs(b.Address) && runtime.GOOS != osWindows {
		return true
	}
	return false
}

type defenderStatus struct {
	IsActive bool `json:"is_active"`
}

// ServicesStatus keep the state of the running services
type ServicesStatus struct {
	SSH          sftpd.ServiceStatus         `json:"ssh"`
	FTP          ftpd.ServiceStatus          `json:"ftp"`
	WebDAV       webdavd.ServiceStatus       `json:"webdav"`
	DataProvider dataprovider.ProviderStatus `json:"data_provider"`
	Defender     defenderStatus              `json:"defender"`
}

// Conf httpd daemon configuration
type Conf struct {
	// Addresses and ports to bind to
	Bindings []Binding `json:"bindings" mapstructure:"bindings"`
	// Deprecated: please use Bindings
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// Deprecated: please use Bindings
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
	TemplatesPath string `json:"templates_path" mapstructure:"templates_path"`
	// Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir.
	// If both TemplatesPath and StaticFilesPath are empty the built-in web interface will be disabled
	StaticFilesPath string `json:"static_files_path" mapstructure:"static_files_path"`
	// Path to the backup directory. This can be an absolute path or a path relative to the config dir
	BackupsPath string `json:"backups_path" mapstructure:"backups_path"`
	// If files containing a certificate and matching private key for the server are provided the server will expect
	// HTTPS connections.
	// Certificate and key files can be reloaded on demand sending a "SIGHUP" signal on Unix based systems and a
	// "paramchange" request to the running service on Windows.
	CertificateFile    string `json:"certificate_file" mapstructure:"certificate_file"`
	CertificateKeyFile string `json:"certificate_key_file" mapstructure:"certificate_key_file"`
	// CACertificates defines the set of root certificate authorities to be used to verify client certificates.
	CACertificates []string `json:"ca_certificates" mapstructure:"ca_certificates"`
	// CARevocationLists defines a set a revocation lists, one for each root CA, to be used to check
	// if a client certificate has been revoked
	CARevocationLists []string `json:"ca_revocation_lists" mapstructure:"ca_revocation_lists"`
}

type apiResponse struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message"`
}

// ShouldBind returns true if there is at least a valid binding
func (c *Conf) ShouldBind() bool {
	for _, binding := range c.Bindings {
		if binding.IsValid() {
			return true
		}
	}

	return false
}

// Initialize configures and starts the HTTP server
func (c *Conf) Initialize(configDir string) error {
	logger.Debug(logSender, "", "initializing HTTP server with config %+v", c)
	backupsPath = getConfigPath(c.BackupsPath, configDir)
	staticFilesPath := getConfigPath(c.StaticFilesPath, configDir)
	templatesPath := getConfigPath(c.TemplatesPath, configDir)
	enableWebAdmin := staticFilesPath != "" || templatesPath != ""
	if backupsPath == "" {
		return fmt.Errorf("Required directory is invalid, backup path %#v", backupsPath)
	}
	if enableWebAdmin && (staticFilesPath == "" || templatesPath == "") {
		return fmt.Errorf("Required directory is invalid, static file path: %#v template path: %#v",
			staticFilesPath, templatesPath)
	}
	certificateFile := getConfigPath(c.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(c.CertificateKeyFile, configDir)
	if enableWebAdmin {
		loadTemplates(templatesPath)
	} else {
		logger.Info(logSender, "", "built-in web interface disabled, please set templates_path and static_files_path to enable it")
	}
	if certificateFile != "" && certificateKeyFile != "" {
		mgr, err := common.NewCertManager(certificateFile, certificateKeyFile, configDir, logSender)
		if err != nil {
			return err
		}
		mgr.SetCACertificates(c.CACertificates)
		if err := mgr.LoadRootCAs(); err != nil {
			return err
		}
		mgr.SetCARevocationLists(c.CARevocationLists)
		if err := mgr.LoadCRLs(); err != nil {
			return err
		}
		certMgr = mgr
	}

	csrfTokenAuth = jwtauth.New("HS256", utils.GenerateRandomBytes(32), nil)

	exitChannel := make(chan error, 1)

	for _, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}

		go func(b Binding) {
			server := newHttpdServer(b, staticFilesPath, enableWebAdmin)

			exitChannel <- server.listenAndServe()
		}(binding)
	}

	startJWTTokensCleanupTicker(tokenDuration)
	return <-exitChannel
}

func isWebAdminRequest(r *http.Request) bool {
	return strings.HasPrefix(r.RequestURI, webBasePath+"/")
}

// ReloadCertificateMgr reloads the certificate manager
func ReloadCertificateMgr() error {
	if certMgr != nil {
		return certMgr.Reload()
	}
	return nil
}

func getConfigPath(name, configDir string) string {
	if !utils.IsFileInputValid(name) {
		return ""
	}
	if name != "" && !filepath.IsAbs(name) {
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
		Defender: defenderStatus{
			IsActive: common.Config.DefenderConfig.Enabled,
		},
	}
	return status
}

func getURLParam(r *http.Request, key string) string {
	v := chi.URLParam(r, key)
	unescaped, err := url.PathUnescape(v)
	if err != nil {
		return v
	}
	return unescaped
}

func fileServer(r chi.Router, path string, root http.FileSystem) {
	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

// GetHTTPRouter returns an HTTP handler suitable to use for test cases
func GetHTTPRouter() http.Handler {
	b := Binding{
		Address:        "",
		Port:           8080,
		EnableWebAdmin: true,
	}
	server := newHttpdServer(b, "../static", true)
	server.initializeRouter()
	return server.router
}

// the ticker cannot be started/stopped from multiple goroutines
func startJWTTokensCleanupTicker(duration time.Duration) {
	stopJWTTokensCleanupTicker()
	jwtTokensCleanupTicker = time.NewTicker(duration)
	jwtTokensCleanupDone = make(chan bool)

	go func() {
		for {
			select {
			case <-jwtTokensCleanupDone:
				return
			case <-jwtTokensCleanupTicker.C:
				cleanupExpiredJWTTokens()
			}
		}
	}()
}

func stopJWTTokensCleanupTicker() {
	if jwtTokensCleanupTicker != nil {
		jwtTokensCleanupTicker.Stop()
		jwtTokensCleanupDone <- true
		jwtTokensCleanupTicker = nil
	}
}

func cleanupExpiredJWTTokens() {
	invalidatedJWTTokens.Range(func(key, value interface{}) bool {
		exp, ok := value.(time.Time)
		if !ok || exp.Before(time.Now().UTC()) {
			invalidatedJWTTokens.Delete(key)
		}
		return true
	})
}
