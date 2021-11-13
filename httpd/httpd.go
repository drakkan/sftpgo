// Package httpd implements REST API and Web interface for SFTPGo.
// The OpenAPI 3 schema for the exposed API can be found inside the source tree:
// https://github.com/drakkan/sftpgo/blob/main/httpd/schema/openapi.yaml
package httpd

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/jwa"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/ftpd"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/sftpd"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/webdavd"
)

const (
	logSender                             = "httpd"
	tokenPath                             = "/api/v2/token"
	logoutPath                            = "/api/v2/logout"
	userTokenPath                         = "/api/v2/user/token"
	userLogoutPath                        = "/api/v2/user/logout"
	activeConnectionsPath                 = "/api/v2/connections"
	quotasBasePath                        = "/api/v2/quotas"
	quotaScanPath                         = "/api/v2/quota-scans"
	quotaScanVFolderPath                  = "/api/v2/folder-quota-scans"
	userPath                              = "/api/v2/users"
	versionPath                           = "/api/v2/version"
	folderPath                            = "/api/v2/folders"
	serverStatusPath                      = "/api/v2/status"
	dumpDataPath                          = "/api/v2/dumpdata"
	loadDataPath                          = "/api/v2/loaddata"
	updateUsedQuotaPath                   = "/api/v2/quota-update"
	updateFolderUsedQuotaPath             = "/api/v2/folder-quota-update"
	defenderHosts                         = "/api/v2/defender/hosts"
	defenderBanTime                       = "/api/v2/defender/bantime"
	defenderUnban                         = "/api/v2/defender/unban"
	defenderScore                         = "/api/v2/defender/score"
	adminPath                             = "/api/v2/admins"
	adminPwdPath                          = "/api/v2/admin/changepwd"
	adminPwdCompatPath                    = "/api/v2/changepwd/admin"
	adminProfilePath                      = "/api/v2/admin/profile"
	userPwdPath                           = "/api/v2/user/changepwd"
	userPublicKeysPath                    = "/api/v2/user/publickeys"
	userFolderPath                        = "/api/v2/user/folder"
	userDirsPath                          = "/api/v2/user/dirs"
	userFilePath                          = "/api/v2/user/file"
	userFilesPath                         = "/api/v2/user/files"
	userStreamZipPath                     = "/api/v2/user/streamzip"
	apiKeysPath                           = "/api/v2/apikeys"
	adminTOTPConfigsPath                  = "/api/v2/admin/totp/configs"
	adminTOTPGeneratePath                 = "/api/v2/admin/totp/generate"
	adminTOTPValidatePath                 = "/api/v2/admin/totp/validate"
	adminTOTPSavePath                     = "/api/v2/admin/totp/save"
	admin2FARecoveryCodesPath             = "/api/v2/admin/2fa/recoverycodes"
	userTOTPConfigsPath                   = "/api/v2/user/totp/configs"
	userTOTPGeneratePath                  = "/api/v2/user/totp/generate"
	userTOTPValidatePath                  = "/api/v2/user/totp/validate"
	userTOTPSavePath                      = "/api/v2/user/totp/save"
	user2FARecoveryCodesPath              = "/api/v2/user/2fa/recoverycodes"
	userProfilePath                       = "/api/v2/user/profile"
	userSharesPath                        = "/api/v2/user/shares"
	retentionBasePath                     = "/api/v2/retention/users"
	retentionChecksPath                   = "/api/v2/retention/users/checks"
	fsEventsPath                          = "/api/v2/events/fs"
	providerEventsPath                    = "/api/v2/events/provider"
	sharesPath                            = "/api/v2/shares"
	healthzPath                           = "/healthz"
	webRootPathDefault                    = "/"
	webBasePathDefault                    = "/web"
	webBasePathAdminDefault               = "/web/admin"
	webBasePathClientDefault              = "/web/client"
	webAdminSetupPathDefault              = "/web/admin/setup"
	webLoginPathDefault                   = "/web/admin/login"
	webAdminTwoFactorPathDefault          = "/web/admin/twofactor"
	webAdminTwoFactorRecoveryPathDefault  = "/web/admin/twofactor-recovery"
	webLogoutPathDefault                  = "/web/admin/logout"
	webUsersPathDefault                   = "/web/admin/users"
	webUserPathDefault                    = "/web/admin/user"
	webConnectionsPathDefault             = "/web/admin/connections"
	webFoldersPathDefault                 = "/web/admin/folders"
	webFolderPathDefault                  = "/web/admin/folder"
	webStatusPathDefault                  = "/web/admin/status"
	webAdminsPathDefault                  = "/web/admin/managers"
	webAdminPathDefault                   = "/web/admin/manager"
	webMaintenancePathDefault             = "/web/admin/maintenance"
	webBackupPathDefault                  = "/web/admin/backup"
	webRestorePathDefault                 = "/web/admin/restore"
	webScanVFolderPathDefault             = "/web/admin/quotas/scanfolder"
	webQuotaScanPathDefault               = "/web/admin/quotas/scanuser"
	webChangeAdminPwdPathDefault          = "/web/admin/changepwd"
	webAdminForgotPwdPathDefault          = "/web/admin/forgot-password"
	webAdminResetPwdPathDefault           = "/web/admin/reset-password"
	webAdminProfilePathDefault            = "/web/admin/profile"
	webAdminMFAPathDefault                = "/web/admin/mfa"
	webAdminTOTPGeneratePathDefault       = "/web/admin/totp/generate"
	webAdminTOTPValidatePathDefault       = "/web/admin/totp/validate"
	webAdminTOTPSavePathDefault           = "/web/admin/totp/save"
	webAdminRecoveryCodesPathDefault      = "/web/admin/recoverycodes"
	webTemplateUserDefault                = "/web/admin/template/user"
	webTemplateFolderDefault              = "/web/admin/template/folder"
	webDefenderPathDefault                = "/web/admin/defender"
	webDefenderHostsPathDefault           = "/web/admin/defender/hosts"
	webClientLoginPathDefault             = "/web/client/login"
	webClientTwoFactorPathDefault         = "/web/client/twofactor"
	webClientTwoFactorRecoveryPathDefault = "/web/client/twofactor-recovery"
	webClientFilesPathDefault             = "/web/client/files"
	webClientSharesPathDefault            = "/web/client/shares"
	webClientSharePathDefault             = "/web/client/share"
	webClientEditFilePathDefault          = "/web/client/editfile"
	webClientDirsPathDefault              = "/web/client/dirs"
	webClientDownloadZipPathDefault       = "/web/client/downloadzip"
	webClientProfilePathDefault           = "/web/client/profile"
	webClientMFAPathDefault               = "/web/client/mfa"
	webClientTOTPGeneratePathDefault      = "/web/client/totp/generate"
	webClientTOTPValidatePathDefault      = "/web/client/totp/validate"
	webClientTOTPSavePathDefault          = "/web/client/totp/save"
	webClientRecoveryCodesPathDefault     = "/web/client/recoverycodes"
	webChangeClientPwdPathDefault         = "/web/client/changepwd"
	webClientLogoutPathDefault            = "/web/client/logout"
	webClientPubSharesPathDefault         = "/web/client/pubshares"
	webClientForgotPwdPathDefault         = "/web/client/forgot-password"
	webClientResetPwdPathDefault          = "/web/client/reset-password"
	webStaticFilesPathDefault             = "/static"
	// MaxRestoreSize defines the max size for the loaddata input file
	MaxRestoreSize       = 10485760 // 10 MB
	maxRequestSize       = 1048576  // 1MB
	maxLoginBodySize     = 262144   // 256 KB
	httpdMaxEditFileSize = 524288   // 512 KB
	maxMultipartMem      = 8388608  // 8MB
	osWindows            = "windows"
	otpHeaderCode        = "X-SFTPGO-OTP"
)

var (
	backupsPath                    string
	certMgr                        *common.CertManager
	cleanupTicker                  *time.Ticker
	cleanupDone                    chan bool
	invalidatedJWTTokens           sync.Map
	csrfTokenAuth                  *jwtauth.JWTAuth
	webRootPath                    string
	webBasePath                    string
	webBaseAdminPath               string
	webBaseClientPath              string
	webAdminSetupPath              string
	webLoginPath                   string
	webAdminTwoFactorPath          string
	webAdminTwoFactorRecoveryPath  string
	webLogoutPath                  string
	webUsersPath                   string
	webUserPath                    string
	webConnectionsPath             string
	webFoldersPath                 string
	webFolderPath                  string
	webStatusPath                  string
	webAdminsPath                  string
	webAdminPath                   string
	webMaintenancePath             string
	webBackupPath                  string
	webRestorePath                 string
	webScanVFolderPath             string
	webQuotaScanPath               string
	webAdminProfilePath            string
	webAdminMFAPath                string
	webAdminTOTPGeneratePath       string
	webAdminTOTPValidatePath       string
	webAdminTOTPSavePath           string
	webAdminRecoveryCodesPath      string
	webChangeAdminPwdPath          string
	webAdminForgotPwdPath          string
	webAdminResetPwdPath           string
	webTemplateUser                string
	webTemplateFolder              string
	webDefenderPath                string
	webDefenderHostsPath           string
	webClientLoginPath             string
	webClientTwoFactorPath         string
	webClientTwoFactorRecoveryPath string
	webClientFilesPath             string
	webClientSharesPath            string
	webClientSharePath             string
	webClientEditFilePath          string
	webClientDirsPath              string
	webClientDownloadZipPath       string
	webClientProfilePath           string
	webChangeClientPwdPath         string
	webClientMFAPath               string
	webClientTOTPGeneratePath      string
	webClientTOTPValidatePath      string
	webClientTOTPSavePath          string
	webClientRecoveryCodesPath     string
	webClientPubSharesPath         string
	webClientLogoutPath            string
	webClientForgotPwdPath         string
	webClientResetPwdPath          string
	webStaticFilesPath             string
	// max upload size for http clients, 1GB by default
	maxUploadFileSize = int64(1048576000)
)

func init() {
	updateWebAdminURLs("")
	updateWebClientURLs("")
}

// Binding defines the configuration for a network listener
type Binding struct {
	// The address to listen on. A blank value means listen on all available network interfaces.
	Address string `json:"address" mapstructure:"address"`
	// The port used for serving requests
	Port int `json:"port" mapstructure:"port"`
	// Enable the built-in admin interface.
	// You have to define TemplatesPath and StaticFilesPath for this to work
	EnableWebAdmin bool `json:"enable_web_admin" mapstructure:"enable_web_admin"`
	// Enable the built-in client interface.
	// You have to define TemplatesPath and StaticFilesPath for this to work
	EnableWebClient bool `json:"enable_web_client" mapstructure:"enable_web_client"`
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
	// List of IP addresses and IP ranges allowed to set X-Forwarded-For, X-Real-IP,
	// X-Forwarded-Proto headers.
	ProxyAllowed []string `json:"proxy_allowed" mapstructure:"proxy_allowed"`
	// If both web admin and web client are enabled each login page will show a link
	// to the other one. This setting allows to hide this link:
	// - 0 login links are displayed on both admin and client login page. This is the default
	// - 1 the login link to the web client login page is hidden on admin login page
	// - 2 the login link to the web admin login page is hidden on client login page
	// The flags can be combined, for example 3 will disable both login links.
	HideLoginURL     int `json:"hide_login_url" mapstructure:"hide_login_url"`
	allowHeadersFrom []func(net.IP) bool
}

func (b *Binding) parseAllowedProxy() error {
	allowedFuncs, err := util.ParseAllowedIPAndRanges(b.ProxyAllowed)
	if err != nil {
		return err
	}
	b.allowHeadersFrom = allowedFuncs
	return nil
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

func (b *Binding) showAdminLoginURL() bool {
	if !b.EnableWebAdmin {
		return false
	}
	if b.HideLoginURL&2 != 0 {
		return false
	}
	return true
}

func (b *Binding) showClientLoginURL() bool {
	if !b.EnableWebClient {
		return false
	}
	if b.HideLoginURL&1 != 0 {
		return false
	}
	return true
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
	MFA          mfa.ServiceStatus           `json:"mfa"`
}

// CorsConfig defines the CORS configuration
type CorsConfig struct {
	AllowedOrigins   []string `json:"allowed_origins" mapstructure:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods" mapstructure:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers" mapstructure:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers" mapstructure:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials" mapstructure:"allow_credentials"`
	Enabled          bool     `json:"enabled" mapstructure:"enabled"`
	MaxAge           int      `json:"max_age" mapstructure:"max_age"`
}

// Conf httpd daemon configuration
type Conf struct {
	// Addresses and ports to bind to
	Bindings []Binding `json:"bindings" mapstructure:"bindings"`
	// Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
	TemplatesPath string `json:"templates_path" mapstructure:"templates_path"`
	// Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir.
	// If both TemplatesPath and StaticFilesPath are empty the built-in web interface will be disabled
	StaticFilesPath string `json:"static_files_path" mapstructure:"static_files_path"`
	// Path to the backup directory. This can be an absolute path or a path relative to the config dir
	BackupsPath string `json:"backups_path" mapstructure:"backups_path"`
	// Defines a base URL for the web admin and client interfaces. If empty web admin and client resources will
	// be available at the root ("/") URI. If defined it must be an absolute URI or it will be ignored.
	WebRoot string `json:"web_root" mapstructure:"web_root"`
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
	// SigningPassphrase defines the passphrase to use to derive the signing key for JWT and CSRF tokens.
	// If empty a random signing key will be generated each time SFTPGo starts. If you set a
	// signing passphrase you should consider rotating it periodically for added security
	SigningPassphrase string `json:"signing_passphrase" mapstructure:"signing_passphrase"`
	// MaxUploadFileSize Defines the maximum request body size, in bytes, for Web Client/API HTTP upload requests.
	// 0 means no limit
	MaxUploadFileSize int64 `json:"max_upload_file_size" mapstructure:"max_upload_file_size"`
	// CORS configuration
	Cors CorsConfig `json:"cors" mapstructure:"cors"`
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

func (c *Conf) isWebAdminEnabled() bool {
	for _, binding := range c.Bindings {
		if binding.EnableWebAdmin {
			return true
		}
	}
	return false
}

func (c *Conf) isWebClientEnabled() bool {
	for _, binding := range c.Bindings {
		if binding.EnableWebClient {
			return true
		}
	}
	return false
}

func (c *Conf) checkRequiredDirs(staticFilesPath, templatesPath string) error {
	if (c.isWebAdminEnabled() || c.isWebClientEnabled()) && (staticFilesPath == "" || templatesPath == "") {
		return fmt.Errorf("required directory is invalid, static file path: %#v template path: %#v",
			staticFilesPath, templatesPath)
	}
	return nil
}

func (c *Conf) getRedacted() Conf {
	conf := *c
	conf.SigningPassphrase = "[redacted]"
	return conf
}

// Initialize configures and starts the HTTP server
func (c *Conf) Initialize(configDir string) error {
	logger.Debug(logSender, "", "initializing HTTP server with config %+v", c.getRedacted())
	backupsPath = getConfigPath(c.BackupsPath, configDir)
	staticFilesPath := getConfigPath(c.StaticFilesPath, configDir)
	templatesPath := getConfigPath(c.TemplatesPath, configDir)
	if backupsPath == "" {
		return fmt.Errorf("required directory is invalid, backup path %#v", backupsPath)
	}
	if err := c.checkRequiredDirs(staticFilesPath, templatesPath); err != nil {
		return err
	}
	certificateFile := getConfigPath(c.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(c.CertificateKeyFile, configDir)
	if c.isWebAdminEnabled() {
		updateWebAdminURLs(c.WebRoot)
		loadAdminTemplates(templatesPath)
	} else {
		logger.Info(logSender, "", "built-in web admin interface disabled")
	}
	if c.isWebClientEnabled() {
		updateWebClientURLs(c.WebRoot)
		loadClientTemplates(templatesPath)
	} else {
		logger.Info(logSender, "", "built-in web client interface disabled")
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

	csrfTokenAuth = jwtauth.New(jwa.HS256.String(), getSigningKey(c.SigningPassphrase), nil)

	exitChannel := make(chan error, 1)

	for _, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}
		if err := binding.parseAllowedProxy(); err != nil {
			return err
		}

		go func(b Binding) {
			server := newHttpdServer(b, staticFilesPath, c.SigningPassphrase, c.Cors)

			exitChannel <- server.listenAndServe()
		}(binding)
	}

	maxUploadFileSize = c.MaxUploadFileSize
	startCleanupTicker(tokenDuration / 2)
	return <-exitChannel
}

func isWebRequest(r *http.Request) bool {
	return strings.HasPrefix(r.RequestURI, webBasePath+"/")
}

func isWebClientRequest(r *http.Request) bool {
	return strings.HasPrefix(r.RequestURI, webBaseClientPath+"/")
}

// ReloadCertificateMgr reloads the certificate manager
func ReloadCertificateMgr() error {
	if certMgr != nil {
		return certMgr.Reload()
	}
	return nil
}

func getConfigPath(name, configDir string) string {
	if !util.IsFileInputValid(name) {
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
		MFA: mfa.GetStatus(),
	}
	return status
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

func updateWebClientURLs(baseURL string) {
	if !path.IsAbs(baseURL) {
		baseURL = "/"
	}
	webRootPath = path.Join(baseURL, webRootPathDefault)
	webBasePath = path.Join(baseURL, webBasePathDefault)
	webBaseClientPath = path.Join(baseURL, webBasePathClientDefault)
	webClientLoginPath = path.Join(baseURL, webClientLoginPathDefault)
	webClientTwoFactorPath = path.Join(baseURL, webClientTwoFactorPathDefault)
	webClientTwoFactorRecoveryPath = path.Join(baseURL, webClientTwoFactorRecoveryPathDefault)
	webClientFilesPath = path.Join(baseURL, webClientFilesPathDefault)
	webClientSharesPath = path.Join(baseURL, webClientSharesPathDefault)
	webClientPubSharesPath = path.Join(baseURL, webClientPubSharesPathDefault)
	webClientSharePath = path.Join(baseURL, webClientSharePathDefault)
	webClientEditFilePath = path.Join(baseURL, webClientEditFilePathDefault)
	webClientDirsPath = path.Join(baseURL, webClientDirsPathDefault)
	webClientDownloadZipPath = path.Join(baseURL, webClientDownloadZipPathDefault)
	webClientProfilePath = path.Join(baseURL, webClientProfilePathDefault)
	webChangeClientPwdPath = path.Join(baseURL, webChangeClientPwdPathDefault)
	webClientLogoutPath = path.Join(baseURL, webClientLogoutPathDefault)
	webClientMFAPath = path.Join(baseURL, webClientMFAPathDefault)
	webClientTOTPGeneratePath = path.Join(baseURL, webClientTOTPGeneratePathDefault)
	webClientTOTPValidatePath = path.Join(baseURL, webClientTOTPValidatePathDefault)
	webClientTOTPSavePath = path.Join(baseURL, webClientTOTPSavePathDefault)
	webClientRecoveryCodesPath = path.Join(baseURL, webClientRecoveryCodesPathDefault)
	webClientForgotPwdPath = path.Join(baseURL, webClientForgotPwdPathDefault)
	webClientResetPwdPath = path.Join(baseURL, webClientResetPwdPathDefault)
}

func updateWebAdminURLs(baseURL string) {
	if !path.IsAbs(baseURL) {
		baseURL = "/"
	}
	webRootPath = path.Join(baseURL, webRootPathDefault)
	webBasePath = path.Join(baseURL, webBasePathDefault)
	webBaseAdminPath = path.Join(baseURL, webBasePathAdminDefault)
	webAdminSetupPath = path.Join(baseURL, webAdminSetupPathDefault)
	webLoginPath = path.Join(baseURL, webLoginPathDefault)
	webAdminTwoFactorPath = path.Join(baseURL, webAdminTwoFactorPathDefault)
	webAdminTwoFactorRecoveryPath = path.Join(baseURL, webAdminTwoFactorRecoveryPathDefault)
	webLogoutPath = path.Join(baseURL, webLogoutPathDefault)
	webUsersPath = path.Join(baseURL, webUsersPathDefault)
	webUserPath = path.Join(baseURL, webUserPathDefault)
	webConnectionsPath = path.Join(baseURL, webConnectionsPathDefault)
	webFoldersPath = path.Join(baseURL, webFoldersPathDefault)
	webFolderPath = path.Join(baseURL, webFolderPathDefault)
	webStatusPath = path.Join(baseURL, webStatusPathDefault)
	webAdminsPath = path.Join(baseURL, webAdminsPathDefault)
	webAdminPath = path.Join(baseURL, webAdminPathDefault)
	webMaintenancePath = path.Join(baseURL, webMaintenancePathDefault)
	webBackupPath = path.Join(baseURL, webBackupPathDefault)
	webRestorePath = path.Join(baseURL, webRestorePathDefault)
	webScanVFolderPath = path.Join(baseURL, webScanVFolderPathDefault)
	webQuotaScanPath = path.Join(baseURL, webQuotaScanPathDefault)
	webChangeAdminPwdPath = path.Join(baseURL, webChangeAdminPwdPathDefault)
	webAdminForgotPwdPath = path.Join(baseURL, webAdminForgotPwdPathDefault)
	webAdminResetPwdPath = path.Join(baseURL, webAdminResetPwdPathDefault)
	webAdminProfilePath = path.Join(baseURL, webAdminProfilePathDefault)
	webAdminMFAPath = path.Join(baseURL, webAdminMFAPathDefault)
	webAdminTOTPGeneratePath = path.Join(baseURL, webAdminTOTPGeneratePathDefault)
	webAdminTOTPValidatePath = path.Join(baseURL, webAdminTOTPValidatePathDefault)
	webAdminTOTPSavePath = path.Join(baseURL, webAdminTOTPSavePathDefault)
	webAdminRecoveryCodesPath = path.Join(baseURL, webAdminRecoveryCodesPathDefault)
	webTemplateUser = path.Join(baseURL, webTemplateUserDefault)
	webTemplateFolder = path.Join(baseURL, webTemplateFolderDefault)
	webDefenderHostsPath = path.Join(baseURL, webDefenderHostsPathDefault)
	webDefenderPath = path.Join(baseURL, webDefenderPathDefault)
	webStaticFilesPath = path.Join(baseURL, webStaticFilesPathDefault)
}

// GetHTTPRouter returns an HTTP handler suitable to use for test cases
func GetHTTPRouter() http.Handler {
	b := Binding{
		Address:         "",
		Port:            8080,
		EnableWebAdmin:  true,
		EnableWebClient: true,
	}
	server := newHttpdServer(b, "../static", "", CorsConfig{})
	server.initializeRouter()
	return server.router
}

// the ticker cannot be started/stopped from multiple goroutines
func startCleanupTicker(duration time.Duration) {
	stopCleanupTicker()
	cleanupTicker = time.NewTicker(duration)
	cleanupDone = make(chan bool)

	go func() {
		for {
			select {
			case <-cleanupDone:
				return
			case <-cleanupTicker.C:
				cleanupExpiredJWTTokens()
				cleanupExpiredResetCodes()
			}
		}
	}()
}

func stopCleanupTicker() {
	if cleanupTicker != nil {
		cleanupTicker.Stop()
		cleanupDone <- true
		cleanupTicker = nil
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

func getSigningKey(signingPassphrase string) []byte {
	if signingPassphrase != "" {
		sk := sha256.Sum256([]byte(signingPassphrase))
		return sk[:]
	}
	return util.GenerateRandomBytes(32)
}
