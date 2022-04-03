// Package httpd implements REST API and Web interface for SFTPGo.
// The OpenAPI 3 schema for the exposed API can be found inside the source tree:
// https://github.com/drakkan/sftpgo/blob/main/openapi/openapi.yaml
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
	userUploadFilePath                    = "/api/v2/user/files/upload"
	userFilesDirsMetadataPath             = "/api/v2/user/files/metadata"
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
	metadataBasePath                      = "/api/v2/metadata/users"
	metadataChecksPath                    = "/api/v2/metadata/users/checks"
	fsEventsPath                          = "/api/v2/events/fs"
	providerEventsPath                    = "/api/v2/events/provider"
	sharesPath                            = "/api/v2/shares"
	healthzPath                           = "/healthz"
	webRootPathDefault                    = "/"
	webBasePathDefault                    = "/web"
	webBasePathAdminDefault               = "/web/admin"
	webBasePathClientDefault              = "/web/client"
	webAdminSetupPathDefault              = "/web/admin/setup"
	webAdminLoginPathDefault              = "/web/admin/login"
	webAdminOIDCLoginPathDefault          = "/web/admin/oidclogin"
	webOIDCRedirectPathDefault            = "/web/oidc/redirect"
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
	webClientOIDCLoginPathDefault         = "/web/client/oidclogin"
	webClientTwoFactorPathDefault         = "/web/client/twofactor"
	webClientTwoFactorRecoveryPathDefault = "/web/client/twofactor-recovery"
	webClientFilesPathDefault             = "/web/client/files"
	webClientFilePathDefault              = "/web/client/file"
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
	webClientViewPDFPathDefault           = "/web/client/viewpdf"
	webStaticFilesPathDefault             = "/static"
	webOpenAPIPathDefault                 = "/openapi"
	// MaxRestoreSize defines the max size for the loaddata input file
	MaxRestoreSize       = 10485760 // 10 MB
	maxRequestSize       = 1048576  // 1MB
	maxLoginBodySize     = 262144   // 256 KB
	httpdMaxEditFileSize = 1048576  // 1 MB
	maxMultipartMem      = 10485760 // 10 MB
	osWindows            = "windows"
	otpHeaderCode        = "X-SFTPGO-OTP"
	mTimeHeader          = "X-SFTPGO-MTIME"
)

var (
	certMgr                        *common.CertManager
	cleanupTicker                  *time.Ticker
	cleanupDone                    chan bool
	invalidatedJWTTokens           sync.Map
	csrfTokenAuth                  *jwtauth.JWTAuth
	webRootPath                    string
	webBasePath                    string
	webBaseAdminPath               string
	webBaseClientPath              string
	webOIDCRedirectPath            string
	webAdminSetupPath              string
	webAdminOIDCLoginPath          string
	webAdminLoginPath              string
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
	webClientOIDCLoginPath         string
	webClientTwoFactorPath         string
	webClientTwoFactorRecoveryPath string
	webClientFilesPath             string
	webClientFilePath              string
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
	webClientViewPDFPath           string
	webStaticFilesPath             string
	webOpenAPIPath                 string
	// max upload size for http clients, 1GB by default
	maxUploadFileSize          = int64(1048576000)
	installationCode           string
	installationCodeHint       string
	fnInstallationCodeResolver FnInstallationCodeResolver
)

func init() {
	updateWebAdminURLs("")
	updateWebClientURLs("")
}

// FnInstallationCodeResolver defines a method to get the installation code.
// If the installation code cannot be resolved the provided default must be returned
type FnInstallationCodeResolver func(defaultInstallationCode string) string

// HTTPSProxyHeader defines an HTTPS proxy header as key/value.
// For example Key could be "X-Forwarded-Proto" and Value "https"
type HTTPSProxyHeader struct {
	Key   string
	Value string
}

// SecurityConf allows to add some security related headers to HTTP responses and to restrict allowed hosts
type SecurityConf struct {
	// Set to true to enable the security configurations
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// AllowedHosts is a list of fully qualified domain names that are allowed.
	// Default is empty list, which allows any and all host names.
	AllowedHosts []string `json:"allowed_hosts" mapstructure:"allowed_hosts"`
	// AllowedHostsAreRegex determines if the provided allowed hosts contains valid regular expressions
	AllowedHostsAreRegex bool `json:"allowed_hosts_are_regex" mapstructure:"allowed_hosts_are_regex"`
	// HostsProxyHeaders is a set of header keys that may hold a proxied hostname value for the request.
	HostsProxyHeaders []string `json:"hosts_proxy_headers" mapstructure:"hosts_proxy_headers"`
	// Set to true to redirect HTTP requests to HTTPS
	HTTPSRedirect bool `json:"https_redirect" mapstructure:"https_redirect"`
	// HTTPSHost defines the host name that is used to redirect HTTP requests to HTTPS.
	// Default is "", which indicates to use the same host.
	HTTPSHost string `json:"https_host" mapstructure:"https_host"`
	// HTTPSProxyHeaders is a list of header keys with associated values that would indicate a valid https request.
	HTTPSProxyHeaders []HTTPSProxyHeader `json:"https_proxy_headers" mapstructure:"https_proxy_headers"`
	// STSSeconds is the max-age of the Strict-Transport-Security header.
	// Default is 0, which would NOT include the header.
	STSSeconds int64 `json:"sts_seconds" mapstructure:"sts_seconds"`
	// If STSIncludeSubdomains is set to true, the "includeSubdomains" will be appended to the
	// Strict-Transport-Security header. Default is false.
	STSIncludeSubdomains bool `json:"sts_include_subdomains" mapstructure:"sts_include_subdomains"`
	// If STSPreload is set to true, the `preload` flag will be appended to the
	// Strict-Transport-Security header. Default is false.
	STSPreload bool `json:"sts_preload" mapstructure:"sts_preload"`
	// If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value "nosniff". Default is false.
	ContentTypeNosniff bool `json:"content_type_nosniff" mapstructure:"content_type_nosniff"`
	// ContentSecurityPolicy allows to set the Content-Security-Policy header value. Default is "".
	ContentSecurityPolicy string `json:"content_security_policy" mapstructure:"content_security_policy"`
	// PermissionsPolicy allows to set the Permissions-Policy header value. Default is "".
	PermissionsPolicy string `json:"permissions_policy" mapstructure:"permissions_policy"`
	// CrossOriginOpenerPolicy allows to set the `Cross-Origin-Opener-Policy` header value. Default is "".
	CrossOriginOpenerPolicy string `json:"cross_origin_opener_policy" mapstructure:"cross_origin_opener_policy"`
	// ExpectCTHeader allows to set the Expect-CT header value. Default is "".
	ExpectCTHeader string `json:"expect_ct_header" mapstructure:"expect_ct_header"`
	proxyHeaders   []string
}

func (s *SecurityConf) updateProxyHeaders() {
	if !s.Enabled {
		s.proxyHeaders = nil
		return
	}
	s.proxyHeaders = s.HostsProxyHeaders
	for _, httpsProxyHeader := range s.HTTPSProxyHeaders {
		s.proxyHeaders = append(s.proxyHeaders, httpsProxyHeader.Key)
	}
}

func (s *SecurityConf) getHTTPSProxyHeaders() map[string]string {
	headers := make(map[string]string)
	for _, httpsProxyHeader := range s.HTTPSProxyHeaders {
		headers[httpsProxyHeader.Key] = httpsProxyHeader.Value
	}
	return headers
}

// CustomCSS defines the configuration for custom CSS
type CustomCSS struct {
	// Path to the CSS file relative to "static_files_path".
	// For example, if you create a directory named "extra_css" inside the static dir
	// and put the "my.css" file in it, you must set "/extra_css/my.css" as path.
	Path string `json:"path" mapstructure:"path"`
}

// WebClientIntegration defines the configuration for an external Web Client integration
type WebClientIntegration struct {
	// Files with these extensions can be sent to the configured URL
	FileExtensions []string `json:"file_extensions" mapstructure:"file_extensions"`
	// URL that will receive the files
	URL string `json:"url" mapstructure:"url"`
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
	// Defines the minimum TLS version. 13 means TLS 1.3, default is TLS 1.2
	MinTLSVersion int `json:"min_tls_version" mapstructure:"min_tls_version"`
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
	HideLoginURL int `json:"hide_login_url" mapstructure:"hide_login_url"`
	// Enable the built-in OpenAPI renderer
	RenderOpenAPI bool `json:"render_openapi" mapstructure:"render_openapi"`
	// Enabling web client integrations you can render or modify the files with the specified
	// extensions using an external tool.
	WebClientIntegrations []WebClientIntegration `json:"web_client_integrations" mapstructure:"web_client_integrations"`
	// Defining an OIDC configuration the web admin and web client UI will use OpenID to authenticate users.
	OIDC OIDC `json:"oidc" mapstructure:"oidc"`
	// Security defines security headers to add to HTTP responses and allows to restrict allowed hosts
	Security SecurityConf `json:"security" mapstructure:"security"`
	// Additional CSS
	ExtraCSS         []CustomCSS `json:"extra_css" mapstructure:"extra_css"`
	allowHeadersFrom []func(net.IP) bool
}

func (b *Binding) checkWebClientIntegrations() {
	var integrations []WebClientIntegration
	for _, integration := range b.WebClientIntegrations {
		if integration.URL != "" && len(integration.FileExtensions) > 0 {
			integrations = append(integrations, integration)
		}
	}
	b.WebClientIntegrations = integrations
}

func (b *Binding) checkExtraCSS() {
	var extraCSS []CustomCSS
	for _, css := range b.ExtraCSS {
		extraCSS = append(extraCSS, CustomCSS{
			Path: path.Join("/", css.Path),
		})
	}
	b.ExtraCSS = extraCSS
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

// SetupConfig defines the configuration parameters for the initial web admin setup
type SetupConfig struct {
	// Installation code to require when creating the first admin account.
	// As for the other configurations, this value is read at SFTPGo startup and not at runtime
	// even if set using an environment variable.
	// This is not a license key or similar, the purpose here is to prevent anyone who can access
	// to the initial setup screen from creating an admin user
	InstallationCode string `json:"installation_code" mapstructure:"installation_code"`
	// Description for the installation code input field
	InstallationCodeHint string `json:"installation_code_hint" mapstructure:"installation_code_hint"`
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
	//BackupsPath string `json:"backups_path" mapstructure:"backups_path"`
	// Path to the directory that contains the OpenAPI schema and the default renderer.
	// This can be an absolute path or a path relative to the config dir
	OpenAPIPath string `json:"openapi_path" mapstructure:"openapi_path"`
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
	// Initial setup configuration
	Setup SetupConfig `json:"setup" mapstructure:"setup"`
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
	redacted := "[redacted]"
	conf := *c
	if conf.SigningPassphrase != "" {
		conf.SigningPassphrase = redacted
	}
	if conf.Setup.InstallationCode != "" {
		conf.Setup.InstallationCode = redacted
	}
	conf.Bindings = nil
	for _, binding := range c.Bindings {
		if binding.OIDC.ClientID != "" {
			binding.OIDC.ClientID = redacted
		}
		if binding.OIDC.ClientSecret != "" {
			binding.OIDC.ClientSecret = redacted
		}
		conf.Bindings = append(conf.Bindings, binding)
	}
	return conf
}

// Initialize configures and starts the HTTP server
func (c *Conf) Initialize(configDir string) error {
	logger.Info(logSender, "", "initializing HTTP server with config %+v", c.getRedacted())
	staticFilesPath := getConfigPath(c.StaticFilesPath, configDir)
	templatesPath := getConfigPath(c.TemplatesPath, configDir)
	openAPIPath := getConfigPath(c.OpenAPIPath, configDir)
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
		binding.checkWebClientIntegrations()
		binding.checkExtraCSS()
		binding.Security.updateProxyHeaders()

		go func(b Binding) {
			if err := b.OIDC.initialize(); err != nil {
				exitChannel <- err
				return
			}
			server := newHttpdServer(b, staticFilesPath, c.SigningPassphrase, c.Cors, openAPIPath)

			exitChannel <- server.listenAndServe()
		}(binding)
	}

	maxUploadFileSize = c.MaxUploadFileSize
	installationCode = c.Setup.InstallationCode
	installationCodeHint = c.Setup.InstallationCodeHint
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

func getServicesStatus() *ServicesStatus {
	status := &ServicesStatus{
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
	webOIDCRedirectPath = path.Join(baseURL, webOIDCRedirectPathDefault)
	webClientLoginPath = path.Join(baseURL, webClientLoginPathDefault)
	webClientOIDCLoginPath = path.Join(baseURL, webClientOIDCLoginPathDefault)
	webClientTwoFactorPath = path.Join(baseURL, webClientTwoFactorPathDefault)
	webClientTwoFactorRecoveryPath = path.Join(baseURL, webClientTwoFactorRecoveryPathDefault)
	webClientFilesPath = path.Join(baseURL, webClientFilesPathDefault)
	webClientFilePath = path.Join(baseURL, webClientFilePathDefault)
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
	webClientViewPDFPath = path.Join(baseURL, webClientViewPDFPathDefault)
}

func updateWebAdminURLs(baseURL string) {
	if !path.IsAbs(baseURL) {
		baseURL = "/"
	}
	webRootPath = path.Join(baseURL, webRootPathDefault)
	webBasePath = path.Join(baseURL, webBasePathDefault)
	webBaseAdminPath = path.Join(baseURL, webBasePathAdminDefault)
	webOIDCRedirectPath = path.Join(baseURL, webOIDCRedirectPathDefault)
	webAdminSetupPath = path.Join(baseURL, webAdminSetupPathDefault)
	webAdminLoginPath = path.Join(baseURL, webAdminLoginPathDefault)
	webAdminOIDCLoginPath = path.Join(baseURL, webAdminOIDCLoginPathDefault)
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
	webOpenAPIPath = path.Join(baseURL, webOpenAPIPathDefault)
}

// GetHTTPRouter returns an HTTP handler suitable to use for test cases
func GetHTTPRouter(b Binding) http.Handler {
	server := newHttpdServer(b, "../static", "", CorsConfig{}, "../openapi")
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

// SetInstallationCodeResolver sets a function to call to resolve the installation code
func SetInstallationCodeResolver(fn FnInstallationCodeResolver) {
	fnInstallationCodeResolver = fn
}

func resolveInstallationCode() string {
	if fnInstallationCodeResolver != nil {
		return fnInstallationCodeResolver(installationCode)
	}
	return installationCode
}
