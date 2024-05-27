// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package httpd implements REST API and Web interface for SFTPGo.
// The OpenAPI 3 schema for the supported API can be found inside the source tree:
// https://github.com/drakkan/sftpgo/blob/main/openapi/openapi.yaml
package httpd

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"

	"github.com/drakkan/sftpgo/v2/internal/acme"
	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

const (
	logSender                             = "httpd"
	tokenPath                             = "/api/v2/token"
	logoutPath                            = "/api/v2/logout"
	userTokenPath                         = "/api/v2/user/token"
	userLogoutPath                        = "/api/v2/user/logout"
	activeConnectionsPath                 = "/api/v2/connections"
	quotasBasePath                        = "/api/v2/quotas"
	userPath                              = "/api/v2/users"
	versionPath                           = "/api/v2/version"
	folderPath                            = "/api/v2/folders"
	groupPath                             = "/api/v2/groups"
	serverStatusPath                      = "/api/v2/status"
	dumpDataPath                          = "/api/v2/dumpdata"
	loadDataPath                          = "/api/v2/loaddata"
	defenderHosts                         = "/api/v2/defender/hosts"
	adminPath                             = "/api/v2/admins"
	adminPwdPath                          = "/api/v2/admin/changepwd"
	adminProfilePath                      = "/api/v2/admin/profile"
	userPwdPath                           = "/api/v2/user/changepwd"
	userDirsPath                          = "/api/v2/user/dirs"
	userFilesPath                         = "/api/v2/user/files"
	userFileActionsPath                   = "/api/v2/user/file-actions"
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
	fsEventsPath                          = "/api/v2/events/fs"
	providerEventsPath                    = "/api/v2/events/provider"
	logEventsPath                         = "/api/v2/events/logs"
	sharesPath                            = "/api/v2/shares"
	eventActionsPath                      = "/api/v2/eventactions"
	eventRulesPath                        = "/api/v2/eventrules"
	rolesPath                             = "/api/v2/roles"
	ipListsPath                           = "/api/v2/iplists"
	healthzPath                           = "/healthz"
	webRootPathDefault                    = "/"
	webBasePathDefault                    = "/web"
	webBasePathAdminDefault               = "/web/admin"
	webBasePathClientDefault              = "/web/client"
	webAdminSetupPathDefault              = "/web/admin/setup"
	webAdminLoginPathDefault              = "/web/admin/login"
	webAdminOIDCLoginPathDefault          = "/web/admin/oidclogin"
	webOIDCRedirectPathDefault            = "/web/oidc/redirect"
	webOAuth2RedirectPathDefault          = "/web/oauth2/redirect"
	webOAuth2TokenPathDefault             = "/web/admin/oauth2/token"
	webAdminTwoFactorPathDefault          = "/web/admin/twofactor"
	webAdminTwoFactorRecoveryPathDefault  = "/web/admin/twofactor-recovery"
	webLogoutPathDefault                  = "/web/admin/logout"
	webUsersPathDefault                   = "/web/admin/users"
	webUserPathDefault                    = "/web/admin/user"
	webConnectionsPathDefault             = "/web/admin/connections"
	webFoldersPathDefault                 = "/web/admin/folders"
	webFolderPathDefault                  = "/web/admin/folder"
	webGroupsPathDefault                  = "/web/admin/groups"
	webGroupPathDefault                   = "/web/admin/group"
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
	webAdminEventRulesPathDefault         = "/web/admin/eventrules"
	webAdminEventRulePathDefault          = "/web/admin/eventrule"
	webAdminEventActionsPathDefault       = "/web/admin/eventactions"
	webAdminEventActionPathDefault        = "/web/admin/eventaction"
	webAdminRolesPathDefault              = "/web/admin/roles"
	webAdminRolePathDefault               = "/web/admin/role"
	webAdminTOTPGeneratePathDefault       = "/web/admin/totp/generate"
	webAdminTOTPValidatePathDefault       = "/web/admin/totp/validate"
	webAdminTOTPSavePathDefault           = "/web/admin/totp/save"
	webAdminRecoveryCodesPathDefault      = "/web/admin/recoverycodes"
	webTemplateUserDefault                = "/web/admin/template/user"
	webTemplateFolderDefault              = "/web/admin/template/folder"
	webDefenderPathDefault                = "/web/admin/defender"
	webIPListsPathDefault                 = "/web/admin/ip-lists"
	webIPListPathDefault                  = "/web/admin/ip-list"
	webDefenderHostsPathDefault           = "/web/admin/defender/hosts"
	webEventsPathDefault                  = "/web/admin/events"
	webEventsFsSearchPathDefault          = "/web/admin/events/fs"
	webEventsProviderSearchPathDefault    = "/web/admin/events/provider"
	webEventsLogSearchPathDefault         = "/web/admin/events/logs"
	webConfigsPathDefault                 = "/web/admin/configs"
	webClientLoginPathDefault             = "/web/client/login"
	webClientOIDCLoginPathDefault         = "/web/client/oidclogin"
	webClientTwoFactorPathDefault         = "/web/client/twofactor"
	webClientTwoFactorRecoveryPathDefault = "/web/client/twofactor-recovery"
	webClientFilesPathDefault             = "/web/client/files"
	webClientFilePathDefault              = "/web/client/file"
	webClientFileActionsPathDefault       = "/web/client/file-actions"
	webClientSharesPathDefault            = "/web/client/shares"
	webClientSharePathDefault             = "/web/client/share"
	webClientEditFilePathDefault          = "/web/client/editfile"
	webClientDirsPathDefault              = "/web/client/dirs"
	webClientDownloadZipPathDefault       = "/web/client/downloadzip"
	webClientProfilePathDefault           = "/web/client/profile"
	webClientPingPathDefault              = "/web/client/ping"
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
	webClientGetPDFPathDefault            = "/web/client/getpdf"
	webClientExistPathDefault             = "/web/client/exist"
	webClientTasksPathDefault             = "/web/client/tasks"
	webStaticFilesPathDefault             = "/static"
	webOpenAPIPathDefault                 = "/openapi"
	// MaxRestoreSize defines the max size for the loaddata input file
	MaxRestoreSize       = 20 * 1048576 // 20 MB
	maxRequestSize       = 1048576      // 1MB
	maxLoginBodySize     = 262144       // 256 KB
	httpdMaxEditFileSize = 2 * 1048576  // 2 MB
	maxMultipartMem      = 10 * 1048576 // 10 MB
	osWindows            = "windows"
	otpHeaderCode        = "X-SFTPGO-OTP"
	mTimeHeader          = "X-SFTPGO-MTIME"
	acmeChallengeURI     = "/.well-known/acme-challenge/"
)

var (
	certMgr                        *common.CertManager
	cleanupTicker                  *time.Ticker
	cleanupDone                    chan bool
	invalidatedJWTTokens           tokenManager
	csrfTokenAuth                  *jwtauth.JWTAuth
	webRootPath                    string
	webBasePath                    string
	webBaseAdminPath               string
	webBaseClientPath              string
	webOIDCRedirectPath            string
	webOAuth2RedirectPath          string
	webOAuth2TokenPath             string
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
	webGroupsPath                  string
	webGroupPath                   string
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
	webAdminEventRulesPath         string
	webAdminEventRulePath          string
	webAdminEventActionsPath       string
	webAdminEventActionPath        string
	webAdminRolesPath              string
	webAdminRolePath               string
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
	webIPListPath                  string
	webIPListsPath                 string
	webEventsPath                  string
	webEventsFsSearchPath          string
	webEventsProviderSearchPath    string
	webEventsLogSearchPath         string
	webConfigsPath                 string
	webDefenderHostsPath           string
	webClientLoginPath             string
	webClientOIDCLoginPath         string
	webClientTwoFactorPath         string
	webClientTwoFactorRecoveryPath string
	webClientFilesPath             string
	webClientFilePath              string
	webClientFileActionsPath       string
	webClientSharesPath            string
	webClientSharePath             string
	webClientEditFilePath          string
	webClientDirsPath              string
	webClientDownloadZipPath       string
	webClientProfilePath           string
	webClientPingPath              string
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
	webClientGetPDFPath            string
	webClientExistPath             string
	webClientTasksPath             string
	webStaticFilesPath             string
	webOpenAPIPath                 string
	// max upload size for http clients, 1GB by default
	maxUploadFileSize          = int64(1048576000)
	hideSupportLink            bool
	installationCode           string
	installationCodeHint       string
	fnInstallationCodeResolver FnInstallationCodeResolver
	configurationDir           string
)

func init() {
	updateWebAdminURLs("")
	updateWebClientURLs("")
	acme.SetReloadHTTPDCertsFn(ReloadCertificateMgr)
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
	proxyHeaders            []string
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

func (s *SecurityConf) redirectHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isTLS(r) && !strings.HasPrefix(r.RequestURI, acmeChallengeURI) {
			url := r.URL
			url.Scheme = "https"
			if s.HTTPSHost != "" {
				url.Host = s.HTTPSHost
			} else {
				host := r.Host
				for _, header := range s.HostsProxyHeaders {
					if h := r.Header.Get(header); h != "" {
						host = h
						break
					}
				}
				url.Host = host
			}
			http.Redirect(w, r, url.String(), http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// UIBranding defines the supported customizations for the web UIs
type UIBranding struct {
	// Name defines the text to show at the login page and as HTML title
	Name string `json:"name" mapstructure:"name"`
	// ShortName defines the name to show next to the logo image
	ShortName string `json:"short_name" mapstructure:"short_name"`
	// Path to your logo relative to "static_files_path".
	// For example, if you create a directory named "branding" inside the static dir and
	// put the "mylogo.png" file in it, you must set "/branding/mylogo.png" as logo path.
	LogoPath string `json:"logo_path" mapstructure:"logo_path"`
	// Path to your favicon relative to "static_files_path"
	FaviconPath string `json:"favicon_path" mapstructure:"favicon_path"`
	// DisclaimerName defines the name for the link to your optional disclaimer
	DisclaimerName string `json:"disclaimer_name" mapstructure:"disclaimer_name"`
	// Path to the HTML page for your disclaimer relative to "static_files_path"
	// or an absolute http/https URL.
	DisclaimerPath string `json:"disclaimer_path" mapstructure:"disclaimer_path"`
	// Path to custom CSS files, relative to "static_files_path", which replaces
	// the default CSS files
	DefaultCSS []string `json:"default_css" mapstructure:"default_css"`
	// Additional CSS file paths, relative to "static_files_path", to include
	ExtraCSS []string `json:"extra_css" mapstructure:"extra_css"`
}

func (b *UIBranding) check() {
	if b.LogoPath != "" {
		b.LogoPath = util.CleanPath(b.LogoPath)
	} else {
		b.LogoPath = "/img/logo.png"
	}
	if b.FaviconPath != "" {
		b.FaviconPath = util.CleanPath(b.FaviconPath)
	} else {
		b.FaviconPath = "/favicon.ico"
	}
	if b.DisclaimerPath != "" {
		if !strings.HasPrefix(b.DisclaimerPath, "https://") && !strings.HasPrefix(b.DisclaimerPath, "http://") {
			b.DisclaimerPath = path.Join(webStaticFilesPath, util.CleanPath(b.DisclaimerPath))
		}
	}
	if len(b.DefaultCSS) > 0 {
		for idx := range b.DefaultCSS {
			b.DefaultCSS[idx] = util.CleanPath(b.DefaultCSS[idx])
		}
	} else {
		b.DefaultCSS = []string{
			"/assets/plugins/global/plugins.bundle.css",
			"/assets/css/style.bundle.css",
		}
	}
	for idx := range b.ExtraCSS {
		b.ExtraCSS[idx] = util.CleanPath(b.ExtraCSS[idx])
	}
}

// Branding defines the branding-related customizations supported
type Branding struct {
	WebAdmin  UIBranding `json:"web_admin" mapstructure:"web_admin"`
	WebClient UIBranding `json:"web_client" mapstructure:"web_client"`
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
	// Enable REST API
	EnableRESTAPI bool `json:"enable_rest_api" mapstructure:"enable_rest_api"`
	// Defines the login methods available for the WebAdmin and WebClient UIs:
	//
	// - 0 means any configured method: username/password login form and OIDC, if enabled
	// - 1 means OIDC for the WebAdmin UI
	// - 2 means OIDC for the WebClient UI
	// - 4 means login form for the WebAdmin UI
	// - 8 means login form for the WebClient UI
	//
	// You can combine the values. For example 3 means that you can only login using OIDC on
	// both WebClient and WebAdmin UI.
	EnabledLoginMethods int `json:"enabled_login_methods" mapstructure:"enabled_login_methods"`
	// you also need to provide a certificate for enabling HTTPS
	EnableHTTPS bool `json:"enable_https" mapstructure:"enable_https"`
	// Certificate and matching private key for this specific binding, if empty the global
	// ones will be used, if any
	CertificateFile    string `json:"certificate_file" mapstructure:"certificate_file"`
	CertificateKeyFile string `json:"certificate_key_file" mapstructure:"certificate_key_file"`
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
	// https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go#L53
	//
	// any invalid name will be silently ignored.
	// The order matters, the ciphers listed first will be the preferred ones.
	TLSCipherSuites []string `json:"tls_cipher_suites" mapstructure:"tls_cipher_suites"`
	// HTTP protocols in preference order. Supported values: http/1.1, h2
	Protocols []string `json:"tls_protocols" mapstructure:"tls_protocols"`
	// List of IP addresses and IP ranges allowed to set client IP proxy headers and
	// X-Forwarded-Proto header.
	ProxyAllowed []string `json:"proxy_allowed" mapstructure:"proxy_allowed"`
	// Allowed client IP proxy header such as "X-Forwarded-For", "X-Real-IP"
	ClientIPProxyHeader string `json:"client_ip_proxy_header" mapstructure:"client_ip_proxy_header"`
	// Some client IP headers such as "X-Forwarded-For" can contain multiple IP address, this setting
	// define the position to trust starting from the right. For example if we have:
	// "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1" and the depth is 0, SFTPGo will use "13.0.0.1"
	// as client IP, if depth is 1, "12.0.0.1" will be used and so on
	ClientIPHeaderDepth int `json:"client_ip_header_depth" mapstructure:"client_ip_header_depth"`
	// If both web admin and web client are enabled each login page will show a link
	// to the other one. This setting allows to hide this link:
	// - 0 login links are displayed on both admin and client login page. This is the default
	// - 1 the login link to the web client login page is hidden on admin login page
	// - 2 the login link to the web admin login page is hidden on client login page
	// The flags can be combined, for example 3 will disable both login links.
	HideLoginURL int `json:"hide_login_url" mapstructure:"hide_login_url"`
	// Enable the built-in OpenAPI renderer
	RenderOpenAPI bool `json:"render_openapi" mapstructure:"render_openapi"`
	// Defining an OIDC configuration the web admin and web client UI will use OpenID to authenticate users.
	OIDC OIDC `json:"oidc" mapstructure:"oidc"`
	// Security defines security headers to add to HTTP responses and allows to restrict allowed hosts
	Security SecurityConf `json:"security" mapstructure:"security"`
	// Branding defines customizations to suit your brand
	Branding         Branding `json:"branding" mapstructure:"branding"`
	allowHeadersFrom []func(net.IP) bool
}

func (b *Binding) checkBranding() {
	b.Branding.WebAdmin.check()
	b.Branding.WebClient.check()
	if b.Branding.WebAdmin.Name == "" {
		b.Branding.WebAdmin.Name = "SFTPGo WebAdmin"
	}
	if b.Branding.WebAdmin.ShortName == "" {
		b.Branding.WebAdmin.ShortName = "WebAdmin"
	}
	if b.Branding.WebClient.Name == "" {
		b.Branding.WebClient.Name = "SFTPGo WebClient"
	}
	if b.Branding.WebClient.ShortName == "" {
		b.Branding.WebClient.ShortName = "WebClient"
	}
}

func (b *Binding) parseAllowedProxy() error {
	if filepath.IsAbs(b.Address) && len(b.ProxyAllowed) > 0 {
		// unix domain socket
		b.allowHeadersFrom = []func(net.IP) bool{func(_ net.IP) bool { return true }}
		return nil
	}
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
	if !b.EnableRESTAPI && !b.EnableWebAdmin && !b.EnableWebClient {
		return false
	}
	if b.Port > 0 {
		return true
	}
	if filepath.IsAbs(b.Address) && runtime.GOOS != osWindows {
		return true
	}
	return false
}

func (b *Binding) isWebAdminOIDCLoginDisabled() bool {
	if b.EnableWebAdmin {
		if b.EnabledLoginMethods == 0 {
			return false
		}
		return b.EnabledLoginMethods&1 == 0
	}
	return false
}

func (b *Binding) isWebClientOIDCLoginDisabled() bool {
	if b.EnableWebClient {
		if b.EnabledLoginMethods == 0 {
			return false
		}
		return b.EnabledLoginMethods&2 == 0
	}
	return false
}

func (b *Binding) isWebAdminLoginFormDisabled() bool {
	if b.EnableWebAdmin {
		if b.EnabledLoginMethods == 0 {
			return false
		}
		return b.EnabledLoginMethods&4 == 0
	}
	return false
}

func (b *Binding) isWebClientLoginFormDisabled() bool {
	if b.EnableWebClient {
		if b.EnabledLoginMethods == 0 {
			return false
		}
		return b.EnabledLoginMethods&8 == 0
	}
	return false
}

func (b *Binding) checkLoginMethods() error {
	if b.isWebAdminLoginFormDisabled() && b.isWebAdminOIDCLoginDisabled() {
		return errors.New("no login method available for WebAdmin UI")
	}
	if !b.isWebAdminOIDCLoginDisabled() {
		if b.isWebAdminLoginFormDisabled() && !b.OIDC.hasRoles() {
			return errors.New("no login method available for WebAdmin UI")
		}
	}
	if b.isWebClientLoginFormDisabled() && b.isWebClientOIDCLoginDisabled() {
		return errors.New("no login method available for WebClient UI")
	}
	if !b.isWebClientOIDCLoginDisabled() {
		if b.isWebClientLoginFormDisabled() && !b.OIDC.isEnabled() {
			return errors.New("no login method available for WebClient UI")
		}
	}
	return nil
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

type allowListStatus struct {
	IsActive bool `json:"is_active"`
}

type rateLimiters struct {
	IsActive  bool     `json:"is_active"`
	Protocols []string `json:"protocols"`
}

// GetProtocolsAsString returns the enabled protocols as comma separated string
func (r *rateLimiters) GetProtocolsAsString() string {
	return strings.Join(r.Protocols, ", ")
}

// ServicesStatus keep the state of the running services
type ServicesStatus struct {
	SSH          sftpd.ServiceStatus         `json:"ssh"`
	FTP          ftpd.ServiceStatus          `json:"ftp"`
	WebDAV       webdavd.ServiceStatus       `json:"webdav"`
	DataProvider dataprovider.ProviderStatus `json:"data_provider"`
	Defender     defenderStatus              `json:"defender"`
	MFA          mfa.ServiceStatus           `json:"mfa"`
	AllowList    allowListStatus             `json:"allow_list"`
	RateLimiters rateLimiters                `json:"rate_limiters"`
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
	AllowedOrigins       []string `json:"allowed_origins" mapstructure:"allowed_origins"`
	AllowedMethods       []string `json:"allowed_methods" mapstructure:"allowed_methods"`
	AllowedHeaders       []string `json:"allowed_headers" mapstructure:"allowed_headers"`
	ExposedHeaders       []string `json:"exposed_headers" mapstructure:"exposed_headers"`
	AllowCredentials     bool     `json:"allow_credentials" mapstructure:"allow_credentials"`
	Enabled              bool     `json:"enabled" mapstructure:"enabled"`
	MaxAge               int      `json:"max_age" mapstructure:"max_age"`
	OptionsPassthrough   bool     `json:"options_passthrough" mapstructure:"options_passthrough"`
	OptionsSuccessStatus int      `json:"options_success_status" mapstructure:"options_success_status"`
	AllowPrivateNetwork  bool     `json:"allow_private_network" mapstructure:"allow_private_network"`
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
	// If files containing a certificate and matching private key for the server are provided you can enable
	// HTTPS connections for the configured bindings.
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
	SigningPassphrase     string `json:"signing_passphrase" mapstructure:"signing_passphrase"`
	SigningPassphraseFile string `json:"signing_passphrase_file" mapstructure:"signing_passphrase_file"`
	// TokenValidation allows to define how to validate JWT tokens, cookies and CSRF tokens.
	// By default all the available security checks are enabled. Set to 1 to disable the requirement
	// that a token must be used by the same IP for which it was issued.
	TokenValidation int `json:"token_validation" mapstructure:"token_validation"`
	// MaxUploadFileSize Defines the maximum request body size, in bytes, for Web Client/API HTTP upload requests.
	// 0 means no limit
	MaxUploadFileSize int64 `json:"max_upload_file_size" mapstructure:"max_upload_file_size"`
	// CORS configuration
	Cors CorsConfig `json:"cors" mapstructure:"cors"`
	// Initial setup configuration
	Setup SetupConfig `json:"setup" mapstructure:"setup"`
	// If enabled, the link to the sponsors section will not appear on the setup screen page
	HideSupportLink bool `json:"hide_support_link" mapstructure:"hide_support_link"`
	acmeDomain      string
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
		return fmt.Errorf("required directory is invalid, static file path: %q template path: %q",
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

func (c *Conf) getKeyPairs(configDir string) []common.TLSKeyPair {
	var keyPairs []common.TLSKeyPair

	for _, binding := range c.Bindings {
		certificateFile := getConfigPath(binding.CertificateFile, configDir)
		certificateKeyFile := getConfigPath(binding.CertificateKeyFile, configDir)
		if certificateFile != "" && certificateKeyFile != "" {
			keyPairs = append(keyPairs, common.TLSKeyPair{
				Cert: certificateFile,
				Key:  certificateKeyFile,
				ID:   binding.GetAddress(),
			})
		}
	}
	var certificateFile, certificateKeyFile string
	if c.acmeDomain != "" {
		certificateFile, certificateKeyFile = util.GetACMECertificateKeyPair(c.acmeDomain)
	} else {
		certificateFile = getConfigPath(c.CertificateFile, configDir)
		certificateKeyFile = getConfigPath(c.CertificateKeyFile, configDir)
	}
	if certificateFile != "" && certificateKeyFile != "" {
		keyPairs = append(keyPairs, common.TLSKeyPair{
			Cert: certificateFile,
			Key:  certificateKeyFile,
			ID:   common.DefaultTLSKeyPaidID,
		})
	}
	return keyPairs
}

func (c *Conf) setTokenValidationMode() {
	if c.TokenValidation == 1 {
		tokenValidationMode = tokenValidationNoIPMatch
	} else {
		tokenValidationMode = tokenValidationFull
	}
}

func (c *Conf) loadFromProvider() error {
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		return fmt.Errorf("unable to load config from provider: %w", err)
	}
	configs.SetNilsToEmpty()
	if configs.ACME.Domain == "" || !configs.ACME.HasProtocol(common.ProtocolHTTP) {
		return nil
	}
	crt, key := util.GetACMECertificateKeyPair(configs.ACME.Domain)
	if crt != "" && key != "" {
		if _, err := os.Stat(crt); err != nil {
			logger.Error(logSender, "", "unable to load acme cert file %q: %v", crt, err)
			return nil
		}
		if _, err := os.Stat(key); err != nil {
			logger.Error(logSender, "", "unable to load acme key file %q: %v", key, err)
			return nil
		}
		for idx := range c.Bindings {
			if c.Bindings[idx].Security.Enabled && c.Bindings[idx].Security.HTTPSRedirect {
				continue
			}
			c.Bindings[idx].EnableHTTPS = true
		}
		c.acmeDomain = configs.ACME.Domain
		logger.Info(logSender, "", "acme domain set to %q", c.acmeDomain)
		return nil
	}
	return nil
}

func (c *Conf) loadTemplates(templatesPath string) {
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
}

// Initialize configures and starts the HTTP server
func (c *Conf) Initialize(configDir string, isShared int) error {
	if err := c.loadFromProvider(); err != nil {
		return err
	}
	logger.Info(logSender, "", "initializing HTTP server with config %+v", c.getRedacted())
	configurationDir = configDir
	invalidatedJWTTokens = newTokenManager(isShared)
	resetCodesMgr = newResetCodeManager(isShared)
	oidcMgr = newOIDCManager(isShared)
	oauth2Mgr = newOAuth2Manager(isShared)
	webTaskMgr = newWebTaskManager(isShared)
	staticFilesPath := util.FindSharedDataPath(c.StaticFilesPath, configDir)
	templatesPath := util.FindSharedDataPath(c.TemplatesPath, configDir)
	openAPIPath := util.FindSharedDataPath(c.OpenAPIPath, configDir)
	if err := c.checkRequiredDirs(staticFilesPath, templatesPath); err != nil {
		return err
	}
	c.loadTemplates(templatesPath)
	keyPairs := c.getKeyPairs(configDir)
	if len(keyPairs) > 0 {
		mgr, err := common.NewCertManager(keyPairs, configDir, logSender)
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

	if c.SigningPassphraseFile != "" {
		passphrase, err := util.ReadConfigFromFile(c.SigningPassphraseFile, configDir)
		if err != nil {
			return err
		}
		c.SigningPassphrase = passphrase
	}

	csrfTokenAuth = jwtauth.New(jwa.HS256.String(), getSigningKey(c.SigningPassphrase), nil)
	hideSupportLink = c.HideSupportLink

	exitChannel := make(chan error, 1)

	for _, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}
		if err := binding.parseAllowedProxy(); err != nil {
			return err
		}
		binding.checkBranding()
		binding.Security.updateProxyHeaders()

		go func(b Binding) {
			if err := b.OIDC.initialize(); err != nil {
				exitChannel <- err
				return
			}
			if err := b.checkLoginMethods(); err != nil {
				exitChannel <- err
				return
			}
			server := newHttpdServer(b, staticFilesPath, c.SigningPassphrase, c.Cors, openAPIPath)
			server.setShared(isShared)

			exitChannel <- server.listenAndServe()
		}(binding)
	}

	maxUploadFileSize = c.MaxUploadFileSize
	installationCode = c.Setup.InstallationCode
	installationCodeHint = c.Setup.InstallationCodeHint
	startCleanupTicker(tokenDuration / 2)
	c.setTokenValidationMode()
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
	rtlEnabled, rtlProtocols := common.Config.GetRateLimitersStatus()
	status := &ServicesStatus{
		SSH:          sftpd.GetStatus(),
		FTP:          ftpd.GetStatus(),
		WebDAV:       webdavd.GetStatus(),
		DataProvider: dataprovider.GetProviderStatus(),
		Defender: defenderStatus{
			IsActive: common.Config.DefenderConfig.Enabled,
		},
		MFA: mfa.GetStatus(),
		AllowList: allowListStatus{
			IsActive: common.Config.IsAllowListEnabled(),
		},
		RateLimiters: rateLimiters{
			IsActive:  rtlEnabled,
			Protocols: rtlProtocols,
		},
	}
	return status
}

func fileServer(r chi.Router, path string, root http.FileSystem, disableDirectoryIndex bool) {
	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		if disableDirectoryIndex {
			root = neuteredFileSystem{root}
		}
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
	webClientFileActionsPath = path.Join(baseURL, webClientFileActionsPathDefault)
	webClientSharesPath = path.Join(baseURL, webClientSharesPathDefault)
	webClientPubSharesPath = path.Join(baseURL, webClientPubSharesPathDefault)
	webClientSharePath = path.Join(baseURL, webClientSharePathDefault)
	webClientEditFilePath = path.Join(baseURL, webClientEditFilePathDefault)
	webClientDirsPath = path.Join(baseURL, webClientDirsPathDefault)
	webClientDownloadZipPath = path.Join(baseURL, webClientDownloadZipPathDefault)
	webClientProfilePath = path.Join(baseURL, webClientProfilePathDefault)
	webClientPingPath = path.Join(baseURL, webClientPingPathDefault)
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
	webClientGetPDFPath = path.Join(baseURL, webClientGetPDFPathDefault)
	webClientExistPath = path.Join(baseURL, webClientExistPathDefault)
	webClientTasksPath = path.Join(baseURL, webClientTasksPathDefault)
	webStaticFilesPath = path.Join(baseURL, webStaticFilesPathDefault)
	webOpenAPIPath = path.Join(baseURL, webOpenAPIPathDefault)
}

func updateWebAdminURLs(baseURL string) {
	if !path.IsAbs(baseURL) {
		baseURL = "/"
	}
	webRootPath = path.Join(baseURL, webRootPathDefault)
	webBasePath = path.Join(baseURL, webBasePathDefault)
	webBaseAdminPath = path.Join(baseURL, webBasePathAdminDefault)
	webOIDCRedirectPath = path.Join(baseURL, webOIDCRedirectPathDefault)
	webOAuth2RedirectPath = path.Join(baseURL, webOAuth2RedirectPathDefault)
	webOAuth2TokenPath = path.Join(baseURL, webOAuth2TokenPathDefault)
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
	webGroupsPath = path.Join(baseURL, webGroupsPathDefault)
	webGroupPath = path.Join(baseURL, webGroupPathDefault)
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
	webAdminEventRulesPath = path.Join(baseURL, webAdminEventRulesPathDefault)
	webAdminEventRulePath = path.Join(baseURL, webAdminEventRulePathDefault)
	webAdminEventActionsPath = path.Join(baseURL, webAdminEventActionsPathDefault)
	webAdminEventActionPath = path.Join(baseURL, webAdminEventActionPathDefault)
	webAdminRolesPath = path.Join(baseURL, webAdminRolesPathDefault)
	webAdminRolePath = path.Join(baseURL, webAdminRolePathDefault)
	webAdminTOTPGeneratePath = path.Join(baseURL, webAdminTOTPGeneratePathDefault)
	webAdminTOTPValidatePath = path.Join(baseURL, webAdminTOTPValidatePathDefault)
	webAdminTOTPSavePath = path.Join(baseURL, webAdminTOTPSavePathDefault)
	webAdminRecoveryCodesPath = path.Join(baseURL, webAdminRecoveryCodesPathDefault)
	webTemplateUser = path.Join(baseURL, webTemplateUserDefault)
	webTemplateFolder = path.Join(baseURL, webTemplateFolderDefault)
	webDefenderHostsPath = path.Join(baseURL, webDefenderHostsPathDefault)
	webDefenderPath = path.Join(baseURL, webDefenderPathDefault)
	webIPListPath = path.Join(baseURL, webIPListPathDefault)
	webIPListsPath = path.Join(baseURL, webIPListsPathDefault)
	webEventsPath = path.Join(baseURL, webEventsPathDefault)
	webEventsFsSearchPath = path.Join(baseURL, webEventsFsSearchPathDefault)
	webEventsProviderSearchPath = path.Join(baseURL, webEventsProviderSearchPathDefault)
	webEventsLogSearchPath = path.Join(baseURL, webEventsLogSearchPathDefault)
	webConfigsPath = path.Join(baseURL, webConfigsPathDefault)
	webStaticFilesPath = path.Join(baseURL, webStaticFilesPathDefault)
	webOpenAPIPath = path.Join(baseURL, webOpenAPIPathDefault)
}

// GetHTTPRouter returns an HTTP handler suitable to use for test cases
func GetHTTPRouter(b Binding) http.Handler {
	server := newHttpdServer(b, filepath.Join("..", "..", "static"), "", CorsConfig{}, filepath.Join("..", "..", "openapi"))
	server.initializeRouter()
	return server.router
}

// the ticker cannot be started/stopped from multiple goroutines
func startCleanupTicker(duration time.Duration) {
	stopCleanupTicker()
	cleanupTicker = time.NewTicker(duration)
	cleanupDone = make(chan bool)

	go func() {
		counter := int64(0)
		for {
			select {
			case <-cleanupDone:
				return
			case <-cleanupTicker.C:
				counter++
				invalidatedJWTTokens.Cleanup()
				resetCodesMgr.Cleanup()
				webTaskMgr.Cleanup()
				if counter%2 == 0 {
					oidcMgr.cleanup()
					oauth2Mgr.cleanup()
				}
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

type neuteredFileSystem struct {
	fs http.FileSystem
}

func (nfs neuteredFileSystem) Open(name string) (http.File, error) {
	f, err := nfs.fs.Open(name)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if s.IsDir() {
		index := path.Join(name, "index.html")
		if _, err := nfs.fs.Open(index); err != nil {
			defer f.Close()

			return nil, err
		}
	}

	return f, nil
}
