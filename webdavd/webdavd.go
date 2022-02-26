// Package webdavd implements the WebDAV protocol
package webdavd

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

type ctxReqParams int

const (
	requestIDKey ctxReqParams = iota
	requestStartKey
)

const (
	logSender = "webdavd"
)

var (
	certMgr       *common.CertManager
	serviceStatus ServiceStatus
)

// ServiceStatus defines the service status
type ServiceStatus struct {
	IsActive bool      `json:"is_active"`
	Bindings []Binding `json:"bindings"`
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

// UsersCacheConfig defines the cache configuration for users
type UsersCacheConfig struct {
	ExpirationTime int `json:"expiration_time" mapstructure:"expiration_time"`
	MaxSize        int `json:"max_size" mapstructure:"max_size"`
}

// MimeCacheConfig defines the cache configuration for mime types
type MimeCacheConfig struct {
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	MaxSize int  `json:"max_size" mapstructure:"max_size"`
}

// Cache configuration
type Cache struct {
	Users     UsersCacheConfig `json:"users" mapstructure:"users"`
	MimeTypes MimeCacheConfig  `json:"mime_types" mapstructure:"mime_types"`
}

// Binding defines the configuration for a network listener
type Binding struct {
	// The address to listen on. A blank value means listen on all available network interfaces.
	Address string `json:"address" mapstructure:"address"`
	// The port used for serving requests
	Port int `json:"port" mapstructure:"port"`
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
	// Prefix for WebDAV resources, if empty WebDAV resources will be available at the
	// root ("/") URI. If defined it must be an absolute URI.
	Prefix string `json:"prefix" mapstructure:"prefix"`
	// List of IP addresses and IP ranges allowed to set X-Forwarded-For/X-Real-IP headers.
	ProxyAllowed     []string `json:"proxy_allowed" mapstructure:"proxy_allowed"`
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

func (b *Binding) isMutualTLSEnabled() bool {
	return b.ClientAuthType == 1 || b.ClientAuthType == 2
}

// GetAddress returns the binding address
func (b *Binding) GetAddress() string {
	return fmt.Sprintf("%s:%d", b.Address, b.Port)
}

// IsValid returns true if the binding port is > 0
func (b *Binding) IsValid() bool {
	return b.Port > 0
}

// Configuration defines the configuration for the WevDAV server
type Configuration struct {
	// Addresses and ports to bind to
	Bindings []Binding `json:"bindings" mapstructure:"bindings"`
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
	// CORS configuration
	Cors CorsConfig `json:"cors" mapstructure:"cors"`
	// Cache configuration
	Cache Cache `json:"cache" mapstructure:"cache"`
}

// GetStatus returns the server status
func GetStatus() ServiceStatus {
	return serviceStatus
}

// ShouldBind returns true if there is at least a valid binding
func (c *Configuration) ShouldBind() bool {
	for _, binding := range c.Bindings {
		if binding.IsValid() {
			return true
		}
	}

	return false
}

// Initialize configures and starts the WebDAV server
func (c *Configuration) Initialize(configDir string) error {
	logger.Info(logSender, "", "initializing WebDAV server with config %+v", *c)
	mimeTypeCache = mimeCache{
		maxSize:   c.Cache.MimeTypes.MaxSize,
		mimeTypes: make(map[string]string),
	}
	if !c.Cache.MimeTypes.Enabled {
		mimeTypeCache.maxSize = 0
	}
	if !c.ShouldBind() {
		return common.ErrNoBinding
	}

	certificateFile := getConfigPath(c.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(c.CertificateKeyFile, configDir)
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
	compressor := middleware.NewCompressor(5, "text/*")
	dataprovider.InitializeWebDAVUserCache(c.Cache.Users.MaxSize)

	serviceStatus = ServiceStatus{
		Bindings: nil,
	}

	exitChannel := make(chan error, 1)

	for _, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}
		if err := binding.parseAllowedProxy(); err != nil {
			return err
		}

		go func(binding Binding) {
			server := webDavServer{
				config:  c,
				binding: binding,
			}
			exitChannel <- server.listenAndServe(compressor)
		}(binding)
	}

	serviceStatus.IsActive = true

	return <-exitChannel
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
