// Package webdavd implements the WebDAV protocol
package webdavd

import (
	"fmt"
	"path/filepath"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
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
	//server *webDavServer
	certMgr       *common.CertManager
	serviceStatus ServiceStatus
)

// ServiceStatus defines the service status
type ServiceStatus struct {
	IsActive bool      `json:"is_active"`
	Bindings []Binding `json:"bindings"`
}

// Cors configuration
type Cors struct {
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
	// set to 1 to require client certificate authentication in addition to basic auth.
	// You need to define at least a certificate authority for this to work
	ClientAuthType int `json:"client_auth_type" mapstructure:"client_auth_type"`
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
	// Deprecated: please use Bindings
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// Deprecated: please use Bindings
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
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
	Cors Cors `json:"cors" mapstructure:"cors"`
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
	logger.Debug(logSender, "", "initializing WebDAV server with config %+v", *c)
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

	serviceStatus = ServiceStatus{
		Bindings: nil,
	}

	exitChannel := make(chan error, 1)

	for _, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}

		go func(binding Binding) {
			server := webDavServer{
				config:  c,
				binding: binding,
			}
			exitChannel <- server.listenAndServe()
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
	if !utils.IsFileInputValid(name) {
		return ""
	}
	if name != "" && !filepath.IsAbs(name) {
		return filepath.Join(configDir, name)
	}
	return name
}
