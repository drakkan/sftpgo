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

// Package webdavd implements the WebDAV protocol
package webdavd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
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
	timeFormats   = []string{
		http.TimeFormat,
		"Mon, _2 Jan 2006 15:04:05 GMT",
		time.RFC850,
		time.ANSIC,
	}
)

// ServiceStatus defines the service status
type ServiceStatus struct {
	IsActive bool      `json:"is_active"`
	Bindings []Binding `json:"bindings"`
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

// CustomMimeMapping defines additional, user defined mime mappings
type CustomMimeMapping struct {
	Ext  string `json:"ext" mapstructure:"ext"`
	Mime string `json:"mime" mapstructure:"mime"`
}

// UsersCacheConfig defines the cache configuration for users
type UsersCacheConfig struct {
	ExpirationTime int `json:"expiration_time" mapstructure:"expiration_time"`
	MaxSize        int `json:"max_size" mapstructure:"max_size"`
}

func (c *UsersCacheConfig) getExpirationTime() time.Time {
	if c.ExpirationTime > 0 {
		return time.Now().Add(time.Duration(c.ExpirationTime) * time.Minute)
	}
	return time.Time{}
}

// MimeCacheConfig defines the cache configuration for mime types
type MimeCacheConfig struct {
	Enabled        bool                `json:"enabled" mapstructure:"enabled"`
	MaxSize        int                 `json:"max_size" mapstructure:"max_size"`
	CustomMappings []CustomMimeMapping `json:"custom_mappings" mapstructure:"custom_mappings"`
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
	// HTTP protocols to enable in preference order. Supported values: http/1.1, h2
	Protocols []string `json:"tls_protocols" mapstructure:"tls_protocols"`
	// Prefix for WebDAV resources, if empty WebDAV resources will be available at the
	// root ("/") URI. If defined it must be an absolute URI.
	Prefix string `json:"prefix" mapstructure:"prefix"`
	// List of IP addresses and IP ranges allowed to set client IP proxy headers
	ProxyAllowed []string `json:"proxy_allowed" mapstructure:"proxy_allowed"`
	// Allowed client IP proxy header such as "X-Forwarded-For", "X-Real-IP"
	ClientIPProxyHeader string `json:"client_ip_proxy_header" mapstructure:"client_ip_proxy_header"`
	// Some client IP headers such as "X-Forwarded-For" can contain multiple IP address, this setting
	// define the position to trust starting from the right. For example if we have:
	// "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1" and the depth is 0, SFTPGo will use "13.0.0.1"
	// as client IP, if depth is 1, "12.0.0.1" will be used and so on
	ClientIPHeaderDepth int `json:"client_ip_header_depth" mapstructure:"client_ip_header_depth"`
	// Do not add the WWW-Authenticate header after an authentication error,
	// only the 401 status code will be sent
	DisableWWWAuthHeader bool `json:"disable_www_auth_header" mapstructure:"disable_www_auth_header"`
	allowHeadersFrom     []func(net.IP) bool
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
	// If files containing a certificate and matching private key for the server are provided you
	// can enable HTTPS connections for the configured bindings
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
	Cache      Cache `json:"cache" mapstructure:"cache"`
	acmeDomain string
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

func (c *Configuration) getKeyPairs(configDir string) []common.TLSKeyPair {
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

func (c *Configuration) loadFromProvider() error {
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		return fmt.Errorf("unable to load config from provider: %w", err)
	}
	configs.SetNilsToEmpty()
	if configs.ACME.Domain == "" || !configs.ACME.HasProtocol(common.ProtocolWebDAV) {
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
			c.Bindings[idx].EnableHTTPS = true
		}
		c.acmeDomain = configs.ACME.Domain
		logger.Info(logSender, "", "acme domain set to %q", c.acmeDomain)
		return nil
	}
	return nil
}

// Initialize configures and starts the WebDAV server
func (c *Configuration) Initialize(configDir string) error {
	if err := c.loadFromProvider(); err != nil {
		return err
	}
	logger.Info(logSender, "", "initializing WebDAV server with config %+v", *c)
	mimeTypeCache = mimeCache{
		maxSize:   c.Cache.MimeTypes.MaxSize,
		mimeTypes: make(map[string]string),
	}
	if !c.Cache.MimeTypes.Enabled {
		mimeTypeCache.maxSize = 0
	} else {
		customMimeTypeMapping = make(map[string]string)
		for _, m := range c.Cache.MimeTypes.CustomMappings {
			if m.Mime != "" {
				logger.Debug(logSender, "", "adding custom mime mapping for extension %q, mime type %q", m.Ext, m.Mime)
				customMimeTypeMapping[m.Ext] = m.Mime
			}
		}
	}

	if !c.ShouldBind() {
		return common.ErrNoBinding
	}

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

func parseTime(text string) (t time.Time, err error) {
	for _, layout := range timeFormats {
		t, err = time.Parse(layout, text)
		if err == nil {
			return
		}
	}
	return
}
