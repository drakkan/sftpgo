// Package webdavd implements the WebDAV protocol
package webdavd

import (
	"path/filepath"

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
	server *webDavServer
)

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

// Cache configuration
type Cache struct {
	Enabled        bool `json:"enabled" mapstructure:"enabled"`
	ExpirationTime int  `json:"expiration_time" mapstructure:"expiration_time"`
	MaxSize        int  `json:"max_size" mapstructure:"max_size"`
}

// Configuration defines the configuration for the WevDAV server
type Configuration struct {
	// The port used for serving FTP requests
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces.
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// If files containing a certificate and matching private key for the server are provided the server will expect
	// HTTPS connections.
	// Certificate and key files can be reloaded on demand sending a "SIGHUP" signal on Unix based systems and a
	// "paramchange" request to the running service on Windows.
	CertificateFile    string `json:"certificate_file" mapstructure:"certificate_file"`
	CertificateKeyFile string `json:"certificate_key_file" mapstructure:"certificate_key_file"`
	// CORS configuration
	Cors Cors `json:"cors" mapstructure:"cors"`
	// Cache configuration
	Cache Cache `json:"cache" mapstructure:"cache"`
}

// Initialize configures and starts the WebDav server
func (c *Configuration) Initialize(configDir string) error {
	var err error
	logger.Debug(logSender, "", "initializing WevDav server with config %+v", *c)
	server, err = newServer(c, configDir)
	if err != nil {
		return err
	}
	return server.listenAndServe()
}

// ReloadTLSCertificate reloads the TLS certificate and key from the configured paths
func ReloadTLSCertificate() error {
	if server != nil && server.certMgr != nil {
		return server.certMgr.LoadCertificate(logSender)
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
