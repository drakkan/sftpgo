// Package telemetry provides telemetry information for SFTPGo, such as:
//		- health information (for health checks)
//		- metrics
// 		- profiling information
package telemetry

import (
	"crypto/tls"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-chi/chi"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const (
	logSender     = "telemetry"
	metricsPath   = "/metrics"
	pprofBasePath = "/debug"
)

var (
	router   *chi.Mux
	httpAuth common.HTTPAuthProvider
	certMgr  *common.CertManager
)

// Conf telemetry server configuration.
type Conf struct {
	// The port used for serving HTTP requests. 0 disable the HTTP server. Default: 10000
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces. Default: "127.0.0.1"
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// Enable the built-in profiler.
	// The profiler will be accessible via HTTP/HTTPS using the base URL "/debug/pprof/"
	EnableProfiler bool `json:"enable_profiler" mapstructure:"enable_profiler"`
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

// ShouldBind returns true if there service must be started
func (c Conf) ShouldBind() bool {
	if c.BindPort > 0 {
		return true
	}
	if filepath.IsAbs(c.BindAddress) && runtime.GOOS != "windows" {
		return true
	}
	return false
}

// Initialize configures and starts the telemetry server.
func (c Conf) Initialize(configDir string) error {
	var err error
	logger.Debug(logSender, "", "initializing telemetry server with config %+v", c)
	authUserFile := getConfigPath(c.AuthUserFile, configDir)
	httpAuth, err = common.NewBasicAuthProvider(authUserFile)
	if err != nil {
		return err
	}
	certificateFile := getConfigPath(c.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(c.CertificateKeyFile, configDir)
	initializeRouter(c.EnableProfiler)
	httpServer := &http.Server{
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 14, // 16KB
		ErrorLog:       log.New(&logger.StdLoggerWrapper{Sender: logSender}, "", 0),
	}
	if certificateFile != "" && certificateKeyFile != "" {
		certMgr, err = common.NewCertManager(certificateFile, certificateKeyFile, logSender)
		if err != nil {
			return err
		}
		config := &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(),
			MinVersion:     tls.VersionTLS12,
		}
		httpServer.TLSConfig = config
		return utils.HTTPListenAndServe(httpServer, c.BindAddress, c.BindPort, true, logSender)
	}
	return utils.HTTPListenAndServe(httpServer, c.BindAddress, c.BindPort, false, logSender)
}

// ReloadTLSCertificate reloads the TLS certificate and key from the configured paths
func ReloadTLSCertificate() error {
	if certMgr != nil {
		return certMgr.LoadCertificate(logSender)
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
