// Package ftpd implements the FTP protocol
package ftpd

import (
	"fmt"
	"path/filepath"

	ftpserver "github.com/fclairamb/ftpserverlib"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const (
	logSender = "ftpd"
)

var (
	certMgr       *common.CertManager
	serviceStatus ServiceStatus
)

// Binding defines the configuration for a network listener
type Binding struct {
	// The address to listen on. A blank value means listen on all available network interfaces.
	Address string `json:"address" mapstructure:"address"`
	// The port used for serving requests
	Port int `json:"port" mapstructure:"port"`
	// apply the proxy configuration, if any, for this binding
	ApplyProxyConfig bool `json:"apply_proxy_config" mapstructure:"apply_proxy_config"`
	// set to 1 to require TLS for both data and control connection
	TLSMode int `json:"tls_mode" mapstructure:"tls_mode"`
	// External IP address to expose for passive connections.
	ForcePassiveIP string `json:"force_passive_ip" mapstructure:"force_passive_ip"`
}

// GetAddress returns the binding address
func (b *Binding) GetAddress() string {
	return fmt.Sprintf("%s:%d", b.Address, b.Port)
}

// IsValid returns true if the binding port is > 0
func (b *Binding) IsValid() bool {
	return b.Port > 0
}

// HasProxy returns true if the proxy protocol is active for this binding
func (b *Binding) HasProxy() bool {
	return b.ApplyProxyConfig && common.Config.ProxyProtocol > 0
}

// GetTLSDescription returns the TLS mode as string
func (b *Binding) GetTLSDescription() string {
	if certMgr == nil {
		return "Disabled"
	}
	switch b.TLSMode {
	case 1:
		return "Explicit required"
	case 2:
		return "Implicit"
	}

	return "Plain and explicit"
}

// PortRange defines a port range
type PortRange struct {
	// Range start
	Start int `json:"start" mapstructure:"start"`
	// Range end
	End int `json:"end" mapstructure:"end"`
}

// ServiceStatus defines the service status
type ServiceStatus struct {
	IsActive         bool      `json:"is_active"`
	Bindings         []Binding `json:"bindings"`
	PassivePortRange PortRange `json:"passive_port_range"`
}

// Configuration defines the configuration for the ftp server
type Configuration struct {
	// Addresses and ports to bind to
	Bindings []Binding `json:"bindings" mapstructure:"bindings"`
	// Deprecated: please use Bindings
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// Deprecated: please use Bindings
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// Deprecated: please use Bindings
	ForcePassiveIP string `json:"force_passive_ip" mapstructure:"force_passive_ip"`
	// Greeting banner displayed when a connection first comes in
	Banner string `json:"banner" mapstructure:"banner"`
	// the contents of the specified file, if any, are diplayed when someone connects to the server.
	// If set, it overrides the banner string provided by the banner option
	BannerFile string `json:"banner_file" mapstructure:"banner_file"`
	// If files containing a certificate and matching private key for the server are provided the server will accept
	// both plain FTP an explicit FTP over TLS.
	// Certificate and key files can be reloaded on demand sending a "SIGHUP" signal on Unix based systems and a
	// "paramchange" request to the running service on Windows.
	CertificateFile    string `json:"certificate_file" mapstructure:"certificate_file"`
	CertificateKeyFile string `json:"certificate_key_file" mapstructure:"certificate_key_file"`
	// Do not impose the port 20 for active data transfer. Enabling this option allows to run SFTPGo with less privilege
	ActiveTransfersPortNon20 bool `json:"active_transfers_port_non_20" mapstructure:"active_transfers_port_non_20"`
	// Port Range for data connections. Random if not specified
	PassivePortRange PortRange `json:"passive_port_range" mapstructure:"passive_port_range"`
	// Deprecated: please use Bindings
	TLSMode int `json:"tls_mode" mapstructure:"tls_mode"`
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

// Initialize configures and starts the FTP server
func (c *Configuration) Initialize(configDir string) error {
	logger.Debug(logSender, "", "initializing FTP server with config %+v", *c)
	if !c.ShouldBind() {
		return common.ErrNoBinding
	}

	certificateFile := getConfigPath(c.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(c.CertificateKeyFile, configDir)
	if certificateFile != "" && certificateKeyFile != "" {
		mgr, err := common.NewCertManager(certificateFile, certificateKeyFile, logSender)
		if err != nil {
			return err
		}
		certMgr = mgr
	}
	serviceStatus = ServiceStatus{
		Bindings:         nil,
		PassivePortRange: c.PassivePortRange,
	}

	exitChannel := make(chan error)

	for idx, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}

		server := NewServer(c, configDir, binding, idx)

		go func(s *Server) {
			ftpServer := ftpserver.NewFtpServer(s)
			exitChannel <- ftpServer.ListenAndServe()
		}(server)

		serviceStatus.Bindings = append(serviceStatus.Bindings, binding)
	}

	serviceStatus.IsActive = true

	return <-exitChannel
}

// ReloadTLSCertificate reloads the TLS certificate and key from the configured paths
func ReloadTLSCertificate() error {
	if certMgr != nil {
		return certMgr.LoadCertificate(logSender)
	}
	return nil
}

// GetStatus returns the server status
func GetStatus() ServiceStatus {
	return serviceStatus
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
