// Package ftpd implements the FTP protocol
package ftpd

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	ftpserver "github.com/fclairamb/ftpserverlib"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

const (
	logSender = "ftpd"
)

var (
	certMgr       *common.CertManager
	serviceStatus ServiceStatus
)

// PassiveIPOverride defines an exception for the configured passive IP
type PassiveIPOverride struct {
	Networks []string `json:"networks" mapstructure:"networks"`
	// if empty the local address will be returned
	IP             string `json:"ip" mapstructure:"ip"`
	parsedNetworks []func(net.IP) bool
}

// GetNetworksAsString returns the configured networks as string
func (p *PassiveIPOverride) GetNetworksAsString() string {
	return strings.Join(p.Networks, ", ")
}

// Binding defines the configuration for a network listener
type Binding struct {
	// The address to listen on. A blank value means listen on all available network interfaces.
	Address string `json:"address" mapstructure:"address"`
	// The port used for serving requests
	Port int `json:"port" mapstructure:"port"`
	// Apply the proxy configuration, if any, for this binding
	ApplyProxyConfig bool `json:"apply_proxy_config" mapstructure:"apply_proxy_config"`
	// Set to 1 to require TLS for both data and control connection.
	// Set to 2 to enable implicit TLS
	TLSMode int `json:"tls_mode" mapstructure:"tls_mode"`
	// Defines the minimum TLS version. 13 means TLS 1.3, default is TLS 1.2
	MinTLSVersion int `json:"min_tls_version" mapstructure:"min_tls_version"`
	// External IP address to expose for passive connections.
	ForcePassiveIP string `json:"force_passive_ip" mapstructure:"force_passive_ip"`
	// PassiveIPOverrides allows to define different IP addresses to expose for passive connections
	// based on the client IP address
	PassiveIPOverrides []PassiveIPOverride `json:"passive_ip_overrides" mapstructure:"passive_ip_overrides"`
	// Set to 1 to require client certificate authentication.
	// Set to 2 to require a client certificate and verfify it if given. In this mode
	// the client is allowed not to send a certificate.
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
	// PassiveConnectionsSecurity defines the security checks for passive data connections.
	// Supported values:
	// - 0 require matching peer IP addresses of control and data connection. This is the default
	// - 1 disable any checks
	PassiveConnectionsSecurity int `json:"passive_connections_security" mapstructure:"passive_connections_security"`
	// ActiveConnectionsSecurity defines the security checks for active data connections.
	// The supported values are the same as described for PassiveConnectionsSecurity.
	// Please note that disabling the security checks you will make the FTP service vulnerable to bounce attacks
	// on active data connections, so change the default value only if you are on a trusted/internal network
	ActiveConnectionsSecurity int `json:"active_connections_security" mapstructure:"active_connections_security"`
	// Debug enables the FTP debug mode. In debug mode, every FTP command will be logged
	Debug   bool `json:"debug" mapstructure:"debug"`
	ciphers []uint16
}

func (b *Binding) setCiphers() {
	b.ciphers = util.GetTLSCiphersFromNames(b.TLSCipherSuites)
	if len(b.ciphers) == 0 {
		b.ciphers = nil
	}
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

func (b *Binding) checkSecuritySettings() error {
	if b.PassiveConnectionsSecurity < 0 || b.PassiveConnectionsSecurity > 1 {
		return fmt.Errorf("invalid passive_connections_security: %v", b.PassiveConnectionsSecurity)
	}
	if b.ActiveConnectionsSecurity < 0 || b.ActiveConnectionsSecurity > 1 {
		return fmt.Errorf("invalid active_connections_security: %v", b.ActiveConnectionsSecurity)
	}
	return nil
}

func (b *Binding) checkPassiveIP() error {
	if b.ForcePassiveIP != "" {
		ip, err := parsePassiveIP(b.ForcePassiveIP)
		if err != nil {
			return err
		}
		b.ForcePassiveIP = ip
	}
	for idx, passiveOverride := range b.PassiveIPOverrides {
		var ip string

		if passiveOverride.IP != "" {
			var err error
			ip, err = parsePassiveIP(passiveOverride.IP)
			if err != nil {
				return err
			}
		}
		if len(passiveOverride.Networks) == 0 {
			return errors.New("passive IP networks override cannot be empty")
		}
		checkFuncs, err := util.ParseAllowedIPAndRanges(passiveOverride.Networks)
		if err != nil {
			return fmt.Errorf("invalid passive IP networks override %+v: %w", passiveOverride.Networks, err)
		}
		b.PassiveIPOverrides[idx].IP = ip
		b.PassiveIPOverrides[idx].parsedNetworks = checkFuncs
	}
	return nil
}

func (b *Binding) getPassiveIP(cc ftpserver.ClientContext) string {
	if b.ForcePassiveIP != "" {
		return b.ForcePassiveIP
	}
	return strings.Split(cc.LocalAddr().String(), ":")[0]
}

func (b *Binding) passiveIPResolver(cc ftpserver.ClientContext) (string, error) {
	if len(b.PassiveIPOverrides) > 0 {
		clientIP := net.ParseIP(util.GetIPFromRemoteAddress(cc.RemoteAddr().String()))
		if clientIP != nil {
			for _, override := range b.PassiveIPOverrides {
				for _, fn := range override.parsedNetworks {
					if fn(clientIP) {
						if override.IP == "" {
							return strings.Split(cc.LocalAddr().String(), ":")[0], nil
						}
						return override.IP, nil
					}
				}
			}
		}
	}
	return b.getPassiveIP(cc), nil
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
	// CACertificates defines the set of root certificate authorities to be used to verify client certificates.
	CACertificates []string `json:"ca_certificates" mapstructure:"ca_certificates"`
	// CARevocationLists defines a set a revocation lists, one for each root CA, to be used to check
	// if a client certificate has been revoked
	CARevocationLists []string `json:"ca_revocation_lists" mapstructure:"ca_revocation_lists"`
	// Do not impose the port 20 for active data transfer. Enabling this option allows to run SFTPGo with less privilege
	ActiveTransfersPortNon20 bool `json:"active_transfers_port_non_20" mapstructure:"active_transfers_port_non_20"`
	// Set to true to disable active FTP
	DisableActiveMode bool `json:"disable_active_mode" mapstructure:"disable_active_mode"`
	// Set to true to enable the FTP SITE command.
	// We support chmod and symlink if SITE support is enabled
	EnableSite bool `json:"enable_site" mapstructure:"enable_site"`
	// Set to 1 to enable FTP commands that allow to calculate the hash value of files.
	// These FTP commands will be enabled: HASH, XCRC, MD5/XMD5, XSHA/XSHA1, XSHA256, XSHA512.
	// Please keep in mind that to calculate the hash we need to read the whole file, for
	// remote backends this means downloading the file, for the encrypted backend this means
	// decrypting the file
	HASHSupport int `json:"hash_support" mapstructure:"hash_support"`
	// Set to 1 to enable support for the non standard "COMB" FTP command.
	// Combine is only supported for local filesystem, for cloud backends it has
	// no advantage as it will download the partial files and will upload the
	// combined one. Cloud backends natively support multipart uploads.
	CombineSupport int `json:"combine_support" mapstructure:"combine_support"`
	// Port Range for data connections. Random if not specified
	PassivePortRange PortRange `json:"passive_port_range" mapstructure:"passive_port_range"`
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
	logger.Info(logSender, "", "initializing FTP server with config %+v", *c)
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
		Bindings:         nil,
		PassivePortRange: c.PassivePortRange,
	}

	exitChannel := make(chan error, 1)

	for idx, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}

		server := NewServer(c, configDir, binding, idx)

		go func(s *Server) {
			ftpLogger := logger.LeveledLogger{Sender: "ftpserverlib"}
			ftpServer := ftpserver.NewFtpServer(s)
			ftpServer.Logger = ftpLogger.With("server_id", fmt.Sprintf("FTP_%v", s.ID))
			logger.Info(logSender, "", "starting FTP serving, binding: %v", s.binding.GetAddress())
			util.CheckTCP4Port(s.binding.Port)
			exitChannel <- ftpServer.ListenAndServe()
		}(server)

		serviceStatus.Bindings = append(serviceStatus.Bindings, binding)
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

// GetStatus returns the server status
func GetStatus() ServiceStatus {
	return serviceStatus
}

func parsePassiveIP(passiveIP string) (string, error) {
	ip := net.ParseIP(passiveIP)
	if ip == nil {
		return "", fmt.Errorf("the provided passive IP %#v is not valid", passiveIP)
	}
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("the provided passive IP %#v is not a valid IPv4 address", passiveIP)
	}
	return ip.String(), nil
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
