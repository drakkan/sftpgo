// Package ftpd implements the FTP protocol
package ftpd

import (
	"path/filepath"

	ftpserver "github.com/fclairamb/ftpserverlib"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const (
	logSender = "ftpd"
)

var (
	server *Server
)

// PortRange defines a port range
type PortRange struct {
	// Range start
	Start int `json:"start" mapstructure:"start"`
	// Range end
	End int `json:"end" mapstructure:"end"`
}

// Configuration defines the configuration for the ftp server
type Configuration struct {
	// The port used for serving FTP requests
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces.
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// External IP address to expose for passive connections.
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
}

// Initialize configures and starts the FTP server
func (c *Configuration) Initialize(configDir string) error {
	var err error
	logger.Debug(logSender, "", "initializing FTP server with config %+v", *c)
	server, err = NewServer(c, configDir)
	if err != nil {
		return err
	}
	ftpServer := ftpserver.NewFtpServer(server)
	return ftpServer.ListenAndServe()
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
