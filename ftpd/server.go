package ftpd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"

	ftpserver "github.com/fclairamb/ftpserverlib"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
)

// Server implements the ftpserverlib MainDriver interface
type Server struct {
	ID           int
	config       *Configuration
	initialMsg   string
	statusBanner string
	binding      Binding
}

// NewServer returns a new FTP server driver
func NewServer(config *Configuration, configDir string, binding Binding, id int) *Server {
	server := &Server{
		config:       config,
		initialMsg:   config.Banner,
		statusBanner: fmt.Sprintf("SFTPGo %v FTP Server", version.Get().Version),
		binding:      binding,
		ID:           id,
	}
	if config.BannerFile != "" {
		bannerFilePath := config.BannerFile
		if !filepath.IsAbs(bannerFilePath) {
			bannerFilePath = filepath.Join(configDir, bannerFilePath)
		}
		bannerContent, err := ioutil.ReadFile(bannerFilePath)
		if err == nil {
			server.initialMsg = string(bannerContent)
		} else {
			logger.WarnToConsole("unable to read FTPD banner file: %v", err)
			logger.Warn(logSender, "", "unable to read banner file: %v", err)
		}
	}
	return server
}

// GetSettings returns FTP server settings
func (s *Server) GetSettings() (*ftpserver.Settings, error) {
	var portRange *ftpserver.PortRange
	if s.config.PassivePortRange.Start > 0 && s.config.PassivePortRange.End > s.config.PassivePortRange.Start {
		portRange = &ftpserver.PortRange{
			Start: s.config.PassivePortRange.Start,
			End:   s.config.PassivePortRange.End,
		}
	}
	var ftpListener net.Listener
	if common.Config.ProxyProtocol > 0 && s.binding.ApplyProxyConfig {
		listener, err := net.Listen("tcp", s.binding.GetAddress())
		if err != nil {
			logger.Warn(logSender, "", "error starting listener on address %v: %v", s.binding.GetAddress(), err)
			return nil, err
		}
		ftpListener, err = common.Config.GetProxyListener(listener)
		if err != nil {
			logger.Warn(logSender, "", "error enabling proxy listener: %v", err)
			return nil, err
		}
	}

	if s.binding.TLSMode < 0 || s.binding.TLSMode > 2 {
		return nil, errors.New("unsupported TLS mode")
	}

	if s.binding.TLSMode > 0 && certMgr == nil {
		return nil, errors.New("to enable TLS you need to provide a certificate")
	}

	return &ftpserver.Settings{
		Listener:                 ftpListener,
		ListenAddr:               s.binding.GetAddress(),
		PublicHost:               s.binding.ForcePassiveIP,
		PassiveTransferPortRange: portRange,
		ActiveTransferPortNon20:  s.config.ActiveTransfersPortNon20,
		IdleTimeout:              -1,
		ConnectionTimeout:        20,
		Banner:                   s.statusBanner,
		TLSRequired:              ftpserver.TLSRequirement(s.binding.TLSMode),
		DisableSite:              !s.config.EnableSite,
		DisableActiveMode:        s.config.DisableActiveMode,
		EnableHASH:               s.config.HASHSupport > 0,
		EnableCOMB:               s.config.CombineSupport > 0,
		DefaultTransferType:      ftpserver.TransferTypeBinary,
	}, nil
}

// ClientConnected is called to send the very first welcome message
func (s *Server) ClientConnected(cc ftpserver.ClientContext) (string, error) {
	ipAddr := utils.GetIPFromRemoteAddress(cc.RemoteAddr().String())
	if common.IsBanned(ipAddr) {
		logger.Log(logger.LevelDebug, common.ProtocolFTP, "", "connection refused, ip %#v is banned", ipAddr)
		return "Access denied, banned client IP", common.ErrConnectionDenied
	}
	if !common.Connections.IsNewConnectionAllowed() {
		logger.Log(logger.LevelDebug, common.ProtocolFTP, "", "connection refused, configured limit reached")
		return "", common.ErrConnectionDenied
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolFTP); err != nil {
		return "", err
	}
	connID := fmt.Sprintf("%v_%v", s.ID, cc.ID())
	user := dataprovider.User{}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, user, nil),
		clientContext:  cc,
	}
	common.Connections.Add(connection)
	return s.initialMsg, nil
}

// ClientDisconnected is called when the user disconnects, even if he never authenticated
func (s *Server) ClientDisconnected(cc ftpserver.ClientContext) {
	connID := fmt.Sprintf("%v_%v_%v", common.ProtocolFTP, s.ID, cc.ID())
	common.Connections.Remove(connID)
}

// AuthUser authenticates the user and selects an handling driver
func (s *Server) AuthUser(cc ftpserver.ClientContext, username, password string) (ftpserver.ClientDriver, error) {
	ipAddr := utils.GetIPFromRemoteAddress(cc.RemoteAddr().String())
	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, common.ProtocolFTP)
	if err != nil {
		user.Username = username
		updateLoginMetrics(&user, ipAddr, err)
		return nil, err
	}

	connection, err := s.validateUser(user, cc)

	defer updateLoginMetrics(&user, ipAddr, err)

	if err != nil {
		return nil, err
	}
	connection.Fs.CheckRootPath(connection.GetUsername(), user.GetUID(), user.GetGID())
	connection.Log(logger.LevelInfo, "User id: %d, logged in with FTP, username: %#v, home_dir: %#v remote addr: %#v",
		user.ID, user.Username, user.HomeDir, ipAddr)
	dataprovider.UpdateLastLogin(&user) //nolint:errcheck
	return connection, nil
}

// GetTLSConfig returns a TLS Certificate to use
func (s *Server) GetTLSConfig() (*tls.Config, error) {
	if certMgr != nil {
		tlsConfig := &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(),
			MinVersion:     tls.VersionTLS12,
		}
		if s.binding.ClientAuthType == 1 {
			tlsConfig.ClientCAs = certMgr.GetRootCAs()
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.VerifyConnection = s.verifyTLSConnection
		}
		return tlsConfig, nil
	}
	return nil, errors.New("no TLS certificate configured")
}

func (s *Server) verifyTLSConnection(state tls.ConnectionState) error {
	if certMgr != nil {
		var clientCrt *x509.Certificate
		var clientCrtName string
		if len(state.PeerCertificates) > 0 {
			clientCrt = state.PeerCertificates[0]
			clientCrtName = clientCrt.Subject.String()
		}
		if len(state.VerifiedChains) == 0 {
			logger.Warn(logSender, "", "TLS connection cannot be verified: unable to get verification chain")
			return errors.New("TLS connection cannot be verified: unable to get verification chain")
		}
		for _, verifiedChain := range state.VerifiedChains {
			var caCrt *x509.Certificate
			if len(verifiedChain) > 0 {
				caCrt = verifiedChain[len(verifiedChain)-1]
			}
			if certMgr.IsRevoked(clientCrt, caCrt) {
				logger.Debug(logSender, "", "tls handshake error, client certificate %#v has beed revoked", clientCrtName)
				return common.ErrCrtRevoked
			}
		}
	}

	return nil
}

func (s *Server) validateUser(user dataprovider.User, cc ftpserver.ClientContext) (*Connection, error) {
	connectionID := fmt.Sprintf("%v_%v_%v", common.ProtocolFTP, s.ID, cc.ID())
	if !filepath.IsAbs(user.HomeDir) {
		logger.Warn(logSender, connectionID, "user %#v has an invalid home dir: %#v. Home dir must be an absolute path, login not allowed",
			user.Username, user.HomeDir)
		return nil, fmt.Errorf("cannot login user with invalid home dir: %#v", user.HomeDir)
	}
	if utils.IsStringInSlice(common.ProtocolFTP, user.Filters.DeniedProtocols) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, protocol FTP is not allowed", user.Username)
		return nil, fmt.Errorf("Protocol FTP is not allowed for user %#v", user.Username)
	}
	if !user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, nil) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, password login method is not allowed", user.Username)
		return nil, fmt.Errorf("Password login method is not allowed for user %#v", user.Username)
	}
	if user.MaxSessions > 0 {
		activeSessions := common.Connections.GetActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Debug(logSender, connectionID, "authentication refused for user: %#v, too many open sessions: %v/%v", user.Username,
				activeSessions, user.MaxSessions)
			return nil, fmt.Errorf("too many open sessions: %v", activeSessions)
		}
	}
	if dataprovider.GetQuotaTracking() > 0 && user.HasOverlappedMappedPaths() {
		logger.Debug(logSender, connectionID, "cannot login user %#v, overlapping mapped folders are allowed only with quota tracking disabled",
			user.Username)
		return nil, errors.New("overlapping mapped folders are allowed only with quota tracking disabled")
	}
	remoteAddr := cc.RemoteAddr().String()
	if !user.IsLoginFromAddrAllowed(remoteAddr) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, remote address is not allowed: %v", user.Username, remoteAddr)
		return nil, fmt.Errorf("Login for user %#v is not allowed from this address: %v", user.Username, remoteAddr)
	}
	fs, err := user.GetFilesystem(connectionID)
	if err != nil {
		return nil, err
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fmt.Sprintf("%v_%v", s.ID, cc.ID()), common.ProtocolFTP, user, fs),
		clientContext:  cc,
	}
	err = common.Connections.Swap(connection)
	if err != nil {
		return nil, errors.New("Internal authentication error")
	}
	return connection, nil
}

func updateLoginMetrics(user *dataprovider.User, ip string, err error) {
	metrics.AddLoginAttempt(dataprovider.LoginMethodPassword)
	if err != nil {
		logger.ConnectionFailedLog(user.Username, ip, dataprovider.LoginMethodPassword,
			common.ProtocolFTP, err.Error())
		event := common.HostEventLoginFailed
		if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
			event = common.HostEventUserNotFound
		}
		common.AddDefenderEvent(ip, event)
	}
	metrics.AddLoginResult(dataprovider.LoginMethodPassword, err)
	dataprovider.ExecutePostLoginHook(user, dataprovider.LoginMethodPassword, ip, common.ProtocolFTP, err)
}
