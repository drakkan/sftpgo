package ftpd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	ftpserver "github.com/fclairamb/ftpserverlib"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
)

// Server implements the ftpserverlib MainDriver interface
type Server struct {
	ID               int
	config           *Configuration
	initialMsg       string
	statusBanner     string
	binding          Binding
	tlsConfig        *tls.Config
	mu               sync.RWMutex
	verifiedTLSConns map[uint32]bool
}

// NewServer returns a new FTP server driver
func NewServer(config *Configuration, configDir string, binding Binding, id int) *Server {
	binding.setCiphers()
	server := &Server{
		config:           config,
		initialMsg:       config.Banner,
		statusBanner:     fmt.Sprintf("SFTPGo %v FTP Server", version.Get().Version),
		binding:          binding,
		ID:               id,
		verifiedTLSConns: make(map[uint32]bool),
	}
	if config.BannerFile != "" {
		bannerFilePath := config.BannerFile
		if !filepath.IsAbs(bannerFilePath) {
			bannerFilePath = filepath.Join(configDir, bannerFilePath)
		}
		bannerContent, err := os.ReadFile(bannerFilePath)
		if err == nil {
			server.initialMsg = string(bannerContent)
		} else {
			logger.WarnToConsole("unable to read FTPD banner file: %v", err)
			logger.Warn(logSender, "", "unable to read banner file: %v", err)
		}
	}
	server.buildTLSConfig()
	return server
}

func (s *Server) isTLSConnVerified(id uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.verifiedTLSConns[id]
}

func (s *Server) setTLSConnVerified(id uint32, value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.verifiedTLSConns[id] = value
}

func (s *Server) cleanTLSConnVerification(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.verifiedTLSConns, id)
}

// GetSettings returns FTP server settings
func (s *Server) GetSettings() (*ftpserver.Settings, error) {
	if err := s.binding.checkPassiveIP(); err != nil {
		return nil, err
	}
	if err := s.binding.checkSecuritySettings(); err != nil {
		return nil, err
	}
	var portRange *ftpserver.PortRange
	if s.config.PassivePortRange.Start > 0 && s.config.PassivePortRange.End > s.config.PassivePortRange.Start {
		portRange = &ftpserver.PortRange{
			Start: s.config.PassivePortRange.Start,
			End:   s.config.PassivePortRange.End,
		}
	}
	var ftpListener net.Listener
	if s.binding.HasProxy() {
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
		if s.binding.TLSMode == 2 && s.tlsConfig != nil {
			ftpListener = tls.NewListener(ftpListener, s.tlsConfig)
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
		PublicIPResolver:         s.binding.passiveIPResolver,
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
		ActiveConnectionsCheck:   ftpserver.DataConnectionRequirement(s.binding.ActiveConnectionsSecurity),
		PasvConnectionsCheck:     ftpserver.DataConnectionRequirement(s.binding.PassiveConnectionsSecurity),
	}, nil
}

// ClientConnected is called to send the very first welcome message
func (s *Server) ClientConnected(cc ftpserver.ClientContext) (string, error) {
	cc.SetDebug(s.binding.Debug)
	ipAddr := util.GetIPFromRemoteAddress(cc.RemoteAddr().String())
	common.Connections.AddClientConnection(ipAddr)
	if common.IsBanned(ipAddr) {
		logger.Log(logger.LevelDebug, common.ProtocolFTP, "", "connection refused, ip %#v is banned", ipAddr)
		return "Access denied: banned client IP", common.ErrConnectionDenied
	}
	if !common.Connections.IsNewConnectionAllowed(ipAddr) {
		logger.Log(logger.LevelDebug, common.ProtocolFTP, "", fmt.Sprintf("connection not allowed from ip %#v", ipAddr))
		return "Access denied", common.ErrConnectionDenied
	}
	_, err := common.LimitRate(common.ProtocolFTP, ipAddr)
	if err != nil {
		return fmt.Sprintf("Access denied: %v", err.Error()), err
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolFTP); err != nil {
		return "Access denied by post connect hook", err
	}
	connID := fmt.Sprintf("%v_%v", s.ID, cc.ID())
	user := dataprovider.User{}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, cc.LocalAddr().String(),
			cc.RemoteAddr().String(), user),
		clientContext: cc,
	}
	common.Connections.Add(connection)
	return s.initialMsg, nil
}

// ClientDisconnected is called when the user disconnects, even if he never authenticated
func (s *Server) ClientDisconnected(cc ftpserver.ClientContext) {
	s.cleanTLSConnVerification(cc.ID())
	connID := fmt.Sprintf("%v_%v_%v", common.ProtocolFTP, s.ID, cc.ID())
	common.Connections.Remove(connID)
	common.Connections.RemoveClientConnection(util.GetIPFromRemoteAddress(cc.RemoteAddr().String()))
}

// AuthUser authenticates the user and selects an handling driver
func (s *Server) AuthUser(cc ftpserver.ClientContext, username, password string) (ftpserver.ClientDriver, error) {
	loginMethod := dataprovider.LoginMethodPassword
	if s.isTLSConnVerified(cc.ID()) {
		loginMethod = dataprovider.LoginMethodTLSCertificateAndPwd
	}
	ipAddr := util.GetIPFromRemoteAddress(cc.RemoteAddr().String())
	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, common.ProtocolFTP)
	if err != nil {
		user.Username = username
		updateLoginMetrics(&user, ipAddr, loginMethod, err)
		return nil, dataprovider.ErrInvalidCredentials
	}

	connection, err := s.validateUser(user, cc, loginMethod)

	defer updateLoginMetrics(&user, ipAddr, loginMethod, err)

	if err != nil {
		return nil, err
	}
	setStartDirectory(user.Filters.StartDirectory, cc)
	connection.Log(logger.LevelInfo, "User %#v logged in with %#v from ip %#v", user.Username, loginMethod, ipAddr)
	dataprovider.UpdateLastLogin(&user)
	return connection, nil
}

// WrapPassiveListener implements the MainDriverExtensionPassiveWrapper interface
func (s *Server) WrapPassiveListener(listener net.Listener) (net.Listener, error) {
	if s.binding.HasProxy() {
		return common.Config.GetProxyListener(listener)
	}
	return listener, nil
}

// VerifyConnection checks whether a user should be authenticated using a client certificate without prompting for a password
func (s *Server) VerifyConnection(cc ftpserver.ClientContext, user string, tlsConn *tls.Conn) (ftpserver.ClientDriver, error) {
	if !s.binding.isMutualTLSEnabled() {
		return nil, nil
	}
	s.setTLSConnVerified(cc.ID(), false)
	if tlsConn != nil {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			ipAddr := util.GetIPFromRemoteAddress(cc.RemoteAddr().String())
			dbUser, err := dataprovider.CheckUserBeforeTLSAuth(user, ipAddr, common.ProtocolFTP, state.PeerCertificates[0])
			if err != nil {
				dbUser.Username = user
				updateLoginMetrics(&dbUser, ipAddr, dataprovider.LoginMethodTLSCertificate, err)
				return nil, dataprovider.ErrInvalidCredentials
			}
			if dbUser.IsTLSUsernameVerificationEnabled() {
				dbUser, err = dataprovider.CheckUserAndTLSCert(user, ipAddr, common.ProtocolFTP, state.PeerCertificates[0])
				if err != nil {
					return nil, err
				}

				s.setTLSConnVerified(cc.ID(), true)

				if dbUser.IsLoginMethodAllowed(dataprovider.LoginMethodTLSCertificate, common.ProtocolFTP, nil) {
					connection, err := s.validateUser(dbUser, cc, dataprovider.LoginMethodTLSCertificate)

					defer updateLoginMetrics(&dbUser, ipAddr, dataprovider.LoginMethodTLSCertificate, err)

					if err != nil {
						return nil, err
					}
					setStartDirectory(dbUser.Filters.StartDirectory, cc)
					connection.Log(logger.LevelInfo, "User id: %d, logged in with FTP using a TLS certificate, username: %#v, home_dir: %#v remote addr: %#v",
						dbUser.ID, dbUser.Username, dbUser.HomeDir, ipAddr)
					dataprovider.UpdateLastLogin(&dbUser)
					return connection, nil
				}
			}
		}
	}

	return nil, nil
}

func (s *Server) buildTLSConfig() {
	if certMgr != nil {
		s.tlsConfig = &tls.Config{
			GetCertificate:           certMgr.GetCertificateFunc(),
			MinVersion:               util.GetTLSVersion(s.binding.MinTLSVersion),
			CipherSuites:             s.binding.ciphers,
			PreferServerCipherSuites: true,
		}
		if s.binding.isMutualTLSEnabled() {
			s.tlsConfig.ClientCAs = certMgr.GetRootCAs()
			s.tlsConfig.VerifyConnection = s.verifyTLSConnection
			switch s.binding.ClientAuthType {
			case 1:
				s.tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			case 2:
				s.tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
			}
		}
	}
}

// GetTLSConfig returns the TLS configuration for this server
func (s *Server) GetTLSConfig() (*tls.Config, error) {
	if s.tlsConfig != nil {
		return s.tlsConfig, nil
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
			if s.binding.ClientAuthType == 2 {
				return nil
			}
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

func (s *Server) validateUser(user dataprovider.User, cc ftpserver.ClientContext, loginMethod string) (*Connection, error) {
	connectionID := fmt.Sprintf("%v_%v_%v", common.ProtocolFTP, s.ID, cc.ID())
	if !filepath.IsAbs(user.HomeDir) {
		logger.Warn(logSender, connectionID, "user %#v has an invalid home dir: %#v. Home dir must be an absolute path, login not allowed",
			user.Username, user.HomeDir)
		return nil, fmt.Errorf("cannot login user with invalid home dir: %#v", user.HomeDir)
	}
	if util.IsStringInSlice(common.ProtocolFTP, user.Filters.DeniedProtocols) {
		logger.Info(logSender, connectionID, "cannot login user %#v, protocol FTP is not allowed", user.Username)
		return nil, fmt.Errorf("protocol FTP is not allowed for user %#v", user.Username)
	}
	if !user.IsLoginMethodAllowed(loginMethod, common.ProtocolFTP, nil) {
		logger.Info(logSender, connectionID, "cannot login user %#v, %v login method is not allowed",
			user.Username, loginMethod)
		return nil, fmt.Errorf("login method %v is not allowed for user %#v", loginMethod, user.Username)
	}
	if user.MustSetSecondFactorForProtocol(common.ProtocolFTP) {
		logger.Info(logSender, connectionID, "cannot login user %#v, second factor authentication is not set",
			user.Username)
		return nil, fmt.Errorf("second factor authentication is not set for user %#v", user.Username)
	}
	if user.MaxSessions > 0 {
		activeSessions := common.Connections.GetActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Info(logSender, connectionID, "authentication refused for user: %#v, too many open sessions: %v/%v",
				user.Username, activeSessions, user.MaxSessions)
			return nil, fmt.Errorf("too many open sessions: %v", activeSessions)
		}
	}
	remoteAddr := cc.RemoteAddr().String()
	if !user.IsLoginFromAddrAllowed(remoteAddr) {
		logger.Info(logSender, connectionID, "cannot login user %#v, remote address is not allowed: %v",
			user.Username, remoteAddr)
		return nil, fmt.Errorf("login for user %#v is not allowed from this address: %v", user.Username, remoteAddr)
	}
	err := user.CheckFsRoot(connectionID)
	if err != nil {
		errClose := user.CloseFs()
		logger.Warn(logSender, connectionID, "unable to check fs root: %v close fs error: %v", err, errClose)
		return nil, common.ErrInternalFailure
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fmt.Sprintf("%v_%v", s.ID, cc.ID()), common.ProtocolFTP,
			cc.LocalAddr().String(), remoteAddr, user),
		clientContext: cc,
	}
	err = common.Connections.Swap(connection)
	if err != nil {
		err = user.CloseFs()
		logger.Warn(logSender, connectionID, "unable to swap connection, close fs error: %v", err)
		return nil, common.ErrInternalFailure
	}
	return connection, nil
}

func setStartDirectory(startDirectory string, cc ftpserver.ClientContext) {
	if startDirectory == "" {
		return
	}
	cc.SetPath(startDirectory)
}

func updateLoginMetrics(user *dataprovider.User, ip, loginMethod string, err error) {
	metric.AddLoginAttempt(loginMethod)
	if err != nil && err != common.ErrInternalFailure {
		logger.ConnectionFailedLog(user.Username, ip, loginMethod,
			common.ProtocolFTP, err.Error())
		event := common.HostEventLoginFailed
		if _, ok := err.(*util.RecordNotFoundError); ok {
			event = common.HostEventUserNotFound
		}
		common.AddDefenderEvent(ip, event)
	}
	metric.AddLoginResult(loginMethod, err)
	dataprovider.ExecutePostLoginHook(user, loginMethod, ip, common.ProtocolFTP, err)
}
