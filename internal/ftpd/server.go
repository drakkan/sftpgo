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

package ftpd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

// Server implements the ftpserverlib MainDriver interface
type Server struct {
	ID           int
	config       *Configuration
	initialMsg   string
	statusBanner string
	binding      Binding
	tlsConfig    *tls.Config
}

// NewServer returns a new FTP server driver
func NewServer(config *Configuration, configDir string, binding Binding, id int) *Server {
	binding.setCiphers()
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

	if !s.binding.isTLSModeValid() {
		return nil, fmt.Errorf("unsupported TLS mode: %d", s.binding.TLSMode)
	}

	if !s.binding.isTLSSessionReuseValid() {
		return nil, fmt.Errorf("unsupported TLS reuse mode %d", s.binding.TLSSessionReuse)
	}

	if (s.binding.TLSMode > 0 || s.binding.TLSSessionReuse > 0) && certMgr == nil {
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
		TLSSessionReuse:          ftpserver.TLSSessionReuse(s.binding.TLSSessionReuse),
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
	if common.IsBanned(ipAddr, common.ProtocolFTP) {
		logger.Log(logger.LevelDebug, common.ProtocolFTP, "", "connection refused, ip %q is banned", ipAddr)
		return "Access denied: banned client IP", common.ErrConnectionDenied
	}
	if err := common.Connections.IsNewConnectionAllowed(ipAddr, common.ProtocolFTP); err != nil {
		logger.Log(logger.LevelDebug, common.ProtocolFTP, "", "connection not allowed from ip %q: %v", ipAddr, err)
		return "Access denied", err
	}
	_, err := common.LimitRate(common.ProtocolFTP, ipAddr)
	if err != nil {
		return fmt.Sprintf("Access denied: %v", err.Error()), err
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolFTP); err != nil {
		return "Access denied", err
	}
	connID := fmt.Sprintf("%v_%v", s.ID, cc.ID())
	user := dataprovider.User{}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, cc.LocalAddr().String(),
			cc.RemoteAddr().String(), user),
		clientContext: cc,
	}
	err = common.Connections.Add(connection)
	return s.initialMsg, err
}

// ClientDisconnected is called when the user disconnects, even if he never authenticated
func (s *Server) ClientDisconnected(cc ftpserver.ClientContext) {
	connID := fmt.Sprintf("%v_%v_%v", common.ProtocolFTP, s.ID, cc.ID())
	common.Connections.Remove(connID)
	common.Connections.RemoveClientConnection(util.GetIPFromRemoteAddress(cc.RemoteAddr().String()))
}

// AuthUser authenticates the user and selects an handling driver
func (s *Server) AuthUser(cc ftpserver.ClientContext, username, password string) (ftpserver.ClientDriver, error) {
	loginMethod := dataprovider.LoginMethodPassword
	if verified, ok := cc.Extra().(bool); ok && verified {
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
	connection.Log(logger.LevelInfo, "User %q logged in with %q from ip %q", user.Username, loginMethod, ipAddr)
	dataprovider.UpdateLastLogin(&user)
	return connection, nil
}

// PreAuthUser implements the MainDriverExtensionUserVerifier interface
func (s *Server) PreAuthUser(cc ftpserver.ClientContext, username string) error {
	if s.binding.TLSMode == 0 && s.tlsConfig != nil {
		user, err := dataprovider.GetFTPPreAuthUser(username, util.GetIPFromRemoteAddress(cc.RemoteAddr().String()))
		if err == nil {
			if user.Filters.FTPSecurity == 1 {
				return cc.SetTLSRequirement(ftpserver.MandatoryEncryption)
			}
			return nil
		}
		if !errors.Is(err, util.ErrNotFound) {
			logger.Error(logSender, fmt.Sprintf("%v_%v_%v", common.ProtocolFTP, s.ID, cc.ID()),
				"unable to get user on pre auth: %v", err)
			return common.ErrInternalFailure
		}
	}
	return nil
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
	cc.SetExtra(false)
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
			if dbUser.IsTLSVerificationEnabled() {
				dbUser, err = dataprovider.CheckUserAndTLSCert(user, ipAddr, common.ProtocolFTP, state.PeerCertificates[0])
				if err != nil {
					return nil, err
				}

				cc.SetExtra(true)

				if dbUser.IsLoginMethodAllowed(dataprovider.LoginMethodTLSCertificate, common.ProtocolFTP) {
					connection, err := s.validateUser(dbUser, cc, dataprovider.LoginMethodTLSCertificate)

					defer updateLoginMetrics(&dbUser, ipAddr, dataprovider.LoginMethodTLSCertificate, err)

					if err != nil {
						return nil, err
					}
					setStartDirectory(dbUser.Filters.StartDirectory, cc)
					connection.Log(logger.LevelInfo, "User id: %d, logged in with FTP using a TLS certificate, username: %q, home_dir: %q remote addr: %q",
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
		certID := common.DefaultTLSKeyPaidID
		if getConfigPath(s.binding.CertificateFile, "") != "" && getConfigPath(s.binding.CertificateKeyFile, "") != "" {
			certID = s.binding.GetAddress()
		}
		if !certMgr.HasCertificate(certID) {
			return
		}
		s.tlsConfig = &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(certID),
			MinVersion:     util.GetTLSVersion(s.binding.MinTLSVersion),
			CipherSuites:   s.binding.ciphers,
		}
		logger.Debug(logSender, "", "configured TLS cipher suites for binding %q: %v, certID: %v",
			s.binding.GetAddress(), s.binding.ciphers, certID)
		if s.binding.isMutualTLSEnabled() {
			s.tlsConfig.ClientCAs = certMgr.GetRootCAs()
			if s.binding.TLSSessionReuse != int(ftpserver.TLSSessionReuseRequired) {
				s.tlsConfig.VerifyConnection = s.verifyTLSConnection
			}
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

// VerifyTLSConnectionState implements the MainDriverExtensionTLSConnectionStateVerifier extension
func (s *Server) VerifyTLSConnectionState(_ ftpserver.ClientContext, cs tls.ConnectionState) error {
	if !s.binding.isMutualTLSEnabled() {
		return nil
	}
	return s.verifyTLSConnection(cs)
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
				logger.Debug(logSender, "", "tls handshake error, client certificate %q has beed revoked", clientCrtName)
				return common.ErrCrtRevoked
			}
		}
	}

	return nil
}

func (s *Server) validateUser(user dataprovider.User, cc ftpserver.ClientContext, loginMethod string) (*Connection, error) {
	connectionID := fmt.Sprintf("%v_%v_%v", common.ProtocolFTP, s.ID, cc.ID())
	if !filepath.IsAbs(user.HomeDir) {
		logger.Warn(logSender, connectionID, "user %q has an invalid home dir: %q. Home dir must be an absolute path, login not allowed",
			user.Username, user.HomeDir)
		return nil, fmt.Errorf("cannot login user with invalid home dir: %q", user.HomeDir)
	}
	if util.Contains(user.Filters.DeniedProtocols, common.ProtocolFTP) {
		logger.Info(logSender, connectionID, "cannot login user %q, protocol FTP is not allowed", user.Username)
		return nil, fmt.Errorf("protocol FTP is not allowed for user %q", user.Username)
	}
	if !user.IsLoginMethodAllowed(loginMethod, common.ProtocolFTP) {
		logger.Info(logSender, connectionID, "cannot login user %q, %v login method is not allowed",
			user.Username, loginMethod)
		return nil, fmt.Errorf("login method %v is not allowed for user %q", loginMethod, user.Username)
	}
	if user.MustSetSecondFactorForProtocol(common.ProtocolFTP) {
		logger.Info(logSender, connectionID, "cannot login user %q, second factor authentication is not set",
			user.Username)
		return nil, fmt.Errorf("second factor authentication is not set for user %q", user.Username)
	}
	if user.MaxSessions > 0 {
		activeSessions := common.Connections.GetActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Info(logSender, connectionID, "authentication refused for user: %q, too many open sessions: %v/%v",
				user.Username, activeSessions, user.MaxSessions)
			return nil, fmt.Errorf("too many open sessions: %v", activeSessions)
		}
	}
	remoteAddr := cc.RemoteAddr().String()
	if !user.IsLoginFromAddrAllowed(remoteAddr) {
		logger.Info(logSender, connectionID, "cannot login user %q, remote address is not allowed: %v",
			user.Username, remoteAddr)
		return nil, fmt.Errorf("login for user %q is not allowed from this address: %v", user.Username, remoteAddr)
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
		errClose := user.CloseFs()
		logger.Warn(logSender, connectionID, "unable to swap connection: %v, close fs error: %v", err, errClose)
		return nil, err
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
		logEv := notifier.LogEventTypeLoginFailed
		if errors.Is(err, util.ErrNotFound) {
			event = common.HostEventUserNotFound
			logEv = notifier.LogEventTypeLoginNoUser
		}
		common.AddDefenderEvent(ip, common.ProtocolFTP, event)
		plugin.Handler.NotifyLogEvent(logEv, common.ProtocolFTP, user.Username, ip, "", err)
	}
	metric.AddLoginResult(loginMethod, err)
	dataprovider.ExecutePostLoginHook(user, loginMethod, ip, common.ProtocolFTP, err)
}
