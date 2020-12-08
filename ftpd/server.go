package ftpd

import (
	"crypto/tls"
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
	config       *Configuration
	certMgr      *common.CertManager
	initialMsg   string
	statusBanner string
	status       ServiceStatus
}

// NewServer returns a new FTP server driver
func NewServer(config *Configuration, configDir string) (*Server, error) {
	var err error
	server := &Server{
		config:       config,
		certMgr:      nil,
		initialMsg:   config.Banner,
		statusBanner: fmt.Sprintf("SFTPGo %v FTP Server", version.Get().Version),
	}
	certificateFile := getConfigPath(config.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(config.CertificateKeyFile, configDir)
	if certificateFile != "" && certificateKeyFile != "" {
		server.certMgr, err = common.NewCertManager(certificateFile, certificateKeyFile, logSender)
		if err != nil {
			return server, err
		}
	}
	if len(config.BannerFile) > 0 {
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
	return server, err
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
	if common.Config.ProxyProtocol > 0 {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.config.BindAddress, s.config.BindPort))
		if err != nil {
			logger.Warn(logSender, "", "error starting listener on address %s:%d: %v", s.config.BindAddress, s.config.BindPort, err)
			return nil, err
		}
		ftpListener, err = common.Config.GetProxyListener(listener)
		if err != nil {
			logger.Warn(logSender, "", "error enabling proxy listener: %v", err)
			return nil, err
		}
	}

	return &ftpserver.Settings{
		Listener:                 ftpListener,
		ListenAddr:               fmt.Sprintf("%s:%d", s.config.BindAddress, s.config.BindPort),
		PublicHost:               s.config.ForcePassiveIP,
		PassiveTransferPortRange: portRange,
		ActiveTransferPortNon20:  s.config.ActiveTransfersPortNon20,
		IdleTimeout:              -1,
		ConnectionTimeout:        20,
		Banner:                   s.statusBanner,
		TLSRequired:              s.config.TLSMode,
	}, nil
}

// ClientConnected is called to send the very first welcome message
func (s *Server) ClientConnected(cc ftpserver.ClientContext) (string, error) {
	if err := common.Config.ExecutePostConnectHook(cc.RemoteAddr().String(), common.ProtocolFTP); err != nil {
		return common.ErrConnectionDenied.Error(), err
	}
	connID := fmt.Sprintf("%v", cc.ID())
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
	connID := fmt.Sprintf("%v_%v", common.ProtocolFTP, cc.ID())
	common.Connections.Remove(connID)
}

// AuthUser authenticates the user and selects an handling driver
func (s *Server) AuthUser(cc ftpserver.ClientContext, username, password string) (ftpserver.ClientDriver, error) {
	remoteAddr := cc.RemoteAddr().String()
	user, err := dataprovider.CheckUserAndPass(username, password, utils.GetIPFromRemoteAddress(remoteAddr), common.ProtocolFTP)
	if err != nil {
		updateLoginMetrics(username, remoteAddr, err)
		return nil, err
	}

	connection, err := s.validateUser(user, cc)

	defer updateLoginMetrics(username, remoteAddr, err)

	if err != nil {
		return nil, err
	}
	connection.Fs.CheckRootPath(connection.GetUsername(), user.GetUID(), user.GetGID())
	connection.Log(logger.LevelInfo, "User id: %d, logged in with FTP, username: %#v, home_dir: %#v remote addr: %#v",
		user.ID, user.Username, user.HomeDir, remoteAddr)
	dataprovider.UpdateLastLogin(user) //nolint:errcheck
	return connection, nil
}

// GetTLSConfig returns a TLS Certificate to use
func (s *Server) GetTLSConfig() (*tls.Config, error) {
	if s.certMgr != nil {
		return &tls.Config{
			GetCertificate: s.certMgr.GetCertificateFunc(),
			MinVersion:     tls.VersionTLS12,
		}, nil
	}
	return nil, errors.New("no TLS certificate configured")
}

func (s *Server) validateUser(user dataprovider.User, cc ftpserver.ClientContext) (*Connection, error) {
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolFTP, cc.ID())
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
		BaseConnection: common.NewBaseConnection(fmt.Sprintf("%v", cc.ID()), common.ProtocolFTP, user, fs),
		clientContext:  cc,
	}
	err = common.Connections.Swap(connection)
	if err != nil {
		return nil, errors.New("Internal authentication error")
	}
	return connection, nil
}

func updateLoginMetrics(username, remoteAddress string, err error) {
	metrics.AddLoginAttempt(dataprovider.LoginMethodPassword)
	ip := utils.GetIPFromRemoteAddress(remoteAddress)
	if err != nil {
		logger.ConnectionFailedLog(username, ip, dataprovider.LoginMethodPassword,
			common.ProtocolFTP, err.Error())
	}
	metrics.AddLoginResult(dataprovider.LoginMethodPassword, err)
	dataprovider.ExecutePostLoginHook(username, dataprovider.LoginMethodPassword, ip, common.ProtocolFTP, err)
}
