package sftpd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
	"github.com/pires/go-proxyproto"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	defaultPrivateRSAKeyName   = "id_rsa"
	defaultPrivateECDSAKeyName = "id_ecdsa"
)

var (
	sftpExtensions = []string{"posix-rename@openssh.com"}
)

// Configuration for the SFTP server
type Configuration struct {
	// Identification string used by the server
	Banner string `json:"banner" mapstructure:"banner"`
	// The port used for serving SFTP requests
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces.
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// Maximum idle timeout as minutes. If a client is idle for a time that exceeds this setting it will be disconnected.
	// 0 means disabled
	IdleTimeout int `json:"idle_timeout" mapstructure:"idle_timeout"`
	// Maximum number of authentication attempts permitted per connection.
	// If set to a negative number, the number of attempts is unlimited.
	// If set to zero, the number of attempts are limited to 6.
	MaxAuthTries int `json:"max_auth_tries" mapstructure:"max_auth_tries"`
	// Umask for new files
	Umask string `json:"umask" mapstructure:"umask"`
	// UploadMode 0 means standard, the files are uploaded directly to the requested path.
	// 1 means atomic: the files are uploaded to a temporary path and renamed to the requested path
	// when the client ends the upload. Atomic mode avoid problems such as a web server that
	// serves partial files when the files are being uploaded.
	// In atomic mode if there is an upload error the temporary file is deleted and so the requested
	// upload path will not contain a partial file.
	// 2 means atomic with resume support: as atomic but if there is an upload error the temporary
	// file is renamed to the requested path and not deleted, this way a client can reconnect and resume
	// the upload.
	UploadMode int `json:"upload_mode" mapstructure:"upload_mode"`
	// Actions to execute on SFTP create, download, delete and rename
	Actions Actions `json:"actions" mapstructure:"actions"`
	// Keys are a list of host keys
	Keys []Key `json:"keys" mapstructure:"keys"`
	// KexAlgorithms specifies the available KEX (Key Exchange) algorithms in
	// preference order.
	KexAlgorithms []string `json:"kex_algorithms" mapstructure:"kex_algorithms"`
	// Ciphers specifies the ciphers allowed
	Ciphers []string `json:"ciphers" mapstructure:"ciphers"`
	// MACs Specifies the available MAC (message authentication code) algorithms
	// in preference order
	MACs []string `json:"macs" mapstructure:"macs"`
	// LoginBannerFile the contents of the specified file, if any, are sent to
	// the remote user before authentication is allowed.
	LoginBannerFile string `json:"login_banner_file" mapstructure:"login_banner_file"`
	// SetstatMode 0 means "normal mode": requests for changing permissions and owner/group are executed.
	// 1 means "ignore mode": requests for changing permissions and owner/group are silently ignored.
	SetstatMode int `json:"setstat_mode" mapstructure:"setstat_mode"`
	// List of enabled SSH commands.
	// We support the following SSH commands:
	// - "scp". SCP is an experimental feature, we have our own SCP implementation since
	//      we can't rely on scp system command to proper handle permissions, quota and
	//      user's home dir restrictions.
	// 		The SCP protocol is quite simple but there is no official docs about it,
	// 		so we need more testing and feedbacks before enabling it by default.
	// 		We may not handle some borderline cases or have sneaky bugs.
	// 		Please do accurate tests yourself before enabling SCP and let us known
	// 		if something does not work as expected for your use cases.
	//      SCP between two remote hosts is supported using the `-3` scp option.
	// - "md5sum", "sha1sum", "sha256sum", "sha384sum", "sha512sum". Useful to check message
	//      digests for uploaded files. These commands are implemented inside SFTPGo so they
	//      work even if the matching system commands are not available, for example on Windows.
	// - "cd", "pwd". Some mobile SFTP clients does not support the SFTP SSH_FXP_REALPATH and so
	//      they use "cd" and "pwd" SSH commands to get the initial directory.
	//      Currently `cd` do nothing and `pwd` always returns the "/" path.
	//
	// The following SSH commands are enabled by default: "md5sum", "sha1sum", "cd", "pwd".
	// "*" enables all supported SSH commands.
	EnabledSSHCommands []string `json:"enabled_ssh_commands" mapstructure:"enabled_ssh_commands"`
	// Deprecated: please use KeyboardInteractiveHook
	KeyboardInteractiveProgram string `json:"keyboard_interactive_auth_program" mapstructure:"keyboard_interactive_auth_program"`
	// Absolute path to an external program or an HTTP URL to invoke for keyboard interactive authentication.
	// Leave empty to disable this authentication mode.
	KeyboardInteractiveHook string `json:"keyboard_interactive_auth_hook" mapstructure:"keyboard_interactive_auth_hook"`
	// Support for HAProxy PROXY protocol.
	// If you are running SFTPGo behind a proxy server such as HAProxy, AWS ELB or NGNIX, you can enable
	// the proxy protocol. It provides a convenient way to safely transport connection information
	// such as a client's address across multiple layers of NAT or TCP proxies to get the real
	// client IP address instead of the proxy IP. Both protocol versions 1 and 2 are supported.
	// - 0 means disabled
	// - 1 means proxy protocol enabled. Proxy header will be used and requests without proxy header will be accepted.
	// - 2 means proxy protocol required. Proxy header will be used and requests without proxy header will be rejected.
	// If the proxy protocol is enabled in SFTPGo then you have to enable the protocol in your proxy configuration too,
	// for example for HAProxy add "send-proxy" or "send-proxy-v2" to each server configuration line.
	ProxyProtocol int `json:"proxy_protocol" mapstructure:"proxy_protocol"`
	// List of IP addresses and IP ranges allowed to send the proxy header.
	// If proxy protocol is set to 1 and we receive a proxy header from an IP that is not in the list then the
	// connection will be accepted and the header will be ignored.
	// If proxy protocol is set to 2 and we receive a proxy header from an IP that is not in the list then the
	// connection will be rejected.
	ProxyAllowed []string `json:"proxy_allowed" mapstructure:"proxy_allowed"`
}

// Key contains information about host keys
type Key struct {
	// The private key path relative to the configuration directory or absolute
	PrivateKey string `json:"private_key" mapstructure:"private_key"`
}

type authenticationError struct {
	err string
}

func (e *authenticationError) Error() string {
	return fmt.Sprintf("Authentication error: %s", e.err)
}

// Initialize the SFTP server and add a persistent listener to handle inbound SFTP connections.
func (c Configuration) Initialize(configDir string) error {
	umask, err := strconv.ParseUint(c.Umask, 8, 8)
	if err == nil {
		utils.SetUmask(int(umask), c.Umask)
	} else {
		logger.Warn(logSender, "", "error reading umask, please fix your config file: %v", err)
		logger.WarnToConsole("error reading umask, please fix your config file: %v", err)
	}
	serverConfig := &ssh.ServerConfig{
		NoClientAuth: false,
		MaxAuthTries: c.MaxAuthTries,
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			sp, err := c.validatePasswordCredentials(conn, pass)
			if err != nil {
				return nil, &authenticationError{err: fmt.Sprintf("could not validate password credentials: %v", err)}
			}

			return sp, nil
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			sp, err := c.validatePublicKeyCredentials(conn, pubKey.Marshal())
			if err == ssh.ErrPartialSuccess {
				return nil, err
			}
			if err != nil {
				return nil, &authenticationError{err: fmt.Sprintf("could not validate public key credentials: %v", err)}
			}

			return sp, nil
		},
		NextAuthMethodsCallback: func(conn ssh.ConnMetadata) []string {
			var nextMethods []string
			user, err := dataprovider.UserExists(dataProvider, conn.User())
			if err == nil {
				nextMethods = user.GetNextAuthMethods(conn.PartialSuccessMethods())
			}
			return nextMethods
		},
		ServerVersion: fmt.Sprintf("SSH-2.0-%v", c.Banner),
	}

	err = c.checkAndLoadHostKeys(configDir, serverConfig)
	if err != nil {
		return err
	}

	sftp.SetSFTPExtensions(sftpExtensions...) //nolint:errcheck // we configure valid SFTP Extensions so we cannot get an error

	c.configureSecurityOptions(serverConfig)
	c.configureKeyboardInteractiveAuth(serverConfig)
	c.configureLoginBanner(serverConfig, configDir)
	c.checkSSHCommands()

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort))
	if err != nil {
		logger.Warn(logSender, "", "error starting listener on address %s:%d: %v", c.BindAddress, c.BindPort, err)
		return err
	}
	proxyListener, err := c.getProxyListener(listener)
	if err != nil {
		logger.Warn(logSender, "", "error enabling proxy listener: %v", err)
		return err
	}
	actions = c.Actions
	uploadMode = c.UploadMode
	setstatMode = c.SetstatMode
	logger.Info(logSender, "", "server listener registered address: %v", listener.Addr().String())
	c.checkIdleTimer()

	for {
		var conn net.Conn
		if proxyListener != nil {
			conn, err = proxyListener.Accept()
		} else {
			conn, err = listener.Accept()
		}
		if conn != nil && err == nil {
			go c.AcceptInboundConnection(conn, serverConfig)
		}
	}
}

func (c *Configuration) getProxyListener(listener net.Listener) (*proxyproto.Listener, error) {
	var proxyListener *proxyproto.Listener
	var err error
	if c.ProxyProtocol > 0 {
		var policyFunc func(upstream net.Addr) (proxyproto.Policy, error)
		if c.ProxyProtocol == 1 && len(c.ProxyAllowed) > 0 {
			policyFunc, err = proxyproto.LaxWhiteListPolicy(c.ProxyAllowed)
			if err != nil {
				return nil, err
			}
		}
		if c.ProxyProtocol == 2 {
			if len(c.ProxyAllowed) == 0 {
				policyFunc = func(upstream net.Addr) (proxyproto.Policy, error) {
					return proxyproto.REQUIRE, nil
				}
			} else {
				policyFunc, err = proxyproto.StrictWhiteListPolicy(c.ProxyAllowed)
				if err != nil {
					return nil, err
				}
			}
		}
		proxyListener = &proxyproto.Listener{
			Listener: listener,
			Policy:   policyFunc,
		}
	}
	return proxyListener, nil
}

func (c Configuration) checkIdleTimer() {
	if c.IdleTimeout > 0 {
		startIdleTimer(time.Duration(c.IdleTimeout) * time.Minute)
	}
}

func (c Configuration) configureSecurityOptions(serverConfig *ssh.ServerConfig) {
	if len(c.KexAlgorithms) > 0 {
		serverConfig.KeyExchanges = c.KexAlgorithms
	}
	if len(c.Ciphers) > 0 {
		serverConfig.Ciphers = c.Ciphers
	}
	if len(c.MACs) > 0 {
		serverConfig.MACs = c.MACs
	}
}

func (c Configuration) configureLoginBanner(serverConfig *ssh.ServerConfig, configDir string) {
	if len(c.LoginBannerFile) > 0 {
		bannerFilePath := c.LoginBannerFile
		if !filepath.IsAbs(bannerFilePath) {
			bannerFilePath = filepath.Join(configDir, bannerFilePath)
		}
		bannerContent, err := ioutil.ReadFile(bannerFilePath)
		if err == nil {
			banner := string(bannerContent)
			serverConfig.BannerCallback = func(conn ssh.ConnMetadata) string {
				return banner
			}
		} else {
			logger.WarnToConsole("unable to read login banner file: %v", err)
			logger.Warn(logSender, "", "unable to read login banner file: %v", err)
		}
	}
}

func (c Configuration) configureKeyboardInteractiveAuth(serverConfig *ssh.ServerConfig) {
	if len(c.KeyboardInteractiveHook) == 0 {
		return
	}
	if !strings.HasPrefix(c.KeyboardInteractiveHook, "http") {
		if !filepath.IsAbs(c.KeyboardInteractiveHook) {
			logger.WarnToConsole("invalid keyboard interactive authentication program: %#v must be an absolute path",
				c.KeyboardInteractiveHook)
			logger.Warn(logSender, "", "invalid keyboard interactive authentication program: %#v must be an absolute path",
				c.KeyboardInteractiveHook)
			return
		}
		_, err := os.Stat(c.KeyboardInteractiveHook)
		if err != nil {
			logger.WarnToConsole("invalid keyboard interactive authentication program:: %v", err)
			logger.Warn(logSender, "", "invalid keyboard interactive authentication program:: %v", err)
			return
		}
	}
	serverConfig.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		sp, err := c.validateKeyboardInteractiveCredentials(conn, client)
		if err != nil {
			return nil, &authenticationError{err: fmt.Sprintf("could not validate keyboard interactive credentials: %v", err)}
		}

		return sp, nil
	}
}

// AcceptInboundConnection handles an inbound connection to the server instance and determines if the request should be served or not.
func (c Configuration) AcceptInboundConnection(conn net.Conn, config *ssh.ServerConfig) {
	// Before beginning a handshake must be performed on the incoming net.Conn
	// we'll set a Deadline for handshake to complete, the default is 2 minutes as OpenSSH
	conn.SetDeadline(time.Now().Add(handshakeTimeout)) //nolint:errcheck
	remoteAddr := conn.RemoteAddr()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		logger.Warn(logSender, "", "failed to accept an incoming connection: %v", err)
		if _, ok := err.(*ssh.ServerAuthError); !ok {
			logger.ConnectionFailedLog("", utils.GetIPFromRemoteAddress(remoteAddr.String()), "no_auth_tryed", err.Error())
		}
		return
	}
	// handshake completed so remove the deadline, we'll use IdleTimeout configuration from now on
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	var user dataprovider.User

	// Unmarshal cannot fails here and even if it fails we'll have a user with no permissions
	json.Unmarshal([]byte(sconn.Permissions.Extensions["user"]), &user) //nolint:errcheck

	loginType := sconn.Permissions.Extensions["login_method"]
	connectionID := hex.EncodeToString(sconn.SessionID())

	fs, err := user.GetFilesystem(connectionID)

	if err != nil {
		logger.Warn(logSender, "", "could create filesystem for user %#v err: %v", user.Username, err)
		conn.Close()
		return
	}

	connection := Connection{
		ID:            connectionID,
		User:          user,
		ClientVersion: string(sconn.ClientVersion()),
		RemoteAddr:    remoteAddr,
		StartTime:     time.Now(),
		lastActivity:  time.Now(),
		netConn:       conn,
		channel:       nil,
		fs:            fs,
	}

	connection.fs.CheckRootPath(user.Username, user.GetUID(), user.GetGID())

	connection.Log(logger.LevelInfo, logSender, "User id: %d, logged in with: %#v, username: %#v, home_dir: %#v remote addr: %#v",
		user.ID, loginType, user.Username, user.HomeDir, remoteAddr.String())
	dataprovider.UpdateLastLogin(dataProvider, user) //nolint:errcheck

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		// If its not a session channel we just move on because its not something we
		// know how to handle at this point.
		if newChannel.ChannelType() != "session" {
			connection.Log(logger.LevelDebug, logSender, "received an unknown channel type: %v", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type") //nolint:errcheck
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			connection.Log(logger.LevelWarn, logSender, "could not accept a channel: %v", err)
			continue
		}

		// Channels have a type that is dependent on the protocol. For SFTP this is "subsystem"
		// with a payload that (should) be "sftp". Discard anything else we receive ("pty", "shell", etc)
		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false

				switch req.Type {
				case "subsystem":
					if string(req.Payload[4:]) == "sftp" {
						ok = true
						connection.protocol = protocolSFTP
						connection.channel = channel
						go c.handleSftpConnection(channel, connection)
					}
				case "exec":
					ok = processSSHCommand(req.Payload, &connection, channel, c.EnabledSSHCommands)
				}
				req.Reply(ok, nil) //nolint:errcheck
			}
		}(requests)
	}
}

func (c Configuration) handleSftpConnection(channel ssh.Channel, connection Connection) {
	addConnection(connection)
	defer removeConnection(connection)
	// Create a new handler for the currently logged in user's server.
	handler := c.createHandler(connection)

	// Create the server instance for the channel using the handler we created above.
	server := sftp.NewRequestServer(channel, handler, sftp.WithRSAllocator())

	if err := server.Serve(); err == io.EOF {
		connection.Log(logger.LevelDebug, logSender, "connection closed, sending exit status")
		exitStatus := sshSubsystemExitStatus{Status: uint32(0)}
		_, err = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatus))
		connection.Log(logger.LevelDebug, logSender, "sent exit status %+v error: %v", exitStatus, err)
		server.Close()
	} else if err != nil {
		connection.Log(logger.LevelWarn, logSender, "connection closed with error: %v", err)
	}
}

func (c Configuration) createHandler(connection Connection) sftp.Handlers {
	return sftp.Handlers{
		FileGet:  connection,
		FilePut:  connection,
		FileCmd:  connection,
		FileList: connection,
	}
}

func loginUser(user dataprovider.User, loginMethod, publicKey string, conn ssh.ConnMetadata) (*ssh.Permissions, error) {
	connectionID := ""
	if conn != nil {
		connectionID = hex.EncodeToString(conn.SessionID())
	}
	if !filepath.IsAbs(user.HomeDir) {
		logger.Warn(logSender, connectionID, "user %#v has an invalid home dir: %#v. Home dir must be an absolute path, login not allowed",
			user.Username, user.HomeDir)
		return nil, fmt.Errorf("cannot login user with invalid home dir: %#v", user.HomeDir)
	}
	if user.MaxSessions > 0 {
		activeSessions := getActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Debug(logSender, "", "authentication refused for user: %#v, too many open sessions: %v/%v", user.Username,
				activeSessions, user.MaxSessions)
			return nil, fmt.Errorf("too many open sessions: %v", activeSessions)
		}
	}
	if !user.IsLoginMethodAllowed(loginMethod, conn.PartialSuccessMethods()) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, login method %#v is not allowed", user.Username, loginMethod)
		return nil, fmt.Errorf("Login method %#v is not allowed for user %#v", loginMethod, user.Username)
	}
	remoteAddr := conn.RemoteAddr().String()
	if !user.IsLoginFromAddrAllowed(remoteAddr) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, remote address is not allowed: %v", user.Username, remoteAddr)
		return nil, fmt.Errorf("Login for user %#v is not allowed from this address: %v", user.Username, remoteAddr)
	}

	json, err := json.Marshal(user)
	if err != nil {
		logger.Warn(logSender, connectionID, "error serializing user info: %v, authentication rejected", err)
		return nil, err
	}
	if len(publicKey) > 0 {
		loginMethod = fmt.Sprintf("%v: %v", loginMethod, publicKey)
	}
	p := &ssh.Permissions{}
	p.Extensions = make(map[string]string)
	p.Extensions["user"] = string(json)
	p.Extensions["login_method"] = loginMethod
	return p, nil
}

func (c *Configuration) checkSSHCommands() {
	if utils.IsStringInSlice("*", c.EnabledSSHCommands) {
		c.EnabledSSHCommands = GetSupportedSSHCommands()
		return
	}
	sshCommands := []string{}
	for _, command := range c.EnabledSSHCommands {
		if utils.IsStringInSlice(command, supportedSSHCommands) {
			sshCommands = append(sshCommands, command)
		} else {
			logger.Warn(logSender, "", "unsupported ssh command: %#v ignored", command)
			logger.WarnToConsole("unsupported ssh command: %#v ignored", command)
		}
	}
	c.EnabledSSHCommands = sshCommands
}

// If no host keys are defined we try to use or generate the default ones.
func (c *Configuration) checkAndLoadHostKeys(configDir string, serverConfig *ssh.ServerConfig) error {
	if len(c.Keys) == 0 {
		defaultKeys := []string{defaultPrivateRSAKeyName, defaultPrivateECDSAKeyName}
		for _, k := range defaultKeys {
			autoFile := filepath.Join(configDir, k)
			if _, err := os.Stat(autoFile); os.IsNotExist(err) {
				logger.Info(logSender, "", "No host keys configured and %#v does not exist; creating new key for server", autoFile)
				logger.InfoToConsole("No host keys configured and %#v does not exist; creating new key for server", autoFile)
				if k == defaultPrivateRSAKeyName {
					err = utils.GenerateRSAKeys(autoFile)
				} else {
					err = utils.GenerateECDSAKeys(autoFile)
				}
				if err != nil {
					return err
				}
			}
			c.Keys = append(c.Keys, Key{PrivateKey: k})
		}
	}
	for _, k := range c.Keys {
		privateFile := k.PrivateKey
		if !filepath.IsAbs(privateFile) {
			privateFile = filepath.Join(configDir, privateFile)
		}
		logger.Info(logSender, "", "Loading private key: %s", privateFile)

		privateBytes, err := ioutil.ReadFile(privateFile)
		if err != nil {
			return err
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return err
		}

		// Add private key to the server configuration.
		serverConfig.AddHostKey(private)
	}
	return nil
}

func (c Configuration) validatePublicKeyCredentials(conn ssh.ConnMetadata, pubKey []byte) (*ssh.Permissions, error) {
	var err error
	var user dataprovider.User
	var keyID string
	var sshPerm *ssh.Permissions

	connectionID := hex.EncodeToString(conn.SessionID())
	method := dataprovider.SSHLoginMethodPublicKey
	if user, keyID, err = dataprovider.CheckUserAndPubKey(dataProvider, conn.User(), pubKey); err == nil {
		if user.IsPartialAuth(method) {
			logger.Debug(logSender, connectionID, "user %#v authenticated with partial success", conn.User())
			return nil, ssh.ErrPartialSuccess
		}
		sshPerm, err = loginUser(user, method, keyID, conn)
	}
	metrics.AddLoginAttempt(method)
	if err != nil {
		logger.ConnectionFailedLog(conn.User(), utils.GetIPFromRemoteAddress(conn.RemoteAddr().String()), method, err.Error())
	}
	metrics.AddLoginResult(method, err)
	return sshPerm, err
}

func (c Configuration) validatePasswordCredentials(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	var err error
	var user dataprovider.User
	var sshPerm *ssh.Permissions

	method := dataprovider.SSHLoginMethodPassword
	if len(conn.PartialSuccessMethods()) == 1 {
		method = dataprovider.SSHLoginMethodKeyAndPassword
	}
	metrics.AddLoginAttempt(method)
	if user, err = dataprovider.CheckUserAndPass(dataProvider, conn.User(), string(pass)); err == nil {
		sshPerm, err = loginUser(user, method, "", conn)
	}
	if err != nil {
		logger.ConnectionFailedLog(conn.User(), utils.GetIPFromRemoteAddress(conn.RemoteAddr().String()), method, err.Error())
	}
	metrics.AddLoginResult(method, err)
	return sshPerm, err
}

func (c Configuration) validateKeyboardInteractiveCredentials(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	var err error
	var user dataprovider.User
	var sshPerm *ssh.Permissions

	method := dataprovider.SSHLoginMethodKeyboardInteractive
	if len(conn.PartialSuccessMethods()) == 1 {
		method = dataprovider.SSHLoginMethodKeyAndKeyboardInt
	}
	metrics.AddLoginAttempt(method)
	if user, err = dataprovider.CheckKeyboardInteractiveAuth(dataProvider, conn.User(), c.KeyboardInteractiveHook, client); err == nil {
		sshPerm, err = loginUser(user, method, "", conn)
	}
	if err != nil {
		logger.ConnectionFailedLog(conn.User(), utils.GetIPFromRemoteAddress(conn.RemoteAddr().String()), method, err.Error())
	}
	metrics.AddLoginResult(method, err)
	return sshPerm, err
}
