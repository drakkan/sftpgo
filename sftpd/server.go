package sftpd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const defaultPrivateKeyName = "id_rsa"

// Configuration for the SFTP server
type Configuration struct {
	// Identification string used by the server
	Banner string `json:"banner" mapstructure:"banner"`
	// The port used for serving SFTP requests
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces.
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
	// Maximum idle timeout as minutes. If a client is idle for a time that exceeds this setting it will be disconnected
	IdleTimeout int `json:"idle_timeout" mapstructure:"idle_timeout"`
	// Maximum number of authentication attempts permitted per connection.
	// If set to a negative number, the number of attempts are unlimited.
	// If set to zero, the number of attempts are limited to 6.
	MaxAuthTries int `json:"max_auth_tries" mapstructure:"max_auth_tries"`
	// Umask for new files
	Umask string `json:"umask" mapstructure:"umask"`
	// UploadMode 0 means standard, the files are uploaded directly to the requested path.
	// 1 means atomic: the files are uploaded to a temporary path and renamed to the requested path
	// when the client ends the upload. Atomic mode avoid problems such as a web server that
	// serves partial files when the files are being uploaded.
	UploadMode int `json:"upload_mode" mapstructure:"upload_mode"`
	// Actions to execute on SFTP create, download, delete and rename
	Actions Actions `json:"actions" mapstructure:"actions"`
	// Keys are a list of host keys
	Keys []Key `json:"keys" mapstructure:"keys"`
	// IsSCPEnabled determines if experimental SCP support is enabled.
	// We have our own SCP implementation since we can't rely on scp system
	// command to properly handle permissions, quota and user's home dir restrictions.
	// The SCP protocol is quite simple but there is no official docs about it,
	// so we need more testing and feedbacks before enabling it by default.
	// We may not handle some borderline cases or have sneaky bugs.
	// Please do accurate tests yourself before enabling SCP and let us known
	// if something does not work as expected for your use cases
	IsSCPEnabled bool `json:"enable_scp" mapstructure:"enable_scp"`
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
}

// Key contains information about host keys
type Key struct {
	// The private key path relative to the configuration directory or absolute
	PrivateKey string `json:"private_key" mapstructure:"private_key"`
}

// Initialize the SFTP server and add a persistent listener to handle inbound SFTP connections.
func (c Configuration) Initialize(configDir string) error {
	umask, err := strconv.ParseUint(c.Umask, 8, 8)
	if err == nil {
		utils.SetUmask(int(umask), c.Umask)
	} else {
		logger.Warn(logSender, "error reading umask, please fix your config file: %v", err)
		logger.WarnToConsole("error reading umask, please fix your config file: %v", err)
	}
	serverConfig := &ssh.ServerConfig{
		NoClientAuth: false,
		MaxAuthTries: c.MaxAuthTries,
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			sp, err := c.validatePasswordCredentials(conn, pass)
			if err != nil {
				return nil, errors.New("could not validate credentials")
			}

			return sp, nil
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			sp, err := c.validatePublicKeyCredentials(conn, string(pubKey.Marshal()))
			if err != nil {
				return nil, errors.New("could not validate credentials")
			}

			return sp, nil
		},
		ServerVersion: "SSH-2.0-" + c.Banner,
	}

	err = c.checkHostKeys(configDir)
	if err != nil {
		return err
	}

	for _, k := range c.Keys {
		privateFile := k.PrivateKey
		if !filepath.IsAbs(privateFile) {
			privateFile = filepath.Join(configDir, privateFile)
		}
		logger.Info(logSender, "Loading private key: %s", privateFile)

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

	c.configureSecurityOptions(serverConfig)
	c.configureLoginBanner(serverConfig, configDir)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort))
	if err != nil {
		logger.Warn(logSender, "error starting listener on address %s:%d: %v", c.BindAddress, c.BindPort, err)
		return err
	}

	actions = c.Actions
	uploadMode = c.UploadMode
	logger.Info(logSender, "server listener registered address: %v", listener.Addr().String())
	if c.IdleTimeout > 0 {
		startIdleTimer(time.Duration(c.IdleTimeout) * time.Minute)
	}

	for {
		conn, _ := listener.Accept()
		if conn != nil {
			go c.AcceptInboundConnection(conn, serverConfig)
		}
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

func (c Configuration) configureLoginBanner(serverConfig *ssh.ServerConfig, configDir string) error {
	var err error
	if len(c.LoginBannerFile) > 0 {
		bannerFilePath := c.LoginBannerFile
		if !filepath.IsAbs(bannerFilePath) {
			bannerFilePath = filepath.Join(configDir, bannerFilePath)
		}
		var banner []byte
		banner, err = ioutil.ReadFile(bannerFilePath)
		if err == nil {
			serverConfig.BannerCallback = func(conn ssh.ConnMetadata) string {
				return string(banner)
			}
		} else {
			logger.WarnToConsole("unable to read login banner file: %v", err)
			logger.Warn(logSender, "unable to read login banner file: %v", err)
		}
	}
	return err
}

// AcceptInboundConnection handles an inbound connection to the server instance and determines if the request should be served or not.
func (c Configuration) AcceptInboundConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	// Before beginning a handshake must be performed on the incoming net.Conn
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		logger.Warn(logSender, "failed to accept an incoming connection: %v", err)
		return
	}
	defer sconn.Close()

	logger.Debug(logSender, "accepted inbound connection, ip: %v", conn.RemoteAddr().String())

	var user dataprovider.User

	err = json.Unmarshal([]byte(sconn.Permissions.Extensions["user"]), &user)

	if err != nil {
		logger.Warn(logSender, "Unable to deserialize user info, cannot serve connection: %v", err)
		return
	}

	connectionID := hex.EncodeToString(sconn.SessionID())

	connection := Connection{
		ID:            connectionID,
		User:          user,
		ClientVersion: string(sconn.ClientVersion()),
		RemoteAddr:    conn.RemoteAddr(),
		StartTime:     time.Now(),
		lastActivity:  time.Now(),
		lock:          new(sync.Mutex),
		sshConn:       sconn,
	}

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		// If its not a session channel we just move on because its not something we
		// know how to handle at this point.
		if newChannel.ChannelType() != "session" {
			logger.Debug(logSender, "received an unknown channel type: %v", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			logger.Warn(logSender, "could not accept a channel: %v", err)
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
						go c.handleSftpConnection(channel, connection)
					}
				case "exec":
					if c.IsSCPEnabled {
						var msg execMsg
						if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
							name, scpArgs, err := parseCommandPayload(msg.Command)
							logger.Debug(logSender, "new exec command: %v args: %v user: %v, error: %v", name, scpArgs,
								connection.User.Username, err)
							if err == nil && name == "scp" && len(scpArgs) >= 2 {
								ok = true
								connection.protocol = protocolSCP
								scpCommand := scpCommand{
									connection: connection,
									args:       scpArgs,
									channel:    channel,
								}
								go scpCommand.handle()
							}
						}
					}
				}
				req.Reply(ok, nil)
			}
		}(requests)
	}
}

func (c Configuration) handleSftpConnection(channel io.ReadWriteCloser, connection Connection) {
	addConnection(connection.ID, connection)
	// Create a new handler for the currently logged in user's server.
	handler := c.createHandler(connection)

	// Create the server instance for the channel using the handler we created above.
	server := sftp.NewRequestServer(channel, handler)

	if err := server.Serve(); err == io.EOF {
		logger.Debug(logSender, "connection closed, id: %v", connection.ID)
		server.Close()
	} else if err != nil {
		logger.Error(logSender, "sftp connection closed with error id %v: %v", connection.ID, err)
	}

	removeConnection(connection.ID)
}

func (c Configuration) createHandler(connection Connection) sftp.Handlers {

	return sftp.Handlers{
		FileGet:  connection,
		FilePut:  connection,
		FileCmd:  connection,
		FileList: connection,
	}
}

func loginUser(user dataprovider.User) (*ssh.Permissions, error) {
	if !filepath.IsAbs(user.HomeDir) {
		logger.Warn(logSender, "user %v has invalid home dir: %v. Home dir must be an absolute path, login not allowed",
			user.Username, user.HomeDir)
		return nil, fmt.Errorf("Cannot login user with invalid home dir: %v", user.HomeDir)
	}
	if _, err := os.Stat(user.HomeDir); os.IsNotExist(err) {
		logger.Debug(logSender, "home directory \"%v\" for user %v does not exist, try to create", user.HomeDir, user.Username)
		err := os.MkdirAll(user.HomeDir, 0777)
		if err == nil {
			utils.SetPathPermissions(user.HomeDir, user.GetUID(), user.GetGID())
		}
	}

	if user.MaxSessions > 0 {
		activeSessions := getActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Debug(logSender, "authentication refused for user: %v, too many open sessions: %v/%v", user.Username,
				activeSessions, user.MaxSessions)
			return nil, fmt.Errorf("Too many open sessions: %v", activeSessions)
		}
	}

	json, err := json.Marshal(user)
	if err != nil {
		logger.Warn(logSender, "error serializing user info: %v, authentication rejected", err)
		return nil, err
	}
	p := &ssh.Permissions{}
	p.Extensions = make(map[string]string)
	p.Extensions["user"] = string(json)
	return p, nil
}

// If no host keys are defined we try to use or generate the default one.
func (c *Configuration) checkHostKeys(configDir string) error {
	var err error
	if len(c.Keys) == 0 {
		autoFile := filepath.Join(configDir, defaultPrivateKeyName)
		if _, err = os.Stat(autoFile); os.IsNotExist(err) {
			logger.Info(logSender, "No host keys configured and %s does not exist; creating new private key for server", autoFile)
			logger.InfoToConsole("No host keys configured and %s does not exist; creating new private key for server", autoFile)
			err = c.generatePrivateKey(autoFile)
		}

		c.Keys = append(c.Keys, Key{PrivateKey: defaultPrivateKeyName})
	}
	return err
}

func (c Configuration) validatePublicKeyCredentials(conn ssh.ConnMetadata, pubKey string) (*ssh.Permissions, error) {
	var err error
	var user dataprovider.User

	if user, err = dataprovider.CheckUserAndPubKey(dataProvider, conn.User(), pubKey); err == nil {
		return loginUser(user)
	}
	return nil, err
}

func (c Configuration) validatePasswordCredentials(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	var err error
	var user dataprovider.User

	if user, err = dataprovider.CheckUserAndPass(dataProvider, conn.User(), string(pass)); err == nil {
		return loginUser(user)
	}
	return nil, err
}

// Generates a private key that will be used by the SFTP server.
func (c Configuration) generatePrivateKey(file string) error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	o, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer o.Close()

	pkey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(o, pkey); err != nil {
		return err
	}

	return nil
}

func parseCommandPayload(command string) (string, []string, error) {
	parts := strings.Split(command, " ")
	if len(parts) < 2 {
		return parts[0], []string{}, nil
	}
	return parts[0], parts[1:], nil
}
