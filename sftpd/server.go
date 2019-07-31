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
	"sync"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Configuration for the SFTP server
type Configuration struct {
	// Identification string used by the server
	Banner string `json:"banner"`
	// The port used for serving SFTP requests
	BindPort int `json:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces.
	BindAddress string `json:"bind_address"`
	// Maximum idle timeout as minutes. If a client is idle for a time that exceeds this setting it will be disconnected
	IdleTimeout int `json:"idle_timeout"`
	// Maximum number of authentication attempts permitted per connection.
	// If set to a negative number, the number of attempts are unlimited.
	// If set to zero, the number of attempts are limited to 6.
	MaxAuthTries int `json:"max_auth_tries"`
	// Umask for new files
	Umask string `json:"umask"`
	// Actions to execute on SFTP create, download, delete and rename
	Actions Actions `json:"actions"`
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
	actions = c.Actions
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

	if _, err := os.Stat(filepath.Join(configDir, "id_rsa")); os.IsNotExist(err) {
		logger.Info(logSender, "creating new private key for server")
		logger.InfoToConsole("id_rsa does not exist, creating new private key for server")
		if err := c.generatePrivateKey(configDir); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	privateBytes, err := ioutil.ReadFile(filepath.Join(configDir, "id_rsa"))
	if err != nil {
		return err
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return err
	}

	// Add our private key to the server configuration.
	serverConfig.AddHostKey(private)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort))
	if err != nil {
		logger.Warn(logSender, "error starting listener on address %s:%d: %v", c.BindAddress, c.BindPort, err)
		return err
	}

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
					}
				}

				req.Reply(ok, nil)
			}
		}(requests)

		var user dataprovider.User

		err = json.Unmarshal([]byte(sconn.Permissions.Extensions["user"]), &user)

		if err != nil {
			logger.Warn(logSender, "Unable to deserialize user info, cannot serve connection: %v", err)
			return
		}

		connectionID := hex.EncodeToString(sconn.SessionID())

		// Create a new handler for the currently logged in user's server.
		handler := c.createHandler(sconn, user, connectionID)

		// Create the server instance for the channel using the handler we created above.
		server := sftp.NewRequestServer(channel, handler)

		if err := server.Serve(); err == io.EOF {
			logger.Debug(logSender, "connection closed, id: %v", connectionID)
			server.Close()
		} else if err != nil {
			logger.Error(logSender, "sftp connection closed with error id %v: %v", connectionID, err)
		}

		removeConnection(connectionID)
	}
}

func (c Configuration) createHandler(conn *ssh.ServerConn, user dataprovider.User, connectionID string) sftp.Handlers {

	connection := Connection{
		ID:            connectionID,
		User:          user,
		ClientVersion: string(conn.ClientVersion()),
		RemoteAddr:    conn.RemoteAddr(),
		StartTime:     time.Now(),
		lastActivity:  time.Now(),
		lock:          new(sync.Mutex),
		sshConn:       conn,
	}

	addConnection(connectionID, connection)

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
func (c Configuration) generatePrivateKey(configDir string) error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	o, err := os.OpenFile(filepath.Join(configDir, "id_rsa"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
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
